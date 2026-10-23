"""Operator-selected factories for existing Python agent applications."""
import asyncio
import copy
import hashlib
import importlib
import inspect
import json
import re
from typing import AsyncContextManager, Callable, Protocol

from .application_host import ApplicationHost
from .application_wire import PROTOCOL
from .host_tools import ExecutionLimit, case_tools


class AgentApplication(Protocol):
    async def run(self, task: str) -> str: ...


def load_factory(specification) -> "ApplicationFactory":
    """Import only an explicit installed module:callable; never eval or a file."""
    if not isinstance(specification, str) or not re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", specification, flags=re.ASCII):
        raise ValueError("Factory must be an installed module:callable")
    module, name = specification.split(":")
    try:
        factory = getattr(importlib.import_module(module), name)
        if not callable(factory):
            raise TypeError()
    except Exception:
        # Import errors can contain configuration or credentials. Keep them local.
        raise ValueError("Cannot load application factory; check its installation and callable") from None
    return factory


class FactoryContext:
    """One case's tool boundary and cooperative model budget, not a model loop."""
    def __init__(self, request, channel, redactions=()):
        self.case_id, self.system, self.task, self.seed = (
            request[key] for key in ("case_id", "system", "task", "seed"))
        self.max_turns = request["limits"]["max_turns"]
        self.max_calls = request["limits"]["max_calls"]
        self._channel, self._turns, self._active = channel, 0, True
        self._redactions = tuple(redactions)
        self._model_lock = asyncio.Lock()

    @property
    def definitions(self):
        # Framework schema edits must not mutate discovery state or another case.
        return copy.deepcopy(self._channel.definitions)

    def remaining(self):
        if not self._active:
            raise ExecutionLimit()
        return self._channel.remaining()

    async def model_call(self, invoke, *args, **kwargs):
        """Await one async provider invocation within the case's turn/deadline budget."""
        async with self._model_lock:
            remaining = self.remaining()
            if self._turns >= self.max_turns:
                self._channel.exhausted = True
                raise ExecutionLimit()
            self._turns += 1
            result = invoke(*args, **kwargs)
            if not inspect.isawaitable(result):
                raise TypeError("model_call requires an asynchronous provider invocation")
            result = await asyncio.wait_for(result, remaining)
            self.remaining()  # Reject a response returned after cancellation/deadline.
            return result

    async def call(self, name, arguments):
        self.remaining()
        # Remove exact known credential echoes before they reach server evidence.
        # The MCP boundary accepts JSON values, regardless of provider message type.
        def redact(value):
            if isinstance(value, str):
                for secret in self._redactions:
                    value = value.replace(secret, "[REDACTED CREDENTIAL]")
            elif isinstance(value, dict):
                value = {redact(key): redact(item) for key, item in value.items()}
            elif isinstance(value, list):
                value = [redact(item) for item in value]
            return value
        return await self._channel.call(redact(name), redact(arguments))

    def close(self):
        self._active = False


ApplicationFactory = Callable[[FactoryContext], AsyncContextManager[AgentApplication]]


class FactoryApplication(ApplicationHost):
    def __init__(self, specification, *, application, version, mode, model, provider,
            configuration, redactions=()):
        if not isinstance(configuration, str) or not configuration or len(configuration) > 200:
            raise ValueError("Configuration must be a non-secret revision label of at most 200 characters")
        info = {"protocol": PROTOCOL, "application": application, "version": version,
            "mode": mode, "model": model, "provider": provider,
            "configuration": hashlib.sha256(json.dumps([specification, configuration], sort_keys=True).encode()).hexdigest()}
        super().__init__(info, self.conversation, redactions)
        # Validate identity before importing operator code. Never accept this path over HTTP.
        self.factory = load_factory(specification)

    async def conversation(self, request):
        async with case_tools(request) as channel:
            context = FactoryContext(request, channel, [*self.secrets, request["mcp"]["token"]])
            try:
                async with self.factory(context) as agent:
                    if not callable(getattr(agent, "run", None)):
                        raise TypeError("Factory must yield an application with async run(task)")
                    final = await agent.run(context.task)
                return final, channel.exhausted
            finally:
                # Retained contexts cannot issue another call after this case ends.
                context.close()
