"""Receipt-preserving MCP tools shared by independent application hosts."""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import time

from .agents import AgentError, Ollama


class ExecutionLimit(Exception):
    """A host budget expired before another operation could begin."""


class CaseTools:
    def __init__(self, request, session, client, listed, deadline):
        self.request, self.session, self.client = request, session, client
        self.deadline = deadline
        self.definitions = [{"type": "function", "function": {"name": tool.name,
            "description": tool.description or "", "parameters": tool.inputSchema}} for tool in listed.tools]
        self.names = {tool["function"]["name"] for tool in self.definitions}
        self.calls, self.exhausted = 0, False
        self.lock = asyncio.Lock()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.exhausted = True
            raise ExecutionLimit()
        return remaining

    async def call(self, name, arguments):
        # Frameworks may schedule a batch concurrently. Serialize the actual
        # effects and budget checks before anything reaches the tool server.
        async with self.lock:
            self.remaining()
            if self.calls >= self.request["limits"]["max_calls"]:
                self.exhausted = True
                raise ExecutionLimit()
            if name not in self.names:
                raise AgentError("Application requested an undiscovered tool")
            self.calls += 1
            result = await self.session.call_tool(name, arguments)
            if len(result.content) != 1 or result.content[0].type != "text":
                raise AgentError("Unsupported tool response")
            text = result.content[0].text
            metadata = (result.meta or {}).get("tripwire", {})
            if (set(metadata) != {"case_id", "delivery_id", "sha256"} or
                    metadata["case_id"] != self.request["case_id"] or
                    metadata["sha256"] != hashlib.sha256(text.encode()).hexdigest()):
                raise AgentError("Mismatched tool delivery identity or digest")
            value = json.loads(text)
            if (not isinstance(value, dict) or len(value) != 1 or
                    not (set(value) <= {"content", "error"}) or
                    any(not isinstance(item, str) for item in value.values())):
                raise AgentError("Malformed tool return value")
            acknowledged = await self.client.post(self.request["mcp"]["url"].removesuffix("/mcp") + "/ack", json=metadata)
            acknowledged.raise_for_status()
            return text


@asynccontextmanager
async def case_tools(request):
    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    capability = request["mcp"]
    deadline = time.monotonic() + request["limits"]["case_timeout"]
    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + capability["token"]},
            timeout=httpx.Timeout(5), trust_env=False, follow_redirects=False) as client:
        async with streamable_http_client(capability["url"], http_client=client,
                terminate_on_close=False) as (read, write, _):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                if initialized.protocolVersion != "2025-11-25":
                    raise AgentError("Unsupported MCP lab version")
                listed = await session.list_tools()
                yield CaseTools(request, session, client, listed, deadline)


class ModelBridge:
    """Translate framework messages to a bounded backend, without owning a loop."""
    def __init__(self, backend, channel):
        self.backend, self.channel = backend, channel
        self.turns, self.call_ids = 0, set()

    async def next(self, messages):
        if self.turns >= self.channel.request["limits"]["max_turns"]:
            self.channel.exhausted = True
            raise ExecutionLimit()
        self.turns += 1
        message = await asyncio.to_thread(self.backend.next, messages, self.channel.definitions, self.channel.remaining())
        message = Ollama.validate_message(message)
        for index, call in enumerate(message.get("tool_calls", [])):
            identifier = call["id"] if "id" in call else f"tripwire-{self.turns}-{index}"
            if not isinstance(identifier, str) or not identifier or identifier in self.call_ids:
                raise AgentError("Duplicate or invalid model tool call identity")
            self.call_ids.add(identifier)
            call["id"] = identifier
        return message
