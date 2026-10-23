"""A LangChain create_agent / LangGraph application, using case MCP tools."""
from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from langsmith import tracing_context
from pydantic import Field

from .agents import AgentError
from .host_tools import ModelBridge, case_tools


def canonical_messages(messages):
    canonical = []
    for message in messages:
        if not isinstance(message.content, str):
            raise AgentError("This host supports text messages only")
        if isinstance(message, SystemMessage):
            item = {"role": "system", "content": message.content}
        elif isinstance(message, HumanMessage):
            item = {"role": "user", "content": message.content}
        elif isinstance(message, ToolMessage):
            item = {"role": "tool", "tool_name": message.name,
                "tool_call_id": message.tool_call_id, "content": message.content}
        elif isinstance(message, AIMessage):
            item = {"role": "assistant", "content": message.content}
            if message.tool_calls:
                item["tool_calls"] = [{"id": call["id"], "function": {"name": call["name"],
                    "arguments": call["args"]}} for call in message.tool_calls]
            if "tripwire_thinking" in message.additional_kwargs:
                item["thinking"] = message.additional_kwargs["tripwire_thinking"]
        else:
            raise AgentError("Unsupported framework message")
        canonical.append(item)
    return canonical


class TripwireChatModel(BaseChatModel):
    bridge: Any = Field(exclude=True)

    @property
    def _llm_type(self):
        return "tripwire-bounded-model-bridge"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        raise AgentError("Use the asynchronous framework host")

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        message = await self.bridge.next(canonical_messages(messages))
        calls = [{"id": call["id"], "name": call["function"]["name"],
            "args": call["function"]["arguments"], "type": "tool_call"} for call in message.get("tool_calls", [])]
        private = {"tripwire_thinking": message["thinking"]} if "thinking" in message else {}
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=message.get("content", ""),
            tool_calls=calls, additional_kwargs=private))])


def native_tools(channel):
    tools = []
    for item in channel.definitions:
        function = item["function"]
        def bind(name):
            async def invoke(**arguments):
                return await channel.call(name, arguments)
            return invoke
        tools.append(StructuredTool.from_function(coroutine=bind(function["name"]), name=function["name"],
            description=function["description"], args_schema=function["parameters"], infer_schema=False))
    return tools


async def conversation(request, factory):
    async with case_tools(request) as channel:
        bridge = ModelBridge(factory(request["seed"]), channel)
        # Never export synthetic evidence or provider data through ambient tracing.
        with tracing_context(enabled=False):
            graph = create_agent(TripwireChatModel(bridge=bridge), native_tools(channel),
                system_prompt=request["system"])
            result = await graph.ainvoke({"messages": [{"role": "user", "content": request["task"]}]},
                config={"callbacks": [], "recursion_limit": request["limits"]["max_turns"] * 3 + 2})
        final = result["messages"][-1]
        if not isinstance(final, AIMessage) or final.tool_calls or not isinstance(final.content, str):
            raise AgentError("Framework did not return a final text answer")
        return final.content, channel.exhausted
