"""A PydanticAI Agent application, with native tools backed by case MCP."""
import json

from pydantic_ai import Agent, Tool
from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import UsageLimits

from .agents import AgentError
from .host_tools import ModelBridge, case_tools


def canonical_messages(messages):
    canonical = []
    for message in messages:
        if isinstance(message, ModelRequest):
            for part in message.parts:
                kind = part.part_kind
                if kind in ("system-prompt", "user-prompt"):
                    if not isinstance(part.content, str):
                        raise AgentError("This host supports text messages only")
                    canonical.append({"role": "system" if kind == "system-prompt" else "user", "content": part.content})
                elif kind == "tool-return":
                    content = part.content if isinstance(part.content, str) else json.dumps(part.content)
                    canonical.append({"role": "tool", "tool_name": part.tool_name,
                        "tool_call_id": part.tool_call_id, "content": content})
                elif kind == "retry-prompt" and part.tool_name and part.tool_call_id:
                    canonical.append({"role": "tool", "tool_name": part.tool_name,
                        "tool_call_id": part.tool_call_id, "content": json.dumps({"error": "Framework rejected invalid tool input"})})
                else:
                    raise AgentError("Unsupported framework request part")
        elif isinstance(message, ModelResponse):
            text, calls = [], []
            for part in message.parts:
                if part.part_kind == "text":
                    text.append(part.content)
                elif part.part_kind == "tool-call":
                    calls.append({"id": part.tool_call_id, "function": {"name": part.tool_name,
                        "arguments": part.args_as_dict()}})
                else:
                    raise AgentError("Unsupported framework response part")
            item = {"role": "assistant", "content": "".join(text)}
            if calls:
                item["tool_calls"] = calls
            if message.provider_details and "tripwire_thinking" in message.provider_details:
                item["thinking"] = message.provider_details["tripwire_thinking"]
            canonical.append(item)
        else:
            raise AgentError("Unsupported framework message")
    return canonical


def native_tools(channel):
    tools = []
    for item in channel.definitions:
        function = item["function"]
        def bind(name):
            async def invoke(**arguments):
                return await channel.call(name, arguments)
            return invoke
        tools.append(Tool.from_schema(bind(function["name"]), name=function["name"],
            description=function["description"], json_schema=function["parameters"], sequential=True))
    return tools


async def conversation(request, factory):
    async with case_tools(request) as channel:
        bridge = ModelBridge(factory(request["seed"]), channel)

        async def model_function(messages, info):
            message = await bridge.next(canonical_messages(messages))
            parts = [TextPart(message["content"])] if message.get("content") else []
            parts.extend(ToolCallPart(call["function"]["name"], call["function"]["arguments"], call["id"])
                for call in message.get("tool_calls", []))
            private = {"tripwire_thinking": message["thinking"]} if "thinking" in message else None
            return ModelResponse(parts=parts, provider_details=private)

        agent = Agent(FunctionModel(model_function, model_name="tripwire-bounded-model-bridge"),
            tools=native_tools(channel), system_prompt=request["system"], retries=0, name="tripwire_case")
        # Override even a process-wide Agent.instrument_all() setting.
        agent.instrument = False
        result = await agent.run(request["task"], usage_limits=UsageLimits(request_limit=None), infer_name=False)
        if not isinstance(result.output, str):
            raise AgentError("Framework did not return a final text answer")
        return result.output, channel.exhausted
