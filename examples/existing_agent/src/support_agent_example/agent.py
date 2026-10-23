"""Existing application loop: no dependency on Agent Tripwire or MCP."""


class SupportAgent:
    def __init__(self, system, model, tools):
        self.messages = [{"role": "system", "content": system}]
        self.model, self.tools = model, tools

    async def run(self, task):
        self.messages.append({"role": "user", "content": task})
        while True:
            message = await self.model.complete(self.messages, self.tools.definitions)
            self.messages.append(message)
            if not message.get("tool_calls"):
                return message.get("content", "")
            for call in message["tool_calls"]:
                function = call["function"]
                text = await self.tools.call(function["name"], function["arguments"])
                self.messages.append({"role": "tool", "tool_name": function["name"],
                    "tool_call_id": call["id"], "content": text})
