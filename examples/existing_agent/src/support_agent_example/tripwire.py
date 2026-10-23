"""Only the adapter knows about the case context; the agent keeps its own loop."""
from contextlib import asynccontextmanager

from .agent import SupportAgent
from .fixture import ScriptedModel


class BudgetedModel:
    def __init__(self, context, model):
        self.context, self.model = context, model

    async def complete(self, messages, tools):
        return await self.context.model_call(self.model.complete, messages, tools)


@asynccontextmanager
async def create_application(context):
    # Fresh app, model and conversation for every attack AND every clean control.
    agent = SupportAgent(context.system, BudgetedModel(context, ScriptedModel()), context)
    try:
        yield agent
    finally:
        # A real application closes its per-case SDK sessions here as well.
        agent.messages.clear()
