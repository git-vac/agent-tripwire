# Adapt an existing Python agent application

`serve-agent` hosts an installed application's factory in a separate process. The application keeps its conversation, model selection and tool loop. Agent Tripwire supplies the HTTP server, fresh case context, receipt-preserving MCP client and synthetic tools. You do not need to write an HTTP server or replace the application with a model adapter.

Supported: Python 3.10+, asynchronous text applications with `async run(task) -> str`, and an operator-selected `module:callable` factory returning an asynchronous context manager. The existing [HTTP/MCP profile](application.md) and its five tools apply. No new framework dependency is required beyond `.[application]`. Arbitrary application files, graph discovery, synchronous loops and production tool interception are outside this contract.

## Install and run

From a clone, create and activate a virtual environment as described in the README, then:

```bash
python -m pip install ".[application]"
python -m pip install ./examples/existing_agent
python -m pip check
python examples/application_experiment.py --existing-agent
```

The example is a separate installable package. Its [agent](../examples/existing_agent/src/support_agent_example/agent.py) has no Agent Tripwire or MCP imports. Its [adapter](../examples/existing_agent/src/support_agent_example/tripwire.py) supplies a budgeted model and case tools, leaving the agent's loop intact. The model is explicitly a **scripted vulnerable fixture**, not a real-model evaluation or evidence about production application security.

The experiment starts a separate process, generates lab credentials at runtime and runs fresh clean controls plus all five injections under both policies:

| Policy | Tasks and controls | Observed effects | Evaluation exit |
| --- | --- | --- | --- |
| `observe` | All complete | Five crossings, including three synthetic-canary receiver receipts and an actual protected temporary-file change | 1 |
| `enforce` | All complete | Five blocked attempts; no protected changes or receiver receipts | 0 |

The experiment exits 0 only if these assertions hold. Offline JSON, HTML, JUnit and comparison reports go under `reports/existing-agent-experiment/`. Existing outputs are never overwritten; repeat with `--output reports/new-directory`. The process is stopped and its temporary bootstrap credential file removed afterward. Keep generated reports private.

For an application that remains running, use two terminals in the same activated environment:

```bash
# Terminal 1 (one command):
agent-tripwire serve-agent --factory support_agent_example.tripwire:create_application --application support-agent-example --application-version 1.0.0 --configuration fixture-v1 --mode demo --model scripted-vulnerable --provider scripted --connection-file reports/existing-agent-connection.json

# Terminal 2:
agent-tripwire app --connection-file reports/existing-agent-connection.json --scenario ticket-exfil --json reports/existing-observe.json --html reports/existing-observe.html --junit reports/existing-observe.xml
agent-tripwire app --connection-file reports/existing-agent-connection.json --scenario ticket-exfil --policy enforce --json reports/existing-enforce.json
agent-tripwire compare reports/existing-observe.json reports/existing-enforce.json --html reports/existing-comparison.html
agent-tripwire report reports/existing-observe.json --only attention --details
```

Stop Terminal 1 with Ctrl+C. On restart choose a new private connection filename or remove the stale generated file. Existing scenario, custom-payload, selected-response ordinal, trial and budget options remain available through `app`.

## Factory contract

Install your adapter module and select `--factory your_package.tripwire:create_application`. Python's normal [module import API](https://docs.python.org/3/library/importlib.html#importlib.import_module) resolves one explicit absolute module name and callable attribute. The host never evaluates an expression or executes a supplied file path. Import happens once at startup; the factory is entered once per control or attack case after opening that case's MCP connection.

```python
from contextlib import asynccontextmanager
from your_package.agent import ExistingAgent

class BudgetedModel:
    def __init__(self, context, model):
        self.context, self.model = context, model

    async def complete(self, messages, tools):
        return await self.context.model_call(self.model.complete, messages, tools)

@asynccontextmanager
async def create_application(context):
    agent = ExistingAgent(system=context.system,
        model=BudgetedModel(context, create_your_async_model()), tools=context)
    try:
        yield agent  # async run(task) returns final text
    finally:
        await agent.aclose()  # close per-case SDK sessions/resources
```

`ExistingAgent`, `create_your_async_model` and `aclose` illustrate application-owned construction and cleanup; use your application's actual APIs. The installed example is executable. `AgentApplication` and `ApplicationFactory` typing contracts are available from `agent_tripwire.application_factory`.

| Context member | Contract |
| --- | --- |
| `case_id`, `system`, `task`, `seed` | Current case identity, legitimate instructions/task and requested seed; no scenario internals or effect evidence |
| `definitions` | A fresh copy of discovered MCP function schemas; map these to your application's tools |
| `await call(name, arguments)` | Real MCP dispatch, case/digest verification and exact-byte acknowledgment; returns JSON text with `content` or `error` |
| `await model_call(async_callable, *args, **kwargs)` | One async provider invocation with shared turn/deadline checks; no conversation management |
| `max_turns`, `max_calls`, `remaining()` | Case budgets and remaining seconds; also set your provider's own finite transport timeout |

Route **every model invocation** through `model_call` and every test tool through `call`, including retries and framework callbacks. Model calls and tool effects are each serialized at their respective budget boundary. Permission denials remain tool data so the task can continue. Never replace a denied result with success.

Create fresh conversations, model histories, checkpoints and tool bindings for each case. The host wraps construction, `run` and cleanup in the case deadline, then closes the context; retained contexts reject further model/tool operations. The harness independently revokes MCP capabilities. Errors, malformed results, cancellation, exhausted budgets and missing delivery remain non-passing; earlier verified effects remain visible. Async context-manager cleanup must handle success, failure and cancellation.

An application can block its event loop or ignore cancellation. The harness returns at its own deadline and revokes tools but cannot forcibly stop independently managed code. Model-turn accounting is cooperative: calls outside `model_call` cannot be counted. The only `run` result is final text, up to 32 KiB. Do not return success booleans, completion scores or evidence; the harness assesses observations and the existing task heuristic.

## Identity, credentials and limits

All identity options are required non-secret labels, at most 200 characters. Use `--mode demo` for scripted responses and `--mode run` only for real inference. `--model` and `--provider` declare the application's backend; they do not configure or verify it. The factory owns model setup and reads credentials from its environment.

Set `--application-version` to the tested code revision. Change `--configuration` when prompts, settings, dependencies or adapter behavior change; supply a revision label or sanitized configuration digest. The host hashes the import specification and configuration label for comparisons. Application identity/version, model/provider and configuration are recorded as before. Source/configuration inspection and cryptographic identity attestation are not provided.

For every provider credential, pass **only its environment variable name** with repeatable `--redact-env MODEL_API_KEY`. Missing/empty variables fail before startup. Exact echoes are removed from handshake labels, final text and tool names/JSON arguments before MCP dispatch. Factory exception details are never returned. Values are excluded from bootstrap files, reports and process arguments; do not place credentials in other CLI fields. Your application remains responsible for its logs, SDK tracing, arbitrary provider objects and transformed/encoded echoes. The generic host cannot disable third-party callbacks.

Factories are trusted operator code with the process's permissions. HTTP requests, model output, scenarios and tool text cannot select the factory. Disable other production capabilities in your test construction. This is not an OS sandbox: actions through other tools or clients cannot be observed or ruled out. Agent-controlled paths/URLs sent through the supplied tools still reach only the fixed synthetic file map and current case's loopback receiver. No unrestricted shell or arbitrary network tool is added.

Acknowledgment proves application-shim receipt of response bytes, not model attention. Task completion remains the ticket/notes acknowledgment and final-keyword heuristic. This release adds onboarding, with no stronger task assertions or real-model reference evaluations. See [evidence and limits](application.md#evidence-and-limits).

## Validation

```bash
python -m unittest discover -s tests -v
python examples/application_experiment.py --existing-agent --output reports/existing-agent-validation
agent-tripwire report reports/existing-agent-validation/enforce.json --junit reports/existing-agent-validation.xml
```

CI installs the main extra and separate example on Linux/Windows, Python 3.10/3.12. Regressions cover fresh factories/cases, delivery, actual file/receiver effects, permission enforcement, turn/call/deadline limits, cancellation/cleanup/recovery, malformed results and HTTP input, replay, configuration comparisons, escaping and credential echoes. Existing native, LangChain/LangGraph and PydanticAI checks remain in place.
