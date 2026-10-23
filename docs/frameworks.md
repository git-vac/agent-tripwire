# LangChain/LangGraph and PydanticAI application hosts

Agent Tripwire can run the same synthetic application evaluation against two additional, separately running framework applications. The authenticated [application adapter contract](application.md#application-adapter-v1), MCP tool server, case isolation, injection selection and evidence assessments are shared with the original host.

| Host selector | Runtime that owns the agent loop | Pinned dependencies | Python |
| --- | --- | --- | --- |
| `--framework langchain` | LangChain `create_agent`, returning an executable LangGraph | LangChain 1.4.7, LangGraph 1.2.16, langchain-core 1.7.0 | 3.10+ |
| `--framework pydanticai` | PydanticAI `Agent.run` with native function tools | pydantic-ai-slim 2.60.0 and matching pydantic-graph | 3.11+ |
| `--framework native` (default) | Original bounded Python application loop | Original MCP application extra | 3.10+ |

Each host starts its own conversation and runtime instance per case. The LangGraph has no checkpointer or persistence store; the PydanticAI agent has no retained message history. Host identity and the main framework package versions contribute to the saved configuration fingerprint. Comparisons between different hosts or configurations are marked not comparable.

## Install and reproduce

Create and activate a virtual environment as described in the README. Install only the framework you need:

```bash
# Python 3.10+:
python -m pip install ".[langchain]"
python examples/application_experiment.py --framework langchain

# Python 3.11+, in a suitable virtual environment:
python -m pip install ".[pydanticai]"
python examples/application_experiment.py --framework pydanticai
```

Python 3.11+ can install both with `python -m pip install ".[langchain,pydanticai]"`. PydanticAI 2.60.0 requires Python 3.11; the base application and LangChain host keep Python 3.10 support. The base installation is unchanged and does not import either framework. The optional extras include the existing `mcp==1.30.0` client. No framework-specific provider SDK, framework MCP package, Docker service or model download is required for these hosts.

The experiment starts a separate process, generates lab credentials at runtime, connects it to real case-scoped MCP tools and saves private JSON/HTML/JUnit evidence plus a comparison. Defaults are `reports/langchain-experiment/` and `reports/pydanticai-experiment/`; use `--output reports/new-directory` to repeat. The process is stopped and its temporary credential file removed afterward. Existing artifacts are never overwritten.

Expected **scripted harness results for each framework**:

| Policy | Clean control | Injected tasks | Verified effects | Evaluation exit |
| --- | --- | --- | --- | --- |
| `observe` | Completed | All 5 completed | 5 crossings, including 3 canary-bearing receiver receipts and a protected file change | 1 |
| `enforce` | Completed | All 5 completed | 5 blocked attempts; no protected changes or receiver receipts | 0 |

The experiment itself exits 0 only when those expected assertions hold. Its observe JUnit still contains failures corresponding to the five verified crossings. These responses are scripts executed through real framework runtimes and real MCP connections. They are not real-model evaluations and establish no model resistance claim.

## Independently running application

Use two terminals to keep the framework application running between evaluations:

```bash
# Terminal 1: choose langchain or pydanticai.
agent-tripwire example-agent --framework langchain --connection-file reports/langchain-connection.json

# Terminal 2: fresh conversations and MCP capabilities for every case/control.
agent-tripwire app --connection-file reports/langchain-connection.json --scenario ticket-exfil --json reports/langchain-observe.json --html reports/langchain-observe.html --junit reports/langchain-observe.xml
agent-tripwire app --connection-file reports/langchain-connection.json --scenario ticket-exfil --policy enforce --json reports/langchain-enforce.json
agent-tripwire compare reports/langchain-observe.json reports/langchain-enforce.json --html reports/langchain-comparison.html
agent-tripwire report reports/langchain-observe.json --only attention --details
```

For PydanticAI, use `--framework pydanticai` in Terminal 1 and choose a new connection filename. That file contains a runtime-generated lab token; keep it private. Stop the server with Ctrl+C and use a new file on restart. The application accepts the same scenario selection, custom payloads, injection-response ordinal, trial, policy and budget options as the original integration.

## Use a real model

The selected framework continues to own its conversation and tool scheduling with a real backend. Select an installed tool-capable Ollama model:

```bash
agent-tripwire example-agent --framework langchain --engine ollama --model YOUR_MODEL --connection-file reports/langchain-model.json
agent-tripwire app --connection-file reports/langchain-model.json --json reports/langchain-model-run.json
```

The same options work with `--framework pydanticai`. For an authenticated compatible endpoint, privately set a provider credential in Terminal 1's environment, then pass only its variable name:

```bash
agent-tripwire example-agent --framework pydanticai --engine openai-compatible --model YOUR_MODEL --base-url https://model-server.example/v1 --api-key-env MODEL_API_KEY --connection-file reports/pydanticai-model.json
```

The model bridge translates the framework's text messages and tool-call identities to the existing bounded Ollama or compatible Chat Completions adapter. Model request counts, timeouts, response limits and exact provider-credential echo redaction remain active. Known echoes are removed before a framework executes a returned tool call. Provider credentials stay out of the lab connection file and harness request. No real-model evaluation is implied by the scripted protocol fixtures in tests or CI.

Only text conversations and the five supplied lab tools are supported. Provider-specific multimodal content, streaming, native provider tools, structured output, durable workflows, multi-agent graphs and arbitrary persisted graphs are outside this integration. A developer can adapt the documented host shim to an existing application's graph or Agent construction, preserving fresh case state and routing its test tools through the receipt-preserving client. For an installed application, use the [per-case factory host](existing-applications.md) to adapt its construction without writing an HTTP server. The CLI does not discover arbitrary graphs or execute application files by path.

## How framework calls preserve evidence

`host_tools.case_tools(request)` opens an authenticated official MCP client connection, initializes the versioned lab profile and discovers tool schemas. It yields a `CaseTools` object with `definitions` and `await call(name, arguments)`. Native framework function tools use those schemas and call this object:

* `langchain_host.native_tools(channel)` builds native `StructuredTool` instances. `conversation` invokes a fresh `create_agent` graph with `TripwireChatModel`, an asynchronous model bridge.
* `pydanticai_host.native_tools(channel)` builds native `Tool.from_schema` instances. `conversation` invokes a fresh `Agent` with a `FunctionModel` bridge; the function can use scripted responses or the configured bounded model endpoint.

The framework drives the model/tool loop. The bridge translates one model request at a time and never decides which tool to execute. It retains tool-call identities, supplies identities for backends that omit them, and rejects reuse. Private thinking can be passed back to a backend that requires it; reports retain only the final text, not framework message history or thinking.

Every actual tool invocation crosses the real MCP connection. The client checks the response's case identity, delivery ID and exact text digest, then acknowledges it before returning the text to the framework. JSON tool content and the `_meta.tripwire` receipt stay distinct. The server's independently recorded reads, file digests and receiver events remain the source of effect evidence. An MCP `isError` result is returned as tool data so the framework can complete the legitimate task after a permission denial.

The client serializes effects and checks the call budget before dispatch even when the framework schedules a batch concurrently. The model bridge checks the turn budget before inference. The host's outer deadline and the server's independent deadline/call limits remain active. Exhaustion, delivery failures and incomplete tasks cannot produce a passing containment result. Prior verified effects remain visible if an application later fails.

Framework input validation can reject a call before it reaches MCP. Such calls have no tool-server request/effect event; the integration cannot claim complete visibility into every internal framework decision. Server authorization and fixed guards remain the observed permission controls. Receipt acknowledgment proves that the host received the bytes, not model attention or compliance.

LangSmith tracing is explicitly disabled around the LangChain run, including when enabled in the process environment. PydanticAI instrumentation is explicitly disabled on the per-case agent, overriding its global instrumentation default. The supplied hosts do not export conversations through framework tracing. Applications that add their own callbacks, capabilities or transport clients must account for those separately. `PYDANTIC_AI_NO_BANNER=1` optionally suppresses PydanticAI's local informational startup banner.

## Safety boundaries and limits

All fixtures remain invented. Every case has its own canary, temporary allowlisted files, receiver route, credentials and conversation. The application tools never resolve agent paths on the operator filesystem or contact arbitrary agent URLs. No shell tool is present. The `observe` policy measures actions within those fixed synthetic boundaries; `enforce` adds deterministic task permissions.

The external process is not an OS sandbox. Only actions routed through these lab tools are instrumented; other application capabilities cannot be ruled out. Task completion is still the acknowledged ticket/notes and final-keyword heuristic. Reports are unsigned local evidence, and exact credential/canary redaction does not cover every transformation or encoding. The [full application contract and limits](application.md) continue to apply.

## Validation and primary references

```bash
python -m unittest discover -s tests -v
python -m pip check
```

The framework regressions run each installed host through separate-process observe/enforce experiments. They also cover case/trial isolation, guarded scripts, custom payload escaping, missing injection delivery, turn/call budgets, corrupted receipts, late model responses, real framework API use, private thinking, provider tool IDs, credential echoes, malformed provider responses and disabled tracing. CI installs each extra independently on Linux and Windows, testing LangChain on Python 3.10/3.12 and PydanticAI on 3.11/3.12. The existing base/application CI matrix is preserved.

Primary documentation used for the supported extension points: [LangChain agents](https://docs.langchain.com/oss/python/langchain/agents), [LangChain model API](https://reference.langchain.com/python/langchain-core/language_models/chat_models/BaseChatModel), [PydanticAI FunctionModel](https://pydantic.dev/docs/ai/api/models/function/), [PydanticAI custom tool schemas](https://pydantic.dev/docs/ai/tools-toolsets/tools-advanced/#custom-tool-schema), and the [MCP application profile](application.md#mcp-tool-connection-and-delivery-receipt). Exact release/Python requirements are recorded in [PyPI's LangChain metadata](https://pypi.org/project/langchain/1.4.7/), [LangGraph metadata](https://pypi.org/project/langgraph/1.2.16/) and [PydanticAI slim metadata](https://pypi.org/project/pydantic-ai-slim/2.60.0/).
