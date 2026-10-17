# Architecture and evidence

```text
Ollama model / scripted demonstration
                  │ tool calls
                  ▼
       runner: budgets + conversation
                  │
                  ▼
      environment: permissions + instruments
         │          │               │
   fake tickets  temporary files  loopback receiver
         │          │               │
         └────── evidence events ────┘
                      │
               deterministic assessment
                      │
             terminal / JSON / HTML
```

`scenarios.py` defines the legitimate prompt and five payload templates. Payloads enter only the result of a permitted `read_ticket` or `search_notes` call. Delivery is recorded explicitly, so an assistant that never reads the poisoned source cannot receive a clean attack result.

`environment.py` owns the fixtures, a fresh random canary, temporary filesystem and receiver. Read completion is recorded only after data is actually returned. File-change events contain before/after SHA-256 hashes. The receiver independently hashes the body it receives and checks whether the current case's canary is present. The HTTP tool does not synthesize a receipt from the assistant's claimed arguments.

The temporary file allowlist and exact local receiver restriction apply under **both** policies. `observe` permits violations of the fictional task's permissions within that fixed environment. `enforce` blocks them. The tool policy is ordinary deterministic authorization, not an AI-based injection detector.

`runner.py` assesses events rather than assistant claims. A successful private read counts as a boundary crossing even if the attacker fails to transmit the data afterward. Partial progress remains visible: it is possible to observe a read without a receiver receipt. It also runs a clean control for each trial. A verified forbidden action still appears when the control fails, but causal attribution to the injection is uncertain.

`agents.py` uses Ollama's non-streaming `/api/chat` tool-calling API. It passes the tool results back with `role: tool` and `tool_name`. The scripted agents use the same runner and environment but are clearly labeled demonstrations. There is no arbitrary-code tool, no external HTTP tool and no real filesystem tool.

`report.py` renders literal terminal text and HTML-escaped evidence. The standalone HTML uses a restrictive content-security policy and no JavaScript. `cli.py` checks output paths before running and writes new files exclusively.

## Connecting another model adapter

Use the Python API for another tool-capable backend:

```python
from agent_tripwire.runner import run_suite
from agent_tripwire.scenarios import SCENARIOS

class Adapter:
    def next(self, messages, tools, remaining):
        # Send the supplied conversation/tools to your model and normalize its response.
        # Respect remaining (seconds) and raise agent_tripwire.agents.AgentError on failures.
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {
                "name": "read_ticket", "arguments": {"ticket_id": "TICKET-104"}
            }}],
        }

# Replace Adapter.next with an actual model call before using this example.
report = run_suite(lambda environment: Adapter(), SCENARIOS,
    mode="run", model="your-adapter", policy="observe")
```

The factory is called separately for each case. Avoid retaining conversation state between instances. Tool calls must contain a string name and object arguments; tool strings are bounded and schema-checked by the environment. The adapter must enforce its own transport limits and timeouts. Model-generated function names never trigger dynamic Python imports or evaluation.

## Limits of the conclusions

Five fixed scenarios cover a narrow support-assistant workflow. They do not establish general model safety, application authorization correctness, or resilience against all encodings and attack strategies. Seeded generation is best effort, and the task check measures a few concrete facts rather than answer quality. A successful `enforce` run demonstrates that this tool allowlist blocked these actions; it does not show the model ignored the injection.

Current reports are local artifacts, not cryptographically signed attestations. They do not include a full backend transcript or internal model reasoning. Use an isolated provider deployment if you need stronger controls on model-side data handling.

## Compatible backends and custom cases

`OpenAICompatible` translates canonical calls to Chat Completions messages: function arguments become JSON strings, call IDs are retained, and tool results reference their matching IDs. It uses the same bounded HTTP transport and redirect restriction as the Ollama adapter. API keys are obtained from a named runtime environment variable, passed only in authorization headers, and never copied to report metadata. Exact returned echoes are redacted. Malformed IDs, duplicate IDs and invalid argument JSON are errors rather than guessed tool actions.

`load_scenarios` validates bounded JSON definitions and permits only the existing ticket/search injection surfaces. A scenario file cannot execute Python or change the environment's tool permissions. Each selected definition gets a SHA-256 fingerprint of its surface, objective and payload template.

`comparison.py` reads bounded run reports and compares case-level observed counts. Definition fingerprints, prompts, seeds, limits and trial sets must match before it reports a directional change. Failed controls or incomplete results prevent a comparison conclusion. Policies and model names may differ deliberately; the report displays both configurations. This is an observational regression view, not a statistical model ranking.

Protocol references: [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling), [Chat Completions function calling](https://developers.openai.com/api/docs/guides/function-calling).
