# Changes

## 0.2.0

- Connect tool-capable models through an OpenAI-compatible Chat Completions endpoint alongside Ollama.
- Read optional API credentials from a named environment variable; keep them out of examples, metadata and request bodies, and redact exact response echoes.
- Load custom injection scenarios from validated JSON without editing Python.
- Record scenario fingerprints and compare saved runs with explicit checks for changed or incomplete test conditions.
- Add comparison reports in the terminal and standalone HTML.

## 0.1.0

- Initial instrumented support assistant, five injection cases, scripted demo and Ollama adapter.
- Action-level evidence with local canaries, temporary file changes and independent receiver receipts.
