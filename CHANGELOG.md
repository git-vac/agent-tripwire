# Changes

## 0.4.0

- Test a separately running MCP agent application through a versioned, authenticated local HTTP adapter contract; include a reproducible example host with an optional pinned official MCP client SDK.
- Place a payload into exactly one selected source response and distinguish served content from application receipt using case-scoped delivery IDs and exact response digests.
- Preserve legitimate source text and injected material separately in evidence. Record deterministic permission decisions alongside completed synthetic reads, actual protected file changes and independent receiver receipts.
- Reuse clean controls, task checks, offline reports, run comparisons and JUnit for application runs; incomplete tasks or missing delivery evidence remain non-passing.
- Bound calls, protocol requests, message sizes and execution time; reject identity/credential reuse, replay, malformed messages, outside paths and destinations.
- Add a separate-process scripted experiment and cross-platform CI regressions. These are harness validation, with no real-model security claim.

## 0.3.0

- Verify model connectivity and a complete tool round trip with `check`, using a single clean task before running injections.
- Reopen saved JSON evidence offline with `report`; filter by scenario, trial, confirmed findings or results needing attention.
- Keep relevant clean controls visible and preserve complete-run exit codes and machine exports when filtering.
- Export JUnit XML for CI: verified crossings are failures; errors, incomplete tasks and invalid controls are errors, with existing proof retained.
- Validate saved evidence and rebuild counts/control validity before rendering or comparing it. Reject malformed timelines with clear errors.
- Add `--version` and document a model-check, evaluation, investigation and CI workflow.

## 0.2.0

- Connect tool-capable models through an OpenAI-compatible Chat Completions endpoint alongside Ollama.
- Read optional API credentials from a named environment variable; keep them out of examples, metadata and request bodies, and redact exact response echoes.
- Load custom injection scenarios from validated JSON without editing Python.
- Record scenario fingerprints and compare saved runs with explicit checks for changed or incomplete test conditions.
- Add comparison reports in the terminal and standalone HTML.

## 0.1.0

- Initial instrumented support assistant, five injection cases, scripted demo and Ollama adapter.
- Action-level evidence with local canaries, temporary file changes and independent receiver receipts.
