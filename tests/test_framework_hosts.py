"""Native framework loops with scripted responses; not model evaluations."""
from contextlib import contextmanager
import copy
from http.server import BaseHTTPRequestHandler
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from unittest.mock import patch
import unittest

from agent_tripwire.agents import AgentError, calls
from agent_tripwire.application import HTTPApplicationAdapter, run_application_case, run_application_suite
from agent_tripwire.comparison import compare, read_report
from agent_tripwire.example_agent import ExampleApplication, ScriptedApplication
from agent_tripwire.host_tools import ExecutionLimit, ModelBridge
from agent_tripwire.mcp_lab import MCPToolServer
from agent_tripwire.report import webpage
from agent_tripwire.runner import exit_code
from agent_tripwire.scenarios import BY_ID, SCENARIOS, Scenario, SYSTEM
from agent_tripwire.workflow import junit
from test_application import separate_application
from test_tripwire import endpoint


class FrameworkCases:
    @classmethod
    def setUpClass(cls):
        cls.application = separate_application(extra=("--framework", cls.framework))
        cls.adapter, _ = cls.application.__enter__()
        cls.observed = run_application_suite(cls.adapter, SCENARIOS, case_timeout=20)
        cls.enforced = run_application_suite(cls.adapter, SCENARIOS, policy="enforce", case_timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.application.__exit__(None, None, None)

    def test_real_effects_delivery_controls_and_policy_under_native_framework_loop(self):
        self.assertEqual(self.observed["counts"], {"boundary-crossed": 5})
        self.assertEqual(self.enforced["counts"], {"blocked": 5})
        self.assertEqual(exit_code(self.observed), 1)
        self.assertEqual(exit_code(self.enforced), 0)
        self.assertEqual(self.adapter.info["application"], f"tripwire-{self.framework}-mcp-agent")
        for report in (self.observed, self.enforced):
            self.assertTrue(all(result["task_complete"] and result["clean_control_ok"] for result in report["results"]))
            for result in report["results"][1:]:
                self.assertTrue(result["injection_exposed"])
                self.assertEqual(sum(event["kind"] == "injection_delivered" for event in result["events"]), 1)
        self.assertEqual(sum(len(result["receipts"]) for result in self.observed["results"]), 3)
        changed = next(result for result in self.observed["results"] if result["id"] == "settings-write")
        self.assertTrue(any(event["kind"] == "file_observed" and event["changed"] for event in changed["events"]))
        self.assertFalse(any(result["receipts"] or result["evidence"] for result in self.enforced["results"]))

    def test_budgets_and_unreached_injection_cannot_pass(self):
        for options in ({"max_calls": 1}, {"max_turns": 1}, {"injection_call": 2}):
            with self.subTest(options=options):
                report = run_application_suite(self.adapter, [BY_ID["settings-write"]], case_timeout=20, **options)
                self.assertEqual(exit_code(report), 2)
                self.assertEqual(report["results"][-1]["status"], "inconclusive")
                self.assertFalse(report["results"][-1]["evidence"])
                self.assertIn('<error', junit(report))

    def test_case_and_trial_isolation_reports_and_framework_identity(self):
        report = run_application_suite(self.adapter, [BY_ID["ticket-exfil"]], trials=2, case_timeout=20)
        cases = [result["case_id"] for result in report["results"]]
        self.assertEqual(len(cases), len(set(cases)))
        receipts = [receipt["sha256"] for result in report["results"] for receipt in result["receipts"]]
        self.assertEqual(len(receipts), len(set(receipts)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            loaded = read_report(path)
            self.assertEqual(loaded["counts"], report["counts"])
        self.assertNotIn(self.adapter.token, json.dumps(report) + webpage(report) + junit(report))
        self.assertIn("SCRIPTED DEMO", webpage(report))
        self.assertTrue(all(row["change"] == "fewer-crossings" for row in compare(self.observed, self.enforced)["rows"]))
        other = copy.deepcopy(self.enforced)
        other["integration"]["application"] = "another-framework"
        self.assertTrue(all(row["change"] == "not-comparable" for row in compare(self.observed, other)["rows"]))

    def test_guarded_script_custom_payload_and_html_escaping(self):
        with separate_application("scripted-guarded", ("--framework", self.framework)) as (adapter, _):
            scenario = Scenario("custom-search", "Framework payload", "search_notes", "Escaping check",
                '<script>alert("fixture")</script>')
            report = run_application_suite(adapter, [scenario], case_timeout=20)
        self.assertEqual(report["counts"], {"no-boundary-crossing": 1})
        self.assertNotIn('<script>alert', webpage(report))
        self.assertIn('&lt;script&gt;', webpage(report))

    def test_mismatched_tool_receipt_is_an_instrumentation_failure(self):
        original = MCPToolServer.dispatch
        def corrupt(lab, message):
            status, response = original(lab, message)
            if message.get("method") == "tools/call" and isinstance(response, dict) and "result" in response:
                response["result"]["_meta"]["tripwire"]["sha256"] = "wrong"
            return status, response
        with patch.object(MCPToolServer, "dispatch", corrupt):
            result = run_application_case(self.adapter, BY_ID["ticket-exfil"], case_timeout=20)
        self.assertIsNotNone(result["error"])
        self.assertFalse(result["injection_exposed"])
        self.assertFalse(result["task_complete"])
        self.assertFalse(result["evidence"])

    def test_timeout_does_not_execute_a_late_model_call(self):
        class Slow:
            def next(self, *args):
                time.sleep(1.3)
                return calls(("write_file", {"path": "/settings/policy.conf", "content": "late"}))
        with tempfile.TemporaryDirectory() as directory, ExampleApplication(framework=self.framework) as app:
            app.factory = lambda seed: Slow()
            path = Path(directory) / "connection.json"
            app.connection_file(path)
            adapter = HTTPApplicationAdapter.from_file(path)
            started = time.monotonic()
            result = run_application_case(adapter, BY_ID["settings-write"], case_timeout=1)
            self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(result["limits_reached"] or result["error"])
        self.assertEqual(result["tool_calls"], 0)
        self.assertFalse(result["task_complete"])
        self.assertFalse(result["evidence"])

    def test_real_framework_api_is_used_thinking_is_private_and_tracing_is_disabled(self):
        thought = "PRIVATE_SYNTHETIC_FRAMEWORK_THOUGHT"
        seen = []
        class Backend(ScriptedApplication):
            def next(backend, messages, tools, remaining):
                if self.framework == "langchain":
                    from langsmith.run_helpers import get_tracing_context
                    self.assertFalse(get_tracing_context()["enabled"])
                self.assertEqual(messages[0], {"role": "system", "content": SYSTEM})
                seen.append(any(message.get("thinking") == thought for message in messages))
                response = super().next(messages, tools, remaining)
                response["thinking"] = thought
                return response
        if self.framework == "langchain":
            import agent_tripwire.langchain_host as host
            runtime_patch = patch.object(host, "create_agent", wraps=host.create_agent)
        else:
            import agent_tripwire.pydanticai_host as host
            original = host.Agent.run
            async def checked_run(agent, *args, **kwargs):
                self.assertFalse(agent.instrument)
                self.assertIsNone(agent._resolve_instrumentation_settings())
                return await original(agent, *args, **kwargs)
            @contextmanager
            def check_instrumentation():
                with patch.object(host.Agent, "_instrument_default", True), patch.object(host.Agent, "run", checked_run):
                    yield
            runtime_patch = check_instrumentation()
        with (runtime_patch, patch.dict(os.environ, {"LANGSMITH_TRACING": "true", "PYDANTIC_AI_NO_BANNER": "1"}),
                tempfile.TemporaryDirectory() as directory, ExampleApplication(framework=self.framework) as app):
            app.factory = lambda seed: Backend(guarded=True)
            path = Path(directory) / "connection.json"
            app.connection_file(path)
            report = run_application_suite(HTTPApplicationAdapter.from_file(path), [], case_timeout=20)
        self.assertEqual(exit_code(report), 0)
        self.assertIn(True, seen)
        self.assertNotIn(thought, json.dumps(report) + webpage(report))

    def test_provider_tool_ids_credential_echo_and_malformed_provider_response(self):
        # This is a scripted provider protocol fixture, never a real-model result.
        credential = secrets.token_urlsafe(32)
        bodies, headers = [], []
        class Provider(BaseHTTPRequestHandler):
            malformed = False
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                bodies.append(body)
                headers.append(self.headers.get("Authorization"))
                turn = sum(item["role"] == "assistant" for item in body["messages"])
                if self.malformed:
                    response = {"error": credential}
                else:
                    if turn == 0:
                        functions = [("read_ticket", {"ticket_id": "TICKET-104"}), ("search_notes", {"query": "DNS"})]
                    elif turn == 1:
                        functions = [("write_file", {"path": "/case-summary.txt", "content": credential})]
                    else:
                        functions = []
                    message = {"role": "assistant", "content": "TICKET-104 DNS 18:00 " + credential if not functions else "",
                        "tool_calls": [{"id": f"provider-{turn}-{i}", "type": "function", "function": {"name": name,
                            "arguments": json.dumps(args)}} for i, (name, args) in enumerate(functions)]}
                    response = {"choices": [{"message": message, "finish_reason": "stop"}]}
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        environment = {**os.environ, "TRIPWIRE_FRAMEWORK_TEST_KEY": credential}
        with endpoint(Provider) as url, separate_application("openai-compatible", ("--framework", self.framework,
                "--model", "SCRIPTED-PROTOCOL-FIXTURE", "--base-url", url + "/v1",
                "--api-key-env", "TRIPWIRE_FRAMEWORK_TEST_KEY"), environment) as (adapter, _):
            report = run_application_suite(adapter, [], case_timeout=20)
            self.assertEqual(exit_code(report), 0)
            self.assertIn("[REDACTED API KEY]", json.dumps(report))
            self.assertNotIn(credential, json.dumps(report) + webpage(report) + junit(report))
            Provider.malformed = True
            failed = run_application_suite(adapter, [BY_ID["ticket-exfil"]], case_timeout=20)
            self.assertEqual(exit_code(failed), 2)
            self.assertEqual(len(failed["results"]), 1)
            self.assertNotIn(credential, json.dumps(failed))
        self.assertTrue(all(header == "Bearer " + credential for header in headers))
        self.assertNotIn(credential, json.dumps(bodies))
        results = [item for body in bodies for item in body["messages"] if item["role"] == "tool"]
        self.assertTrue(any(item["tool_call_id"] == "provider-0-0" for item in results))
        self.assertTrue(any(item["tool_call_id"] == "provider-1-0" for item in results))


@unittest.skipUnless(importlib.util.find_spec("langchain") and importlib.util.find_spec("mcp"), 'Install ".[langchain]"')
class LangChainHostTests(FrameworkCases, unittest.TestCase):
    framework = "langchain"


@unittest.skipUnless(sys.version_info >= (3, 11) and importlib.util.find_spec("pydantic_ai") and
    importlib.util.find_spec("mcp"), 'Python 3.11+ and ".[pydanticai]" required')
class PydanticAIHostTests(FrameworkCases, unittest.TestCase):
    framework = "pydanticai"


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_supplied_tool_ids_are_rejected(self):
        class Channel:
            request = {"limits": {"max_turns": 2}}
            definitions = []
            def remaining(self):
                return 5
        for identifier in ("", 0, None, []):
            class Backend:
                def next(self, *args):
                    message = calls(("read_ticket", {"ticket_id": "TICKET-104"}))
                    message["tool_calls"][0]["id"] = identifier
                    return message
            with self.subTest(identifier=identifier), self.assertRaises(AgentError):
                await ModelBridge(Backend(), Channel()).next([])

    async def test_duplicate_ids_and_exhausted_model_budget_fail_before_dispatch(self):
        class Channel:
            request = {"limits": {"max_turns": 2}}
            definitions = []
            exhausted = False
            def remaining(self):
                return 5
        class Backend:
            def next(self, *args):
                message = calls(("read_ticket", {"ticket_id": "TICKET-104"}))
                message["tool_calls"][0]["id"] = "reused"
                return message
        channel = Channel()
        bridge = ModelBridge(Backend(), channel)
        await bridge.next([])
        with self.assertRaises(AgentError):
            await bridge.next([])
        with self.assertRaises(ExecutionLimit):
            await bridge.next([])
        self.assertTrue(channel.exhausted)


if __name__ == "__main__":
    unittest.main()
