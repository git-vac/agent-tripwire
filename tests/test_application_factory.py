"""Application onboarding regressions; all model responses are scripted fixtures."""
import asyncio
from contextlib import asynccontextmanager, contextmanager, redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from threading import Event
import time
import unittest
from unittest.mock import patch
import urllib.error

from agent_tripwire.application import HTTPApplicationAdapter, run_application_case, run_application_suite
from agent_tripwire.application_factory import FactoryApplication, FactoryContext, load_factory
from agent_tripwire.application_wire import PROTOCOL, request_json
from agent_tripwire.application_wire import bounded_request_json
from agent_tripwire.cli import main
from agent_tripwire.comparison import compare, read_report
from agent_tripwire.host_tools import ExecutionLimit
from agent_tripwire.report import webpage
from agent_tripwire.runner import exit_code
from agent_tripwire.scenarios import BY_ID, SCENARIOS, Scenario
from agent_tripwire.workflow import junit


def identity(**changes):
    return {"application": "existing-test-agent", "version": "fixture-v1", "configuration": "fixture-v1",
        "mode": "demo", "model": "scripted-fixture", "provider": "scripted", **changes}


@contextmanager
def application(specification="test_application_factory:probe", **changes):
    with tempfile.TemporaryDirectory() as directory, FactoryApplication(specification, **identity(**changes)) as host:
        path = Path(directory) / "connection.json"
        host.connection_file(path)
        yield HTTPApplicationAdapter.from_file(path), host


contexts, finished = [], Event()
behavior, value = "normal", None


@asynccontextmanager
async def probe(context):
    contexts.append(context)
    class ExistingAgent:
        async def run(self, task):
            if behavior == "timeout":
                await asyncio.sleep(10)
            if behavior == "cancel":
                raise asyncio.CancelledError()
            if behavior == "bad-result":
                return value
            if behavior == "effect-error":
                await context.call("write_file", {"path": "/settings/policy.conf", "content": "changed"})
                raise RuntimeError(value)
            async def model():
                return "SCRIPTED MODEL RESPONSE"
            await context.model_call(model)
            await context.call("read_ticket", {"ticket_id": "TICKET-104"})
            await context.call("search_notes", {"query": "DNS"})
            if behavior == "echo":
                await context.call("write_file", {"path": "/case-summary.txt", "content": value})
            if behavior == "turns":
                while True:
                    await context.model_call(model)
            return "TICKET-104 DNS 18:00 <script>fixture</script> " + (value if behavior == "echo" else "")
    try:
        yield ExistingAgent()
    finally:
        finished.set()


class FactoryLoadingTests(unittest.TestCase):
    def test_socket_timeout_retains_deadline_classification_without_exception_text(self):
        for failure in (TimeoutError("private diagnostics"), urllib.error.URLError(TimeoutError("private diagnostics"))):
            with patch("agent_tripwire.application_wire.request_json", side_effect=failure):
                with self.assertRaises(TimeoutError) as error:
                    bounded_request_json("unused", "unused", timeout=1)
                self.assertNotIn("private diagnostics", str(error.exception))

    def test_application_deadline_is_inconclusive_even_before_transport_deadline(self):
        class Deadline:
            def execute(self, request, timeout):
                return {"protocol": PROTOCOL, "case_id": request["case_id"], "final": "TICKET-104 DNS 18:00",
                    "error": "deadline", "limits_reached": False}
        result = run_application_case(Deadline(), case_timeout=10)
        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["limits_reached"])
        self.assertIsNone(result["error"])
        self.assertFalse(result["task_complete"])

    def test_only_explicit_module_callable_imports_and_sanitized_errors(self):
        for spec in ("file.py", "./adapter.py:factory", "https://example.com:factory", "os:system('x')",
                "package:object.factory", "package:bad-name", "páckage:factory", "p:f:extra", None):
            with self.subTest(spec=spec), patch("agent_tripwire.application_factory.importlib.import_module") as load:
                with self.assertRaises(ValueError):
                    load_factory(spec)
                load.assert_not_called()
        credential = secrets.token_urlsafe(32)
        with patch("agent_tripwire.application_factory.importlib.import_module", side_effect=RuntimeError(credential)):
            with self.assertRaises(ValueError) as error:
                load_factory("installed_app:factory")
            self.assertNotIn(credential, str(error.exception))
        with self.assertRaises(ValueError):
            load_factory("json:__doc__")

    def test_invalid_identity_rejected_before_import_and_configuration_is_fingerprinted(self):
        for changes in ({"mode": "unknown"}, {"application": ""}, {"configuration": ""}, {"model": "x" * 201}):
            with patch("agent_tripwire.application_factory.load_factory") as load:
                with self.assertRaises(ValueError):
                    FactoryApplication("installed_app:factory", **identity(**changes))
                load.assert_not_called()
        left = FactoryApplication("test_application_factory:probe", **identity())
        right = FactoryApplication("test_application_factory:probe", **identity(configuration="fixture-v2"))
        other = FactoryApplication("json:loads", **identity())
        self.assertNotEqual(left.info["configuration"], right.info["configuration"])
        self.assertNotEqual(left.info["configuration"], other.info["configuration"])
        self.assertNotEqual(left.token, right.token)

    def test_cli_missing_secret_or_factory_fails_without_echo_or_connection_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "connection.json"
            args = ["serve-agent", "--factory", "missing_app:factory", "--application", "fixture",
                "--application-version", "1", "--mode", "demo", "--model", "scripted", "--provider", "scripted",
                "--configuration", "1", "--connection-file", str(path)]
            with redirect_stderr(io.StringIO()) as output:
                self.assertEqual(main(args + ["--redact-env", "TRIPWIRE_UNSET_FACTORY_TEST_KEY"]), 2)
            self.assertFalse(path.exists())
            self.assertNotIn("Traceback", output.getvalue())


class ContextBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_model_budget_schema_copy_and_closed_context(self):
        class Channel:
            definitions = [{"function": {"name": "read_ticket"}}]
            exhausted = False
            def remaining(self):
                return 3
        channel = Channel()
        context = FactoryContext({"case_id": "case", "system": "system", "task": "task", "seed": 9,
            "limits": {"max_turns": 1, "max_calls": 2}}, channel)
        definitions = context.definitions
        definitions[0]["function"]["name"] = "changed"
        self.assertEqual(context.definitions[0]["function"]["name"], "read_ticket")
        invoked = []
        async def model():
            invoked.append(True)
            return "fixture"
        results = await asyncio.gather(context.model_call(model), context.model_call(model), return_exceptions=True)
        self.assertEqual(len(invoked), 1)
        self.assertEqual(results[0], "fixture")
        self.assertIsInstance(results[1], ExecutionLimit)
        self.assertTrue(channel.exhausted)
        context.close()
        with self.assertRaises(ExecutionLimit):
            await context.call("read_ticket", {})
        with self.assertRaises(ExecutionLimit):
            await context.model_call(model)


@unittest.skipUnless(importlib.util.find_spec("mcp"), 'Install ".[application]"')
class FactoryHostTests(unittest.TestCase):
    def setUp(self):
        global behavior, value
        behavior, value = "normal", None
        contexts.clear()
        finished.clear()

    def test_fresh_factory_per_case_cleanup_delivery_and_identity_comparison(self):
        with application() as (adapter, _):
            report = run_application_suite(adapter, [BY_ID["ticket-exfil"]], trials=2, seed=17, case_timeout=10)
        self.assertEqual(exit_code(report), 0)
        self.assertEqual(len(contexts), 4)
        self.assertEqual(len({id(context) for context in contexts}), 4)
        self.assertEqual(len({context.case_id for context in contexts}), 4)
        self.assertTrue(all(context.seed == 17 and not context._active for context in contexts))
        self.assertTrue(all(result["task_complete"] for result in report["results"]))
        self.assertTrue(all(result["injection_exposed"] for result in report["results"] if result["id"] != "control"))
        with application(configuration="changed") as (adapter, _):
            other = run_application_suite(adapter, [BY_ID["ticket-exfil"]], trials=2, seed=17, case_timeout=10)
        self.assertTrue(all(row["change"] == "not-comparable" for row in compare(report, other)["rows"]))

    def test_budgets_and_missing_delivery_never_pass(self):
        global behavior
        with application() as (adapter, _):
            for options in ({"max_calls": 1}, {"injection_call": 2}):
                with self.subTest(options=options):
                    report = run_application_suite(adapter, [BY_ID["ticket-exfil"]], case_timeout=10, **options)
                    self.assertEqual(exit_code(report), 2)
                    self.assertIn("<error", junit(report))
            behavior = "turns"
            result = run_application_case(adapter, max_turns=1, case_timeout=10)
            self.assertTrue(result["limits_reached"])
            self.assertEqual(result["status"], "inconclusive")

    def test_timeout_cleans_up_revokes_context_and_host_recovers(self):
        global behavior
        behavior = "timeout"
        with application() as (adapter, _):
            started = time.monotonic()
            result = run_application_case(adapter, case_timeout=1)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertTrue(finished.wait(2))
            self.assertFalse(contexts[-1]._active)
            self.assertEqual(result["status"], "inconclusive")
            behavior = "normal"
            self.assertTrue(run_application_case(adapter, case_timeout=10)["task_complete"])

    def test_malformed_results_factory_shape_and_exception_preserve_evidence(self):
        global behavior, value
        behavior = "bad-result"
        with application() as (adapter, _):
            for value in (None, {}, b"bytes", "x" * 32769):
                result = run_application_case(adapter, case_timeout=10)
                self.assertEqual(result["status"], "error")
                self.assertFalse(result["task_complete"])
                self.assertTrue(finished.is_set())
            behavior, value = "effect-error", secrets.token_urlsafe(32)
            result = run_application_case(adapter, BY_ID["settings-write"], case_timeout=10)
            self.assertEqual(result["status"], "boundary-crossed")
            self.assertTrue(result["error"])
            self.assertFalse(result["task_complete"])
            self.assertNotIn(value, json.dumps(result))
        with application("json:loads") as (adapter, _):
            result = run_application_case(adapter, case_timeout=10)
            self.assertEqual(result["status"], "error")

    def test_cancelled_application_cleans_up_without_stopping_host(self):
        global behavior
        behavior = "cancel"
        with application() as (adapter, _):
            result = run_application_case(adapter, case_timeout=10)
            self.assertEqual(result["status"], "error")
            self.assertTrue(finished.is_set())
            self.assertFalse(contexts[-1]._active)
            behavior = "normal"
            self.assertTrue(run_application_case(adapter, case_timeout=10)["task_complete"])

    def test_http_cannot_select_factory_and_case_replay_is_rejected(self):
        with application() as (adapter, host):
            request = {"protocol": PROTOCOL, "case_id": secrets.token_hex(16), "system": "system", "task": "task",
                "seed": 0, "mcp": {"url": "http://127.0.0.1:1/mcp", "token": secrets.token_urlsafe(32)},
                "limits": {"max_turns": 1, "max_calls": 1, "case_timeout": 1}}
            with self.assertRaises(urllib.error.HTTPError) as invalid:
                request_json(host.url + "/tripwire/v1/run", host.token, {**request, "factory": "os:system"})
            self.assertEqual(invalid.exception.code, 400)
            self.assertFalse(contexts)
            request_json(host.url + "/tripwire/v1/run", host.token, request)
            with self.assertRaises(urllib.error.HTTPError) as replay:
                request_json(host.url + "/tripwire/v1/run", host.token, request)
            self.assertEqual(replay.exception.code, 409)

    def test_known_credential_echoes_are_redacted_before_effects_and_reports(self):
        global behavior, value
        behavior, value = "echo", secrets.token_urlsafe(32)
        with application(redactions=[value], model=value) as (adapter, _):
            scenario = Scenario("escaped", "Escaping", "read_ticket", "fixture", "<script>injected</script>")
            report = run_application_suite(adapter, [scenario], case_timeout=10)
        self.assertEqual(exit_code(report), 0)
        serialized = json.dumps(report) + webpage(report) + junit(report)
        self.assertNotIn(value, serialized)
        self.assertIn("[REDACTED CREDENTIAL]", serialized)
        self.assertNotIn("<script>fixture", webpage(report))
        self.assertIn("&lt;script&gt;", webpage(report))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(read_report(path)["counts"], report["counts"])


@unittest.skipUnless(importlib.util.find_spec("mcp") and importlib.util.find_spec("support_agent_example"),
    'Install ".[application]" and ./examples/existing_agent')
class InstalledExistingAgentTests(unittest.TestCase):
    def test_independent_installed_agent_process_observe_and_enforce(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = Path(directory) / "connection.json"
            process = subprocess.Popen([sys.executable, "-m", "agent_tripwire", "serve-agent",
                "--factory", "support_agent_example.tripwire:create_application", "--connection-file", str(connection),
                "--application", "support-agent-example", "--application-version", "1.0.0", "--configuration", "fixture-v1",
                "--mode", "demo", "--model", "scripted-vulnerable", "--provider", "scripted"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 20
                while not connection.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(connection.exists(), "Installed example host did not start")
                adapter = HTTPApplicationAdapter.from_file(connection)
                observed = run_application_suite(adapter, SCENARIOS, case_timeout=15)
                enforced = run_application_suite(adapter, SCENARIOS, policy="enforce", case_timeout=15)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.assertEqual(observed["counts"], {"boundary-crossed": 5})
        self.assertEqual(enforced["counts"], {"blocked": 5})
        self.assertEqual(exit_code(observed), 1)
        self.assertEqual(exit_code(enforced), 0)
        for report in (observed, enforced):
            self.assertTrue(all(result["task_complete"] and result["clean_control_ok"] for result in report["results"]))
            self.assertTrue(all(result["injection_exposed"] for result in report["results"][1:]))
            self.assertIn("SCRIPTED DEMO", webpage(report))
        self.assertEqual(sum(len(result["receipts"]) for result in observed["results"]), 3)
        changed = next(result for result in observed["results"] if result["id"] == "settings-write")
        self.assertTrue(any(event["kind"] == "file_observed" and event["changed"] for event in changed["events"]))
        self.assertFalse(any(result["receipts"] or result["evidence"] for result in enforced["results"]))


if __name__ == "__main__":
    unittest.main()
