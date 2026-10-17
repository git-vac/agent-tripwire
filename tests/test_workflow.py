from contextlib import redirect_stdout, redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from rich.console import Console

from agent_tripwire.agents import AgentError, calls
from agent_tripwire.cli import main
from agent_tripwire.comparison import read_report
from agent_tripwire.report import terminal, webpage
from agent_tripwire.runner import run_suite
from agent_tripwire.scenarios import SCENARIOS
from agent_tripwire.workflow import junit, select_results
from test_tripwire import demo, endpoint, ModelHandler
from test_upgrade import CompatibleHandler


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = demo(trials=2)
        cls.enforced = demo('enforce')

    def test_check_performs_only_clean_tool_round_trip_for_both_providers(self):
        for provider, handler in [('ollama', ModelHandler), ('openai-compatible', CompatibleHandler)]:
            handler.requests = []
            with endpoint(handler) as url, tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'check.json'
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(['check', '--provider', provider, '--model', 'synthetic-model', '--base-url', url,
                        '--json', str(path), '--no-color'])
                report = read_report(path)
            self.assertEqual(code, 0)
            self.assertEqual(len(handler.requests), 2)
            self.assertEqual(report['purpose'], 'connection-check')
            self.assertEqual(report['selected_scenarios'], [])
            self.assertEqual([item['id'] for item in report['results']], ['control'])
            self.assertFalse(any(event['kind'] == 'injection_delivered' for event in report['results'][0]['events']))
            self.assertIn('CONNECTION CHECK', webpage(report))

    def test_check_failure_and_model_without_tools_cannot_pass(self):
        for response in [AgentError('Synthetic connection error'), {'role': 'assistant', 'content': 'TICKET-104 DNS 18:00'}]:
            with patch('agent_tripwire.agents.Ollama.next') as next_message, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                if isinstance(response, Exception):
                    next_message.side_effect = response
                else:
                    next_message.return_value = response
                self.assertEqual(main(['check', '--model', 'synthetic-model', '--no-color']), 2)
                self.assertEqual(next_message.call_count, 1)

    def test_runtime_credential_echo_stays_out_of_all_check_exports(self):
        # Deliberately invented credential; no user or provider secret is used.
        dummy = 'invented-tripwire-test-credential'
        def response(payload, remaining, headers):
            self.assertEqual(headers['Authorization'], 'Bearer ' + dummy)
            self.assertNotIn(dummy, json.dumps(payload))
            if len(payload['messages']) == 2:
                message = {'role': 'assistant', 'content': None, 'tool_calls': [
                    {'id': 'ticket', 'type': 'function', 'function': {'name': 'read_ticket', 'arguments': '{"ticket_id":"TICKET-104"}'}},
                    {'id': 'notes', 'type': 'function', 'function': {'name': 'search_notes', 'arguments': '{"query":"DNS"}'}}]}
            else:
                message = {'role': 'assistant', 'content': 'TICKET-104 DNS 18:00 ' + dummy}
            return {'choices': [{'message': message, 'finish_reason': 'stop'}]}
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('run.json', 'run.html', 'run.xml')]
            output = io.StringIO()
            with (patch.dict(os.environ, {'TRIPWIRE_TEST_ONLY': dummy}),
                    patch('agent_tripwire.agents.OpenAICompatible.request', side_effect=response),
                    redirect_stdout(output), redirect_stderr(io.StringIO())):
                self.assertEqual(main(['check', '--provider', 'openai-compatible', '--model', 'synthetic',
                    '--api-key-env', 'TRIPWIRE_TEST_ONLY', '--details', '--no-color',
                    '--json', str(paths[0]), '--html', str(paths[1]), '--junit', str(paths[2])]), 0)
            for text in [output.getvalue(), *(path.read_text(encoding='utf-8') for path in paths)]:
                self.assertNotIn(dummy, text)
            self.assertIn('[REDACTED API KEY]', paths[0].read_text(encoding='utf-8'))

    def test_filter_keeps_trial_control_and_recounts_without_mutating_source(self):
        original = copy.deepcopy(self.report)
        view = select_results(self.report, ['settings-write'], 2, 'findings')
        self.assertEqual([(item['id'], item['trial']) for item in view['results']], [('control', 2), ('settings-write', 2)])
        self.assertEqual(view['counts'], {'boundary-crossed': 1})
        self.assertEqual(self.report, original)
        self.assertIn('Filtered view', webpage(view))

    def test_empty_and_attention_filters(self):
        empty = select_results(self.enforced, only='findings')
        self.assertEqual([item['id'] for item in empty['results']], ['control'])
        self.assertIn('No results match', ' '.join(empty['notes']))
        attention = select_results(self.enforced, only='attention')
        self.assertEqual(len(attention['results']), 6)
        for kwargs in ({'scenarios': ['missing']}, {'trial': 19}):
            with self.assertRaises(ValueError):
                select_results(self.report, **kwargs)

    def test_offline_cli_keeps_whole_run_exit_and_machine_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            source, html, xml, data = [Path(directory) / name for name in ('source.json', 'view.html', 'ci.xml', 'copy.json')]
            source.write_text(json.dumps(self.report), encoding='utf-8')
            with (patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('Offline command made a request')),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
                code = main(['report', str(source), '--scenario', 'control', '--trial', '1', '--details',
                    '--html', str(html), '--junit', str(xml), '--json', str(data), '--no-color'])
            self.assertEqual(code, 1)
            self.assertIn('Filtered view', html.read_text(encoding='utf-8'))
            self.assertNotIn('Canary transfer verified', html.read_text(encoding='utf-8'))
            self.assertEqual(ET.parse(xml).getroot().get('failures'), '10')
            self.assertEqual(len(read_report(data)['results']), 12)

    def test_junit_counts_control_failures_and_escaped_text(self):
        report = copy.deepcopy(self.report)
        report['model'] = '<fake>&\x00\ufffe\uffff'
        root = ET.fromstring(junit(report))
        self.assertEqual(root.attrib['tests'], '12')
        self.assertEqual(root.attrib['failures'], '10')
        self.assertEqual(root.attrib['errors'], '0')
        self.assertEqual(len(root.findall('.//failure')), 10)
        self.assertEqual(root.find(".//property[@name='model']").get('value'), '<fake>&')
        self.assertEqual(ET.fromstring(junit(self.enforced)).get('failures'), '0')

    def test_junit_marks_incomplete_crossings_as_errors_and_retains_proof(self):
        class Failing:
            turn = 0
            def next(self, *args):
                self.turn += 1
                if self.turn == 1:
                    return calls(('read_file', {'path': '/private/canary.txt'}))
                raise AgentError('Synthetic backend failure')
        report = run_suite(lambda env: Failing(), SCENARIOS[:1], mode='run', model='synthetic')
        root = ET.fromstring(junit(report))
        self.assertGreater(int(root.get('errors')), 0)
        self.assertIn('Unauthorized read completed', root.find('.//error').text)

    def test_saved_report_recounts_and_does_not_trust_control_flags(self):
        report = copy.deepcopy(self.report)
        report['counts'] = {'boundary-crossed': 0}
        report['results'][0]['limits_reached'] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.json'
            path.write_text(json.dumps(report), encoding='utf-8')
            loaded = read_report(path)
        self.assertEqual(loaded['counts']['boundary-crossed'], 10)
        self.assertFalse(loaded['results'][1]['clean_control_ok'])
        self.assertTrue(loaded['results'][-1]['clean_control_ok'])

    def test_malformed_saved_evidence_returns_clear_cli_error(self):
        for mutate in [lambda r: r.update(notes=123),
                lambda r: r['results'][0].update(events=[{'step': 'bad', 'kind': 'assistant'}]),
                lambda r: r['results'][0].update(evidence=[{'step': 999, 'finding': 'nonexistent'}]),
                lambda r: r['results'][0].update(elapsed_ms=-1),
                lambda r: r.update(results=r['results'][1:])]:
            report = copy.deepcopy(self.report)
            mutate(report)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'bad.json'
                path.write_text(json.dumps(report), encoding='utf-8')
                errors = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                    self.assertEqual(main(['report', str(path), '--no-color']), 2)
                self.assertIn('Error:', errors.getvalue())
                self.assertNotIn('Traceback', errors.getvalue())

    def test_no_overwrite_or_duplicate_export_before_contacting_model(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'existing.xml'
            path.write_text('original')
            with (patch('agent_tripwire.agents.Ollama.next', side_effect=AssertionError('Unexpected request')),
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
                self.assertEqual(main(['check', '--model', 'synthetic', '--junit', str(path)]), 2)
                new = str(Path(directory) / 'new.xml')
                self.assertEqual(main(['check', '--model', 'synthetic', '--junit', new, '--html', new]), 2)
            self.assertEqual(path.read_text(), 'original')

    def test_saved_metadata_cannot_emit_terminal_control_sequences(self):
        report = copy.deepcopy(self.report)
        report['provider'] = 'provider\x1b[31m\u202e'
        report['results'][1]['id'] = 'case\x1b[31m\u202e'
        output = io.StringIO()
        terminal(report, Console(file=output, no_color=True), details=True)
        self.assertNotIn('\x1b', output.getvalue())
        self.assertNotIn('\u202e', output.getvalue())


if __name__ == '__main__':
    unittest.main()
