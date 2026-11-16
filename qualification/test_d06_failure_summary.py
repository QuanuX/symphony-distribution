import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('d06_summary', Path(__file__).with_name('d06_failure_summary.py'))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class FailureSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.cohort, self.external = self.root / 'cohort', self.root / 'external'
        self.cohort.mkdir(); self.external.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def failed_log(self, raw):
        logs = self.cohort / 'round-1/logs'; logs.mkdir(parents=True)
        log = logs / 'component-build.log'; log.write_bytes(raw)
        (self.cohort / 'INCOMPLETE.json').write_text(json.dumps({'reason': 'step failed: component-build; private log retained'}))
        (self.cohort / 'round-1/progress.json').write_text(json.dumps({'completed_native': ['first'], 'expected_native': 51}))
        return log

    def report(self, baseline=None):
        return summary.summarize(self.cohort, self.external, self.root / 'workspace', self.root, baseline)

    def test_failure_retains_exact_hash_and_useful_neutral_diagnostic(self):
        raw = (f'{self.cohort}/source/library.cpp:12: error: undeclared function\n'
               'USER=Publisher\npassword=secret\nAuthorization: Bearer sensitive\n'
               '/Users/Publisher/private/cache: error: denied\nPublisher@example.org 192.0.2.99\n'
               'https://user:pass@example.org/source?token=private\n').encode()
        self.failed_log(raw)
        result = self.report()
        self.assertEqual(result['status'], 'failure_observed')
        self.assertEqual(result['log']['sha256'], summary.digest(raw))
        self.assertEqual(result['native_progress'], {'completed': 1, 'expected': 51})
        tail = result['log']['tail']
        self.assertIn('<cohort>/source/library.cpp:12: error: undeclared function', tail)
        for private in ('Publisher', 'secret', 'sensitive', '192.0.2.99', 'user:pass', str(self.root)):
            self.assertNotIn(private, tail)
        self.assertFalse(result['candidate_privacy_approved'])

    def test_tail_is_bounded_in_bytes_and_lines_and_scrubs_detached_key_body(self):
        text = '\n'.join(f'{i}: error: ' + '界' * 800 for i in range(100))
        tail = summary.sanitize(text + '\n' + 'Abcdef12345+/' * 6)
        self.assertLessEqual(len(tail.encode()), summary.TAIL_BYTES)
        self.assertLessEqual(len(tail.splitlines()), summary.TAIL_LINES)
        self.assertNotIn('Abcdef12345', tail)

    def test_symlink_log_is_never_read(self):
        log = self.failed_log(b'old')
        private = self.root / 'private'; private.write_text('confidential contents')
        log.unlink(); log.symlink_to(private)
        result = self.report()
        self.assertEqual(result['status'], 'diagnostic_evidence_refused')
        self.assertNotIn('confidential', json.dumps(result))
        self.assertNotIn('log', result)

    def test_oversized_log_is_refused(self):
        self.failed_log(b'long diagnostic')
        with patch.object(summary, 'MAX_LOG', 4):
            self.assertEqual(self.report()['status'], 'diagnostic_evidence_refused')

    def test_failed_step_cannot_select_outside_log_directory(self):
        (self.cohort / 'INCOMPLETE.json').write_text(json.dumps({'reason': 'step failed: ../../private; private log retained'}))
        result = self.report()
        self.assertEqual(result['status'], 'failure_observed')
        self.assertNotIn('log', result)

    def test_external_failure_and_missing_output_are_distinguished(self):
        self.assertEqual(self.report()['status'], 'no_failure_recorded')
        (self.external / 'logs').mkdir()
        (self.external / 'logs/curl-configure.log').write_text('CMake Error: required platform library absent\n')
        (self.external / 'external-build.json').write_text(json.dumps({'status': 'failed', 'failure': 'external build failed',
            'commands': [{'name': 'curl-configure', 'exit_code': 1}]}))
        result = self.report()
        self.assertEqual(result['failed_step'], 'curl-configure')
        self.assertIn('required platform library absent', result['log']['tail'])

    def test_sdk_and_owner_logs_use_known_paths_only(self):
        directory = self.cohort / 'round-1/sdk-audit/logs'; directory.mkdir(parents=True)
        (directory / 'api-build.log').write_text('error: SDK target missing\n')
        (self.cohort / 'INCOMPLETE.json').write_text(json.dumps({'reason': 'Detached SDK api-build failed; retained log: private'}))
        self.assertEqual(self.report()['failed_step'], 'sdk-api-build')
        owner = self.cohort / 'round-1/owner-audit'; owner.mkdir()
        (owner / '0-events.jsonl').write_text(json.dumps({'Output': '--- FAIL: TestInstalled\n'}) + '\n')
        (self.cohort / 'INCOMPLETE.json').write_text(json.dumps({'reason': 'installed owner tests failed; private output retained'}))
        result = self.report()
        self.assertEqual(result['failed_step'], 'installed-owner-0')
        self.assertIn('FAIL: TestInstalled', result['log']['tail'])

    def test_helper_baseline_has_exact_inventory_and_digest(self):
        baseline = self.root / 'baseline.json'
        manifest = summary.manifest()
        summary.write_new(baseline, manifest)
        self.assertTrue(self.report(baseline)['extra_helper_closure']['unchanged_from_baseline'])
        changed = json.loads(json.dumps(manifest))
        changed['files'][0]['sha256'] = '0' * 64
        changed['manifest_sha256'] = summary.digest(json.dumps(changed['files'], sort_keys=True, separators=(',', ':')).encode())
        baseline.write_text(json.dumps(changed))
        self.assertFalse(self.report(baseline)['extra_helper_closure']['unchanged_from_baseline'])
        changed['manifest_sha256'] = 'private unexpected string'
        with self.assertRaises(ValueError):
            summary.validate_manifest(changed)

    def test_sdk_closure_incomplete_retains_failed_command_context(self):
        closure = self.root / 'd06-sdk-closure'
        (closure / 'logs').mkdir(parents=True)
        (closure / 'logs/source-sdk-build.log').write_text('error: SDK symbol absent\n')
        (closure / 'result.json').write_text(json.dumps({'status': 'incomplete', 'logs': [
            {'name': 'source-sdk-build.log', 'exit_code': 1, 'expected': 'success'}]}))
        result = self.report()
        self.assertEqual(result['failed_step'], 'sdk-closure-source-sdk-build')
        self.assertIn('SDK symbol absent', result['log']['tail'])

    def test_output_never_overwrites_or_follows_links(self):
        output = self.root / 'summary.json'
        summary.write_new(output, {'retained': True})
        with self.assertRaises(FileExistsError):
            summary.write_new(output, {'overwrite': True})
        alias = self.root / 'alias'; alias.symlink_to(output)
        with self.assertRaises(ValueError):
            summary.write_new(alias, {})
        self.assertEqual(json.loads(output.read_text()), {'retained': True})


if __name__ == '__main__':
    unittest.main()
