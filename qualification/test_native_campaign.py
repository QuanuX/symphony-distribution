import importlib.util
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native_campaign', Path(__file__).with_name('native_campaign.py'))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


def events(*rows):
    return '\n'.join(json.dumps(row) for row in rows)


def stream(name='TestBound', subtest=False):
    rows = [{'Action': 'run', 'Test': name}]
    if subtest:
        rows += [{'Action': 'run', 'Test': name + '/child'}, {'Action': 'pass', 'Test': name + '/child'}]
    return rows + [{'Action': 'pass', 'Test': name}, {'Action': 'pass'}]


class EventEvidenceTests(unittest.TestCase):
    def check_failure(self, rows, expected=('TestBound',), code=0):
        result = campaign.parse_events(events(*rows), expected, code)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['errors'])

    def test_exact_tests_and_subtests_recorded(self):
        result = campaign.parse_events(events(*stream(subtest=True)), ['TestBound'], 0)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['top_level_tests'], ['TestBound'])
        self.assertEqual(result['subtests'], ['TestBound/child'])
        self.assertEqual(result['skipped_tests'], [])

    def test_empty_selection_is_not_qualification(self):
        self.check_failure([{'Action': 'pass'}])

    def test_one_missing_selector_cannot_be_hidden_by_package_pass(self):
        self.check_failure(stream(), ('TestBound', 'TestMissing'))

    def test_skip_is_never_pass(self):
        self.check_failure([{'Action': 'run', 'Test': 'TestBound'}, {'Action': 'skip', 'Test': 'TestBound'}, {'Action': 'pass'}])

    def test_skipped_child_is_never_pass(self):
        rows = stream(subtest=True)
        rows[2]['Action'] = 'skip'
        self.check_failure(rows)

    def test_truncated_child_even_with_parent_pass_refuses(self):
        rows = stream(subtest=True)
        del rows[2]
        self.check_failure(rows)

    def test_no_test_start_refuses_invented_pass(self):
        self.check_failure([{'Action': 'pass', 'Test': 'TestBound'}, {'Action': 'pass'}])

    def test_duplicate_test_run_refuses_replayed_coverage(self):
        self.check_failure(stream() + stream())

    def test_failed_exit_overrules_pass_events(self):
        self.check_failure(stream(), code=1)

    def test_unselected_test_refuses_changed_selector(self):
        self.check_failure(stream() + stream('TestOther'))

    def test_missing_package_completion_refuses(self):
        self.check_failure(stream()[:-1])

    def test_invalid_json_refuses(self):
        result = campaign.parse_events(events(*stream()) + '\nnot an event', ['TestBound'], 0)
        self.assertEqual(result['status'], 'failed')

    def test_source_requires_exact_named_test(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tests = root / 'module/internal/guard'
            tests.mkdir(parents=True)
            (tests / 'guard_test.go').write_text('package guard\nfunc TestExact(t *testing.T) {}\n')
            suite = {'module': 'module', 'package': './internal/guard'}
            row = campaign.source_case(root, suite, {'test': 'TestExact'})
            self.assertEqual(row['source']['line'], 2)
            with self.assertRaises(ValueError):
                campaign.source_case(root, suite, {'test': 'TestMissing'})
            (tests / 'duplicate_test.go').write_text('func TestExact(t *testing.T) {}\n')
            with self.assertRaises(ValueError):
                campaign.source_case(root, suite, {'test': 'TestExact'})

    def test_existing_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'evidence'
            output.mkdir()
            sentinel = output / 'result.json'
            sentinel.write_text('retained prior result')
            with self.assertRaises(ValueError):
                campaign.run_campaign(root, output, 'local-macos-amd64-fixture', 'go')
            self.assertEqual(sentinel.read_text(), 'retained prior result')

    def test_report_does_not_promote_gaps_to_acceptance(self):
        self.assertTrue(campaign.GAPS)
        self.assertTrue(all(gap['status'] == 'incomplete' for gap in campaign.GAPS))
        self.assertTrue(any('D05-S29' == gap['acceptance'] for gap in campaign.GAPS))

    def test_uncertain_native_outcomes_never_trigger_reconciliation(self):
        component = 'secure-identity-access-governance'
        unit = campaign.owners.OWNERS[component]
        for fault in ('owner-failed', 'still-retiring', 'payload-remains', 'receipt-remains'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                calls = []
                def owner(argv, **kwargs):
                    calls.append(argv)
                    work = root / ('lost-response-' + component)
                    prefix = work / 'runtime'
                    state = prefix / '.symphony-package-retirement' / component / unit['native_version'] / 'state.json'
                    receipt = prefix / 'share/symphony/receipts/fixture/install-receipt.json'
                    payload = prefix / 'libexec/fixture'
                    if argv[1] == 'build':
                        (work / unit['binary_name']).write_bytes(b'fixture controller')
                    elif 'install' in argv:
                        state.parent.mkdir(parents=True)
                        state.write_text(json.dumps({'phase': 'open', 'epoch': 'fixture-epoch', 'identity': {'owner': component}}))
                        receipt.parent.mkdir(parents=True)
                        receipt.write_text(json.dumps({'files': [{'path': 'libexec/fixture'}], 'receipt_digest': 'fixture'}))
                        payload.parent.mkdir(parents=True)
                        payload.write_bytes(b'fixture payload')
                    else:
                        if fault == 'owner-failed':
                            return 1
                        value = json.loads(state.read_text())
                        value['phase'] = 'retiring' if fault == 'still-retiring' else 'retired'
                        state.write_text(json.dumps(value))
                        if fault != 'payload-remains':
                            payload.unlink()
                        if fault != 'receipt-remains':
                            receipt.unlink()
                    return 0
                with patch.object(campaign.owners, 'SERVICE_IDS', {component}), patch.object(campaign, 'bounded_run', side_effect=owner):
                    rows = campaign.lost_response_campaign(root, root, 'go', {}, 'fixture')
                self.assertEqual(rows[0]['status'], 'failed')
                self.assertEqual(len(calls), 3, 'uncertain effect must never invoke a second uninstall')


class OwnedProcessCleanupTests(unittest.TestCase):
    def test_interruptions_terminate_owned_child_group(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                record = Path(directory) / 'owned-pids.json'
                child_script = (
                    'import json,os,subprocess,sys,time; from pathlib import Path; '
                    'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],pass_fds=(int(sys.argv[2]),)); '
                    'p=Path(sys.argv[1]); p.with_suffix(".new").write_text(json.dumps([os.getpid(),child.pid])); '
                    'os.replace(p.with_suffix(".new"),p); time.sleep(60)')
                wrapper_script = (
                    'import importlib.util,sys; '
                    's=importlib.util.spec_from_file_location("campaign",sys.argv[1]); '
                    'm=importlib.util.module_from_spec(s); s.loader.exec_module(m)\n'
                    'try:\n m.bounded_run([sys.executable,"-c",sys.argv[2],sys.argv[3],sys.argv[4]],pass_fds=(int(sys.argv[4]),),timeout=60)\n'
                    'except m.CampaignInterrupted as e:\n sys.exit(128+e.signum)\n')
                read_fd, write_fd = os.pipe()
                process = subprocess.Popen([sys.executable, '-c', wrapper_script, str(Path(campaign.__file__)), child_script, str(record), str(write_fd)],
                                           pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.close(write_fd)
                try:
                    deadline = time.monotonic() + 10
                    while not record.exists() and time.monotonic() < deadline and process.poll() is None:
                        time.sleep(0.02)
                    self.assertTrue(record.exists(), 'owned child did not reach readiness barrier')
                    pids = json.loads(record.read_text())
                    process.send_signal(signum)
                    self.assertEqual(process.wait(timeout=10), 128 + signum)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pids[0], 0)
                    # Both the child and grandchild hold the pipe writer for
                    # their entire sleep. EOF proves all holders terminated,
                    # without enumerating unrelated host processes or treating
                    # a briefly unreaped zombie as a surviving worker.
                    ready, _, _ = select.select([read_fd], [], [], 5)
                    self.assertTrue(ready, 'owned descendant retained its lifetime descriptor')
                    self.assertEqual(os.read(read_fd, 1), b'')
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                        process.wait(timeout=10)
                    os.close(read_fd)

    def test_timeout_terminates_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'pid'
            script = 'import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)'
            result = campaign.bounded_run([sys.executable, '-c', script, str(record)], timeout=5)
            self.assertEqual(result, 124)
            self.assertTrue(record.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(int(record.read_text()), 0)


if __name__ == '__main__':
    unittest.main()
