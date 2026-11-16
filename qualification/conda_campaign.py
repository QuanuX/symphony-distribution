#!/usr/bin/env python3
"""Record focused real-Conda fault evidence without claiming host acceptance."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest

from host_platform import observe_host

ROOT = Path(__file__).resolve().parents[1]
SUITES = ('test_conda_transaction', 'test_conda_faults')
REQUIRED = {
    'test_conda_transaction.Transactions': '''
test_real_install_update_swap_rollback_remove_preserves_sentinels
test_existing_attempt_and_symlink_refused_without_touching_sentinel
test_unreviewed_dependency_delta_refused_before_execution
test_archive_hook_and_escape_refused_before_extraction
test_repodata_hash_tamper_refused_and_evidence_retained
test_missing_expected_unlink_and_foreign_collision_refused
test_prepared_extra_action_refused_before_execute
test_execution_lost_outcome_retained_and_never_retried
test_real_cache_cleanup_keeps_retained_copy_and_foreign_sentinels
test_cache_cleanup_refuses_installed_package_and_external_cache
test_cache_cleanup_lost_acknowledgement_never_retries
test_foreign_destination_hook_preserved_but_never_executed
test_full_delta_cannot_authorize_runtime_dependency_or_prepared_metadata_change
test_carrier_source_deletion_and_private_channel_tamper
'''.split(),
    'test_conda_faults.CondaFaults': '''
test_fork_inheritance_does_not_transfer_live_attempt_authority
test_competing_threads_reach_guard_without_poisoning_active_operation
test_independent_processes_racing_same_new_root_have_one_effect
test_intent_write_failure_poisoned_before_any_manager_effect
test_damaged_retained_rollback_archive_never_changes_installed_replacement
test_kill_after_validation_before_execution_retains_unreopenable_attempt
test_kill_after_execution_marker_before_effect_retains_uncertainty
test_kill_after_real_execution_before_ack_retains_uncertainty
test_kill_during_real_unlink_preserves_partial_state_without_replay
test_custody_replacement_after_real_prepare_refuses_before_execution
test_changed_or_missing_installed_payload_refuses_rollback
test_foreign_metadata_claim_blocks_removal_without_touching_foreign_state
test_lock_hardlink_and_reused_descriptor_refuse_before_execution
test_early_create_failure_retains_root_and_releases_only_its_lock
'''.split(),
}
BOUND_FILES = ('source-binding.json', 'lifecycle/conda_transaction.py',
               'lifecycle/test_conda_transaction.py', 'lifecycle/test_conda_faults.py',
               'qualification/conda_campaign.py', 'qualification/host_platform.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RecordedResult(unittest.TextTestResult):
    """Keep test names and outcomes; tracebacks stay in the private raw log."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = []

    def record(self, test, outcome, *, subtest=False):
        self.cases.append({'test': test.id(), 'outcome': outcome, 'subtest': subtest})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, 'pass')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, 'fail')

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, 'error')

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, 'skip', subtest=isinstance(test, unittest.case._SubTest))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, 'expected_failure')

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, 'unexpected_success')

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        self.record(subtest, 'pass' if err is None else 'fail', subtest=True)


def test_ids(suite):
    result = []
    for item in suite:
        result.extend(test_ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


def record_suite(suite, stream, required=None):
    discovered = test_ids(suite)
    required = list(discovered if required is None else required)
    expected = len(required)
    runner = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordedResult)
    result = runner.run(suite)
    completed = [row['test'] for row in result.cases if not row['subtest']]
    closed_coverage = (len(set(discovered)) == len(discovered) and
                       sorted(discovered) == sorted(required) == sorted(completed))
    accepted = bool(expected and closed_coverage and result.testsRun == expected and result.wasSuccessful()
                    and not result.skipped and not result.expectedFailures
                    and all(row['outcome'] == 'pass' for row in result.cases))
    return {'status': 'passed' if accepted else 'incomplete_or_failed',
            'expected_tests': expected, 'tests_run': result.testsRun,
            'required_case_coverage': closed_coverage,
            'skipped': len(result.skipped), 'failures': len(result.failures),
            'errors': len(result.errors), 'cases': result.cases}


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def worker(output):
    sys.path.insert(0, str(ROOT / 'lifecycle'))
    suites = []
    loader = unittest.TestLoader()
    for name in SUITES:
        suite = loader.loadTestsFromName(name)
        if not suite.countTestCases():
            raise ValueError('Required Conda test module has no cases: ' + name)
        suites.append(suite)
    with (output / 'tests.log').open('x') as log, redirect_stdout(log), redirect_stderr(log):
        required = [prefix + '.' + name for prefix, names in REQUIRED.items() for name in names]
        result = record_suite(unittest.TestSuite(suites), log, required)
    write_json(output / 'tests.json', result)
    return 0 if result['status'] == 'passed' else 1


def run(output):
    output = output.absolute()
    # An old attempt/report is never adopted or overwritten.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    before = {name: digest(ROOT / name) for name in BOUND_FILES}
    source = json.loads((ROOT / 'source-binding.json').read_text())
    report = {'protocol': 'symphony.distribution.conda-fault-campaign.v1',
              'source_commit': source['source_commit'], 'source_tree': source['source_tree'],
              'source_binding_digest': source['binding_digest'], 'file_sha256': before,
              'observed_host': observe_host(),
              'evidence_level': 'E1_real_conda_inert_carriers',
              'scope': 'new_private_attempts_only', 'authority': 'creator_process_live_object',
              'host_acceptance': 'not_run', 'publisher_acceptance': 'not_run',
              'runtime_activation': False, 'status': 'incomplete',
              'recovery': 'Fault fixture sources and interrupted attempts remain under private-attempts; '
                          'no reopen or replay is supported. Prior transaction fixtures are disposable. '
                          'Raw logs and private attempts are not package payloads.'}
    try:
        report['tools'] = {name: importlib.metadata.version(name) for name in ('conda', 'conda-build')}
        report['tools']['python'] = '.'.join(map(str, sys.version_info[:3]))
        if report['tools']['conda'] != '26.10.0' or report['tools']['conda-build'] != '26.9.1':
            raise ValueError('Pinned Conda 26.10.0 and conda-build 26.9.1 are required')
        retained = output / 'private-attempts'
        retained.mkdir(mode=0o700)
        env = dict(os.environ, SYMPHONY_CONDA_FAULT_EVIDENCE_ROOT=str(retained))
        with (output / 'worker.log').open('x') as log:
            child = None
            def interrupted(signum, _frame):
                raise InterruptedError('Campaign controller interrupted')
            previous = signal.signal(signal.SIGTERM, interrupted)
            try:
                child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                          '--output', str(output), '--worker'],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                         start_new_session=True, env=env)
                child.wait(timeout=900)
            except BaseException:
                # Bound only this campaign's new process group, including its
                # disposable fault children, if the controller is interrupted.
                if child is not None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
                raise
            finally:
                signal.signal(signal.SIGTERM, previous)
        report['worker_exit_code'] = child.returncode
        if (output / 'tests.json').is_file():
            report['tests'] = json.loads((output / 'tests.json').read_text())
        report['file_binding_unchanged'] = before == {name: digest(ROOT / name) for name in BOUND_FILES}
        if child.returncode == 0 and report.get('tests', {}).get('status') == 'passed' and report['file_binding_unchanged']:
            report['status'] = 'passed'
    except Exception as error:
        # Error strings/tracebacks can contain local identities; record only type
        # publicly and preserve detail in the private output directory.
        report['error_type'] = type(error).__name__
        with (output / 'campaign-error.log').open('x') as log:
            import traceback
            traceback.print_exc(file=log)
    report['logs'] = {p.name: digest(p) for p in sorted(output.glob('*.log'))}
    write_json(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.output)
    report = run(args.output)
    print(json.dumps({'status': report['status'], 'tests_run': report.get('tests', {}).get('tests_run', 0),
                      'host_acceptance': report['host_acceptance']}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
