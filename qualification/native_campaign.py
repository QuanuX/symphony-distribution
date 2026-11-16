#!/usr/bin/env python3
"""Run the closed S07 native fault campaign against the reviewed core source.

This is E1 source/owner-fixture qualification. It does not start host services,
qualify delivered installers, or turn a refused removal into successful removal.
Full Go event logs stay in the selected evidence directory; the portable report
contains source links, exact selectors, actual test names and artifact digests.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNNER_BYTES = Path(__file__).read_bytes()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


owners = load_module('native_campaign_owners', ROOT / 'owner-catalog/native_owners.py')


def case(test, acceptance, oracle, kind='refusal'):
    return {'test': test, 'acceptance': acceptance.split(), 'expected': oracle, 'oracle_kind': kind}


GUARDS = [
    case('TestLiveChildClosesAdmissionUntilTerminalRelease', 'D05-S10 D05-S12 D05-S15', 'A real child confirms its lease before retirement; busy refusal retains payload, late starts refuse, terminal release permits exact retirement and durable tombstone.', 'real-child'),
    case('TestControllerCrashPreservesClosedAdmission', 'D05-S15', 'Kill the disposable controller after lease-held barrier; admission stays closed and exact recovery retains retirement intent.', 'real-child'),
    case('TestReplacedUseLockCannotBypassLiveConsumer', 'D05-S16', 'Replacing use.lock cannot bypass live use; payload remains.'),
    case('TestUnsafeGuardAndRootRefuse', 'D05-S16', 'Symlink, hardlink, changed state and replacement root refuse both use and reclamation.'),
    case('TestSharedRootMarkersRefuseNativeMutation', 'D05-S17 D05-S19', 'Standalone native mutation refuses shared-root markers without changing open admission.'),
    case('TestConcurrentAdmissionAndRetirementHaveOneWinner', 'D05-S09 D05-S11', 'Twelve simultaneous admission/retirement pairs never obtain both conflicting leases; this is a shared-start barrier, not injection at each delete boundary.', 'concurrency'),
    case('TestFreshGuardCannotAdoptExistingBytes', 'D05-S12', 'Missing custody cannot silently adopt existing payload.'),
    case('TestClosedAdmissionAllowsBoundedRecoveryButNotStarts', 'D05-S12 D05-S15', 'Recovery use excludes reclamation and never reopens ordinary start admission.'),
    case('TestPublicationRefusesReplacementAndConflictingFile', 'D05-S16', 'Publication refuses replacement parent and conflicting files without overwriting foreign bytes.'),
    case('TestDelegatedRetirementPreservesUseFence', 'D05-S10 D05-S19', 'Delegated retirement preserves use exclusion.'),
    case('TestDelegationRejectsForeignClaimsAndChangedRegistry', 'D05-S09 D05-S17', 'Foreign retained claims and changed registry after proof read refuse delegation.'),
    case('TestDelegationRejectsFalseCustody', 'D05-S16 D05-S19', 'Unlocked or different lock description, wrong root/registry/component/nonce/operation refuses.'),
    case('TestDelegatedDescriptorsCrossExec', 'D05-S19', 'A real child validates inherited authority descriptors across exec.', 'real-child'),
    case('TestDistinctPrefixesKeepIndependentUse', 'D05-S28', 'A use lease in one prefix does not authorize or interfere with another prefix.', 'isolation'),
]


def suites():
    result = []
    for component in ('secure-identity-access-governance', 'stav-append-authority', 'accordare-stav-producer'):
        result.append({'id': component + '-guards', 'module': 'modules/' + component,
                       'package': './internal/packageretirement', 'owner': component, 'cases': GUARDS})
    specs = [
        ('ssiag-owner', 'modules/secure-identity-access-governance', 'packageinstall', [
            case('TestRetirementRetainsLivePackageAndRecoversExactAttempt', 'D05-S10 D05-S15', 'Held use retains bytes; closed admission blocks new use; release permits exact retirement and idempotent replay.', 'native-owner-fixture'),
            case('TestUninstallRefusesSupervisorReference', 'D05-S13 D05-S19', 'A retained native descriptor prevents removal.'),
            case('TestMissingGuardRefusesLegacyAdoptionAndRemoval', 'D05-S12', 'Missing guard refuses adoption/removal and preserves payload.'),
            case('TestInstallRefusesUncontrolledSourceBytes', 'D05-S12', 'Uncontrolled source cannot create native custody.'),
            case('TestActivationRequiresExactReceiptAtPublishedPath', 'D05-S16', 'Moved or changed published receipt never activates.')]),
        ('ssiag-supervision', 'modules/secure-identity-access-governance', 'supervision', [
            case('TestRetirementFencesSupervisorInstallAndStart', 'D05-S11 D05-S12 D05-S19', 'Closed retirement admission blocks descriptor mutation and start before native manager invocation; descriptor cleanup remains possible.')]),
        ('stav-owner', 'modules/stav-append-authority', 'lifecycle', [
            case('TestManagedRetirementBlocksUseAndNewReferences', 'D05-S10 D05-S11 D05-S12', 'Installed real child confirms use; removal retains payload/receipt and late enroll, descriptor, restart refuse; release allows retirement.', 'real-child'),
            case('TestManagedRetirementRecoversAfterPayloadUnlink', 'D05-S15 D05-S16 D05-S28', 'Receipt-last interruption recovery preserves unrelated sentinel and exact retry is unchanged.', 'recovery-fixture'),
            case('TestRetirementRetainsOrphanedNativeDescriptor', 'D05-S13 D05-S19', 'Orphan descriptor retains executable.'),
            case('TestRetirementRecoveryPreservesUnenrolledData', 'D05-S28', 'Native retirement after explicit unenrollment preserves user configuration and state.', 'native-owner-fixture'),
            case('TestManagedAdmissionRefusesMissingOrChangedReceipt', 'D05-S16', 'Missing/changed receipt refuses installed use.'),
            case('TestMaintenanceExcludesStartsWithoutReopeningRetirement', 'D05-S11 D05-S12', 'Exclusive maintenance excludes live use/start without reopening pending retirement.'),
            case('TestRetirementRetainsExecutingController', 'D05-S18', 'A real installed child refuses to remove itself and leaves admission unchanged.', 'real-child'),
            case('TestActivationRefusesReplacedPublicationPaths', 'D05-S16 D05-S28', 'Replaced payload/receipt path refuses activation and preserves administrator bytes.')]),
        ('stav-manager-unavailable', 'modules/stav-append-authority', 'supervision', [
            case('TestObserveReportsManagerUnavailableOffline', 'D05-S13', 'An isolated empty PATH yields manager_unavailable, never stopped.', 'manager-absence-fixture')]),
        ('accordare-owner', 'modules/accordare-stav-producer', 'packageinstall', [
            case('TestRetirementClosesAdmissionUntilExactRecovery', 'D05-S10 D05-S15', 'Held use retains receipt; retirement remains closed until release; exact recovery creates tombstone.', 'native-owner-fixture'),
            case('TestMaintenanceFencesStartAndPreservesOpenAdmission', 'D05-S11 D05-S12', 'Maintenance excludes use/start without retiring an open package.'),
            case('TestRetirementRecoversReceiptLastInterruption', 'D05-S15 D05-S16', 'Recovery after payload removal and after receipt removal finishes the exact attempt.', 'recovery-fixture'),
            case('TestOrphanPendingStateBlocksReclamation', 'D05-S18 D05-S19', 'Pending intents and outbox retain payload; unresolved audit work cannot be removed.'),
            case('TestLegacyAndForeignSourcesCannotAcquireCustody', 'D05-S12', 'Legacy/foreign bytes cannot acquire managed custody.'),
            case('TestActivationRechecksBothFinalFiles', 'D05-S16', 'Fresh/existing activation refuses altered payload-parent and receipt.')]),
        ('scoped-native-dispatch', 'tools/qxctl', 'knowledgelifecycle', [
            case('TestNativeControllerIndependentCustody', 'D05-S16 D05-S18 D05-S26', 'Retained exact controller has independent inode; changed carrier, symlink, hardlink refuse.'),
            case('TestNativeOwnersSharedRootDispatch', 'D05-S17 D05-S19 D05-S28', 'Real executables of all three native owners install/remove in disposable shared roots; inherited parent lock persists; foreign claim and real caller descriptor retain bytes; sentinels and other claims survive.', 'real-owner-executables'),
            case('TestNativeOwnerBindingsAndClosedArguments', 'D05-S19', 'Only exact native routes and closed owner arguments are accepted.'),
            case('TestNativeOwnerOutputIsBounded', 'D05-S19', 'Owner output is bounded.'),
            case('TestNativeRecoveryRejectsReplacedRootLock', 'D05-S16', 'Recovery refuses replacement root lock.'),
            case('TestNativeOutcomeRejectsSharedEvidenceInodes', 'D05-S16', 'Shared evidence inodes cannot prove completed native removal.'),
            case('TestNativeSourcesMustSurviveScopedRemoval', 'D05-S18', 'Native recovery source/controller inside approved roots refuses.'),
            case('TestExecutionLeaseSerializesWholeExternalExecution', 'D05-S09', 'A channel confirms executor entry; competing executor refuses busy without callback; release admits next executor.', 'concurrency'),
            case('TestScopedOwnershipPreservesOtherClaimsAndRefusesImplicitAdoption', 'D05-S09 D05-S17', 'Scoped reconciliation preserves unrelated claims and refuses unknown adoption/fence repair.'),
            case('TestOwnershipNewRootEnforcesClaimsAndTwoProfileRetirement', 'D05-S17', 'One retained foreign claim blocks reclamation until complete release.'),
            case('TestScopedExecutorRejectsUnauthorizedActionBeforeBinding', 'D05-S09', 'Unauthorized scoped action refuses before binding.'),
            case('TestScopedActionProjectionProtectsUnrelatedFields', 'D05-S28', 'Scoped action projection protects unrelated desired fields.'),
            case('TestScopedEffectCompletionLeavesSelectionPending', 'D05-S07', 'Effect completion leaves selection pending; it is not global convergence.'),
        ]),
    ]
    for identifier, module, package, cases in specs:
        result.append({'id': identifier, 'module': module, 'package': './internal/' + package,
                       'owner': module.split('/')[-1], 'cases': cases})
    return result


GAPS = [
    {'acceptance': 'D05-S11', 'status': 'incomplete', 'reason': 'Simultaneous guard race and closed-start fixtures do not inject restart at each reference-scan/stop-completion/first-delete boundary.'},
    {'acceptance': 'D05-S13 D05-S14', 'status': 'incomplete', 'reason': 'Actual manager, stale/reused process identity, inaccessible user domain and detached descendant lifetime require separate supported-host evidence.'},
    {'acceptance': 'D05-S15', 'status': 'incomplete', 'reason': 'Real controller crash is covered at held retirement intent; deletion interruptions are fixtures. Completed native response loss is covered by observe-before-reconcile; mid-operation response loss and every crash boundary remain unqualified.'},
    {'acceptance': 'D05-S18', 'status': 'incomplete', 'reason': 'Accordare unresolved pending audit work refuses safely; successful audit recovery after process death is not established.'},
    {'acceptance': 'D05-S27', 'status': 'incomplete', 'reason': 'Two distinct compatible native releases and explicit selection/rollback acceptance are not supplied by this campaign.'},
    {'acceptance': 'D05-S29', 'status': 'incomplete', 'reason': 'E1 source/child/owner fixtures only; actual installed-manager, user/system privileges, fresh-host, delivered-installers and independent operator E2 acceptance remain separate.'},
]


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def check_source(source):
    expected = owners.reviewed_binding()
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-C', str(source), *args], timeout=30).decode().strip()
    owners.require(git('rev-parse', 'HEAD') == expected['source_commit'], 'checkout is not the reviewed source commit')
    owners.require(git('rev-parse', 'HEAD^{tree}') == expected['source_tree'], 'checkout tree differs')
    owners.require(not git('status', '--porcelain=v1', '--untracked-files=all'), 'core checkout is dirty')
    owners.require(owners.bind_source(source, expected['source_commit']) == expected, 'reviewed core binding differs')
    for row in expected['source_evidence']:
        path = source / row['path']
        owners.require(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'], 'working source evidence differs: ' + row['path'])
    ignored = git('ls-files', '--others', '--ignored', '--exclude-standard').splitlines()
    owners.require(not any(Path(p).suffix in ('.go', '.c', '.h', '.s', '.syso') or Path(p).name in ('go.mod', 'go.sum') for p in ignored), 'ignored build inputs are not reviewed')
    return expected


def source_case(source, suite, row):
    directory = source / suite['module'] / suite['package'].removeprefix('./')
    matches = []
    for path in directory.glob('*_test.go'):
        content = path.read_text()
        match = re.search(r'^func ' + re.escape(row['test']) + r'\(t \*testing\.T\)', content, re.M)
        if match:
            matches.append({'path': str(path.relative_to(source)), 'line': content[:match.start()].count('\n') + 1, 'sha256': digest(path.read_bytes())})
    owners.require(len(matches) == 1, 'selected test missing or ambiguous: ' + row['test'])
    return {**row, 'source': matches[0]}


def parse_events(data, expected, exit_code):
    """Reject missing, skipped, truncated or invented coverage, even on exit zero."""
    terminal = {}
    started = set()
    package_passes = []
    errors = []
    expected = set(expected)
    for line in data.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            errors.append('non-JSON Go event')
            continue
        if not isinstance(event, dict):
            errors.append('invalid Go event')
            continue
        action, name = event.get('Action'), event.get('Test')
        if name:
            if not isinstance(name, str) or name.split('/')[0] not in expected:
                errors.append('unselected test event')
                continue
            if action == 'run':
                if name in started:
                    errors.append('duplicate test start: ' + name)
                started.add(name)
            elif action in ('pass', 'fail', 'skip'):
                if name in terminal:
                    errors.append('duplicate test completion: ' + name)
                terminal[name] = action
                if action != 'pass':
                    errors.append(action + ': ' + name)
        elif action in ('pass', 'fail', 'skip'):
            package_passes.append(action)
    if exit_code != 0:
        errors.append('Go command failed: ' + str(exit_code))
    if package_passes != ['pass']:
        errors.append('package did not finish exactly once successfully')
    if not expected.issubset(started) or not expected.issubset(terminal):
        errors.append('selected tests missing')
    if started != set(terminal):
        errors.append('test event stream is incomplete')
    return {'status': 'passed' if not errors else 'failed', 'errors': sorted(set(errors)),
            'top_level_tests': sorted(name for name in terminal if '/' not in name),
            'subtests': sorted(name for name in terminal if '/' in name),
            'skipped_tests': sorted(name for name, action in terminal.items() if action == 'skip'),
            'test_outcomes': dict(sorted(terminal.items()))}


def bounded_run(argv, **kwargs):
    """Bound only our process group, including Go test child fixtures."""
    timeout = kwargs.pop('timeout', 900)
    previous = {}
    def interrupted(signum, frame):
        raise CampaignInterrupted(signum)
    try:
        # Install before spawning, closing the window in which a default
        # SIGTERM would leave the separately-sessioned fixture running.
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupted)
        with subprocess.Popen(argv, start_new_session=True, **kwargs) as process:
            try:
                process.wait(timeout=timeout)
                return process.returncode
            except BaseException as error:
                # The group was created by this invocation. Never enumerate
                # host services or signal a process discovered by name.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if isinstance(error, subprocess.TimeoutExpired):
                    return 124
                raise
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


class CampaignInterrupted(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum


def lost_response_campaign(source, output, executable, env, profile):
    """Discard an actual completed owner response, observe, then reconcile.

    This deliberately does not model an unknown still-running owner, supervisor
    shutdown, automatic replay, or interrupted deletion. No service is started.
    """
    rows = []
    for component in sorted(owners.SERVICE_IDS):
        unit = owners.OWNERS[component]
        work = output / ('lost-response-' + component)
        work.mkdir(mode=0o700)
        controller = work / unit['binary_name']
        build = ['build', '-mod=readonly', '-trimpath', '-ldflags',
                 '-X github.com/QuanuX/Symphony/modules/' + component + '/internal/version.Version=' + unit['native_version'],
                 '-o', str(controller), unit['build_package']]
        build_log = work / 'build.log'
        with build_log.open('wb') as stream:
            code = bounded_run([executable, *build], cwd=source / unit['source_root'], env=env,
                               stdout=stream, stderr=subprocess.STDOUT)
        row = {'id': component + '-completed-response-loss', 'scope_id': 'S07/E1/' + profile + '/' + component + '/completed-response-loss',
               'acceptance': ['D05-S15', 'D05-S28'], 'owner': component, 'native_version': unit['native_version'],
               'evidence_level': 'E1', 'kind': 'real-owner-executable', 'status': 'failed',
               'expected': 'Discard completed native removal response; first observe exact retired epoch and owned-byte absence, preserve foreign bytes, then explicit same-identity reconciliation returns unchanged.',
               'host_service_started': False, 'automatic_retry': False, 'mid_operation_loss_qualified': False}
        try:
            owners.require(code == 0, 'native owner fixture build failed')
            row['controller_digest'] = digest(controller.read_bytes())
            prefix = work / 'runtime'
            fixture_env = dict(env)
            home = work / 'home'
            home.mkdir(mode=0o700)
            fixture_env.update({'HOME': str(home), 'XDG_CONFIG_HOME': str(home / 'config'),
                                'XDG_STATE_HOME': str(home / 'state'), 'XDG_RUNTIME_DIR': str(home / 'runtime')})
            install = owners.install_argv(component, controller, prefix)
            with (work / 'install.log').open('wb') as stream:
                code = bounded_run(install, env=fixture_env, stdout=stream, stderr=subprocess.STDOUT, timeout=45)
            owners.require(code == 0, 'fresh native fixture install failed')
            state_path = prefix / '.symphony-package-retirement' / component / unit['native_version'] / 'state.json'
            original = json.loads(state_path.read_text())
            owners.require(original['phase'] == 'open', 'fresh fixture did not open admission')
            receipt_paths = list((prefix / 'share/symphony/receipts').rglob('install-receipt.json'))
            owners.require(len(receipt_paths) == 1, 'fresh native receipt coverage differs')
            receipt_path = receipt_paths[0]
            receipt = json.loads(receipt_path.read_text())
            payload_paths = [prefix / file['path'] for file in receipt['files']]
            row['receipt_digest'] = receipt['receipt_digest']
            row['retirement_epoch_digest'] = digest(original['epoch'].encode())
            sentinel = prefix / 'foreign-user-sentinel'
            sentinel.write_bytes(b'foreign bytes must survive native maintenance\n')
            before = digest(sentinel.read_bytes())
            uninstall = list(install)
            uninstall[uninstall.index('install')] = 'uninstall'
            # The client loses stdout; exit status only confirms the fixture
            # completed. It is never used as the successful-removal oracle.
            with (work / 'lost-response.stderr.log').open('wb') as stream:
                code = bounded_run(uninstall, env=fixture_env, stdout=subprocess.DEVNULL, stderr=stream, timeout=45)
            owners.require(code == 0, 'completed-response fixture did not complete; no retry attempted')
            observed = json.loads(state_path.read_text())
            owners.require(observed['phase'] == 'retired' and observed['epoch'] == original['epoch'] and observed['identity'] == original['identity'], 'exact durable retirement was not observed; no retry attempted')
            owners.require(not receipt_path.exists() and all(not p.exists() for p in payload_paths), 'owned bytes remain; no retry attempted')
            owners.require(digest(sentinel.read_bytes()) == before, 'foreign sentinel changed')
            state_before_reconcile = state_path.read_bytes()
            with (work / 'explicit-reconcile.log').open('wb') as stream:
                code = bounded_run(uninstall, env=fixture_env, stdout=stream, stderr=subprocess.STDOUT, timeout=45)
            owners.require(code == 0, 'explicit exact reconciliation failed')
            response = (work / 'explicit-reconcile.log').read_text()
            unchanged = 'no change' in response if component == 'stav-append-authority' else 'changed=false' in response
            owners.require(unchanged and state_path.read_bytes() == state_before_reconcile, 'reconciliation changed retired epoch')
            owners.require(digest(sentinel.read_bytes()) == before, 'reconciliation changed foreign sentinel')
            row.update({'status': 'passed', 'observed_phase': 'retired', 'response_deliberately_discarded': True,
                        'observation_preceded_reconciliation': True, 'reconciliation_changed': False,
                        'retirement_state_unchanged': True, 'foreign_sentinel_unchanged': True})
        except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
            # Do not expose personal paths from native diagnostic output.
            row['failure'] = str(error).replace(str(output), '<evidence>').replace(str(source), '<source>')
        row['artifacts'] = [{'path': str(p.relative_to(output)), 'sha256': digest(p.read_bytes())} for p in sorted(work.glob('*.log'))]
        rows.append(row)
        print(row['id'] + ': ' + row['status'], flush=True)
    return rows


def run_campaign(source, output, profile, go, gomodcache=None, gocache=None):
    source = source.resolve(strict=True)
    output = output.resolve()
    owners.require(not output.exists() or not any(output.iterdir()), 'evidence directory must be new or empty')
    owners.require(output != source and source not in output.parents, 'evidence must be outside core checkout')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    host_tools = load_module('native_campaign_platform', ROOT / 'qualification/host_platform.py')
    host = host_tools.observe_host()
    owners.require(profile in host_tools.PROFILES and host_tools.profile_matches(profile, host), 'actual host differs from requested profile')
    binding = check_source(source)
    executable = shutil.which(go)
    owners.require(executable is not None, 'Go executable not found')
    executable = str(Path(executable).resolve(strict=True))
    home = output / 'private-home'
    home.mkdir(mode=0o700)
    env = {k: os.environ[k] for k in ('PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'SDKROOT', 'DEVELOPER_DIR') if k in os.environ}
    env.update({'HOME': str(home), 'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_STATE_HOME': str(home / 'state'),
                'XDG_RUNTIME_DIR': str(home / 'runtime'), 'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off',
                'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOFLAGS': '', 'CGO_ENABLED': '1',
                'GOMODCACHE': str(Path(gomodcache or os.environ.get('GOMODCACHE') or home / 'go/pkg/mod').resolve()),
                'GOCACHE': str(Path(gocache or os.environ.get('GOCACHE') or output / 'go-cache').resolve())})
    version = subprocess.check_output([executable, 'env', 'GOVERSION'], env=env, text=True, timeout=30).strip()
    owners.require(version == 'go1.26.5', 'exact Go1.26.5 is required')
    results = []
    for suite in suites():
        cases = [source_case(source, suite, row) for row in suite['cases']]
        selector = '^(' + '|'.join(row['test'] for row in cases) + ')$'
        args = ['test', '-mod=readonly', '-race', '-json', '-count=1', '-timeout=10m', '-run', selector, suite['package']]
        log_path = output / (suite['id'] + '.jsonl')
        stderr_path = output / (suite['id'] + '.stderr.log')
        started = time.monotonic()
        with log_path.open('wb') as log, stderr_path.open('wb') as errors:
            code = bounded_run([executable, *args], cwd=source / suite['module'], env=env,
                               stdout=log, stderr=errors, timeout=900)
        parsed = parse_events(log_path.read_text(), [row['test'] for row in cases], code)
        results.append({**{k: v for k, v in suite.items() if k != 'cases'}, **parsed, 'cases': cases,
                        'scope_id': 'S07/E1/' + profile + '/' + suite['id'], 'command': ['go', *args],
                        'duration_seconds': round(time.monotonic() - started, 3), 'exit_code': code,
                        'artifacts': [{'path': p.name, 'sha256': digest(p.read_bytes())} for p in (log_path, stderr_path)]})
        print(suite['id'] + ': ' + parsed['status'], flush=True)
    response_loss = lost_response_campaign(source, output, executable, env, profile)
    final_binding = check_source(source)
    owners.require(final_binding == binding, 'core source changed during campaign')
    report = {'schema': 'symphony.distribution.native-fault-qualification.v1', 'evidence_level': 'E1',
              'status': 'passed' if all(r['status'] == 'passed' for r in results + response_loss) else 'failed',
              'profile': profile, 'host': host, 'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
              'source_binding_digest': binding['binding_digest'], 'runner_sha256': digest(RUNNER_BYTES),
              'runner_dependencies': [{'path': str(path.relative_to(ROOT)), 'sha256': digest(path.read_bytes())}
                                      for path in (ROOT / 'qualification/host_platform.py', ROOT / 'owner-catalog/native_owners.py')],
              'go_version': version, 'race_detector': True, 'native_services_started': False,
              'core_source_changed': False, 'live_removal_accepted': False, 'fresh_host_accepted': False,
              'publication_authorized': False, 'release_acceptance_complete': False,
              'top_level_test_count': sum(len(r['top_level_tests']) for r in results),
              'subtest_count': sum(len(r['subtests']) for r in results),
              'skip_count': sum(len(r['skipped_tests']) for r in results), 'suites': results,
              'completed_native_response_loss': response_loss, 'remaining_gates': GAPS}
    (output / 'result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='new private evidence directory')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--gomodcache')
    parser.add_argument('--gocache')
    args = parser.parse_args()
    try:
        report = run_campaign(args.source, args.output, args.profile, args.go, args.gomodcache, args.gocache)
        print(json.dumps({k: report[k] for k in ('status', 'top_level_test_count', 'subtest_count', 'skip_count')}))
        return 0 if report['status'] == 'passed' else 1
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('Native qualification preflight refused: ' + str(error), file=sys.stderr)
        return 2
    except CampaignInterrupted as error:
        print('Native qualification interrupted; owned fixture process group terminated.', file=sys.stderr)
        return 128 + error.signum


if __name__ == '__main__':
    sys.exit(main())
