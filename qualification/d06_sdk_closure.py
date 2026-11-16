#!/usr/bin/env python3
"""Close source-SDK and disposable native-removal gates on a final D06 cohort.

Uses existing source consumers, receipt validators and configured CMake owners.
Only a newly owned disposable prefix is mutated; final candidate bytes are inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build-cohort'))
sys.path.insert(0, str(ROOT))
import plan as cohort_plan
import build as cohort_build
from qualification.native_campaign import bounded_run, parse_events


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return cohort_build.sha(path)


def dump(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def source_inventory(source):
    entries = []
    for path in sorted(source.rglob('*')):
        require(not path.is_symlink(), 'source provenance symlink refused')
        if path.is_file():
            mode = path.stat().st_mode & 0o777
            require(mode in (0o644, 0o755), 'source provenance mode differs')
            entries.append({'path': path.relative_to(source).as_posix(),
                            'mode': '100755' if mode == 0o755 else '100644', 'sha256': sha(path)})
        else:
            require(path.is_dir(), 'source provenance special file refused')
    return sorted(entries, key=lambda row: row['path'])


def verify_source(cohort, summary):
    entries = source_inventory(cohort / 'source')
    observed = hashlib.sha256(canonical(entries)).hexdigest()
    provenance = summary['source_input']
    if provenance['kind'] == 'verified_reviewed_derived_export':
        require(provenance['verified'] is True and observed == provenance['export_digest'],
                'reviewed derived source changed after cohort build')
    else:
        require(provenance['kind'] == 'exact_committed_source_archive', 'unknown cohort source provenance')
        archive = cohort / 'committed-source.tar'
        require(sha(archive) == provenance['archive_sha256'], 'committed source archive changed')
        expected = []
        with tarfile.open(archive) as tar:
            for member in tar:
                if member.isdir(): continue
                require(member.isfile(), 'nonregular committed source archive entry')
                name = cohort_plan.relative(member.name)
                expected.append({'path': name, 'mode': '100755' if member.mode & 0o111 else '100644',
                                 'sha256': hashlib.sha256(tar.extractfile(member).read()).hexdigest()})
        expected.sort(key=lambda row: row['path'])
        require(entries == expected, 'committed source changed after cohort build')
    return observed


def file_snapshot(root):
    """L22 compares files; native owners may remove their now-empty directories."""
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(root), 'external payload symlink escaped prefix')
            result[name] = {'link': os.readlink(path)}
        elif path.is_file():
            result[name] = {'sha256': sha(path), 'mode': path.stat().st_mode & 0o777}
        else:
            require(path.is_dir(), 'special payload file refused')
    return result


def owned_paths(receipt, receipt_name):
    paths = [cohort_plan.relative(row['path']) for row in receipt['files']] + [cohort_plan.relative(receipt_name)]
    require(len(paths) == len(set(paths)) and len(paths) > 1, 'empty or duplicate receipt ownership')
    return paths


def compare_inventory(configured, expected):
    require(len(configured) == len(set(configured)) and set(configured) == set(expected),
            'configured uninstaller does not own the exact final receipt file set')


def validate_roundtrip(report):
    expected = {'status': 'passed', 'provider_requests': '0', 'spend_usd': '0',
                'resume_executed': '0', 'external_trials': '2', 'selected_proposal': 'proposal-2',
                'calibration': 'not_verified', 'consumer_cancellation': 'incomplete_and_reaped'}
    require(all(report.get(key) == value for key, value in expected.items()), 'copied Go SDK roundtrip incomplete')
    require(report.get('signals') == 2 and isinstance(report.get('replay_rows'), int) and report['replay_rows'] > 0,
            'native source/replay fixture not consumed')
    require(all(report.get(key, {}).get('complete') is True for key in ('source_stream', 'replay_stream', 'bundle_stream')),
            'copied Go SDK stream incomplete')
    return {**expected, 'signals': report['signals'], 'replay_rows': report['replay_rows']}


class Runner:
    def __init__(self, work, env, timeout):
        self.work, self.env, self.timeout = work, env, timeout
        (work / 'logs').mkdir(mode=0o700)
        self.logs = []

    def run(self, label, argv, cwd=None, success=True):
        path = self.work / 'logs' / (label + '.log')
        with path.open('x') as stream:
            code = bounded_run([str(x) for x in argv], cwd=cwd or self.work, env=self.env,
                               stdout=stream, stderr=subprocess.STDOUT, timeout=self.timeout)
        self.logs.append({'name': path.name, 'sha256': sha(path), 'exit_code': code,
                          'expected': 'success' if success else 'refusal'})
        # CMake FATAL_ERROR is exit 1. A timeout/signal is never a valid refusal.
        require(code == 0 if success else code == 1, 'unexpected command result: ' + label)
        return path


CENSUS_WRAPPER = r'''package main
import "testing"
func TestD06SourceFixture(t *testing.T) {
    prefix = os.Getenv("D06_NATIVE_PREFIX")
    work = os.Getenv("D06_SOURCE_FIXTURE_WORK")
    qxctl = os.Getenv("D06_FINAL_QXCTL")
    if prefix == "" || work == "" || qxctl == "" { t.Fatal("explicit final inputs required") }
    census()
    write(filepath.Join(work, "census-evidence.json"), object{
        "status": "passed", "scope": "existing census function only; not full L20 campaign",
        "checks": checks, "data": evidence["data"],
        "qxctl_sha256": digest(qxctl),
        "native_sha256": digest(filepath.Join(prefix, "libexec/symphony/sbv-engine/0.33.0-dev/symphony-sbv")),
        "evaluation_sha256": digest(filepath.Join(work, "outputs/evaluation.json")),
    })
}
'''.replace('import "testing"', 'import ("testing"; "os"; "path/filepath")')


def copy_regular_tree(source, destination):
    require(source.is_dir() and not source.is_symlink() and not destination.exists(), 'source copy inputs differ')
    for path in source.rglob('*'):
        require(not path.is_symlink() and (path.is_file() or path.is_dir()), 'source SDK contains a nonregular input')
        require(not any(part in ('.git', 'build', 'CMakeFiles', '__pycache__') for part in path.relative_to(source).parts),
                'source SDK contains build artifacts')
    shutil.copytree(source, destination)


def source_roundtrip(args, source, prefix, work, runner):
    fixture = work / 'source-fixture'
    fixture.mkdir(mode=0o700)
    for name in ('source', 'outputs', 'logs', 'bin'):
        (fixture / name).mkdir(mode=0o700)
    copied = {
        'tests/sbv-launch-boundary/main.go': 'main.go',
        'tests/sbv-launch-boundary/fixture.cpp': 'fixture.cpp',
        'modules/sqav-databento-dbn-cpp/tests/public_fixture.hpp': 'public_fixture.hpp',
        'modules/sqav-databento-dbn-cpp/tests/third_party/README.md': 'fixture-attribution.md',
        'modules/sqav-databento-dbn-cpp/tests/third_party/LICENSE.Apache-2.0': 'fixture-LICENSE.Apache-2.0',
    }
    inputs = {}
    for original, name in copied.items():
        path = source / original
        require(path.is_file() and not path.is_symlink(), 'source fixture file missing or symlinked')
        shutil.copyfile(path, fixture / 'source' / name)
        inputs[original] = sha(path)
    wrapper = fixture / 'source/d06_test.go'; wrapper.write_text(CENSUS_WRAPPER)
    inputs['generated_d06_test.go'] = sha(wrapper)
    data_builder = fixture / 'bin/launch-data'
    runner.run('source-fixture-build', [args.cxx, '-std=c++2c', '-O2', fixture / 'source/fixture.cpp', '-o', data_builder])
    runner.run('source-fixture-produce', [data_builder, fixture / 'outputs/fixture.dbn'])
    qxctl = prefix / 'go/qxctl/bin/qxctl'
    runner.env.update(D06_NATIVE_PREFIX=str(prefix), D06_SOURCE_FIXTURE_WORK=str(fixture), D06_FINAL_QXCTL=str(qxctl))
    events = runner.run('source-fixture-census', [args.go, 'test', '-mod=readonly', '-trimpath', '-count=1', '-json',
        '-timeout=180s', '-run', '^TestD06SourceFixture$', 'main.go', 'd06_test.go'], fixture / 'source')
    parsed = parse_events(events.read_text(), ['TestD06SourceFixture'], 0)
    require(parsed['status'] == 'passed' and not parsed['skipped_tests'], 'native source fixture skipped or incomplete')
    census = json.loads((fixture / 'census-evidence.json').read_bytes())
    require(census['status'] == 'passed' and census['qxctl_sha256'] == sha(qxctl) and
            census['native_sha256'] == sha(prefix / 'libexec/symphony/sbv-engine/0.33.0-dev/symphony-sbv'),
            'native source fixture used different final binaries')
    require(census['checks'] and census['data']['calibrated_market_evidence'] is False,
            'native source fixture evidence incomplete')
    module = work / 'copied-sbv-go'
    copy_regular_tree(source / 'libraries/sbv-go', module)
    module_before = file_snapshot(module)
    consumer = work / 'source-roundtrip'
    runner.run('source-sdk-public-closure', [args.go, 'list', '-mod=readonly', '-m', '-f', '{{if .Replace}}{{.Path}}{{end}}', 'all'], module)
    require(not (work / 'logs/source-sdk-public-closure.log').read_text().strip(), 'Go SDK workspace replacement used')
    runner.run('source-sdk-verify', [args.go, 'mod', 'verify'], module)
    runner.run('source-sdk-build', [args.go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o', consumer, './examples/roundtrip'], module)
    require(file_snapshot(module) == module_before, 'copied Go SDK source changed during independent build')
    requests = work / 'requests'; requests.mkdir(mode=0o700)
    config = work / 'sbv-go.json'
    dump(config, {'Executable': str(qxctl), 'ExecutableSHA256': sha(qxctl), 'Prefix': str(prefix),
                  'Version': '0.33.0-dev', 'WorkDir': str(work), 'RequestDir': str(requests)})
    output = work / 'source-roundtrip-output'
    runner.run('source-sdk-roundtrip', [consumer, config, fixture / 'outputs/evaluation.json', output])
    raw_report = output / 'report.json'
    summary = validate_roundtrip(json.loads(raw_report.read_bytes()))
    return {'status': 'passed', 'source_inputs': inputs, 'copied_module_inventory_sha256': hashlib.sha256(canonical(module_before)).hexdigest(),
            'consumer_binary_sha256': sha(consumer), 'qxctl_sha256': sha(qxctl),
            'native_sha256': census['native_sha256'], 'census_checks': census['checks'],
            'census_evidence_sha256': sha(fixture / 'census-evidence.json'),
            'native_evaluation_sha256': census['evaluation_sha256'], 'roundtrip_report_sha256': sha(raw_report),
            'roundtrip': summary, 'full_L20_campaign_executed': False}


def receipt_path(unit):
    return 'share/symphony/receipts/' + unit['component_id'] + '/' + unit['version'] + '/install-receipt.json'


def removal_campaign(args, source, prefix, work, units, runner):
    metadata = work / 'metadata'; metadata.mkdir(mode=0o700)
    originals = {row['component_id']: row for row in json.loads((source / 'cmake/mvp-dependencies.json').read_bytes())['native_components']}
    uninstallers = work / 'uninstallers'; uninstallers.mkdir(mode=0o700)
    scripts, receipts, all_owned = {}, {}, set()
    copied_helpers = {}
    common = [f'-DCMAKE_C_COMPILER={args.cc}', f'-DCMAKE_CXX_COMPILER={args.cxx}', '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DCMAKE_INSTALL_LIBDIR=lib', f'-DCMAKE_INSTALL_PREFIX={prefix}',
        f'-DCMAKE_PREFIX_PATH={prefix};{prefix}/third-party', '-DBUILD_TESTING=OFF', '-DSYMPHONY_KVE_BUILD_TESTING=OFF',
        '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
        '-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON', '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON',
        '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF', '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
        f'-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={source}/tests/mvp-dependencies/prove-imports.cmake',
        f'-DMVP_SELECTED_PREFIX={prefix}', f'-DMVP_EXTERNAL_PREFIX={prefix}/third-party', f'-DMVP_REPOSITORY={source}']
    for unit in units:
        cid = unit['component_id']; record = metadata / (cid + '.json'); dump(record, originals[cid])
        receipt_name = receipt_path(unit)
        receipt = json.loads((prefix / receipt_name).read_bytes()); receipts[cid] = receipt
        paths = owned_paths(receipt, receipt_name)
        require(not all_owned.intersection(paths), 'multiple native owners claim final payload')
        all_owned.update(paths)
        configured = work / 'configure-only' / cid
        runner.run(cid + '-owner-configure', [args.cmake, '-S', source / unit['source_root'], '-B', configured, *common,
            *[f'-D{k}={v}' for k, v in unit['installed_options'].items()],
            f'-DMVP_COMPONENT_FILE={record}', f'-DMVP_PROOF_LOG={work}/logs/{cid}-imports.txt'])
        detached = uninstallers / cid; detached.mkdir(mode=0o700)
        identities = list(configured.glob('symphony-receipt-v2-identity-*.cmake'))
        require(len(identities) == 1, 'exact configured native owner identity missing')
        files = [configured / name for name in ('uninstall.cmake', 'SymphonyUninstallReceiptV2.cmake', 'SymphonyReceiptV2Support.cmake')] + identities
        for path in files:
            require(path.is_file() and not path.is_symlink(), 'configured owner helper missing or aliased')
            shutil.copyfile(path, detached / path.name)
            copied_helpers[cid + '/' + path.name] = sha(path)
        script = detached / 'uninstall.cmake'; inventory = detached / 'configured-files.txt'
        runner.run(cid + '-owner-inventory', [args.cmake, f'-DSDK_UNINSTALLER={script}', f'-DSDK_INVENTORY_OUTPUT={inventory}',
            '-P', source / 'tests/native-sdk-distribution/inspect-uninstaller.cmake'])
        compare_inventory(inventory.read_text().split(';'), paths)
        scripts[cid] = script
        # Only recreated configuration files are discarded, never native candidate builds.
        shutil.rmtree(configured)
    disposable = work / 'disposable-prefix'; shutil.copytree(prefix, disposable, symlinks=True)
    sentinel = disposable / 'unrelated/user-evidence.txt'; sentinel.parent.mkdir(mode=0o700); sentinel.write_text('Caller evidence survives removal.\n')
    expected = file_snapshot(disposable)
    unrelated = {name: value for name, value in expected.items() if name not in all_owned}
    checks = []
    def receipt_check(unit, label, success):
        runner.run(unit['component_id'] + '-' + label, [args.cmake, f'-DMVP_REPOSITORY={source}',
            f'-DMVP_COMPONENT_FILE={metadata}/{unit["component_id"]}.json', f'-DMVP_SELECTED_PREFIX={disposable}',
            '-P', source / 'tests/mvp-dependencies/verify-receipt.cmake'], success=success)
    def remove(unit, label, success):
        runner.run(unit['component_id'] + '-' + label, [args.cmake, f'-DINSTALL_PREFIX={disposable}',
                   '-P', scripts[unit['component_id']]], success=success)
    def refuse(unit, relative, label, mutation, admission=True):
        target = disposable / cohort_plan.relative(relative); original = target.read_bytes(); mode = target.stat().st_mode & 0o777
        target.write_bytes(mutation(original)); target.chmod(mode)
        before = file_snapshot(disposable)
        remove(unit, label, False)
        require(file_snapshot(disposable) == before, 'refused owner mutated another final file: ' + label)
        if admission: receipt_check(unit, label + '-admission', False)
        target.write_bytes(original); target.chmod(mode)
    for unit in reversed(units):
        cid = unit['component_id']; receipt = receipts[cid]; files = receipt['files']; kinds = []
        append = lambda raw: raw + b'\nintentional qualification tamper\n'
        refuse(unit, files[0]['path'], 'owned-byte-tamper', append); kinds.append('owned-byte-tamper')
        if unit['exported_packages']:
            header = next((r['path'] for r in files if r['path'].endswith(('.h', '.hpp'))), None)
            export = next((r['path'] for r in files if r['path'].endswith('Config.cmake')), None)
            require(header and export, 'SDK public header or CMake export missing from receipt')
            for kind, path in [('header-tamper', header), ('export-tamper', export)]:
                refuse(unit, path, kind, append); kinds.append(kind)
        def bad_digest(raw):
            value = json.loads(raw); value['receipt_digest'] = 'sha256:' + '0' * 64; return canonical(value)
        def wrong_identity(raw):
            value = json.loads(raw); value['component_kind'] = 'qualification-forged-kind'; value.pop('receipt_digest')
            value['receipt_digest'] = 'sha256:' + hashlib.sha256(canonical(value)).hexdigest(); return canonical(value)
        refuse(unit, receipt_path(unit), 'receipt-digest-tamper', bad_digest); kinds.append('receipt-digest-tamper')
        refuse(unit, receipt_path(unit), 'resealed-identity-tamper', wrong_identity, False); kinds.append('resealed-identity-tamper')
        require(file_snapshot(disposable) == expected, 'tamper restoration differs')
        (disposable / files[0]['path']).unlink()
        receipt_check(unit, 'partial-removal-admission', False)
        remove(unit, 'resume-removal', True)
        for name in owned_paths(receipt, receipt_path(unit)): expected.pop(name)
        require(file_snapshot(disposable) == expected, 'native removal changed unrelated packages or user evidence')
        remove(unit, 'repeat-removal', True)
        require(file_snapshot(disposable) == expected, 'native removal retry was not idempotent')
        checks.append({'component_id': cid, 'refusals': kinds, 'partial_admission_refused': True,
                       'resumed_removal': True, 'idempotent_retry': True, 'unrelated_bytes_preserved': True})
    require(expected == unrelated and file_snapshot(disposable) == unrelated, 'non-native or caller bytes were removed')
    return {'status': 'passed', 'native_units': len(checks), 'units': checks,
        'detached_helpers_sha256': copied_helpers, 'unrelated_file_count_preserved': len(unrelated),
        'unrelated_inventory_sha256': hashlib.sha256(canonical(unrelated)).hexdigest(),
        'external_and_Go_ownership_claimed': False, 'live_removal_claimed': False}


def run(args):
    for name in ('repository', 'cohort_output', 'go', 'cmake', 'cc', 'cxx', 'gomodcache'):
        setattr(args, name, Path(getattr(args, name)).resolve(strict=True))
    binding = cohort_plan.read_json((ROOT / 'source-binding.json').read_bytes())
    plan = cohort_plan.read_json((ROOT / 'build-cohort/cohort.json').read_bytes())
    cohort_plan.validate(plan, args.repository, binding)
    summary = cohort_plan.read_json((args.cohort_output / 'result.json').read_bytes())
    require(summary['state'] == 'built_and_sdk_checked' and summary['source_commit'] == plan['source_commit'] and
            summary['source_tree'] == plan['source_tree'], 'complete exact cohort required')
    round_name = 'round-' + str(args.round)
    rows = [r for r in summary['rounds'] if r['directory'] == round_name]
    require(len(rows) == 1, 'selected completed round missing')
    round_file = args.cohort_output / round_name / 'result.json'
    require(rows[0]['result_sha256'] == sha(round_file), 'final round evidence changed')
    observed = cohort_plan.read_json(round_file.read_bytes())
    prefix = args.cohort_output / round_name / 'relocated-prefix'
    source = args.cohort_output / 'source'
    source_digest = verify_source(args.cohort_output, summary)
    units = plan['profiles'][summary['host']['requested_profile']]['native_build_order']
    require(len(units) == 51 and cohort_build.verify_receipts(prefix, units) == observed['native_receipts'], 'final51 receipt cohort differs')
    require(cohort_build.snapshot(prefix) == observed['payload_inventory'], 'final cohort inventory differs')
    for name, expected in summary['build_helpers'].items():
        require(sha(ROOT / 'build-cohort' / name) == expected, 'cohort helper provenance changed')
    extra_helpers = {str(Path(__file__).relative_to(ROOT)): sha(__file__),
                     'qualification/native_campaign.py': sha(ROOT / 'qualification/native_campaign.py')}
    output = cohort_build.fresh(args.output, [args.repository, args.cohort_output, args.gomodcache, ROOT, args.go])
    args.owned_output = output
    environment = cohort_build.clean_environment(output, args.go, args.gomodcache, args.cc, args.cxx)
    environment['PATH'] = str(args.cmake.parent) + ':' + environment['PATH']
    if args.developer_dir:
        developer = Path(args.developer_dir).resolve(strict=True); require(developer.is_dir(), 'selected Apple developer directory absent')
        environment['DEVELOPER_DIR'] = str(developer)
    require(subprocess.check_output([args.go, 'env', 'GOVERSION'], env=environment, text=True).strip() == 'go1.26.5', 'exact Go1.26.5 required')
    runner = Runner(output, environment, args.timeout)
    before = file_snapshot(prefix)
    report = {'protocol': 'symphony.distribution.d06-sdk-closure.v1', 'status': 'incomplete',
        'source_commit': plan['source_commit'], 'source_tree': plan['source_tree'], 'round': round_name,
        'cohort_result_sha256': sha(args.cohort_output / 'result.json'), 'round_result_sha256': sha(round_file),
        'harness_sha256': sha(__file__), 'extra_helpers_sha256': extra_helpers, 'source_inventory_sha256': source_digest,
        'original_payload_inventory_sha256': hashlib.sha256(canonical(before)).hexdigest(),
        'source_consumer': None, 'disposable_native_removal': None,
        'release_acceptance_complete': False, 'publication_authorized': False, 'fresh_host_accepted': False,
        'full_original_L22_campaign_replayed': False, 'scope': 'existing source consumer and native removal assertions on final core51 cohort'}
    try:
        report['source_consumer'] = source_roundtrip(args, source, prefix, output, runner)
        report['disposable_native_removal'] = removal_campaign(args, source, prefix, output, units, runner)
        require(file_snapshot(prefix) == before and cohort_build.verify_receipts(prefix, units) == observed['native_receipts'],
                'qualification modified original final candidate')
        require(verify_source(args.cohort_output, summary) == source_digest, 'qualification source changed during execution')
        require(all(sha(ROOT / 'build-cohort' / name) == expected for name, expected in summary['build_helpers'].items()) and
                all(sha(ROOT / name) == expected for name, expected in extra_helpers.items()),
                'qualification helper changed during execution')
        report.update(status='passed', original_final_candidate_unchanged=True)
    finally:
        report['logs'] = runner.logs
        dump(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'cohort-output', 'output', 'go', 'cmake', 'cc', 'cxx', 'gomodcache'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--round', type=int, default=1)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--developer-dir', type=Path)
    args = parser.parse_args()
    require(1 <= args.round <= 2 and 1 <= args.timeout <= 3600, 'bounded round and timeout required')
    try:
        result = run(args)
        print(json.dumps({'status': result['status'], 'native_units': result['disposable_native_removal']['native_units'],
                          'source_sdk_roundtrip': result['source_consumer']['status'], 'release_acceptance_complete': False}))
    except Exception:
        if hasattr(args, 'owned_output'):
            (args.owned_output / 'INCOMPLETE').write_text('SDK closure incomplete; retained private evidence is not acceptance.\n')
        raise


if __name__ == '__main__':
    main()
