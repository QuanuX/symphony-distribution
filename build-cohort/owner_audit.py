#!/usr/bin/env python3
"""Run existing core-only installed owner fixtures against final payload bytes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import plan as cohort_plan

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('owner_bounded', ROOT / 'qualification/native_campaign.py')
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)

SELECTED = {
    './internal/knowledgeengine': {
        'TestSNVInterfaceResourcesRejectTampering', 'TestSNVInstalledConsumer',
        'TestSNVInstalledAdversarialTransport', 'TestSBVInstalledBoundary', 'TestSQAVInstalled'},
    './internal/sovcloudflare': {'TestCloudflareInstalledReceiptProcess'},
}
PREFIX_VARIABLES = ('SNV_TEST_PREFIX', 'SYMPHONY_SNV_TEST_PREFIX', 'SYMPHONY_SBV_TEST_PREFIX',
                    'SQAV_REQUEST_TEST_PREFIX', 'SYMPHONY_CLOUDFLARE_TEST_PREFIX')
SNV_CORE_IDS = {'sniv-engine', 'snrv-engine', 'sciv-engine', 'scnv-engine', 'snv-engine'}
SNV_CLOSURE_IDS = SNV_CORE_IDS | {'knowledge-vector-engine-cpp', 'snv-common-cpp'}
TAMPER_TEST = 'TestSNVInterfaceResourcesRejectTampering'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(prefix):
    result = {}
    for path in sorted(prefix.rglob('*')):
        mode = path.lstat().st_mode
        name = str(path.relative_to(prefix))
        if stat.S_ISLNK(mode):
            result[name] = {'link': os.readlink(path), 'mode': stat.S_IMODE(mode)}
        elif stat.S_ISREG(mode):
            result[name] = {'sha256': sha(path.read_bytes()), 'mode': stat.S_IMODE(mode)}
        else:
            require(stat.S_ISDIR(mode), 'special final payload file refused')
            result[name] = {'directory': True, 'mode': stat.S_IMODE(mode)}
    require(result, 'empty final payload refused')
    return result


def selection(manifest):
    available = {}
    for suite in manifest['installed_go_suites']:
        if suite['module'] != 'tools/qxctl':
            continue
        available.setdefault(suite['package'], set()).update(suite['tests'])
    for package, tests in SELECTED.items():
        require(tests <= available.get(package, set()), 'selected installed owner test missing from core manifest')
    pending = [{'package': package, 'test': name} for package, tests in available.items()
               for name in sorted(tests - SELECTED.get(package, set()))]
    suites = [{'package': './internal/knowledgeengine', 'tests': [TAMPER_TEST],
               'prefix_scope': 'complete_snv_runtime_receipt_projection'}]
    suites += [{'package': package, 'tests': sorted(tests - {TAMPER_TEST}),
                'prefix_scope': 'complete_final_payload'} for package, tests in SELECTED.items()]
    return suites, pending


def snv_runtime_closure(mapping):
    """Derive runtime dependencies; never select files by filename convenience."""
    components = {row['path']: row for row in mapping['native_components']}
    require(len(components) == len(mapping['native_components']), 'duplicate native source root')
    seeds = {path for path, row in components.items() if row['component_id'] in SNV_CORE_IDS}
    require(len(seeds) == 5, 'five core SNV owner roots required')
    selected, visiting = set(), set()
    def visit(path):
        require(path in components and path not in visiting, 'missing or cyclic SNV runtime dependency')
        if path in selected: return
        visiting.add(path)
        for dependency in components[path]['first_party_sdk_dependencies']:
            if dependency['scope'] == 'runtime': visit(dependency['path'])
        visiting.remove(path); selected.add(path)
    for path in seeds: visit(path)
    ordered = [components[path] for path in mapping['native_build_order'] if path in selected]
    require(len(ordered) == len(selected) == 7 and {row['component_id'] for row in ordered} == SNV_CLOSURE_IDS,
            'exact seven-unit core SNV runtime closure changed')
    return ordered


def project_snv_receipts(source, prefix, destination):
    """Copy seven complete immutable units for the strict regular-file fixture.

    The full distribution legitimately contains external library symlinks. The
    original SNV tamper fixture accepts only regular files, so its input is the
    exact independent SNV dependency closure, not a weakened copy guard.
    """
    mapping_path = source / 'cmake/mvp-dependencies.json'
    rows = snv_runtime_closure(cohort_plan.read_json(mapping_path.read_bytes()))
    require(not destination.exists(), 'SNV projection destination must be new')
    destination.mkdir(mode=0o700)
    expected, receipts = {}, []
    def copy(name, expected_hash=None, expected_size=None):
        name = cohort_plan.relative(name)
        require(name not in expected, 'SNV projection has overlapping native owners')
        original = prefix / name
        require(not any(path.is_symlink() for path in (original, *original.parents) if path != prefix.parent),
                'SNV receipt-owned file or ancestor is symlinked')
        fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode), 'SNV receipt-owned file is not regular')
            with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read()
        finally:
            os.close(fd)
        require(expected_hash is None or sha(raw) == expected_hash, 'SNV receipt-owned bytes differ')
        require(expected_size is None or len(raw) == expected_size, 'SNV receipt-owned size differs')
        target = destination / name; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream: stream.write(raw)
        mode = stat.S_IMODE(info.st_mode)
        require(not mode & 0o7000, 'SNV owned special permission bits refused')
        target.chmod(mode)
        expected[name] = {'sha256': sha(raw), 'mode': mode}
        return raw
    for row in rows:
        name = 'share/symphony/receipts/' + row['component_id'] + '/' + row['package_release_version'] + '/install-receipt.json'
        raw = copy(name)
        receipt = cohort_plan.read_json(raw)
        claimed = receipt.pop('receipt_digest')
        require(claimed == 'sha256:' + sha(json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()),
                'SNV receipt canonical digest differs')
        require(receipt['protocol'] == 'symphony.knowledge.install-receipt.v2' and
                receipt['component_id'] == row['component_id'] and receipt['version'] == row['package_release_version'] and
                receipt['files'], 'SNV receipt identity or complete payload absent')
        for entry in receipt['files']:
            require(re.fullmatch(r'sha256:[0-9a-f]{64}', entry['digest']), 'SNV owned digest invalid')
            copy(entry['path'], entry['digest'].removeprefix('sha256:'), entry['size'])
        receipts.append({'component_id': row['component_id'], 'version': row['package_release_version'],
                         'receipt_sha256': sha(raw), 'owned_file_count': len(receipt['files'])})
    observed = {name: value for name, value in snapshot(destination).items() if not value.get('directory')}
    require(observed == expected and not any(p.is_symlink() for p in destination.rglob('*')), 'SNV projection is incomplete or aliased')
    return {'scope': 'complete_seven_native_receipts_only_for_SNV_tamper_fixture',
        'source_map_sha256': sha(mapping_path.read_bytes()), 'components': receipts, 'file_count': len(expected),
        'inventory_sha256': sha(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()),
        'all_original_bytes_and_modes_preserved': True, 'external_library_closure_selected': False}


def evaluate(events, expected):
    """Every selected top-level test must run/pass; every nested skip fails."""
    ran, passed = set(), set()
    for event in events:
        action, name = event.get('Action'), event.get('Test', '')
        require(action not in ('fail', 'skip'), 'installed owner failed or skipped')
        if not name:
            continue
        top = name.split('/', 1)[0]
        require(top in expected, 'unselected installed owner test executed')
        if name == top and action == 'run': ran.add(top)
        if name == top and action == 'pass': passed.add(top)
    require(ran == passed == set(expected), 'selected installed owner result missing')
    require(any(event.get('Action') == 'pass' and not event.get('Test') for event in events),
            'installed owner package result missing')
    return {'tests': len(passed), 'skips': 0, 'status': 'passed'}


def run_owner_audit(source, prefix, work, go, gomodcache, timeout=300, env=None):
    source, prefix, work = Path(source).resolve(), Path(prefix).resolve(), Path(work).absolute()
    go, gomodcache = Path(go).resolve(), Path(gomodcache).resolve()
    require(source.is_dir() and prefix.is_dir() and go.is_file() and gomodcache.is_dir(), 'missing owner audit input')
    require(not work.exists() and not any(p.is_symlink() for p in (work, *work.parents)), 'owner audit work must be new and non-symlink')
    for protected in (source, prefix, gomodcache, go.parent):
        require(work != protected and work not in protected.parents and protected not in work.parents,
                'owner audit work must be disjoint from inputs')
    manifest_path = source / 'tests/release-qualification/manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    suites, pending = selection(manifest)
    before = snapshot(prefix)
    work.mkdir(mode=0o700, parents=True)
    environment = {k: v for k, v in (env or os.environ).items() if k in ('PATH', 'DEVELOPER_DIR', 'SDKROOT', 'LANG', 'LC_ALL')}
    for name in ('home', 'temporary', 'cache', 'gopath'):
        (work / name).mkdir(mode=0o700)
    environment.update(HOME=str(work / 'home'), TMPDIR=str(work / 'temporary'),
        XDG_CONFIG_HOME=str(work / 'home/config'), XDG_STATE_HOME=str(work / 'home/state'),
        GOWORK='off', GOENV='off', GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off',
        GOTELEMETRY='off', GOMODCACHE=str(gomodcache), GOCACHE=str(work / 'cache'),
        GOPATH=str(work / 'gopath'), CGO_ENABLED='0')
    environment.update({name: str(prefix) for name in PREFIX_VARIABLES})
    version = subprocess.check_output([str(go), 'env', 'GOVERSION'], env=environment, text=True, timeout=10).strip()
    require(version == 'go1.26.5', 'owner audit requires exact Go 1.26.5')
    module = source / 'tools/qxctl'
    manifests_before = {name: sha((module / name).read_bytes()) for name in ('go.mod', 'go.sum')}
    report = {'protocol': 'symphony.distribution.d06-owner-audit.v1',
        'scope': 'six core-only existing installed Go owner fixtures against final relocated native payload',
        'harness_sha256': sha(Path(__file__).read_bytes()),
        'qualification_manifest_sha256': sha(manifest_path.read_bytes()), 'go': version,
        'input_payload_inventory_sha256': sha(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()),
        'selected_suites': suites, 'results': [], 'status': 'incomplete',
        'tamper_fixture_projection': None,
        'optional_installed_tests_not_run': pending,
        'full_native_ctest_and_direct_process_campaigns': 'not_run',
        'publisher_or_live_provider_qualification': False, 'fresh_host_accepted': False,
        'release_acceptance_complete': False, 'publication_authorized': False}
    try:
        projection = work / 'snv-receipt-projection'
        report['tamper_fixture_projection'] = project_snv_receipts(source, prefix, projection)
        projection_before = snapshot(projection)
        for index, suite in enumerate(suites):
            output, errors = work / f'{index}-events.jsonl', work / f'{index}-stderr.log'
            expression = '^(' + '|'.join(re.escape(x) for x in suite['tests']) + ')$'
            command = [str(go), 'test', '-mod=readonly', '-trimpath', '-count=1', '-json',
                       '-timeout=' + str(timeout) + 's', '-run', expression, suite['package']]
            suite_environment = dict(environment)
            if suite['prefix_scope'] == 'complete_snv_runtime_receipt_projection':
                suite_environment['SNV_TEST_PREFIX'] = str(projection)
                suite_environment['SYMPHONY_SNV_TEST_PREFIX'] = str(projection)
            with output.open('x') as stdout, errors.open('x') as stderr:
                code = bounded.bounded_run(command, cwd=module, env=suite_environment, stdout=stdout,
                                           stderr=stderr, timeout=timeout + 60)
            require(code == 0, 'installed owner tests failed; private output retained')
            events = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
            observed = evaluate(events, set(suite['tests']))
            report['results'].append({'package': suite['package'], 'prefix_scope': suite['prefix_scope'], **observed,
                'events_sha256': sha(output.read_bytes()), 'stderr_sha256': sha(errors.read_bytes())})
        require(snapshot(prefix) == before, 'owner fixture modified the selected final payload')
        require(snapshot(projection) == projection_before, 'owner fixture modified the original SNV projection')
        require({name: sha((module / name).read_bytes()) for name in manifests_before} == manifests_before,
                'owner fixture changed Go manifests')
        report.update(status='passed', selected_test_count=6, prefix_unchanged=True, projection_unchanged=True, go_manifests_unchanged=True)
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'prefix', 'work', 'go', 'gomodcache'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    report = run_owner_audit(**vars(args))
    print(json.dumps({'status': report['status'], 'selected_test_count': 6,
                      'full_native_campaign_run': False, 'release_acceptance_complete': False}))


if __name__ == '__main__':
    main()
