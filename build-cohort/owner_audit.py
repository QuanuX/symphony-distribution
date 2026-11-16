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
    return [{'package': package, 'tests': sorted(tests)} for package, tests in SELECTED.items()], pending


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
        'qualification_manifest_sha256': sha(manifest_path.read_bytes()), 'go': version,
        'input_payload_inventory_sha256': sha(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()),
        'selected_suites': suites, 'results': [], 'status': 'incomplete',
        'optional_installed_tests_not_run': pending,
        'full_native_ctest_and_direct_process_campaigns': 'not_run',
        'publisher_or_live_provider_qualification': False, 'fresh_host_accepted': False,
        'release_acceptance_complete': False, 'publication_authorized': False}
    try:
        for index, suite in enumerate(suites):
            output, errors = work / f'{index}-events.jsonl', work / f'{index}-stderr.log'
            expression = '^(' + '|'.join(re.escape(x) for x in suite['tests']) + ')$'
            command = [str(go), 'test', '-mod=readonly', '-trimpath', '-count=1', '-json',
                       '-timeout=' + str(timeout) + 's', '-run', expression, suite['package']]
            with output.open('x') as stdout, errors.open('x') as stderr:
                code = bounded.bounded_run(command, cwd=module, env=environment, stdout=stdout,
                                           stderr=stderr, timeout=timeout + 60)
            require(code == 0, 'installed owner tests failed; private output retained')
            events = [json.loads(line) for line in output.read_text().splitlines() if line.strip()]
            observed = evaluate(events, set(suite['tests']))
            report['results'].append({'package': suite['package'], **observed,
                'events_sha256': sha(output.read_bytes()), 'stderr_sha256': sha(errors.read_bytes())})
        require(snapshot(prefix) == before, 'owner fixture modified the selected final payload')
        require({name: sha((module / name).read_bytes()) for name in manifests_before} == manifests_before,
                'owner fixture changed Go manifests')
        report.update(status='passed', selected_test_count=6, prefix_unchanged=True, go_manifests_unchanged=True)
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
