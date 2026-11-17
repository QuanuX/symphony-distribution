#!/usr/bin/env python3
"""Independently qualify a declared D06 payload retained after owner-fixture failure.

Never resumes a build, installs over retained bytes, rewrites old evidence, or
adopts a live installation. The original full payload must still match the
inventory sealed by the failed owner audit. A second completed build can be
supplied for exact final-byte comparison in a separate new report.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build-cohort'))
sys.path.insert(0, str(ROOT))
import build as builder
import plan as planner
import owner_audit
import loader_audit
from qualification import d06_delivery_record as delivery

ORIGINAL_TOOL_COMMIT = '51bfd5e3a25f2b9c11b0cbb95f84c55d6f27a016'
IMPORTED = ('qualification/native_campaign.py', 'source-export/export_source.py', 'owner-catalog/native_owners.py')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = builder.safe_path(path)
    require(path.is_file(), 'required regular evidence is absent')
    return planner.read_json(path.read_bytes())


def original_blob(path):
    planner.relative(path)
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(ROOT), 'show',
                                    ORIGINAL_TOOL_COMMIT + ':' + path], timeout=30,
                                   env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'})


def verify_helpers(original):
    names = subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(ROOT), 'ls-tree', '-r', '--name-only',
                                     ORIGINAL_TOOL_COMMIT, 'build-cohort'], text=True, timeout=30).splitlines()
    expected = {Path(name).name: digest(original_blob(name)) for name in names
                if Path(name).suffix in ('.py', '.cmake') and not Path(name).name.startswith('test_')}
    require(original['build_helpers'] == expected and original['builder_sha256'] == expected['build.py'],
            'original builder/helper record differs from reviewed Git revision')
    current = {name: builder.sha(ROOT / 'build-cohort' / name) for name in expected}
    require(all(current[name] == value for name, value in expected.items() if name != 'owner_audit.py'),
            'a static build helper changed; retained qualification is not authorized for that change')
    imported = {name: digest(original_blob(name)) for name in IMPORTED}
    require(original['imported_helpers'] == {name: imported[name] for name in IMPORTED[:2]}, 'original imported-helper record differs')
    require(all(builder.sha(ROOT / name) == value for name, value in imported.items()), 'imported source or execution helper changed')
    return {'original_git_commit': ORIGINAL_TOOL_COMMIT, 'original_build_helpers': expected,
            'current_build_helpers': current, 'unchanged_imported_helpers': imported,
            'allowed_changed_helper': 'owner_audit.py'}


def verify_static_state(original, incomplete, progress, profile, plan):
    require(original.get('protocol') == 'symphony.distribution.clean-cohort.v1' and original.get('state') == 'building' and
            original.get('rounds') == [] and original.get('publication_authorized') is False and original.get('acceptance_complete') is False,
            'only the declared first-round retained build is admitted')
    require(incomplete == {'state': 'incomplete', 'acceptance_complete': False,
                           'reason': 'installed owner tests failed; private output retained'},
            'original stop was not the declared owner-fixture failure')
    expected = [row['component_id'] for row in profile['native_build_order']]
    require(len(expected) == 51 and progress == {'completed_native': expected, 'expected_native': 51, 'acceptance': False},
            'all 51 native units must have completed in the frozen order')
    require(len(profile['go_commands']) == 6, 'six Go command closure required')
    require(original['source_commit'] == plan['source_commit'] and original['source_tree'] == plan['source_tree'],
            'retained source identity differs from frozen plan')


def source_inventory(source, entries):
    expected = {row['path']: row for row in entries}
    require(len(expected) == len(entries), 'duplicate source identity')
    observed = set()
    for path in source.rglob('*'):
        require(not path.is_symlink(), 'retained source symlink refused')
        if path.is_dir():
            continue
        require(path.is_file(), 'nonregular retained source input')
        name = path.relative_to(source).as_posix()
        require(name in expected, 'retained source has an extra file')
        row = expected[name]
        require(builder.sha(path) == row['export_sha256'] and path.stat().st_size == row['export_size'] and
                path.stat().st_mode & 0o777 == (0o755 if row['mode'] == '100755' else 0o644),
                'retained source bytes or modes differ from reviewed export')
        observed.add(name)
    require(observed == set(expected), 'retained source is incomplete')
    return digest(canonical([{'path': name, 'sha256': expected[name]['export_sha256'], 'mode': expected[name]['mode']}
                             for name in sorted(expected)]))


def verify_sdk(round_root, source, profile):
    sdk_root = round_root / 'sdk-audit'
    report = read(sdk_root / 'sdk-audit.json')
    expected = sorted(row['component_id'] for row in profile['native_build_order'] if row['exported_packages'])
    require(report.get('protocol') == 'symphony.distribution.detached-sdk-audit.v1' and report.get('status') == 'passed' and
            report['selected_sdk_producers'] == expected and len(expected) == 20, 'detached SDK proof did not complete all selected producers')
    require(report['source_map_sha256'] == builder.sha(source / 'cmake/mvp-dependencies.json'), 'SDK source map differs')
    require(report['checks'] and all(row['exit_code'] == 0 for row in report['checks']), 'SDK check did not pass')
    for row in report['checks']:
        planner.relative(row['name'])
        require('/' not in row['name'] and builder.sha(builder.safe_path(sdk_root / 'logs' / (row['name'] + '.log'))) == row['log_sha256'],
                'SDK check log differs')
    for name, value in report['harness_sha256'].items():
        require(name in ('common.cmake', 'prove-imports.cmake') and
                builder.sha(source / 'tests/mvp-dependencies' / name) == value and builder.sha(sdk_root / 'harness' / name) == value,
                'SDK copied harness differs')
    return report


def bound_inventory(prefix, original_owner):
    current = owner_audit.snapshot(prefix)
    value = digest(json.dumps(current, sort_keys=True, separators=(',', ':')).encode())
    require(original_owner.get('protocol') == 'symphony.distribution.d06-owner-audit.v1' and
            original_owner.get('status') == 'incomplete' and original_owner['input_payload_inventory_sha256'] == value,
            'retained payload changed since original owner-audit admission')
    return current, value


def verify_completed_owner(work, source, expected_inventory):
    report = read(work / 'result.json')
    suites, _ = owner_audit.selection(read(source / 'tests/release-qualification/manifest.json'))
    require(report.get('status') == 'passed' and report.get('selected_test_count') == 6 and
            report.get('prefix_unchanged') is True and report.get('projection_unchanged') is True and
            report.get('go_manifests_unchanged') is True and report.get('harness_sha256') == builder.sha(ROOT / 'build-cohort/owner_audit.py') and
            report['input_payload_inventory_sha256'] == expected_inventory and report['selected_suites'] == suites and
            report['qualification_manifest_sha256'] == builder.sha(source / 'tests/release-qualification/manifest.json'),
            'corrected owner proof does not bind this unchanged payload and current harness')
    require(len(report['results']) == len(suites), 'owner suite result missing')
    for index, (suite, row) in enumerate(zip(suites, report['results'])):
        events_path = builder.safe_path(work / f'{index}-events.jsonl')
        stderr_path = builder.safe_path(work / f'{index}-stderr.log')
        require(builder.sha(events_path) == row['events_sha256'] and builder.sha(stderr_path) == row['stderr_sha256'], 'owner event or stderr evidence differs')
        observed = owner_audit.evaluate([json.loads(line) for line in events_path.read_text().splitlines() if line.strip()], set(suite['tests']))
        require(all(row[key] == value for key, value in observed.items()) and row['package'] == suite['package'] and
                row['prefix_scope'] == suite['prefix_scope'], 'owner suite observation differs')
    return report


def verify_comparison(root, original, inventory, units):
    summary = read(root / 'result.json')
    require(not (root / 'INCOMPLETE.json').exists() and summary.get('state') == 'built_and_sdk_checked' and summary.get('rounds'),
            'independent comparison build has not completed')
    for key in ('source_commit', 'source_tree', 'source_input', 'plan_sha256', 'host'):
        require(summary.get(key) == original.get(key), 'independent source or platform differs: ' + key)
    first = summary['rounds'][0]
    require(first['directory'] == 'round-1' and first['native_count'] == 51 and first['go_count'] == 6, 'comparison cohort counts differ')
    result_path = root / 'round-1/result.json'
    require(builder.sha(result_path) == first['result_sha256'], 'comparison round result hash differs')
    result = read(result_path)
    prefix = root / 'round-1/relocated-prefix'
    require(result['state'] == 'built_and_sdk_checked' and builder.snapshot(prefix) == result['payload_inventory'] == inventory,
            'independent final payload bytes, modes or inventory differ')
    require(builder.verify_receipts(prefix, units) == result['native_receipts'], 'comparison receipt proof differs')
    return {'status': 'exact_final_payload_match', 'build_result_sha256': builder.sha(root / 'result.json'),
            'round_result_sha256': builder.sha(result_path), 'payload_inventory_sha256': digest(canonical(inventory)),
            'independent_completed_build': True, 'source_and_platform_equal': True, 'fresh_host_accepted': False}


def run(args):
    for name in ('build_root', 'repository', 'export', 'privacy_policy', 'gomodcache'):
        path = builder.safe_path(getattr(args, name)); require(path.exists(), 'required input absent'); setattr(args, name, path)
    for name in ('owner_audit', 'comparison'):
        if getattr(args, name):
            setattr(args, name, builder.safe_path(getattr(args, name)))
    args.go = Path(args.go).resolve(strict=True)
    original = read(args.build_root / 'result.json')
    original_hash = builder.sha(args.build_root / 'result.json')
    helpers = verify_helpers(original)
    binding, plan = read(ROOT / 'source-binding.json'), read(ROOT / 'build-cohort/cohort.json')
    planner.validate(plan, args.repository, binding)
    require(original['plan_sha256'] == builder.sha(ROOT / 'build-cohort/cohort.json'), 'retained frozen plan differs')
    profile = plan['profiles'][original['host']['requested_profile']]
    round_root = args.build_root / 'round-1'
    verify_static_state(original, read(args.build_root / 'INCOMPLETE.json'), read(round_root / 'progress.json'), profile, plan)
    source, prefix = args.build_root / 'source', round_root / 'relocated-prefix'
    require(builder.selected_host(original['host']['requested_profile'], profile['platform_contract'],
            original['host']['scope'] == 'supplemental_local_build') == original['host'], 'current native qualification host differs')
    require(not (round_root / 'stage').exists() and prefix.is_dir(), 'only completed relocated payload is admitted')
    scanner = builder.load_exporter(); scanner.configure_policy(args.privacy_policy)
    export_proof = scanner.verify(args.export, args.repository)
    require(original['source_input'] == {'kind': 'verified_reviewed_derived_export', **export_proof}, 'retained build used a different source export')
    entries = read(args.export / 'SOURCE-EXPORT.json')['source_files']
    source_digest = source_inventory(source, entries)
    old_owner = read(round_root / 'owner-audit/result.json')
    before, admitted_digest = bound_inventory(prefix, old_owner)
    units = profile['native_build_order']
    receipts = builder.verify_receipts(prefix, units)
    sdk = verify_sdk(round_root, source, profile)
    protected = [args.build_root, args.repository, args.export, args.privacy_policy, args.gomodcache, args.go, ROOT]
    protected += [p for p in (args.owner_audit, args.comparison) if p]
    output = builder.fresh(args.output, protected); args.owned_output = output
    qualification_helpers = {str(path.relative_to(ROOT)): builder.sha(path) for path in
                             (Path(__file__), ROOT / 'qualification/d06_delivery_record.py')}
    for name in ('home', 'tmp', 'logs'):
        (output / name).mkdir(mode=0o700)
    env = {'PATH': str(args.go.parent) + ':/usr/bin:/bin', 'HOME': str(output / 'home'), 'TMPDIR': str(output / 'tmp'),
           'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOENV': 'off', 'GOPROXY': 'off', 'GOSUMDB': 'off',
           'GOVCS': '*:off', 'GOAUTH': 'off', 'GOTELEMETRY': 'off', 'CGO_ENABLED': '0',
           'GOMODCACHE': str(args.gomodcache), 'GOCACHE': str(output / 'go-cache')}
    logs = []
    def command(label, argv, cwd=None):
        value = subprocess.run([str(x) for x in argv], cwd=cwd or output / 'tmp', env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (output / 'logs' / (label + '.log')).write_bytes(value.stdout)
        logs.append({'name': label, 'sha256': digest(value.stdout), 'exit_code': value.returncode})
        require(value.returncode == 0, 'retained qualification command failed: ' + label)
        return value.stdout
    host = original['host']
    observed = command('native-go-toolchain', [args.go, 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH']).decode().splitlines()
    require(observed == ['go1.26.5', 'darwin' if host['os'] == 'macos' else 'linux', host['architecture']], 'native exact Go toolchain differs')
    owner_work = args.owner_audit or output / 'owner-audit'
    if args.owner_audit is None:
        owner_audit.run_owner_audit(source, prefix, owner_work, args.go, args.gomodcache, timeout=args.timeout, env=env)
    owner = verify_completed_owner(owner_work, source, admitted_digest)
    mapping = read(source / 'cmake/mvp-dependencies.json')
    graphs = {row['path']: row for row in mapping['go_modules']}
    go_results = []
    for unit in profile['go_commands']:
        cid = unit['component_id']; module = source / unit['source_root']; binary = prefix / 'go' / cid / 'bin' / unit['binary_name']
        require(binary.is_file() and not binary.is_symlink(), 'Go command missing')
        require(not command(cid + '-module-closure', [args.go, 'list', '-mod=readonly', '-m', '-f', '{{if .Replace}}{{.Path}}{{end}}', 'all'], module).strip(), 'Go replacement is not admitted')
        command(cid + '-module-verify', [args.go, 'mod', 'verify'], module)
        info = json.loads(command(cid + '-buildinfo', [args.go, 'version', '-m', '-json', binary]))
        sums = {}
        if (module / 'go.sum').exists():
            for line in (module / 'go.sum').read_text().splitlines():
                fields = line.split(); require(len(fields) == 3, 'Go source sum malformed'); sums[tuple(fields[:2])] = fields[2]
        linked = delivery.go_modules(info, graphs[unit['source_root']], sums)
        settings = {row['Key']: row['Value'] for row in info['Settings']}
        require(settings['GOOS'] == observed[1] and settings['GOARCH'] == observed[2], 'Go command native architecture differs')
        require(command(cid + '-version', [binary, '--version']).decode().strip() == unit['version_output_prefix'] + unit['package_version'], 'Go command version differs')
        go_results.append({'component_id': cid, 'version': unit['package_version'], 'sha256': builder.sha(binary), 'linked_modules': linked})
    loader = loader_audit.audit(prefix)
    inventory = builder.snapshot(prefix, scanner, forbidden=(source, args.build_root, args.repository, args.export, args.privacy_policy))
    require(owner_audit.snapshot(prefix) == before and source_inventory(source, entries) == source_digest and
            builder.verify_receipts(prefix, units) == receipts, 'retained source or final payload changed during requalification')
    require(builder.sha(args.build_root / 'result.json') == original_hash and verify_helpers(original) == helpers,
            'original aggregate or helper provenance changed')
    require(all(builder.sha(ROOT / path) == value for path, value in qualification_helpers.items()), 'requalification helper changed during observation')
    comparison = verify_comparison(args.comparison, original, inventory, units) if args.comparison else None
    report = {'protocol': 'symphony.distribution.retained-cohort-requalification.v1', 'state': 'retained_payload_requalified',
              'scope': 'independent read-only qualification of a declared completed static cohort stopped at owner fixtures; no build resumed',
              'source_commit': original['source_commit'], 'source_tree': original['source_tree'], 'host': host,
              'source_input': original['source_input'], 'source_inventory_sha256': source_digest,
              'original_build_result_sha256': original_hash, 'original_incomplete_sha256': builder.sha(args.build_root / 'INCOMPLETE.json'),
              'original_owner_report_sha256': builder.sha(round_root / 'owner-audit/result.json'),
              'original_admitted_payload_inventory_sha256': admitted_digest, 'original_evidence_unchanged': True,
              'requalifier_sha256': builder.sha(Path(__file__)), 'helper_provenance': helpers,
              'requalification_helpers': qualification_helpers, 'original_external_evidence_sha256': original['external_evidence_sha256'],
              'native_count': 51, 'native_receipts': receipts, 'go_count': 6, 'go_commands': go_results,
              'sdk_audit_sha256': builder.sha(round_root / 'sdk-audit/sdk-audit.json'), 'selected_sdk_producers': sdk['selected_sdk_producers'],
              'corrected_owner_report_sha256': builder.sha(owner_work / 'result.json'), 'corrected_owner_audit': owner,
              'loader_audit': loader, 'payload_inventory': inventory, 'payload_inventory_sha256': digest(canonical(inventory)),
              'qualification_logs': logs, 'comparison': comparison,
              'two_independent_full_builds_match': comparison is not None,
              'external_payload_ownership': 'separate_distribution_build_inventory_not_native_receipt',
              'acceptance_complete': False, 'publication_authorized': False, 'fresh_host_accepted': False}
    scanner.scan('retained-requalification.json', canonical(report))
    builder.dump(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build-root', 'repository', 'export', 'privacy-policy', 'output', 'go', 'gomodcache'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--owner-audit', type=Path, help='existing completed corrected audit, fully rebound and checked; otherwise run fresh')
    parser.add_argument('--comparison', type=Path, help='separate completed full clean build for exact final-byte comparison')
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    require(1 <= args.timeout <= 3600, 'owner qualification timeout must be bounded')
    try:
        result = run(args)
    except BaseException:
        if hasattr(args, 'owned_output'):
            builder.dump(args.owned_output / 'INCOMPLETE.json', {'state': 'incomplete', 'acceptance_complete': False})
        raise
    print(json.dumps({'state': result['state'], 'native_count': 51, 'go_count': 6,
                      'two_independent_full_builds_match': result['two_independent_full_builds_match'], 'acceptance_complete': False}))


if __name__ == '__main__':
    main()
