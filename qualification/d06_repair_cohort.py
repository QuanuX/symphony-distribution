#!/usr/bin/env python3
"""Repair the bounded archive/link closure in a new, inherited D06 candidate.

Original candidates and their evidence remain immutable. Existing native owners
remove/reinstall the eight affected units; six Go executables and 43 native
units are inherited with explicit provenance, never described as freshly built.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build-cohort'))
sys.path.insert(0, str(ROOT))
import build as builder
import plan as planner
from qualification import d06_sdk_closure as closure

ORIGIN_COMMITS = {'51bfd5e3a25f2b9c11b0cbb95f84c55d6f27a016', '917402857b127e0f5baedaa7321799d79e4255a6'}
SEEDS = {'sqav-capture-cpp', 'sqpv-local-store-cpp'}
REPAIR_IDS = {'sqav-capture-cpp', 'sqpv-local-store-cpp', 'sqav-databento-dbn-cpp', 'sqdv-delivery-cpp',
              'sbv-engine', 'sqav-databento-reference-cpp', 'sqav-fred-cpp', 'sqav-request-engine'}
EXTERNAL_REPAIR = 'third-party/lib/libzstd.a'
require, sha, dump = builder.require, builder.sha, builder.dump
canonical = closure.canonical


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    path = builder.safe_path(path)
    require(path.is_file(), 'required regular evidence absent')
    return planner.read_json(path.read_bytes())


def repair_units(units):
    by_root = {u['source_root']: u['component_id'] for u in units}
    require(len(by_root) == len(units), 'duplicate source ownership')
    selected = set(SEEDS)
    require(selected <= {u['component_id'] for u in units}, 'repair seeds absent')
    while True:
        more = {u['component_id'] for u in units
                if any(by_root.get(p) in selected for p in u['dependency_source_roots'])}
        if more <= selected: break
        selected |= more
    require(selected == REPAIR_IDS, 'bounded eight-unit repair dependency closure changed')
    return [u for u in units if u['component_id'] in selected]


def original_helpers(summary, commit):
    require(commit in ORIGIN_COMMITS, 'origin tool revision is not a reviewed D06 build')
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(ROOT), *args], env=env, timeout=30)
    names = git('ls-tree', '-r', '--name-only', commit, 'build-cohort').decode().splitlines()
    expected = {Path(n).name: hashlib.sha256(git('show', commit + ':' + n)).hexdigest()
                for n in names if Path(n).suffix in ('.py', '.cmake') and not Path(n).name.startswith('test_')}
    require(summary['build_helpers'] == expected and summary['builder_sha256'] == expected['build.py'],
            'origin build helpers differ from their reviewed Git revision')
    imported = {n: hashlib.sha256(git('show', commit + ':' + n)).hexdigest()
                for n in ('qualification/native_campaign.py', 'source-export/export_source.py')}
    require(summary['imported_helpers'] == imported, 'origin imported helpers differ')
    return {'git_commit': commit, 'build_helpers': expected, 'imported_helpers': imported}


def current_helpers():
    return {p.name: sha(p) for p in sorted((ROOT / 'build-cohort').iterdir())
            if p.suffix in ('.py', '.cmake') and not p.name.startswith('test_')}


def admit_record(args, summary, plan):
    require(summary.get('protocol') == 'symphony.distribution.clean-cohort.v1' and
            summary.get('acceptance_complete') is False and summary.get('publication_authorized') is False,
            'origin is not a bounded D06 qualification build')
    require(summary['source_commit'] == plan['source_commit'] and summary['source_tree'] == plan['source_tree'] and
            summary['plan_sha256'] == sha(ROOT / 'build-cohort/cohort.json'), 'origin source/plan binding differs')
    original_helpers(summary, args.origin_tool_commit)
    if args.retained_qualification:
        report_path = args.retained_qualification / 'result.json'
        require(re.fullmatch('[0-9a-f]{64}', args.retained_qualification_sha256 or '') and
                sha(report_path) == args.retained_qualification_sha256, 'retained qualification report digest differs')
        report = read(report_path)
        require(report.get('protocol') == 'symphony.distribution.retained-cohort-requalification.v1' and
                report.get('state') == 'retained_payload_requalified' and report.get('original_evidence_unchanged') is True and
                report.get('acceptance_complete') is False and report.get('publication_authorized') is False,
                'retained payload was not independently requalified')
        require(summary['state'] == 'building' and summary['rounds'] == [] and
                report['original_build_result_sha256'] == sha(args.origin / 'result.json') and
                report['original_incomplete_sha256'] == sha(args.origin / 'INCOMPLETE.json') and
                report['helper_provenance']['original_git_commit'] == args.origin_tool_commit,
                'retained evidence does not bind original stopped build')
        require(all(report[k] == summary[k] for k in ('source_commit', 'source_tree', 'source_input', 'host')) and
                report['original_external_evidence_sha256'] == summary['external_evidence_sha256'],
                'retained source/host/external binding differs')
        require(report['native_count'] == 51 and report['go_count'] == 6 and
                report['corrected_owner_audit']['status'] == 'passed' and report['loader_audit']['status'] == 'passed',
                'retained qualification gates incomplete')
        return report, {'kind': 'independently_requalified_retained_payload', 'report_sha256': sha(report_path)}, None
    require(args.retained_qualification_sha256 is None, 'report digest requires explicit retained qualification')
    require(not (args.origin / 'INCOMPLETE.json').exists() and summary['state'] == 'built_and_sdk_checked',
            'origin build did not complete')
    rows = [r for r in summary['rounds'] if r['directory'] == 'round-1']
    require(len(rows) == 1 and rows[0]['native_count'] == 51 and rows[0]['go_count'] == 6 and
            sha(args.origin / 'round-1/result.json') == rows[0]['result_sha256'], 'origin completed round differs')
    report = read(args.origin / 'round-1/result.json')
    require(report['state'] == 'built_and_sdk_checked' and report['native_count'] == 51 and len(report['go_commands']) == 6 and
            report['sdk_audit']['status'] == 'passed' and report['installed_owner_audit']['status'] == 'passed' and
            report['loader_audit']['status'] == 'passed', 'origin qualification gates incomplete')
    return report, {'kind': 'completed_full_cohort', 'round_result_sha256': rows[0]['result_sha256']}, report['logs']


def verify_go(prefix, records, commands):
    by_id = {r['component_id']: r for r in records}
    require(len(by_id) == len(records) == len(commands) == 6, 'six unique Go artifacts required')
    result = []
    for unit in commands:
        cid = unit['component_id']; row = by_id[cid]
        path = builder.safe_path(prefix / 'go' / cid / 'bin' / unit['binary_name'])
        require(path.is_file() and row['version'] == unit['package_version'] and sha(path) == row['sha256'],
                'inherited Go artifact differs')
        result.append({k: row[k] for k in ('component_id', 'version', 'sha256')})
    return result


def receipt_files(prefix, units):
    paths = set()
    for unit in units:
        name = closure.receipt_path(unit)
        owned = closure.owned_paths(read(prefix / name), name)
        require(not paths.intersection(owned), 'repair native ownership overlaps')
        paths.update(owned)
    return paths


def expected_inherited(inventory, removed):
    require(removed <= {r['path'] for r in inventory}, 'repair owned file missing from original inventory')
    return [r for r in inventory if r['path'] not in removed]


def verify_inherited(before, after, removed, allow_external=False):
    expected = {r['path']: r for r in expected_inherited(before, removed)}
    observed = {r['path']: r for r in after if r['path'] not in removed}
    require(set(observed) == set(expected), 'inherited file set changed')
    changed = sorted(p for p in expected if expected[p] != observed[p])
    require(not changed or (allow_external and changed == [EXTERNAL_REPAIR]), 'unaffected inherited bytes changed')
    return changed


def copy_configure_logs(origin_round, work, units, repaired, sealed_logs):
    sealed = {r['name']: r for r in sealed_logs or []}
    require(len(sealed) == len(sealed_logs or []), 'duplicate original log entry')
    rows, provenance = [], []
    for unit in units:
        cid = unit['component_id']
        if cid in repaired: continue
        name = cid + '-configure.log'; source = builder.safe_path(origin_round / 'logs' / name)
        require(source.is_file(), 'inherited configure log missing')
        value = sha(source)
        if sealed_logs is not None:
            require(name in sealed and sealed[name]['exit_code'] == 0 and sealed[name]['sha256'] == value,
                    'sealed inherited configure log changed')
        # Retained first build has no round result. Its files are exact preserved
        # observations, explicitly hashed at repair admission rather than retroactively sealed.
        require('The CXX compiler identification is ' in source.read_text(), 'inherited compiler observation absent')
        shutil.copyfile(source, work / 'logs' / name)
        rows.append({'name': name, 'sha256': value, 'exit_code': 0})
        provenance.append({'component_id': cid, 'kind': 'inherited_native_receipt_and_bytes',
                           'configure_log_sha256': value, 'original_log_sealed_by_round': sealed_logs is not None})
    return rows, provenance


def configure_base(args, source, stage, work):
    require(hasattr(builder, 'native_link_policy'), 'reviewed stable native link policy not integrated')
    flags = f'"-ffile-prefix-map={source}=/symphony-source" "-fdebug-prefix-map={work}=/symphony-build"'
    values = [f'-DCMAKE_INSTALL_PREFIX={stage}', f'-DCMAKE_PREFIX_PATH={stage};{stage}/third-party',
        '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DCMAKE_INSTALL_LIBDIR=lib',
        '-DBUILD_TESTING=OFF', '-DSYMPHONY_KVE_BUILD_TESTING=OFF', '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF',
        '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON',
        '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON', '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF',
        '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local', *builder.native_link_policy(),
        f'-DCMAKE_C_COMPILER={args.cc}', f'-DCMAKE_CXX_COMPILER={args.cxx}', f'-DCMAKE_C_FLAGS={flags}', f'-DCMAKE_CXX_FLAGS={flags}',
        f'-DSYMPHONY_PACKAGE_FINALIZER={ROOT}/build-cohort/FinalizeNative.cmake',
        f'-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={source}/tests/mvp-dependencies/prove-imports.cmake',
        f'-DMVP_SELECTED_PREFIX={stage}', f'-DMVP_EXTERNAL_PREFIX={stage}/third-party', f'-DMVP_REPOSITORY={source}']
    if platform.system() == 'Darwin':
        values += ['-DCMAKE_EXE_LINKER_FLAGS=-Wl,-headerpad_max_install_names', '-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-headerpad_max_install_names']
        if not args.supplemental: values.append('-DCMAKE_OSX_DEPLOYMENT_TARGET=15.0')
    return values


def remove_selected(args, source, stage, work, selected, base, runner, metadata):
    scripts, proof = {}, {}
    for unit in selected:
        cid = unit['component_id']; configured = work / 'configure-removal' / cid
        runner.run(cid + '-removal-configure', [args.cmake, '-S', source / unit['source_root'], '-B', configured, *base,
            *[f'-D{k}={v}' for k, v in unit['installed_options'].items()], f'-DMVP_COMPONENT_FILE={metadata}/{cid}.json',
            f'-DMVP_PROOF_LOG={work}/logs/{cid}-removal-imports.txt'])
        detached = work / 'uninstallers' / cid; detached.mkdir(parents=True, mode=0o700)
        identities = list(configured.glob('symphony-receipt-v2-identity-*.cmake'))
        require(len(identities) == 1, 'configured owner identity absent')
        hashes = {}
        for path in [configured / n for n in ('uninstall.cmake', 'SymphonyUninstallReceiptV2.cmake', 'SymphonyReceiptV2Support.cmake')] + identities:
            require(path.is_file() and not path.is_symlink(), 'configured owner helper missing or aliased')
            shutil.copyfile(path, detached / path.name); hashes[path.name] = sha(path)
        script = detached / 'uninstall.cmake'; inventory = detached / 'configured-files.txt'
        runner.run(cid + '-removal-inventory', [args.cmake, f'-DSDK_UNINSTALLER={script}', f'-DSDK_INVENTORY_OUTPUT={inventory}',
                    '-P', source / 'tests/native-sdk-distribution/inspect-uninstaller.cmake'])
        name = closure.receipt_path(unit)
        closure.compare_inventory(inventory.read_text().split(';'), closure.owned_paths(read(stage / name), name))
        scripts[cid] = script; proof[cid] = hashes
        shutil.rmtree(configured)
    for unit in reversed(selected):
        cid = unit['component_id']
        runner.run(cid + '-remove', [args.cmake, f'-DINSTALL_PREFIX={stage}', '-P', scripts[cid]])
    return proof


def run(args):
    for name in ('origin', 'repository', 'gomodcache'):
        setattr(args, name, builder.safe_path(getattr(args, name)).resolve(strict=True))
    for name in ('go', 'cmake', 'cc', 'cxx'):
        path = Path(os.path.abspath(getattr(args, name)))
        require(path.is_file() and os.access(path, os.X_OK), 'selected executable absent')
        setattr(args, name, path)
    for name in ('retained_qualification', 'privacy_policy', 'developer_dir'):
        value = getattr(args, name)
        if value: setattr(args, name, builder.safe_path(value).resolve(strict=True))
    plan = read(ROOT / 'build-cohort/cohort.json')
    planner.validate(plan, args.repository, read(ROOT / 'source-binding.json'))
    summary = read(args.origin / 'result.json'); origin_summary_sha = sha(args.origin / 'result.json')
    original, origin_proof, sealed_logs = admit_record(args, summary, plan)
    reviewed = summary['source_input']['kind'] == 'verified_reviewed_derived_export'
    require(bool(args.privacy_policy) == reviewed, 'reviewed source requires explicit private privacy policy; raw source does not accept one')
    evidence_inputs = {args.origin / 'result.json': origin_summary_sha}
    if args.retained_qualification:
        evidence_inputs[args.retained_qualification / 'result.json'] = args.retained_qualification_sha256
        evidence_inputs[args.origin / 'INCOMPLETE.json'] = original['original_incomplete_sha256']
    else:
        evidence_inputs[args.origin / 'round-1/result.json'] = origin_proof['round_result_sha256']
    profile = plan['profiles'][summary['host']['requested_profile']]
    args.supplemental = summary['host']['scope'] == 'supplemental_local_build'
    require(builder.selected_host(summary['host']['requested_profile'], profile['platform_contract'], args.supplemental) == summary['host'],
            'repair actual platform differs from origin')
    source_digest = closure.verify_source(args.origin, summary)
    units = profile['native_build_order']; selected = repair_units(units); repaired = {u['component_id'] for u in selected}
    require(len(units) == 51, 'full frozen native cohort required')
    prefix = args.origin / 'round-1/relocated-prefix'
    original_inventory = builder.snapshot(prefix)
    require(original_inventory == original['payload_inventory'] and builder.verify_receipts(prefix, units) == original['native_receipts'],
            'original retained payload or receipt proof changed')
    if args.retained_qualification:
        require(digest(original_inventory) == original['payload_inventory_sha256'] and source_digest == original['source_inventory_sha256'],
                'retained inventory/source digest differs')
    go_commands = verify_go(prefix, original['go_commands'], profile['go_commands'])
    removed = receipt_files(prefix, selected)
    out = builder.fresh(args.output, [args.origin, args.repository, args.gomodcache, ROOT, args.go,
                                    *[p for p in (args.retained_qualification, args.privacy_policy) if p]])
    args.owned_output = out
    shutil.copytree(args.origin / 'source', out / 'source'); source = out / 'source'
    if summary['source_input']['kind'] == 'exact_committed_source_archive':
        shutil.copyfile(args.origin / 'committed-source.tar', out / 'committed-source.tar')
    require(closure.verify_source(out, summary) == source_digest, 'copied source differs')
    work = out / 'round-1'; work.mkdir(mode=0o700)
    env = builder.clean_environment(work, args.go, args.gomodcache, args.cc, args.cxx)
    env['PATH'] = str(args.cmake.parent) + ':' + env['PATH']
    if args.developer_dir: env['DEVELOPER_DIR'] = str(args.developer_dir)
    env.update(SYMPHONY_D06_EXTERNAL_PREFIX=str(prefix / 'third-party'), SYMPHONY_D06_STAGE_EXTERNAL=str(work / 'stage/third-party'),
               SYMPHONY_D06_PYTHON=sys.executable)
    runner = builder.Runner(work, env, args.timeout)
    observed = runner.run('repair-go-toolchain', [args.go, 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH']).read_text().splitlines()
    require(observed == ['go1.26.5', 'darwin' if summary['host']['os'] == 'macos' else 'linux', summary['host']['architecture']],
            'exact native Go1.26.5 required')
    stage = work / 'stage'; shutil.copytree(prefix, stage, symlinks=True)
    require(builder.snapshot(stage) == original_inventory, 'fresh payload copy differs')
    log_rows, provenance = copy_configure_logs(args.origin / 'round-1', work, units, repaired, sealed_logs)
    runner.logs.extend(log_rows)
    for row in log_rows: evidence_inputs[args.origin / 'round-1/logs' / row['name']] = row['sha256']
    imported = {p: sha(ROOT / p) for p in ('qualification/native_campaign.py', 'source-export/export_source.py')}
    extra = {p: sha(ROOT / p) for p in ('qualification/d06_repair_cohort.py', 'qualification/d06_sdk_closure.py', 'owner-catalog/native_owners.py')}
    result = {**{k: summary[k] for k in ('protocol', 'source_commit', 'source_tree', 'plan_sha256', 'host', 'source_input', 'external_evidence_sha256')},
        'builder_sha256': sha(ROOT / 'build-cohort/build.py'), 'build_helpers': current_helpers(), 'imported_helpers': imported,
        'repair_helpers': extra, 'state': 'building', 'rounds': [], 'acceptance_complete': False, 'publication_authorized': False,
        'fresh_whole_cohort_build': False, 'repeated_payload_bytes_equal': False,
        'repair_provenance': {**origin_proof, 'origin_build_result_sha256': origin_summary_sha,
            'origin_tool_commit': args.origin_tool_commit, 'origin_payload_inventory_sha256': digest(original_inventory),
            'source_inventory_sha256': source_digest, 'rebuild_ids': [u['component_id'] for u in selected],
            'inherited_native_count': 43, 'inherited_go_count': 6, 'external_repair_allowlist': [EXTERNAL_REPAIR]},
        'selected_tool_sha256': {n: sha(getattr(args, n)) for n in ('go', 'cmake', 'cc', 'cxx')}}
    dump(out / 'result.json', result)
    metadata = work / 'metadata'; metadata.mkdir()
    source_map = {u['component_id']: u for u in read(source / 'cmake/mvp-dependencies.json')['native_components']}
    for unit in selected: dump(metadata / (unit['component_id'] + '.json'), source_map[unit['component_id']])
    base = configure_base(args, source, stage, work)
    owner_proof = remove_selected(args, source, stage, work, selected, base, runner, metadata)
    require(builder.snapshot(stage) == expected_inherited(original_inventory, removed), 'native owners removed unexpected files')
    for index, unit in enumerate(selected):
        cid = unit['component_id']; build = work / 'build' / cid
        print(f'Repair native {index + 1}/{len(selected)}: {cid}', flush=True)
        runner.run(cid + '-configure', [args.cmake, '-S', source / unit['source_root'], '-B', build, *base,
            *[f'-D{k}={v}' for k, v in unit['installed_options'].items()], f'-DMVP_COMPONENT_FILE={metadata}/{cid}.json',
            f'-DMVP_PROOF_LOG={work}/logs/{cid}-imports.txt'])
        runner.run(cid + '-build', [args.cmake, '--build', build, '--parallel', str(args.jobs)])
        runner.run(cid + '-install', [args.cmake, f'-DSYMPHONY_PACKAGE_STAGE_ROOT={stage}', '-P', build / 'cmake_install.cmake'])
        runner.run(cid + '-receipt', [args.cmake, f'-DMVP_REPOSITORY={source}', f'-DMVP_COMPONENT_FILE={metadata}/{cid}.json',
                   f'-DMVP_SELECTED_PREFIX={stage}', '-P', source / 'tests/mvp-dependencies/verify-receipt.cmake'])
        builder.verify_receipts(stage, [unit])
        provenance.append({'component_id': cid, 'kind': 'rebuilt_from_exact_origin_source',
                           'configure_log_sha256': sha(work / 'logs' / (cid + '-configure.log'))})
        if args.prune_builds: shutil.rmtree(build)
    verify_inherited(original_inventory, builder.snapshot(stage), removed)
    external_before = [r for r in builder.snapshot(stage) if r['path'].startswith('third-party/')]
    runner.run('external-finalization', [sys.executable, ROOT / 'build-cohort/finalize_native.py', '--root', stage,
               '--external', '--evidence', work / 'external-finalization.json'])
    external_after = [r for r in builder.snapshot(stage) if r['path'].startswith('third-party/')]
    changed_external = verify_inherited(original_inventory, builder.snapshot(stage), removed, allow_external=True)
    from loader_audit import audit as loader_audit
    loader = loader_audit(stage); dump(work / 'loader-audit.json', loader)
    receipts = builder.verify_receipts(stage, units)
    relocated = work / 'relocated-prefix'; stage.rename(relocated)
    from sdk_audit import run_audit
    sdk = run_audit(source, relocated, work / 'sdk-audit', cmake=str(args.cmake), cxx=str(args.cxx),
                    components=[u['component_id'] for u in units], external_prefix=relocated / 'third-party',
                    timeout=args.timeout, developer_dir=args.developer_dir)
    from owner_audit import run_owner_audit
    owner = run_owner_audit(source, relocated, work / 'owner-audit', go=args.go, gomodcache=args.gomodcache, timeout=args.timeout, env=env)
    require(builder.verify_receipts(relocated, units) == receipts, 'audits changed final native receipts')
    privacy = None
    if args.privacy_policy:
        privacy = builder.load_exporter(); privacy.configure_policy(args.privacy_policy)
    inventory = builder.snapshot(relocated, privacy, forbidden=(source, work, args.repository, args.origin))
    verify_inherited(original_inventory, inventory, removed, allow_external=True)
    verify_go(relocated, go_commands, profile['go_commands'])
    round_result = {'state': 'built_and_sdk_checked', 'native_count': 51, 'native_receipts': receipts, 'go_commands': go_commands,
        'sdk_audit': sdk, 'installed_owner_audit': owner, 'loader_audit': loader, 'payload_inventory': inventory, 'logs': runner.logs,
        'build_cache_fresh': False, 'repair_build_cache_fresh': True, 'private_home': True, 'installed_stage_relocated': True,
        'fresh_whole_cohort_build': False, 'native_unit_provenance': sorted(provenance, key=lambda r: r['component_id']),
        'repaired_native_count': 8, 'inherited_native_count': 43, 'inherited_go_count': 6,
        'detached_removal_helpers_sha256': owner_proof,
        'external_repair': {'input_inventory_sha256': digest(external_before), 'output_inventory_sha256': digest(external_after),
                            'changed_paths': changed_external, 'separately_inventoried': True},
        'external_payload_ownership': 'separate_distribution_build_inventory_not_native_receipt',
        'native_live_owner_acceptance': False, 'publication_authorized': False}
    dump(work / 'result.json', round_result)
    require(builder.snapshot(prefix) == original_inventory and builder.verify_receipts(prefix, units) == original['native_receipts'] and
            all(sha(path) == expected for path, expected in evidence_inputs.items()) and closure.verify_source(args.origin, summary) == source_digest,
            'original evidence/source/payload changed during repair')
    require(closure.verify_source(out, result) == source_digest and current_helpers() == result['build_helpers'] and
            all(sha(ROOT / p) == h for p, h in {**imported, **extra}.items()), 'repair source/helpers changed during run')
    result.update(state='built_and_sdk_checked', original_evidence_unchanged=True,
        rounds=[{'directory': 'round-1', 'result_sha256': sha(work / 'result.json'), 'native_count': 51, 'go_count': 6}],
        blockers=['supported platform and fresh-host acceptance remain separate',
                  'external runtime carrier ownership, signing, delivery and independent review remain open'])
    dump(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('origin', 'repository', 'output', 'cmake', 'cc', 'cxx', 'go', 'gomodcache'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--origin-tool-commit', required=True)
    parser.add_argument('--retained-qualification', type=Path); parser.add_argument('--retained-qualification-sha256')
    parser.add_argument('--privacy-policy', type=Path); parser.add_argument('--developer-dir', type=Path)
    parser.add_argument('--prune-builds', action='store_true'); parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    try:
        require(1 <= args.jobs <= 16 and 1 <= args.timeout <= 7200, 'bounded jobs/timeout required')
        result = run(args); print(json.dumps({'state': result['state'], 'rebuilt_native': 8, 'inherited_native': 43, 'inherited_go': 6}))
    except BaseException as exc:
        if hasattr(args, 'owned_output'):
            dump(args.owned_output / 'INCOMPLETE.json', {'state': 'incomplete', 'reason': str(exc), 'acceptance_complete': False})
        raise


if __name__ == '__main__': main()
