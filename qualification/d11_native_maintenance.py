#!/usr/bin/env python3
"""Qualify existing native owners against one retained primary58 carrier capsule.

Only new private disposable prefixes are changed. The existing51 source owners
are configured, then exercised for refusal/removal/recovery. No native install,
service retirement, two-release transition, trust or acceptance is inferred.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import primary_rewrap as reuse
from qualification import primary_artifacts as transport
from qualification import d09_maintenance as existing
from qualification import d09_platform as platform_gate

c = reuse.c
PROTOCOL = 'symphony.distribution.d11-primary-native-maintenance.v1'
HELPERS = tuple(sorted(set(reuse.HELPERS) | {
    'qualification/d11_native_maintenance.py', 'qualification/d09_maintenance.py',
    'qualification/d06_sdk_closure.py', 'build-cohort/cohort.json',
    'build-cohort/build.py', 'build-cohort/plan.py'}))


def helpers():
    return {name: existing.file_sha(ROOT / name) for name in HELPERS}


def committed_helpers(expected):
    commit = os.environ.get('GITHUB_SHA', '')
    c.require(re.fullmatch('[0-9a-f]{40}', commit) and
              existing.git(ROOT, 'rev-parse', 'HEAD').decode().strip() == commit,
              'Exact current workflow toolkit commit required')
    for name, digest in expected.items():
        c.require(c.sha(existing.git(ROOT, 'show', commit + ':' + name)) == digest,
                  'Executing qualification helper differs from selected committed source')
    return {'commit': commit, 'tree': existing.git(ROOT, 'rev-parse', 'HEAD^{tree}').decode().strip()}


def dependency_map_binding(source, capsule, manifest, record):
    """Admit only the exact reviewed source-input rebindings, never owner changes."""
    return dependency_map_files(source / 'cmake/mvp-dependencies.json',
        capsule / 'evidence/mvp-dependencies.json', manifest, record['dependency_map_sha256'])


def dependency_map_files(original_path, reviewed_path, manifest, reviewed_sha256):
    """Same source-input proof for actual source files, independent of carriers."""
    name = 'cmake/mvp-dependencies.json'
    original_raw, _ = c.bounded(original_path)
    exported_raw, _ = c.bounded(reviewed_path)
    rows = {row['path']: row for row in manifest['source_files']}
    excluded = {row['path']: row for row in manifest['excluded_files']}
    c.require(len(excluded) == len(manifest['excluded_files']) and not rows.keys() & excluded.keys(),
              'Derived source exclusion inventory differs')
    c.require(c.sha(original_raw) == rows[name]['source_sha256'] and
              c.sha(exported_raw) == rows[name]['export_sha256'] == reviewed_sha256,
              'Original or retained reviewed dependency map differs')
    original = reuse.supplements.parse(original_raw)
    transformed = reuse.supplements.parse(original_raw)
    retained, rebindings, omitted, seen = [], [], [], set()
    for item in transformed['source_inputs']:
        path = item['path']; c.relative(path)
        c.require(path not in seen, 'Duplicate dependency-map source input'); seen.add(path)
        if path in rows:
            c.require(item['sha256'] == rows[path]['source_sha256'], 'Original dependency-map input differs')
            digest = rows[path]['export_sha256']
            if item['sha256'] != digest:
                rebindings.append({'path': path, 'original_sha256': item['sha256'], 'export_sha256': digest})
                item['sha256'] = digest
            retained.append(item)
        else:
            c.require(path.startswith('tests/public-beta/') and path in excluded and
                      item['sha256'] == excluded[path]['source_sha256'], 'Unreviewed dependency-map input omission')
            omitted.append(dict(item, reason='private publisher dossier/test artifact omitted from derived public source'))
    transformed['source_inputs'] = retained
    reproduced = (json.dumps(transformed, indent=2) + '\n').encode() if rebindings or omitted else original_raw
    c.require(exported_raw == reproduced and manifest['source_map_rebindings'] == rebindings and
              manifest['source_map_omitted_private_publisher_test_inputs'] == omitted,
              'Dependency map differs beyond reviewed source-input rebindings')
    projection = {key: value for key, value in original.items() if key != 'source_inputs'}
    c.require(projection == {key: value for key, value in reuse.supplements.parse(exported_raw).items() if key != 'source_inputs'},
              'Configuration-relevant dependency map changed')
    return {'original_sha256': c.sha(original_raw), 'reviewed_sha256': c.sha(exported_raw),
            'configuration_projection_sha256': c.sha(c.canonical(projection)),
            'source_input_rebinding_count': len(rebindings), 'omitted_dossier_input_count': len(omitted),
            'configuration_projection_unchanged': True}


def source_binding(source, capsule, cohort):
    record = c.document(capsule / 'result.json')
    manifest = c.document(capsule / 'evidence/source-manifest.json')
    build = c.document(capsule / 'evidence/build-result.json')
    c.require(existing.file_sha(ROOT / 'build-cohort/cohort.json') == build['plan_sha256'],
              'Current configuration plan differs from retained build plan')
    c.require(record['source_commit'] == existing.COMMIT and record['source_tree'] == existing.TREE and
              manifest['origin_commit'] == existing.COMMIT and manifest['origin_tree'] == existing.TREE and
              manifest['derived_export_digest'] == record['source_export_digest'], 'Retained owner source identity differs')
    units, register, bound = existing.source_register(source, cohort)
    plan = c.document(ROOT / 'build-cohort/cohort.json')
    c.require(units == plan['profiles'][record['profile']]['native_build_order'], 'Selected native configuration profile differs')
    dependency_map_binding(source, capsule, manifest, record)
    selected = (set(bound) | {'tests/mvp-dependencies/prove-imports.cmake'}) - {'cmake/mvp-dependencies.json'}
    rows = {row['path']: row for row in manifest['source_files']}
    c.require(len(rows) == len(manifest['source_files']), 'Duplicate source manifest paths')
    selected |= {name for name in rows if Path(name).name == 'CMakeLists.txt' or name.endswith(('.cmake', '.cmake.in'))}
    c.require(selected <= rows.keys(), 'Configuration source omitted from reviewed export')
    for name in sorted(selected):
        row = rows[name]; raw, mode = c.bounded(source / c.relative(name))
        c.require(row['source_sha256'] == row['export_sha256'] == c.sha(raw) and
                  row['mode'] == ('100755' if mode == 0o755 else '100644') and mode in (0o644, 0o755),
                  'Owner configuration differs from original or reviewed built source')
        bound[name] = c.sha(raw)
    bound['cmake/mvp-dependencies.json'] = rows['cmake/mvp-dependencies.json']['source_sha256']
    return units, register, bound


def validate_payload_rows(rows):
    """Validate all paths and the bounded external curl link graph before writing."""
    c.require(rows, 'Empty native payload refused')
    for name, row in rows.items():
        path = c.relative(name)
        c.require(row['path'] == name and not any(str(parent) in rows for parent in path.parents),
                  'Payload file/directory or linked-parent collision')
        if 'link' in row:
            target = row['link']
            c.require(name.startswith('third-party/lib/libcurl') and isinstance(target, str) and
                      target.startswith('libcurl') and '/' not in target and '\\' not in target and
                      target not in ('.', '..'), 'Unqualified external runtime link')
            current = name; seen = set()
            while 'link' in rows[current]:
                c.require(current not in seen and len(seen) < 16, 'Cyclic or unbounded curl link chain')
                seen.add(current)
                current = str(Path(current).parent / rows[current]['link'])
                c.require(current in rows, 'External runtime link target absent')
            c.require('sha256' in rows[current], 'External runtime link lacks a regular target')
        else:
            c.digest(row['sha256'])
            c.require(type(row['size']) is int and 0 <= row['size'] <= c.LIMIT and row['mode'] in (0o444, 0o555, 0o644, 0o755),
                      'Unsafe retained payload file')


def materialize(capsule, cohort, output):
    """Copy validated opaque payloads only; no carrier hook or executable runs."""
    c.require(cohort['profile'] in platform_gate.PROFILES and len(cohort['entries']) == len(cohort['archives']) == 58 and
              sum(entry['kind'] == 'native_receipt_unit' for entry in cohort['entries']) == 51 and
              sum(entry['kind'] == 'go_command' for entry in cohort['entries']) == 6 and
              sum(entry['kind'] == 'external_inert_runtime_and_sdk' for entry in cohort['entries']) == 1,
              'Exact completed primary58 ownership set required')
    retained = output / 'retained'; retained.mkdir(mode=0o700)
    prefix = output / 'retained-prefix'
    c.require(not prefix.exists(), 'Retained payload destination must be new')
    archives = {row['unit_id']: row for row in cohort['archives']}
    c.require(len(archives) == 58, 'Duplicate carrier archive unit')
    source = capsule / 'carriers/channel' / cohort['conda_subdir']
    assigned, rows, locations = {}, {}, {}
    for entry in cohort['entries']:
        unit, path = existing.read_carrier(source, cohort, entry, archives[entry['unit_id']], retained)
        selected = set(unit['payload_paths']); inventory = c.rows_by_path(unit['files'])
        c.require(selected <= inventory.keys(), 'Unlisted unit payload path')
        for name in selected:
            c.require(name not in rows, 'Overlapping native payload ownership')
            assigned[name], rows[name], locations[name] = unit['unit_id'], inventory[name], path
    c.require(assigned == cohort['payload_assignment'] and len(rows) == cohort['payload_entry_count'],
              'Incomplete native payload ownership coverage')
    validate_payload_rows(rows)
    prefix.mkdir(mode=0o700); expected = {}
    for name, row in sorted(rows.items()):
        target = prefix / c.relative(name); target.parent.mkdir(parents=True, exist_ok=True)
        if 'link' in row:
            target.symlink_to(row['link']); expected[name] = {'link': row['link']}
        else:
            with tarfile.open(locations[name], mode='r:') as stream:
                data = stream.extractfile(name).read(row['size'] + 1)
            c.require(len(data) == row['size'] and c.sha(data) == row['sha256'], 'Retained payload changed during copy')
            reuse.signing.write(target, data, row['mode'])
            expected[name] = {'sha256': row['sha256'], 'mode': row['mode']}
    c.require(existing.file_snapshot(prefix) == expected, 'Materialized payload differs from selected carrier bytes')
    return prefix, expected


def environment(output, tools, profile, developer_dir=None):
    for name in ('home', 'tmp'): (output / name).mkdir(mode=0o700)
    home = output / 'home'
    for name in ('.condarc', '.bashrc', '.zshrc'):
        (home / name).write_bytes(b'# isolated caller state must survive\n')
    env = {'PATH': str(tools['cmake'].parent) + ':/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home),
           'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'USER': 'builder', 'LOGNAME': 'builder',
           'CMAKE_GENERATOR': 'Unix Makefiles'}
    if profile == 'macos15-arm64':
        c.require(developer_dir is not None, 'Explicit selected Apple developer directory required')
        developer = c.safe_root(developer_dir)
        c.require(developer.is_dir(), 'Selected Apple developer directory absent')
        env['DEVELOPER_DIR'] = str(developer)
    else:
        c.require(developer_dir is None, 'Apple developer environment cannot enter Linux qualification')
    return env


def validate_completion(units, results, logs):
    wanted = {unit['component_id']: unit['version'] for unit in units}
    c.require(len(wanted) == len(units) == len(results) == 51 and
              {row['component_id']: row['version'] for row in results} == wanted,
              'Complete unique native51 observations required')
    fields = ('immutable_reinstall_refused', 'managed_root_marker_presence_refused', 'aliased_receipt_refused',
              'changed_owned_bytes_refused', 'interrupted_removal_resumed', 'absent_removal_idempotent',
              'empty_version_preflight_passed', 'same_candidate_restoration_exact', 'other_package_and_user_bytes_preserved')
    c.require(all(all(row[key] is True for key in fields) and all(row[key] is False for key in
        ('native_install_execution_qualified', 'different_version_upgrade_qualified', 'rollback_qualified', 'live_retirement_qualified'))
        for row in results), 'Owner observations changed scope or left incomplete checks')
    c.require(len(logs) == 51 * 12 and len({row['name'] for row in logs}) == len(logs) and
              all(row['exit_code'] == (0 if row['expected'] == 'success' else 1) and
                  row['expected'] in ('success', 'refusal') for row in logs), 'Missing commands or invalid refusal outcomes')


def run(args):
    c.require(args.allow_ephemeral_maintenance is True, 'Explicit disposable maintenance opt-in required')
    selection = transport.validate_selection(args.selection, args.selection_sha256)
    capsule, source = c.safe_root(args.artifact), c.safe_root(args.source)
    selected = reuse.selected_capsule(capsule, selection, args.selection_sha256, args.transport_proof)
    custody = reuse.custody(selected['profile'], args.output)
    inspection = reuse.inspection_tools(args.inspection_tools, selected['profile'])
    cohort = c.audit_cohort(capsule / 'carriers')
    units, register, source_files = source_binding(source, capsule, cohort)
    map_evidence = dependency_map_binding(source, capsule, c.document(capsule / 'evidence/source-manifest.json'), selected)
    helper_map = helpers(); toolkit = committed_helpers(helper_map)
    tools = existing.selected_tools(args)
    for name, path in tools.items(): setattr(args, name, path)
    tool_hashes = {name: platform_gate.sha(path) for name, path in tools.items()}
    c.require(type(args.timeout) is int and 1 <= args.timeout <= 600, 'Bounded per-command timeout required')
    before = reuse.tree_inventory(capsule)
    selected_raw = c.bounded(args.selection)[0]; proof_raw = c.bounded(args.transport_proof)[0]
    output = platform_gate.fresh(args.output, (capsule, source, args.selection, args.transport_proof, args.inspection_tools, ROOT))
    env = environment(output, tools, selected['profile'], args.developer_dir)
    home_before = platform_gate.inventory(output / 'home')
    runner = existing.Runner(output, env, args.timeout)
    reuse.signing.write(output / 'maintenance-register.json', c.canonical({'protocol': PROTOCOL,
        'state': 'source_bound_requirements_pending_campaign', 'profile': selected['profile'],
        'source_commit': existing.COMMIT, 'source_tree': existing.TREE, 'source_export_digest': selected['source_export_digest'],
        'source_files': source_files, 'dependency_map_binding': map_evidence, 'units': register, 'native_maintenance_acceptance': False}), 0o644)
    prefix, payload = materialize(capsule, cohort, output)
    owners = existing.configure(source, prefix, output, units, args, runner)
    observations = existing.campaign(prefix, output, units, owners, args, runner)
    validate_completion(units, observations, runner.logs)
    c.require(existing.file_snapshot(prefix) == payload, 'Original retained native bytes changed')
    reuse.records_equal(capsule, before)
    c.require(reuse.selected_capsule(capsule, selection, args.selection_sha256, args.transport_proof) == selected and
              c.bounded(args.selection)[0] == selected_raw and c.bounded(args.transport_proof)[0] == proof_raw and
              source_binding(source, capsule, cohort)[2] == source_files and helpers() == helper_map and
              committed_helpers(helper_map) == toolkit and platform_gate.inventory(output / 'home') == home_before and
              tool_hashes == {name: platform_gate.sha(path) for name, path in tools.items()} and
              reuse.inspection_tools(args.inspection_tools, selected['profile']) == inspection,
              'Selected source, tools, helpers, proofs or caller state changed')
    result = {'protocol': PROTOCOL, 'state': 'primary_disposable_unmanaged_owner_campaign_passed',
        'profile': selected['profile'], 'hosted_custody': custody, 'selection_sha256': args.selection_sha256,
        'selected_primary_result_sha256': selection['pins']['primary_result_sha256'],
        'transport_proof_sha256': c.sha(proof_raw), 'cohort_digest': cohort['cohort_digest'],
        'source_commit': existing.COMMIT, 'source_tree': existing.TREE, 'source_export_digest': selected['source_export_digest'],
        'inherited_build_result_sha256': selected['build_result_sha256'], 'inherited_sdk_closure_sha256': selected['sdk_closure_sha256'],
        'source_files': source_files, 'dependency_map_binding': map_evidence, 'qualification_toolkit': toolkit, 'imported_helpers': helper_map,
        'inspection_tools': inspection, 'configuration_tools': tool_hashes,
        'maintenance_register_sha256': existing.file_sha(output / 'maintenance-register.json'),
        'native_unit_count': 51, 'units': observations, 'logs': runner.logs, 'retained_payload_entry_count': len(payload),
        'retained_payload_unchanged': True, 'selected_capsule_unchanged': True, 'caller_state_preserved': True,
        'restoration_kind': 'same_exact_candidate_recovery_not_upgrade_or_rollback',
        'processes_or_services_started': False, 'external_runtime_ownership_qualified': False,
        'native_install_execution_qualified': False, 'live_retirement_qualified': False,
        'two_release_upgrade_qualified': False, 'two_release_rollback_qualified': False,
        'independent_fresh_host_acceptance': False, 'publisher_trust_accepted': False,
        'release_acceptance_complete': False, 'publication_authorized': False}
    reuse.signing.write(output / 'result.json', c.canonical(result), 0o644)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('selection', 'artifact', 'transport-proof', 'source', 'inspection-tools', 'cmake', 'cc', 'cxx', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--developer-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--allow-ephemeral-maintenance', action='store_true')
    args = parser.parse_args()
    try:
        result = run(args); print(json.dumps({'state': result['state'], 'native_unit_count': 51, 'publication_authorized': False}))
    except BaseException as error:
        output = platform_gate.safe(args.output)
        info = output.stat() if output.is_dir() else None
        if info and platform_gate.OWNED_OUTPUTS.get(output) == (info.st_dev, info.st_ino):
            reuse.signing.write(output / 'INCOMPLETE.json', c.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
                'error_class': type(error).__name__, 'private_logs_retained': True, 'publication_authorized': False}), 0o644)
        raise


if __name__ == '__main__': main()
