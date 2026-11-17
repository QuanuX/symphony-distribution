#!/usr/bin/env python3
"""Exercise existing51 owners against retained native bytes on a primary runner.

No carrier is fabricated and no native build or live installation is performed.
The original source/build/SDK provenance and user state remain separate from this
new disposable refusal/removal/same-candidate recovery campaign.
"""
import argparse
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_rewrap as native
from qualification import native_artifacts as transport
from qualification import d11_native_maintenance as common

existing, gate, c, reuse = common.existing, common.platform_gate, common.c, common.reuse
PROTOCOL = 'symphony.distribution.retained-native-maintenance.v1'
HELPERS = tuple(sorted(set(native.HELPERS) | set(common.HELPERS) | {
    'qualification/native_maintenance.py', '.github/workflows/d13-native-maintenance.yml'}))


def helper_hashes():
    return {name: existing.file_sha(ROOT / name) for name in HELPERS}


def native_selection_rows(units, receipts):
    """Configuration inputs from verified native receipts, never carrier records."""
    selected = {row['component_id']: row for row in receipts}
    c.require(len(units) == len(receipts) == len(selected) == 51 and
        {row['component_id'] for row in units} == set(selected), 'Complete unique native51 receipt selection required')
    result = []
    for unit in units:
        row = selected[unit['component_id']]
        c.require(row['version'] == unit['version'] and type(row['owned_file_count']) is int and row['owned_file_count'] > 0,
                  'Selected receipt owner version or coverage differs')
        c.digest(row['receipt_sha256'])
        result.append({'component_id': unit['component_id'], 'native_version': row['version'],
                       'sdk_exports': unit['exported_packages']})
    return result


def source_inputs(source, restored, lineage):
    """Reuse the unchanged owner and reviewed-map checks on real source inputs."""
    root = restored; build = c.document(root / 'cohort/result.json')
    first = c.document(root / 'cohort/round-1/result.json')
    manifest = c.document(root / 'export/SOURCE-EXPORT.json')
    plan = c.document(ROOT / 'build-cohort/cohort.json')
    c.require(existing.file_sha(ROOT / 'build-cohort/cohort.json') == build['plan_sha256'] and
        build['source_commit'] == lineage['source_commit'] == manifest['origin_commit'] == existing.COMMIT and
        build['source_tree'] == lineage['source_tree'] == manifest['origin_tree'] == existing.TREE and
        manifest['derived_export_digest'] == lineage['source_export_digest'], 'Native owner source/plan selection differs')
    units = plan['profiles'][lineage['profile']]['native_build_order']
    rows = native_selection_rows(units, first['native_receipts'])
    registered, register, bound = existing.source_register_units(source, rows,
        {'commit': lineage['source_commit'], 'tree': lineage['source_tree']})
    c.require(registered == units, 'Original owner configuration differs from selected native profile')
    reviewed = root / 'export/source/cmake/mvp-dependencies.json'
    map_proof = common.dependency_map_files(source / 'cmake/mvp-dependencies.json', reviewed, manifest, existing.file_sha(reviewed))
    entries = {row['path']: row for row in manifest['source_files']}
    c.require(len(entries) == len(manifest['source_files']), 'Duplicate source manifest paths')
    selected = (set(bound) | {'tests/mvp-dependencies/prove-imports.cmake'}) - {'cmake/mvp-dependencies.json'}
    selected |= {name for name in entries if Path(name).name == 'CMakeLists.txt' or name.endswith(('.cmake', '.cmake.in'))}
    c.require(selected <= entries.keys(), 'Owner configuration source omitted from reviewed export')
    for name in sorted(selected):
        row = entries[name]; raw, mode = c.bounded(source / c.relative(name))
        c.require(row['source_sha256'] == row['export_sha256'] == c.sha(raw) and
                  mode in (0o644, 0o755) and row['mode'] == ('100755' if mode == 0o755 else '100644'),
                  'Owner configuration differs from original or reviewed native source')
        bound[name] = c.sha(raw)
    bound['cmake/mvp-dependencies.json'] = entries['cmake/mvp-dependencies.json']['source_sha256']
    return units, register, bound, map_proof


def run(args):
    c.require(args.allow_ephemeral_maintenance is True, 'Explicit disposable maintenance opt-in required')
    c.require(type(args.timeout) is int and 1 <= args.timeout <= 600, 'Bounded per-command timeout required')
    selected = transport.validate_selection(args.selection, args.selection_sha256)
    source, artifact = c.safe_root(args.source), c.safe_root(args.artifact)
    native.selected_inputs(artifact, selected, args.selection_sha256, args.transport_proof)
    custody = reuse.custody(selected['profile'], args.output)
    inspection = reuse.inspection_tools(args.inspection_tools, selected['profile'])
    imported = helper_hashes(); toolkit = common.committed_helpers(imported)
    tools = existing.selected_tools(args)
    for name, path in tools.items(): setattr(args, name, path)
    tool_hashes = {name: gate.sha(path) for name, path in tools.items()}
    output = gate.fresh(args.output, (artifact, source, args.selection, args.transport_proof,
                                     args.inspection_tools, args.privacy_policy, ROOT))
    verified = output / 'verified-native'
    restoration = native.restore(SimpleNamespace(selection=args.selection, selection_sha256=args.selection_sha256,
        artifact=artifact, transport_proof=args.transport_proof, repository=source, privacy_policy=args.privacy_policy, output=verified))
    restore_sha = existing.file_sha(verified / 'restore-result.json')
    lineage = restoration['lineage']
    units, register, source_files, map_proof = source_inputs(source, verified / 'restored', lineage)
    prefix = verified / 'restored/cohort/round-1/relocated-prefix'
    payload = existing.file_snapshot(prefix)
    env = common.environment(output, tools, selected['profile'], args.developer_dir)
    home_before = gate.inventory(output / 'home')
    runner = existing.Runner(output, env, args.timeout)
    reuse.signing.write(output / 'maintenance-register.json', c.canonical({'protocol': PROTOCOL,
        'state': 'source_bound_requirements_pending_campaign', 'profile': selected['profile'],
        'source_commit': existing.COMMIT, 'source_tree': existing.TREE,
        'source_export_digest': lineage['source_export_digest'], 'source_files': source_files,
        'dependency_map_binding': map_proof, 'units': register, 'native_maintenance_acceptance': False,
        'input_kind': 'authenticated_native_retention_not_carriers'}), 0o644)
    owners = existing.configure(source, prefix, output, units, args, runner)
    observations = existing.campaign(prefix, output, units, owners, args, runner)
    common.validate_completion(units, observations, runner.logs)
    c.require(existing.file_snapshot(prefix) == payload, 'Retained original native bytes changed')
    c.require(native.admit_restore(verified, restore_sha, source, args.privacy_policy)[0] == restoration and
        source_inputs(source, verified / 'restored', lineage)[2:] == (source_files, map_proof) and
        helper_hashes() == imported and common.committed_helpers(imported) == toolkit and
        {name: gate.sha(path) for name, path in tools.items()} == tool_hashes and
        gate.inventory(output / 'home') == home_before and
        reuse.inspection_tools(args.inspection_tools, selected['profile']) == inspection,
        'Native source, helpers, tools, evidence or caller state changed')
    # Recheck original fetched inputs as well as the private retained copy.
    native.selected_inputs(artifact, selected, args.selection_sha256, args.transport_proof)
    c.require(transport.validate_selection(args.selection, args.selection_sha256) == selected and
              c.sha(c.bounded(args.transport_proof)[0]) == restoration['transport_proof_sha256'],
              'Original selected native record changed')
    result = {'protocol': PROTOCOL, 'state': 'primary_retained_native_disposable_owner_campaign_passed',
        'profile': selected['profile'], 'hosted_custody': custody, 'selection_sha256': args.selection_sha256,
        'transport_proof_sha256': restoration['transport_proof_sha256'], 'restore_result_sha256': restore_sha,
        'lineage': lineage, 'qualification_toolkit': toolkit, 'imported_helpers': imported,
        'source_files': source_files, 'dependency_map_binding': map_proof, 'inspection_tools': inspection,
        'configuration_tools': tool_hashes, 'native_unit_count': 51, 'units': observations, 'logs': runner.logs,
        'maintenance_register_sha256': existing.file_sha(output / 'maintenance-register.json'),
        'retained_payload_entry_count': len(payload), 'retained_payload_unchanged': True,
        'original_artifacts_unchanged': True, 'caller_state_preserved': True,
        'input_kind': 'authenticated_native_retention_not_carriers', 'carrier_delivery_qualified': False,
        'restoration_kind': 'same_exact_candidate_recovery_not_upgrade_or_rollback',
        'processes_or_services_started': False, 'external_runtime_ownership_qualified': False,
        'native_install_execution_qualified': False, 'live_retirement_qualified': False,
        'two_release_upgrade_qualified': False, 'two_release_rollback_qualified': False,
        'native_build_executed': False, 'original_sdk_campaign_reexecuted': False,
        'independent_fresh_host_acceptance': False, 'publisher_trust_accepted': False,
        'release_acceptance_complete': False, 'publication_authorized': False}
    reuse.signing.write(output / 'result.json', c.canonical(result), 0o644)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('selection', 'artifact', 'transport-proof', 'source', 'inspection-tools', 'privacy-policy', 'cmake', 'cc', 'cxx', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--developer-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--allow-ephemeral-maintenance', action='store_true')
    args = parser.parse_args()
    try:
        result = run(args); print(json.dumps({'state': result['state'], 'native_unit_count': 51, 'publication_authorized': False}))
    except BaseException as error:
        output = gate.safe(args.output); info = output.stat() if output.is_dir() else None
        if info and gate.OWNED_OUTPUTS.get(output) == (info.st_dev, info.st_ino) and not (output / 'INCOMPLETE.json').exists():
            reuse.signing.write(output / 'INCOMPLETE.json', c.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
                'error_class': type(error).__name__, 'private_logs_retained': True, 'publication_authorized': False}), 0o644)
        raise


if __name__ == '__main__': main()
