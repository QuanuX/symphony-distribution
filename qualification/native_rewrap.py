#!/usr/bin/env python3
"""Resume packaging from authenticated native bytes; never replay native builds.

Original build and SDK evidence remain immutable. New delivery/carrier/wrapper
work has its own committed source identity and separate disposable consumer.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'qualification'))
sys.path.insert(0, str(ROOT / 'build-cohort'))
sys.path.insert(0, str(ROOT))
from qualification import primary_rewrap as reuse
from qualification import d09_platform as gate
import d10_build_retention as retention
import d06_delivery_record as delivery

c, signing, construct = reuse.c, reuse.signing, reuse.construct
RESTORE = 'symphony.distribution.native-packaging-restore.v1'
PACKAGE = 'symphony.distribution.native-packaging-resumption.v1'
CONSUMER = 'symphony.distribution.native-packaging-consumer.v1'
HELPERS = tuple(sorted(set(reuse.HELPERS) | {
    'qualification/native_rewrap.py', 'qualification/native_artifacts.py',
    'qualification/d10_build_retention.py', 'qualification/d06_sdk_closure.py',
    'qualification/host_platform.py'}))
FALSE_FLAGS = ('publication_authorized', 'publisher_trust_accepted', 'independent_fresh_host_acceptance',
    'release_acceptance_complete', 'native_runtime_owner_invoked', 'runtime_activation',
    'native_pkg_executed', 'fresh_whole_cohort_build', 'native_build_executed', 'sdk_campaign_reexecuted')


def transport():
    from qualification import native_artifacts
    return native_artifacts


def helpers():
    return {name: signing.digest(signing.regular(ROOT / name)) for name in HELPERS}


def git_bytes(commit, name):
    c.require(re.fullmatch('[0-9a-f]{40}', commit), 'Exact original toolkit commit required')
    c.relative(name)
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(ROOT), 'show', commit + ':' + name],
                                   env=env, stderr=subprocess.PIPE, timeout=30)


def git_tree(commit):
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(ROOT), 'rev-parse', commit + '^{tree}'],
        env=env, stderr=subprocess.PIPE, timeout=30).decode().strip()


def selected_inputs(root, selection, selection_sha256, proof):
    """The transport owns authoritative run/artifact and exact directory custody."""
    transport().verify_transport(root / 'capsule', root / 'evidence', proof, selection, selection_sha256)
    return {'native': root / 'capsule', 'evidence': root / 'evidence'}


def original_records(inputs, selection):
    native, evidence = inputs['native'], inputs['evidence']
    report = c.document(native / 'capsule.json')
    aggregate_path = evidence / 'd06-cohort/result.json'
    sdk_path = evidence / 'd06-sdk-closure/result.json'
    old_delivery_path = evidence / 'd06-delivery/delivery-record.json'
    aggregate, sdk, old_delivery = map(c.document, (aggregate_path, sdk_path, old_delivery_path))
    c.require(report['protocol'] == retention.PROTOCOL and report['state'] == 'complete_primary_native_bytes_retained' and
        report['profile'] == selection['profile'] and report['native_count'] == 51 and report['go_count'] == 6 and
        report['producer'] == retention.producer_record(selection['run_id'], selection['run_attempt'], selection['workflow_commit']) and
        report['selected_payload_round'] == 'round-1' and report['both_original_payloads_verified'] is True and
        report['second_round_payload_retained'] is False and all(report[k] is False for k in
            ('publication_authorized', 'release_acceptance_complete', 'wrapper_qualified')),
        'Original native retention scope or producer differs')
    c.require(signing.digest(aggregate_path) == report['aggregate_sha256'], 'Original engineering aggregate differs')
    gate.primary_build(aggregate, selection['profile'])
    c.require(sdk['protocol'] == 'symphony.distribution.d06-sdk-closure.v1' and sdk['status'] == 'passed' and
        sdk['round'] == 'round-1' and sdk['cohort_result_sha256'] == report['aggregate_sha256'] and
        sdk['round_result_sha256'] == report['round_sha256']['round-1'] and
        sdk['source_inventory_sha256'] == report['source_export_digest'] and
        sdk.get('original_final_candidate_unchanged') is True and
        all(sdk[k] is False for k in ('publication_authorized', 'release_acceptance_complete', 'fresh_host_accepted')),
        'Original SDK closure is incomplete or belongs to different bytes')
    c.require(old_delivery['protocol'] == 'symphony.distribution.d06-delivery-record.v1' and
        old_delivery['state'] == 'inventory_complete_publisher_review_pending' and
        old_delivery['build_result_sha256'] == report['aggregate_sha256'] and
        old_delivery['round_result_sha256'] == report['round_sha256']['round-1'], 'Original delivery evidence differs')
    for key in ('source_commit', 'source_tree'):
        c.require(report[key] == aggregate[key] == sdk[key] == selection['pins'][key], 'Original source identity differs')
    for key in ('source_export_digest', 'source_manifest_sha256'):
        c.require(report[key] == selection['pins'][key], 'Original reviewed source selection differs')
    return report, aggregate, sdk, old_delivery


def helper_lineage(restored, report, aggregate, sdk, original_delivery):
    """Match inherited builders to both the original Git tree and current bytes."""
    commit = report['producer']['commit']
    selected = delivery.selected_helpers(aggregate)
    selected.update({'build-cohort/cohort.json': aggregate['plan_sha256'],
                     'source-binding.json': signing.digest(ROOT / 'source-binding.json')})
    retained = {p.relative_to(restored / 'toolkit').as_posix() for p in (restored / 'toolkit').rglob('*') if p.is_file()}
    c.require(retained == set(selected), 'Retained builder source membership differs')
    for name, expected in selected.items():
        c.require(signing.digest(restored / 'toolkit' / name) == expected == c.sha(git_bytes(commit, name)) ==
                  signing.digest(ROOT / name), 'Original/current selected builder identity differs: ' + name)
    original = {**selected, 'qualification/d10_build_retention.py': report['helper_sha256'],
        'qualification/d06_sdk_closure.py': sdk['harness_sha256'],
        'qualification/d06_delivery_record.py': original_delivery['tool_sha256']}
    c.require(set(sdk['extra_helpers_sha256']) == {'qualification/d06_sdk_closure.py', 'qualification/native_campaign.py'},
              'Original SDK imported helper set differs')
    for name, digest in sdk['extra_helpers_sha256'].items():
        c.require(name not in original or original[name] == digest, 'Original helper identity conflicts')
        original[name] = digest
    for name, expected in original.items():
        c.require(c.sha(git_bytes(commit, name)) == expected == signing.digest(ROOT / name),
                  'Inherited qualification helper identity differs: ' + name)
    return {'original_toolkit_commit': commit, 'original_toolkit_tree': git_tree(commit),
            'original_helpers_sha256': original, 'current_builder_and_qualification_helpers_identical': True}


def validate_restored(restored, inputs, selection, repository, policy):
    report, aggregate, sdk, old_delivery = original_records(inputs, selection)
    root = restored / 'cohort'; export = restored / 'export'; round_root = root / 'round-1'
    c.require(signing.digest(root / 'result.json') == report['aggregate_sha256'] and
              c.document(root / 'result.json') == aggregate, 'Restored original aggregate differs')
    for name in ('round-1', 'round-2'):
        c.require(signing.digest(root / name / 'result.json') == report['round_sha256'][name], 'Original round report differs')
    first, second = [c.document(root / name / 'result.json') for name in ('round-1', 'round-2')]
    c.require(first['payload_inventory'] == second['payload_inventory'] and
              c.sha(retention.canonical(first['payload_inventory'])) == report['payload_inventory_sha256'] and
              not (root / 'round-2/relocated-prefix').exists(), 'Inherited repeated payload identity differs')
    for record in (first, second):
        c.require(record['state'] == 'built_and_sdk_checked' and record['native_count'] == 51 and
            len(record['go_commands']) == 6 and record['publication_authorized'] is False and
            all(record[k]['status'] == 'passed' for k in ('sdk_audit', 'installed_owner_audit', 'loader_audit')),
            'Original completed native round audits differ')
    gate.check_source(export, repository, policy, report['source_export_digest'], report['source_manifest_sha256'])
    manifest = c.document(export / 'SOURCE-EXPORT.json')
    rows = [{'path': r['path'], 'sha256': r['export_sha256'], 'size': r['export_size'],
             'mode': 0o755 if r['mode'] == '100755' else 0o644} for r in manifest['source_files']]
    delivery.verify_inventory(root / 'source', rows)
    prefix = round_root / 'relocated-prefix'
    delivery.verify_inventory(prefix, first['payload_inventory'])
    builder = gate.module('native_resume_builder', 'build-cohort/build.py')
    plan = c.document(ROOT / 'build-cohort/cohort.json'); units = plan['profiles'][selection['profile']]['native_build_order']
    c.require(len(units) == 51 and builder.verify_receipts(prefix, units) == first['native_receipts'], 'Restored native receipts differ')
    qx = [r for r in first['go_commands'] if r['component_id'] == 'qxctl']
    c.require(len(qx) == 1, 'Original qxctl row missing')
    delivery.go_build_provenance('qxctl', qx[0], aggregate, {'repair_provenance': None}, round_root,
        root / 'source', prefix / 'go/qxctl/bin/qxctl', manifest)
    c.require(signing.digest(restored / 'external/external-build.json') == aggregate['external_evidence_sha256'],
              'Restored external build report differs')
    privacy = retention.scanner(policy)
    selected = {r['path']: restored / r['path'] for r in report['files']}
    c.require(retention.file_inventory(selected, privacy) == report['files'], 'Restored retention inventory changed')
    lineage = helper_lineage(restored, report, aggregate, sdk, old_delivery)
    return {**lineage, 'original_producer': report['producer'], 'profile': report['profile'],
        'native_capsule_sha256': signing.digest(inputs['native'] / 'capsule.json'),
        'native_archive_sha256': report['archive']['sha256'], 'build_result_sha256': report['aggregate_sha256'],
        'round_sha256': report['round_sha256'], 'sdk_closure_sha256': signing.digest(inputs['evidence'] / 'd06-sdk-closure/result.json'),
        'original_delivery_record_sha256': signing.digest(inputs['evidence'] / 'd06-delivery/delivery-record.json'),
        'source_commit': report['source_commit'], 'source_tree': report['source_tree'],
        'source_export_digest': report['source_export_digest'], 'source_manifest_sha256': report['source_manifest_sha256'],
        'payload_inventory_sha256': report['payload_inventory_sha256'], 'native_count': 51, 'go_count': 6,
        'second_round_payload_retained': False, 'original_sdk_result_reused': True,
        **{key: False for key in FALSE_FLAGS}}


def restore(args):
    selected = transport().validate_selection(args.selection, args.selection_sha256)
    root = c.safe_root(args.artifact); original = selected_inputs(root, selected, args.selection_sha256, args.transport_proof)
    host = reuse.custody(selected['profile'], args.output)
    before = {name: reuse.tree_inventory(path) for name, path in original.items()}; imported = helpers()
    selection_raw = c.bounded(args.selection)[0]; proof_raw = c.bounded(args.transport_proof)[0]
    report, _, _, _ = original_records(original, selected)
    out = gate.fresh(args.output, (root, args.selection, args.transport_proof, args.repository, args.privacy_policy, ROOT))
    copies = out / 'inputs'; copies.mkdir(mode=0o700)
    for name, path in original.items(): reuse.copy_tree(path, copies / ('capsule' if name == 'native' else name))
    signing.write(copies / 'selection.json', selection_raw, 0o644)
    signing.write(copies / 'transport-proof.json', proof_raw, 0o644)
    copied = selected_inputs(copies, selected, args.selection_sha256, copies / 'transport-proof.json')
    retention.restore(copied['native'], out / 'restored', signing.digest(copied['native'] / 'capsule.json'),
                      report['archive']['sha256'], args.privacy_policy)
    lineage = validate_restored(out / 'restored', copied, selected, args.repository, args.privacy_policy)
    for name, path in original.items(): reuse.records_equal(path, before[name])
    c.require(c.bounded(args.selection)[0] == selection_raw and c.bounded(args.transport_proof)[0] == proof_raw and
              helpers() == imported, 'Original selection or executing helpers changed during restoration')
    result = {'protocol': RESTORE, 'state': 'original_native_bytes_restored_and_source_verified',
        'selection_sha256': args.selection_sha256, 'transport_proof_sha256': c.sha(proof_raw),
        'inputs_inventory': reuse.tree_inventory(copies), 'lineage': lineage, 'executing_helpers': imported,
        'restoration_host': host, 'original_inputs_unchanged': True, **{key: False for key in FALSE_FLAGS}}
    signing.write(out / 'restore-result.json', signing.canonical(result), 0o644)
    return result


def admit_restore(root, digest, repository, policy):
    c.require(signing.digest(root / 'restore-result.json') == c.digest(digest), 'Selected restore result differs')
    result = c.document(root / 'restore-result.json')
    c.require(result['protocol'] == RESTORE and result['state'] == 'original_native_bytes_restored_and_source_verified' and
              all(result[k] is False for k in FALSE_FLAGS) and result['executing_helpers'] == helpers(), 'Restore state or helpers differ')
    inputs = root / 'inputs'; reuse.records_equal(inputs, result['inputs_inventory'])
    selected = transport().validate_selection(inputs / 'selection.json', result['selection_sha256'])
    c.require(signing.digest(inputs / 'transport-proof.json') == result['transport_proof_sha256'], 'Original transport changed')
    copied = selected_inputs(inputs, selected, result['selection_sha256'], inputs / 'transport-proof.json')
    c.require(validate_restored(root / 'restored', copied, selected, repository, policy) == result['lineage'],
              'Restored native/source lineage changed')
    return result, selected


def verify_source(root, expected_helpers, identity):
    index = c.document(root / 'WRAPPER-TOOLKIT-SOURCE.json')
    raw, _ = c.bounded(root / 'WRAPPER-TOOLKIT-SOURCE.tar')
    c.require(set(expected_helpers) == set(HELPERS) and index['protocol'] == reuse.source_capture.SOURCE and
        index['source'] == identity and index['executing_helpers'] == expected_helpers and
        index['archive_sha256'] == c.sha(raw) and index['privacy_scan'] == 'pass' and
        index['publication_authorized'] is False, 'New packaging toolkit source differs')
    reuse.supplements.source_tree(raw, identity)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        rows = [{'path': m.name, 'sha256': c.sha(archive.extractfile(m).read()), 'size': m.size, 'mode': m.mode} for m in archive]
        c.require(rows == index['files'], 'New packaging source inventory differs')
        for name, expected in expected_helpers.items():
            c.require(c.sha(archive.extractfile(name).read()) == expected, 'New packaging source helper differs')
    return index


def package(args):
    restored = c.safe_root(args.restored)
    previous, selected = admit_restore(restored, args.restore_result_sha256, args.repository, args.privacy_policy)
    host = reuse.custody(selected['profile'], args.output); imported = helpers()
    out = gate.fresh(args.output, (restored, args.delivery, args.repository, args.privacy_policy, ROOT))
    inherited = restored / 'restored'
    work = out / 'work'
    result = gate.package(SimpleNamespace(build_root=inherited / 'cohort', export=inherited / 'export',
        delivery=args.delivery, sdk_closure=restored / 'inputs/evidence/d06-sdk-closure', repository=args.repository,
        privacy_policy=args.privacy_policy, export_digest=selected['pins']['source_export_digest'],
        manifest_sha256=selected['pins']['source_manifest_sha256'], profile=selected['profile'], output=work,
        python=args.python, standalone=args.standalone, standalone_archive=args.standalone_archive))
    portable = out / 'artifact'; portable.mkdir(mode=0o700)
    reuse.copy_tree(restored / 'inputs', portable / 'inputs')
    reuse.copy_tree(work / 'carrier-capsule', portable / 'carrier-capsule')
    source = portable / 'wrapper-source'; source.mkdir(mode=0o700)
    source_record = reuse.source_capture.toolkit_source(source, args.toolkit_commit, args.privacy_policy, imported)
    wrappers = portable / 'wrappers'; wrappers.mkdir(mode=0o700)
    audit = c.document(work / 'wrappers/result.json')
    for name in ['result.json'] + [row['filename'] for row in audit['wrappers']]:
        shutil.copyfile(signing.regular(work / 'wrappers' / name), wrappers / name)
        (wrappers / name).chmod(0o644)
    cohort = c.audit_cohort(portable / 'carrier-capsule/carriers'); reuse.wrapper_selection(cohort, audit)
    c.require(admit_restore(restored, args.restore_result_sha256, args.repository, args.privacy_policy)[0] == previous and
              helpers() == imported, 'Original native inputs or packaging helpers changed')
    record = {'protocol': PACKAGE, 'state': 'inherited_native_and_sdk_new_carriers_and_wrappers_audited',
        'profile': selected['profile'], 'lineage': previous['lineage'], 'selection_sha256': previous['selection_sha256'],
        'transport_proof_sha256': previous['transport_proof_sha256'], 'inputs_inventory': previous['inputs_inventory'],
        'restore_result_sha256': args.restore_result_sha256, 'carrier_capsule_result_sha256': result['carrier_capsule_result_sha256'],
        'wrapper_result_sha256': signing.digest(wrappers / 'result.json'), 'cohort_digest': cohort['cohort_digest'],
        'wrapper_toolkit_source': source_record['source'], 'wrapper_source_index_sha256': signing.digest(source / 'WRAPPER-TOOLKIT-SOURCE.json'),
        'executing_helpers': imported, 'producer': host, 'carrier_count': 58, 'client_included': False,
        'original_native_bytes_changed': False, 'original_sdk_result_reused': True, 'signature_created': False,
        'scope': 'new delivery collection and inert carrier/wrapper assembly; original51 native and6 Go bytes and SDK evidence inherited',
        **{key: False for key in FALSE_FLAGS}}
    signing.write(portable / 'result.json', signing.canonical(record), 0o644)
    admit_package(portable, signing.digest(portable / 'result.json'))
    return record


def admit_package(root, digest):
    root = c.safe_root(root)
    c.require(signing.digest(root / 'result.json') == c.digest(digest), 'Selected resumed package differs')
    result = c.document(root / 'result.json')
    c.require(result['protocol'] == PACKAGE and result['state'] == 'inherited_native_and_sdk_new_carriers_and_wrappers_audited' and
        result['carrier_count'] == 58 and result['original_native_bytes_changed'] is False and
        result['original_sdk_result_reused'] is True and result['client_included'] is False and result['signature_created'] is False and
        all(result[k] is False for k in FALSE_FLAGS), 'Resumed package changes inherited scope')
    inputs = root / 'inputs'; reuse.records_equal(inputs, result['inputs_inventory'])
    selected = transport().validate_selection(inputs / 'selection.json', result['selection_sha256'])
    c.require(signing.digest(inputs / 'transport-proof.json') == result['transport_proof_sha256'], 'Native transport differs')
    original = selected_inputs(inputs, selected, result['selection_sha256'], inputs / 'transport-proof.json')
    report, aggregate, sdk, old_delivery = original_records(original, selected)
    lineage = result['lineage']
    original_helpers = {**delivery.selected_helpers(aggregate),
        'build-cohort/cohort.json': aggregate['plan_sha256'],
        'source-binding.json': signing.digest(ROOT / 'source-binding.json'),
        'qualification/d10_build_retention.py': report['helper_sha256'],
        'qualification/d06_sdk_closure.py': sdk['harness_sha256'],
        'qualification/d06_delivery_record.py': old_delivery['tool_sha256']}
    original_helpers.update(sdk['extra_helpers_sha256'])
    c.require(lineage['original_toolkit_commit'] == selected['workflow_commit'] and
        lineage['original_toolkit_tree'] == git_tree(selected['workflow_commit']) and
        lineage['original_helpers_sha256'] == original_helpers and
        lineage['current_builder_and_qualification_helpers_identical'] is True and
        all(c.sha(git_bytes(selected['workflow_commit'], name)) == expected == signing.digest(ROOT / name)
            for name, expected in original_helpers.items()), 'Inherited original Git/helper lineage differs')
    c.require(lineage['original_producer'] == report['producer'] and lineage['profile'] == result['profile'] == selected['profile'] and
        lineage['native_capsule_sha256'] == signing.digest(original['native'] / 'capsule.json') and
        lineage['native_archive_sha256'] == report['archive']['sha256'] and
        lineage['build_result_sha256'] == report['aggregate_sha256'] and lineage['round_sha256'] == report['round_sha256'] and
        lineage['sdk_closure_sha256'] == signing.digest(original['evidence'] / 'd06-sdk-closure/result.json') and
        lineage['original_delivery_record_sha256'] == signing.digest(original['evidence'] / 'd06-delivery/delivery-record.json') and
        all(lineage[k] is False for k in FALSE_FLAGS), 'Original native lineage changed')
    c.require(all(lineage[key] == report[key] for key in
        ('source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256', 'payload_inventory_sha256')) and
        lineage['native_count'] == 51 and lineage['go_count'] == 6 and lineage['second_round_payload_retained'] is False and
        lineage['original_sdk_result_reused'] is True, 'Inherited source or payload scope differs')
    capsule = gate.verify_capsule(root / 'carrier-capsule', result['carrier_capsule_result_sha256'])
    c.require(capsule['build_result_sha256'] == lineage['build_result_sha256'] and
        capsule['round_result_sha256'] == lineage['round_sha256']['round-1'] and
        capsule['round_2_result_sha256'] == lineage['round_sha256']['round-2'] and
        capsule['sdk_closure_sha256'] == lineage['sdk_closure_sha256'] and
        capsule['original_toolkit_commit'] == result['wrapper_toolkit_source']['commit'] and
        capsule['original_toolkit_tree'] == result['wrapper_toolkit_source']['tree'], 'New carrier source or inherited evidence differs')
    source = root / 'wrapper-source'
    c.require(signing.digest(source / 'WRAPPER-TOOLKIT-SOURCE.json') == result['wrapper_source_index_sha256'], 'Packaging source index changed')
    verify_source(source, result['executing_helpers'], result['wrapper_toolkit_source'])
    cohort = c.audit_cohort(root / 'carrier-capsule/carriers')
    audit = c.document(root / 'wrappers/result.json')
    c.require(signing.digest(root / 'wrappers/result.json') == result['wrapper_result_sha256'] and
              result['cohort_digest'] == cohort['cohort_digest'], 'Wrapper/carrier binding changed')
    row = reuse.wrapper_selection(cohort, audit)
    c.require({p.name for p in root.iterdir()} == {'inputs', 'carrier-capsule', 'wrapper-source', 'wrappers', 'result.json'} and
        {p.name for p in source.iterdir()} == {'WRAPPER-TOOLKIT-SOURCE.tar', 'WRAPPER-TOOLKIT-SOURCE.json'} and
        {p.name for p in (root / 'wrappers').iterdir()} == {'result.json'} | {r['filename'] for r in audit['wrappers']},
        'Unexpected portable packaging material')
    for item in audit['wrappers']:
        path = signing.regular(root / 'wrappers' / item['filename'])
        c.require(path.stat().st_size == item['size'] and signing.digest(path) == item['sha256'], 'New wrapper bytes differ')
    return result, cohort, row


def fresh_user(args):
    c.require(args.allow_ephemeral_install is True, 'Explicit ephemeral installer opt-in required')
    root = c.safe_root(args.artifact); result, cohort, row = admit_package(root, args.result_sha256)
    host = reuse.custody(result['profile'], args.output)
    c.require((host['run_id'], host['run_attempt'], host['job']) !=
        tuple(result['producer'][k] for k in ('run_id', 'run_attempt', 'job')), 'Consumer must use a separate hosted job')
    tools = reuse.inspection_tools(args.inspection_tools, result['profile']); imported = helpers()
    c.require(imported == result['executing_helpers'], 'Consumer differs from selected committed packaging helpers')
    before = reuse.tree_inventory(root); expected = {}
    for entry in cohort['entries']:
        _, files = c.validate_recipe(root / 'carrier-capsule/carriers', entry)
        c.require(not expected.keys() & files.keys(), 'Carrier ownership overlaps'); expected.update(files)
    c.require(len(expected) == 174, 'Exactly58 opaque carrier closures required')
    out = gate.fresh(args.output, (root, args.inspection_tools, ROOT))
    execution = reuse.snapshot_wrapper(root / 'wrappers' / row['filename'], row, out)
    construct.audit_sh(execution, construct.archive_records(cohort), row['bootstrap_sha256'], [])
    logs = reuse.exercise(execution, row, cohort, expected, out)
    reuse.records_equal(root, before)
    c.require(admit_package(root, args.result_sha256)[0] == result and signing.digest(execution) == row['sha256'] and
        helpers() == imported and reuse.inspection_tools(args.inspection_tools, result['profile']) == tools,
        'Original inputs, executing helpers or private tool closure changed')
    report = {'protocol': CONSUMER, 'state': 'primary_shell_install_refusals_and_named_removal_passed',
        'profile': result['profile'], 'selected_package_result_sha256': args.result_sha256,
        'lineage': result['lineage'], 'wrapper_toolkit_source': result['wrapper_toolkit_source'], 'observed_custody': host,
        'cohort_digest': cohort['cohort_digest'], 'shell_wrapper_sha256': row['sha256'],
        'private_execution_snapshot_sha256': signing.digest(execution), 'executing_helpers': imported,
        'inspection_tools': tools, 'logs': logs, 'carrier_count': 58, 'linked_file_count': 174,
        'all_named_carriers_removed': True, 'fresh_prefix_refusals': ['existing', 'force', 'upgrade', 'dangling'],
        'original_artifacts_unchanged': True, 'caller_state_preserved': True, 'wrapper_support_files_preserved': True,
        'account_credentials_supplied': False, 'client_qualified': False, 'cli_route_qualified_by_this_run': False,
        'two_release_upgrade_qualified': False, 'two_release_rollback_qualified': False, **{key: False for key in FALSE_FLAGS}}
    signing.write(out / 'result.json', signing.canonical(report), 0o644)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('restore')
    for key in ('selection', 'artifact', 'transport-proof', 'repository', 'privacy-policy', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--selection-sha256', required=True)
    p = commands.add_parser('package')
    for key in ('restored', 'delivery', 'repository', 'privacy-policy', 'output', 'python', 'standalone', 'standalone-archive'):
        p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--restore-result-sha256', required=True); p.add_argument('--toolkit-commit', required=True)
    p = commands.add_parser('fresh-user')
    for key in ('artifact', 'inspection-tools', 'output'): p.add_argument('--' + key, type=Path, required=True)
    p.add_argument('--result-sha256', required=True); p.add_argument('--allow-ephemeral-install', action='store_true')
    args = parser.parse_args()
    try:
        result = {'restore': restore, 'package': package, 'fresh-user': fresh_user}[args.command](args)
        print(json.dumps({'state': result['state'], 'publication_authorized': False}))
    except BaseException as error:
        output = gate.safe(args.output); info = output.stat() if output.is_dir() else None
        if info and gate.OWNED_OUTPUTS.get(output) == (info.st_dev, info.st_ino) and not (output / 'INCOMPLETE.json').exists():
            signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PACKAGE, 'state': 'incomplete',
                'error_class': type(error).__name__, 'private_logs_retained': True, 'publication_authorized': False}), 0o644)
        raise


if __name__ == '__main__': main()
