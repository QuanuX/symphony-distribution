#!/usr/bin/env python3
"""Retrieve explicitly selected native recovery bytes and original SDK evidence.

This transport verifies hosted provenance and exact retained-record bindings.
It does not restore or execute the inner TAR, repeat qualification, authenticate
a publisher, or turn the earlier native checkpoint into a carrier capsule.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qualification import primary_artifacts as transport

gate = transport.gate
ROOT = Path(__file__).resolve().parents[1]
REPOSITORY, WORKFLOW = transport.REPOSITORY, transport.WORKFLOW
SELECTION = 'symphony.distribution.native-recovery-selection.v1'
PROTOCOL = 'symphony.distribution.native-artifact-transport.v1'
REQUIRED_STEPS = (
    'Build two clean cohorts and qualify final installed SDKs',
    'Retain verified native bytes before delivery collection',
    'Upload completed native recovery capsule before later gates',
    'Record final package and public dependency closure',
    'Qualify core SNV APIs, copied Go SDK and disposable removal',
    'Retain bounded engineering evidence',
)
SOURCE_FIELDS = {'source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256'}
PIN_FIELDS = SOURCE_FIELDS | {'capsule_sha256', 'native_archive_sha256', 'aggregate_sha256',
    'round1_result_sha256', 'round2_result_sha256', 'payload_inventory_sha256',
    'retention_helper_sha256', 'sdk_closure_sha256', 'delivery_record_sha256'}
SELECTION_FIELDS = {'protocol', 'repository', 'profile', 'run_id', 'run_attempt',
                    'workflow_commit', 'artifact', 'evidence_artifact', 'pins'}
MAX_DOCUMENT = 16 * 1024 * 1024
EVIDENCE_FILES = {'d06-cohort/result.json', 'd06-sdk-closure/result.json', 'd06-delivery/delivery-record.json',
    'd09-native-failure-summary.json', 'd09-tools/publisher.explicit.txt', 'd09-tools/result.json',
    'd09-tools/failure.json', 'd09-primary/failure.json', 'd09-source/failure.json'}
HELPERS = ('qualification/native_artifacts.py', 'qualification/primary_artifacts.py',
           'qualification/d09_platform.py', 'source-binding.json')


def document(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            gate.require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    gate.require(isinstance(value, dict), 'JSON object required')
    return value


def read_document(path, expected=None, limit=MAX_DOCUMENT):
    path = transport.regular(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        gate.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                     'Selected document exceeds regular custody bound')
        raw = stream.read(limit + 1); after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    gate.require(identity(before) == identity(after) == identity(path.lstat()) and len(raw) == before.st_size,
                 'Selected document changed while reading')
    if expected is not None:
        gate.require(transport.sha(raw) == gate.digest(expected), 'Independently selected document differs')
    return document(raw)


def frozen_source():
    return read_document(ROOT / 'source-binding.json')


def validate_selection(path, expected_sha256):
    selected = read_document(path, expected_sha256, 262144)
    gate.require(set(selected) == SELECTION_FIELDS and selected['protocol'] == SELECTION and
                 selected['repository'] == REPOSITORY and selected['profile'] in gate.PROFILES and
                 transport.positive(selected['run_id'], string=True) and
                 transport.positive(selected['run_attempt'], string=True) and
                 isinstance(selected['workflow_commit'], str) and re.fullmatch('[0-9a-f]{40}', selected['workflow_commit']),
                 'Exact native recovery producer selection required')
    for field, prefix in (('artifact', 'd10-native-recovery-'), ('evidence_artifact', 'd09-evidence-')):
        row = selected[field]
        gate.require(set(row) == {'id', 'name', 'sha256', 'size'} and transport.positive(row['id']) and
                     type(row['size']) is int and 0 < row['size'] <= transport.MAX_ZIP and
                     row['name'] == prefix + selected['profile'] + '-' + selected['run_attempt'],
                     'Selected native or evidence artifact identity differs')
        gate.digest(row['sha256'])
    gate.require(selected['artifact']['id'] != selected['evidence_artifact']['id'], 'Native and evidence artifacts must differ')
    pins = selected['pins']; gate.require(set(pins) == PIN_FIELDS, 'Required native recovery and original SDK pins differ')
    binding = frozen_source()
    for name, value in pins.items():
        if name in ('source_commit', 'source_tree'):
            gate.require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) and value == binding[name],
                         'Source differs from frozen distribution binding')
        else:
            gate.digest(value)
    return selected


def validate_metadata(selection, run, artifact, evidence_artifact, jobs):
    gate.require(type(run['id']) is int and type(run['run_attempt']) is int and
                 run['id'] == int(selection['run_id']) and run['run_attempt'] == int(selection['run_attempt']) and
                 run['status'] == 'completed' and run['event'] == 'workflow_dispatch' and
                 run['head_sha'] == selection['workflow_commit'] and run['path'] == WORKFLOW and
                 run['repository']['full_name'] == REPOSITORY and run['head_repository']['full_name'] == REPOSITORY,
                 'Completed selected native producer run differs')
    for field, metadata in (('artifact', artifact), ('evidence_artifact', evidence_artifact)):
        row = selection[field]
        gate.require(type(metadata['id']) is int and metadata['id'] == row['id'] and metadata['name'] == row['name'] and
                     metadata['expired'] is False and metadata['size_in_bytes'] == row['size'] and
                     metadata['digest'] == 'sha256:' + row['sha256'] and
                     metadata['workflow_run']['id'] == int(selection['run_id']) and
                     metadata['workflow_run']['head_sha'] == selection['workflow_commit'],
                     'GitHub native/evidence artifact metadata differs from explicit selection')
    gate.require(isinstance(jobs, list) and jobs and len({j['id'] for j in jobs}) == len(jobs), 'Duplicate or empty job snapshot')
    native = [j for j in jobs if j['name'] == 'native' and j['run_attempt'] == int(selection['run_attempt'])]
    gate.require(len(native) == 1 and native[0]['status'] == 'completed', 'Exact completed native job required')
    for name in REQUIRED_STEPS:
        found = [step for step in native[0]['steps'] if step['name'] == name]
        gate.require(len(found) == 1 and found[0]['status'] == 'completed' and found[0]['conclusion'] == 'success',
                     'Native retention, original SDK/delivery or evidence upload did not complete successfully')
    return {'workflow_path': WORKFLOW, 'event': run['event'], 'status': run['status'], 'conclusion': run['conclusion'],
            'job_id': native[0]['id'], 'job_name': 'native', 'job_conclusion': native[0]['conclusion'],
            'successful_steps': list(REQUIRED_STEPS)}


def validate_capsule(root, selection, evidence_root):
    """Cross-bind selected outer bytes/records; inner TAR restoration is separate."""
    root, evidence_root = gate.safe(root), gate.safe(evidence_root)
    gate.require(root != evidence_root and root not in evidence_root.parents and evidence_root not in root.parents,
                 'Native and evidence custody must be separate')
    gate.require(root.is_dir() and {p.name for p in root.iterdir()} == {'capsule.json', 'native-cohort.tar.gz'},
                 'Native recovery ZIP must contain only its two selected files')
    for name, bound in (('capsule.json', MAX_DOCUMENT), ('native-cohort.tar.gz', transport.MAX_ZIP)):
        path = transport.regular(root / name)
        gate.require(0 < path.stat().st_size <= bound, 'Native recovery member exceeds bound')
    gate.require(evidence_root.is_dir(), 'Original evidence directory absent')
    for path in evidence_root.rglob('*'):
        name = path.relative_to(evidence_root).as_posix()
        gate.require(not path.is_symlink(), 'Linked evidence member refused')
        if path.is_dir():
            gate.require(name in {str(Path(n).parent) for n in EVIDENCE_FILES}, 'Unexpected evidence directory')
        else:
            transport.regular(path)
            gate.require(name in EVIDENCE_FILES and 0 < path.stat().st_size <= MAX_DOCUMENT,
                         'Unexpected or oversized original evidence member')
    native_inventory = transport.inventory(root); evidence_inventory = transport.inventory(evidence_root)
    gate.require({row['path'] for row in native_inventory['entries']} == {'capsule.json', 'native-cohort.tar.gz'},
                 'Native recovery ZIP must contain only its two selected files')
    pins = selection['pins']; capsule = read_document(root / 'capsule.json', pins['capsule_sha256'])
    gate.require(capsule['protocol'] == 'symphony.distribution.native-build-retention.v1' and
                 capsule['state'] == 'complete_primary_native_bytes_retained' and capsule['profile'] == selection['profile'] and
                 capsule['selected_payload_round'] == 'round-1' and capsule['both_original_payloads_verified'] is True and
                 capsule['second_round_payload_retained'] is False and capsule['native_count'] == 51 and capsule['go_count'] == 6 and
                 all(capsule[key] is False for key in ('publication_authorized', 'release_acceptance_complete', 'wrapper_qualified')),
                 'Native checkpoint is incomplete or claims unselected authority')
    producer = capsule['producer']
    gate.require(producer['repository'] == REPOSITORY and producer['run_id'] == selection['run_id'] and
                 producer['run_attempt'] == selection['run_attempt'] and producer['commit'] == selection['workflow_commit'],
                 'Retained producer differs from selected GitHub run')
    gate.require(all(capsule[key] == pins[key] for key in SOURCE_FIELDS) and
                 capsule['aggregate_sha256'] == pins['aggregate_sha256'] and
                 capsule['round_sha256'] == {'round-1': pins['round1_result_sha256'], 'round-2': pins['round2_result_sha256']} and
                 capsule['payload_inventory_sha256'] == pins['payload_inventory_sha256'] and
                 capsule['helper_sha256'] == pins['retention_helper_sha256'], 'Native checkpoint source or build pins differ')
    archive = transport.regular(root / 'native-cohort.tar.gz')
    gate.require(capsule['archive']['path'] == 'native-cohort.tar.gz' and
                 capsule['archive']['sha256'] == pins['native_archive_sha256'] == gate.sha(archive) and
                 type(capsule['archive']['size']) is int and archive.stat().st_size == capsule['archive']['size'],
                 'Independently selected native TAR differs')
    rows = capsule['files']
    gate.require(isinstance(rows, list) and 0 < len(rows) <= 25000 and
                 transport.sha(transport.canonical(rows)) == capsule['inventory_sha256'], 'Native retention inventory seal differs')
    members = {row['path']: row for row in rows}
    gate.require(len(members) == len(rows), 'Duplicate native retention member')
    for name, field in (('cohort/result.json', 'aggregate_sha256'), ('cohort/round-1/result.json', 'round1_result_sha256'),
                        ('cohort/round-2/result.json', 'round2_result_sha256'), ('export/SOURCE-EXPORT.json', 'source_manifest_sha256')):
        gate.require(members.get(name, {}).get('sha256') == pins[field], 'Native retention record ledger differs')
    build = read_document(evidence_root / 'd06-cohort/result.json', pins['aggregate_sha256'])
    delivery = read_document(evidence_root / 'd06-delivery/delivery-record.json', pins['delivery_record_sha256'])
    sdk = read_document(evidence_root / 'd06-sdk-closure/result.json', pins['sdk_closure_sha256'])
    gate.primary_build(build, selection['profile'])
    rounds = {row['directory']: row for row in build['rounds']}
    gate.require(build['protocol'] == 'symphony.distribution.clean-cohort.v1' and not build.get('repair_provenance') and
                 all(build[key] == pins[key] for key in ('source_commit', 'source_tree')) and
                 build['source_input']['export_digest'] == pins['source_export_digest'] and
                 all(rounds['round-' + str(i)]['result_sha256'] == pins['round' + str(i) + '_result_sha256'] and
                     rounds['round-' + str(i)]['native_count'] == 51 and rounds['round-' + str(i)]['go_count'] == 6 for i in (1, 2)),
                 'Original two-round build evidence differs')
    gate.require(delivery['protocol'] == 'symphony.distribution.d06-delivery-record.v1' and
                 delivery['state'] == 'inventory_complete_publisher_review_pending' and
                 delivery['source_binding'] == {'commit': pins['source_commit'], 'tree': pins['source_tree']} and
                 delivery['source']['derived_export_digest'] == pins['source_export_digest'] and
                 delivery['build_result_sha256'] == pins['aggregate_sha256'] and
                 delivery['round_result_sha256'] == pins['round1_result_sha256'] and
                 delivery['host']['requested_profile'] == selection['profile'] and
                 all(delivery[key] is False for key in ('publication_authorized', 'release_ready', 'fresh_host_accepted')),
                 'Original delivery evidence differs')
    payload = delivery['payload_files']
    gate.require(transport.sha(transport.canonical(payload)) == pins['payload_inventory_sha256'] and payload and
                 len({row['path'] for row in payload}) == len(payload), 'Original payload inventory differs')
    sdk_payload = {row['path']: {'link': row['link']} if 'link' in row else
                   {'sha256': row['sha256'], 'mode': row['mode']} for row in payload}
    gate.require(sdk['protocol'] == 'symphony.distribution.d06-sdk-closure.v1' and sdk['status'] == 'passed' and
                 all(sdk[key] == pins[key] for key in ('source_commit', 'source_tree')) and
                 sdk['source_inventory_sha256'] == pins['source_export_digest'] and sdk['round'] == 'round-1' and
                 sdk['cohort_result_sha256'] == pins['aggregate_sha256'] and sdk['round_result_sha256'] == pins['round1_result_sha256'] and
                 sdk['original_payload_inventory_sha256'] == transport.sha(transport.canonical(sdk_payload)) and
                 sdk['original_final_candidate_unchanged'] is True and
                 all(sdk[key]['status'] == 'passed' for key in ('core_snv_api_smoke', 'source_consumer', 'disposable_native_removal')) and
                 sdk['disposable_native_removal']['native_units'] == 51 and
                 all(sdk[key] is False for key in ('publication_authorized', 'release_acceptance_complete', 'fresh_host_accepted')),
                 'Original completed SDK evidence differs from selected payload')
    toolkit = {row['path']: row for row in delivery['source']['toolkit_files']}
    gate.require(len(toolkit) == len(delivery['source']['toolkit_files']) and
                 set(sdk['extra_helpers_sha256']) == {'qualification/d06_sdk_closure.py', 'qualification/native_campaign.py'} and
                 sdk['extra_helpers_sha256']['qualification/d06_sdk_closure.py'] == sdk['harness_sha256'] and
                 delivery['source']['toolkit_snapshot']['git_baseline_commit'] == selection['workflow_commit'],
                 'Original SDK/toolkit helper closure differs')
    helper_pins = {**sdk['extra_helpers_sha256'], 'qualification/d10_build_retention.py': pins['retention_helper_sha256'],
                   'qualification/d06_delivery_record.py': delivery['tool_sha256']}
    gate.require(all(toolkit.get(name, {}).get('sha256') == gate.digest(digest) for name, digest in helper_pins.items()),
                 'Original SDK or retention helpers differ from delivered toolkit ledger')
    gate.require(transport.inventory(root) == native_inventory and transport.inventory(evidence_root) == evidence_inventory,
                 'Selected capsule or original evidence changed during validation')
    return {'profile': selection['profile'], 'native_count': 51, 'go_count': 6,
            'original_sdk_evidence_bound': True, 'original_delivery_evidence_bound': True,
            'native_tar_restored': False, 'native_bytes_requalified': False, 'source_or_notice_payload_recreated': False,
            'carrier_capsule_completed': False, 'publication_authorized': False, 'release_acceptance_complete': False}


def helper_hashes():
    return {name: gate.sha(transport.regular(ROOT / name)) for name in HELPERS}


def verify_transport(root, evidence_root, proof_path, selection, selection_sha256):
    proof = read_document(proof_path)
    gate.require(proof['protocol'] == PROTOCOL and proof['selection_sha256'] == gate.digest(selection_sha256) and
                 all(proof[key] == selection[key] for key in SELECTION_FIELDS - {'protocol'}) and
                 proof['github_observation']['workflow_path'] == WORKFLOW and
                 proof['github_observation']['event'] == 'workflow_dispatch' and
                 proof['github_observation']['status'] == 'completed' and
                 proof['github_observation']['successful_steps'] == list(REQUIRED_STEPS) and
                 proof['publisher_trust_accepted'] is False and proof['publication_authorized'] is False and
                 proof['release_acceptance_complete'] is False, 'Selected native transport proof differs')
    gate.require(transport.inventory(root) == proof['inventory'] and
                 transport.inventory(evidence_root) == proof['evidence_inventory'], 'Transported native/evidence inventory changed')
    gate.require(validate_capsule(root, selection, evidence_root) == proof['record_binding'], 'Native record binding changed')
    return proof


def fetch(selection_path, selection_sha256, output, gh):
    selection = validate_selection(selection_path, selection_sha256); helpers = helper_hashes()
    output = gate.fresh(output, (gate.safe(selection_path), ROOT))
    gh, env = transport.transport_environment(output, gh); gh_sha = gate.sha(gh)
    base = 'repos/' + REPOSITORY + '/actions'
    run = transport.gh_json(gh, base + '/runs/' + selection['run_id'] + '/attempts/' + selection['run_attempt'], env)
    artifact = transport.gh_json(gh, base + '/artifacts/' + str(selection['artifact']['id']), env)
    evidence_artifact = transport.gh_json(gh, base + '/artifacts/' + str(selection['evidence_artifact']['id']), env)
    jobs, total = [], None
    for page in range(1, 5):
        response = transport.gh_json(gh, base + '/runs/' + selection['run_id'] + '/attempts/' + selection['run_attempt'] +
                                     '/jobs?per_page=100&page=' + str(page), env)
        count, entries = response['total_count'], response['jobs']
        gate.require(type(count) is int and 0 < count <= 400 and isinstance(entries, list) and
                     0 < len(entries) <= 100 and (total is None or total == count), 'Incomplete or changed job enumeration')
        total = count; jobs.extend(entries)
        gate.require(len(jobs) <= total, 'Extra producer jobs')
        if len(jobs) == total: break
    gate.require(len(jobs) == total, 'Producer job enumeration exceeds bound')
    observation = validate_metadata(selection, run, artifact, evidence_artifact, jobs)
    inventories = {}
    for field, directory in (('artifact', 'capsule'), ('evidence_artifact', 'evidence')):
        row = selection[field]; archive = output / (directory + '.zip')
        transport.download_zip(gh, base + '/artifacts/' + str(row['id']) + '/zip', env, archive, row['size'])
        inventories[directory] = transport.extract_zip(archive, output / directory, row['sha256'], row['size'])
    binding = validate_capsule(output / 'capsule', selection, output / 'evidence')
    gate.require(validate_selection(selection_path, selection_sha256) == selection and helper_hashes() == helpers and
                 gate.sha(gh) == gh_sha, 'Selection, executing helpers or GitHub transport changed')
    proof = {'protocol': PROTOCOL, 'selection_sha256': selection_sha256,
        **{key: selection[key] for key in SELECTION_FIELDS - {'protocol'}},
        'github_observation': observation, 'inventory': inventories['capsule'], 'evidence_inventory': inventories['evidence'],
        'record_binding': binding, 'executing_helpers': helpers, 'transport_executable_sha256': gh_sha,
        'publisher_trust_accepted': False, 'publication_authorized': False, 'release_acceptance_complete': False}
    gate.write(output / 'transport-proof.json', proof)
    verify_transport(output / 'capsule', output / 'evidence', output / 'transport-proof.json', selection, selection_sha256)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    for name in ('fetch', 'verify-selection'):
        item = commands.add_parser(name); item.add_argument('--selection', type=Path, required=True)
        item.add_argument('--selection-sha256', required=True)
        for field in (('output', 'gh') if name == 'fetch' else ('capsule', 'evidence')):
            item.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'fetch':
        result = fetch(args.selection, args.selection_sha256, args.output, args.gh)['record_binding']
        state = 'selected_native_and_original_sdk_records_retrieved'
    else:
        selected = validate_selection(args.selection, args.selection_sha256)
        result = validate_capsule(args.capsule, selected, args.evidence)
        state = 'offline_record_bindings_checked_hosted_metadata_refetch_required'
    print(json.dumps({'state': state, **result}))


if __name__ == '__main__': main()
