#!/usr/bin/env python3
"""Prepare an explicit wrapper selection from a local verified carrier ZIP.

This offline check does not authenticate supplied GitHub metadata. The hosted
consumer must retrieve current authoritative metadata and the selected bytes
again. No producer, wrapper, installer, service or provider is executed here.
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
from qualification import d09_platform as gate

ROOT = Path(__file__).resolve().parents[1]
REQUEST = 'symphony.distribution.primary-selection-request.v1'
REVIEW = 'symphony.distribution.primary-selection-review.v1'
SOURCE_FIELDS = {'source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256'}
HELPERS = tuple(sorted(set(gate.CAPSULE_HELPERS) | {
    'qualification/primary_selection.py', 'qualification/primary_artifacts.py', 'source-binding.json'}))


def stable_file(path, bound, *, read=False):
    """Capture independent regular input bytes through a nofollow descriptor."""
    path = transport.regular(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        first = os.fstat(stream.fileno())
        gate.require(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and 0 < first.st_size <= bound,
                     'Input size or independent file custody differs')
        digest, total, contents = hashlib.sha256(), 0, []
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            total += len(block); gate.require(total <= bound, 'Input grew beyond its bound')
            digest.update(block)
            if read: contents.append(block)
        last = os.fstat(stream.fileno())
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    gate.require(identity(first) == identity(last) == identity(path.lstat()) and total == first.st_size,
                 'Input changed while being read')
    return {'sha256': digest.hexdigest(), 'size': total, 'identity': identity(first)}, b''.join(contents) if read else None


def document(raw):
    def unique(rows):
        value = {}
        for key, entry in rows:
            gate.require(key not in value, 'Duplicate JSON field')
            value[key] = entry
        return value
    result = json.loads(raw, object_pairs_hook=unique)
    gate.require(isinstance(result, dict), 'JSON object required')
    return result


def source_binding():
    return gate.read(transport.regular(ROOT / 'source-binding.json'))


def validate_request(value, binding):
    gate.require(set(value) == {'protocol', 'repository', 'profile', 'run_id', 'run_attempt',
                               'workflow_commit', 'artifact', 'source'}, 'Explicit request fields differ')
    gate.require(value['protocol'] == REQUEST and value['repository'] == transport.REPOSITORY and
                 value['profile'] in gate.PROFILES and transport.positive(value['run_id'], string=True) and
                 transport.positive(value['run_attempt'], string=True) and
                 isinstance(value['workflow_commit'], str) and re.fullmatch('[0-9a-f]{40}', value['workflow_commit']),
                 'Exact selected producer identity required')
    artifact = value['artifact']
    gate.require(set(artifact) == {'id', 'name', 'sha256', 'size'} and transport.positive(artifact['id']) and
                 type(artifact['size']) is int and 0 < artifact['size'] <= transport.MAX_ZIP and
                 artifact['name'] == f"d10-carrier-capsule-{value['profile']}-{value['run_attempt']}",
                 'Explicit artifact identity differs')
    gate.digest(artifact['sha256'])
    source = value['source']
    gate.require(set(source) == SOURCE_FIELDS, 'Independently selected source pins required')
    for key in ('source_commit', 'source_tree'):
        gate.require(isinstance(source[key], str) and re.fullmatch('[0-9a-f]{40}', source[key]) and
                     source[key] == binding[key], 'Core source differs from frozen distribution binding')
    gate.digest(source['source_export_digest']); gate.digest(source['source_manifest_sha256'])
    return value


def helpers():
    return {name: stable_file(ROOT / name, 16 * 1024 * 1024)[0]['sha256'] for name in HELPERS}


def private_scanner(path):
    path = transport.regular(path)
    gate.require(path.stat().st_mode & 0o777 == 0o600, 'Private scan policy must have mode0600')
    module = gate.module('primary_selection_privacy', 'source-export/export_source.py')
    module.configure_policy(path)
    return module


def write_exclusive(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(raw)


def prepare(request, request_sha256, archive, run_metadata, artifact_metadata, jobs_metadata, privacy_policy, output):
    inputs = {'request': (gate.safe(request), 256 * 1024), 'archive': (gate.safe(archive), transport.MAX_ZIP),
        'run_metadata': (gate.safe(run_metadata), 4 * 1024 * 1024),
        'artifact_metadata': (gate.safe(artifact_metadata), 4 * 1024 * 1024),
        'jobs_metadata': (gate.safe(jobs_metadata), 16 * 1024 * 1024),
        'privacy_policy': (gate.safe(privacy_policy), 65536)}
    before, documents = {}, {}
    for label, (path, bound) in inputs.items():
        state, raw = stable_file(path, bound, read=label not in ('archive', 'privacy_policy'))
        before[label] = state
        if raw is not None: documents[label] = document(raw)
    gate.require(len({state['identity'][:2] for state in before.values()}) == len(before), 'Selected input aliases refused')
    gate.require(before['request']['sha256'] == gate.digest(request_sha256), 'Independently selected request differs')
    imported = helpers()
    request = validate_request(documents['request'], source_binding())
    scan = private_scanner(inputs['privacy_policy'][0])
    jobs = documents['jobs_metadata']
    gate.require(type(jobs.get('total_count')) is int and isinstance(jobs.get('jobs'), list) and
                 0 < jobs['total_count'] == len(jobs['jobs']) <= 1000 and
                 len({job['id'] for job in jobs['jobs']}) == len(jobs['jobs']), 'Complete bounded job snapshot required')
    observation = transport.validate_metadata(request, documents['run_metadata'], documents['artifact_metadata'], jobs['jobs'])
    gate.require(before['archive']['sha256'] == request['artifact']['sha256'] and
                 before['archive']['size'] == request['artifact']['size'], 'Archive differs from explicit artifact selection')
    out = gate.fresh(output, [path for path, _ in inputs.values()] + [ROOT])
    output_identity = out.stat().st_dev, out.stat().st_ino
    capsule = out / 'capsule'
    extracted = transport.extract_zip(inputs['archive'][0], capsule,
                                      request['artifact']['sha256'], request['artifact']['size'])
    result_sha = stable_file(capsule / 'result.json', 4 * 1024 * 1024)[0]['sha256']
    # This is the complete established audit, including actual58 .conda files,
    # nested native bytes, original Git toolkit tree/helpers, both rounds,
    # source/qxctl/delivery/SDK records and the unchanged36 pending cells.
    record = gate.verify_capsule(capsule, result_sha)
    gate.require(record['profile'] == request['profile'] and
                 record['original_toolkit_commit'] == request['workflow_commit'], 'Capsule differs from selected producer/profile')
    commit_observation = documents['run_metadata'].get('head_commit', {})
    gate.require(commit_observation.get('id') == request['workflow_commit'] and
                 commit_observation.get('tree_id') == record['original_toolkit_tree'],
                 'Original toolkit Git tree differs from saved producer commit observation')
    gate.require(all(record[key] == request['source'][key] for key in SOURCE_FIELDS),
                 'Capsule differs from independently selected source/export pins')
    pins = {key: result_sha if key == 'primary_result_sha256' else record[key] for key in transport.PIN_FIELDS}
    selection = {'protocol': transport.SELECTION,
        **{key: request[key] for key in ('repository', 'profile', 'run_id', 'run_attempt', 'workflow_commit', 'artifact')},
        'pins': pins}
    # The final full inventory and every original input are rechecked after
    # all nested validators. No report is emitted for changed custody.
    gate.require(transport.inventory(capsule) == extracted, 'Extracted capsule changed during verification')
    gate.require(all(stable_file(path, bound)[0] == before[label]
                     for label, (path, bound) in inputs.items()), 'Selected input changed during verification')
    gate.require(helpers() == imported and (out.stat().st_dev, out.stat().st_ino) == output_identity and
                 not out.is_symlink(), 'Executing helpers or output custody changed')
    selected_raw = transport.canonical(selection) + b'\n'
    selection_sha = hashlib.sha256(selected_raw).hexdigest()
    review = {'protocol': REVIEW, 'state': 'offline_selection_prepared_hosted_metadata_recheck_required',
        'request_sha256': request_sha256, 'selection_sha256': selection_sha,
        **{key: request[key] for key in ('repository', 'profile', 'run_id', 'run_attempt', 'workflow_commit', 'artifact', 'source')},
        'input_sha256': {label: before[label]['sha256'] for label in before if label != 'privacy_policy'},
        'api_snapshot_authenticated': False, 'authoritative_metadata_refetch_required': True,
        'saved_metadata_observation': observation, 'capsule_inventory_sha256': extracted['sha256'],
        'capsule_file_count': sum(row['kind'] == 'file' for row in extracted['entries']),
        'primary_result_sha256': result_sha, 'carrier_count': 58, 'client_included': False,
        'original_toolkit_commit': record['original_toolkit_commit'], 'original_toolkit_tree': record['original_toolkit_tree'],
        'original_source_and_helper_closure_verified': True, 'capsule_full_validation': 'passed',
        'executing_helpers': imported, 'inputs_unchanged': True,
        'privacy_policy_digest': scan.POLICY_DIGEST, 'output_record_privacy_scan': 'passed',
        'privacy_scope': 'new selection and review records; original capsule qualification and source bindings are verified separately',
        'pending_independent_acceptance_cells': 36, 'wrapper_qualification_started': False,
        'native_build_executed': False, 'installer_executed': False, 'runtime_activated': False,
        'publisher_trust_accepted': False, 'independent_fresh_host_acceptance': False,
        'publication_authorized': False, 'release_acceptance_complete': False}
    review_raw = json.dumps(review, sort_keys=True, indent=2).encode() + b'\n'
    scan.scan('selection.json', selected_raw); scan.scan('review.json', review_raw)
    # The actionable selection is the last exclusive write. A partial/failed
    # extraction has neither output record and can never become a selection.
    write_exclusive(out / 'review.json', review_raw)
    write_exclusive(out / 'selection.json', selected_raw)
    transport.validate_selection(out / 'selection.json', selection_sha)
    return review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('request', 'request-sha256', 'archive', 'run-metadata', 'artifact-metadata', 'jobs-metadata', 'privacy-policy', 'output'):
        parser.add_argument('--' + name, required=True)
    result = prepare(**vars(parser.parse_args()))
    print(json.dumps({'state': result['state'], 'profile': result['profile'],
                      'selection_sha256': result['selection_sha256'], 'publication_authorized': False}))


if __name__ == '__main__':
    main()
