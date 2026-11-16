#!/usr/bin/env python3
"""Retrieve one explicitly selected hosted carrier capsule without trusting ZIP paths.

GitHub transport provenance and reviewed bytes are engineering evidence, not
publisher trust, independent acceptance, or permission to publish.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import sys
import unicodedata
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from qualification import d09_platform as gate

REPOSITORY = 'QuanuX/symphony-distribution'
WORKFLOW = '.github/workflows/d09-platform.yml'
SELECTION = 'symphony.distribution.primary-rewrap-selection.v1'
PROTOCOL = 'symphony.distribution.primary-artifact-transport.v1'
REQUIRED_STEPS = (
    'Build two clean cohorts and qualify final installed SDKs',
    'Qualify core SNV APIs, copied Go SDK and disposable removal',
    'Retain completed pre-wrapper primary carrier capsule',
)
PIN_FIELDS = {'primary_result_sha256', 'cohort_digest', 'build_result_sha256',
              'round_result_sha256', 'sdk_closure_sha256', 'delivery_record_sha256',
              'source_manifest_sha256', 'source_export_digest',
              'fresh_host_requirements_sha256', 'source_commit', 'source_tree'}
MAX_ZIP = 1024 ** 3
MAX_EXPANDED = 4 * 1024 ** 3
MAX_FILES = 50000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def positive(value, *, string=False):
    if string:
        return isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,19}', value)
    return type(value) is int and value > 0


def regular(path):
    path = gate.safe(path)
    info = path.lstat()
    gate.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Selected file is not an independent regular file')
    return path


def validate_selection(path, expected_sha256):
    path = regular(path)
    gate.require(path.stat().st_size <= 262144 and gate.sha(path) == gate.digest(expected_sha256),
                 'Explicit artifact selection differs')
    selected = gate.read(path)
    gate.require(set(selected) == {'protocol', 'repository', 'profile', 'run_id', 'run_attempt',
                                  'workflow_commit', 'artifact', 'pins'}, 'Selection fields differ')
    gate.require(selected['protocol'] == SELECTION and selected['repository'] == REPOSITORY and
                 selected['profile'] in gate.PROFILES and positive(selected['run_id'], string=True) and
                 positive(selected['run_attempt'], string=True) and
                 re.fullmatch('[0-9a-f]{40}', selected['workflow_commit']), 'Unselected producer identity')
    artifact = selected['artifact']
    gate.require(set(artifact) == {'id', 'name', 'sha256', 'size'} and positive(artifact['id']) and
                 type(artifact['size']) is int and 0 < artifact['size'] <= MAX_ZIP and
                 artifact['name'] == f"d10-carrier-capsule-{selected['profile']}-{selected['run_attempt']}",
                 'Selected artifact identity differs')
    gate.digest(artifact['sha256'])
    gate.require(set(selected['pins']) == PIN_FIELDS, 'Required capsule/source pins differ')
    for name, value in selected['pins'].items():
        if name in ('source_commit', 'source_tree'):
            gate.require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'Exact source identity required')
        elif name == 'cohort_digest':
            gate.require(isinstance(value, str) and value.startswith('sha256:'), 'Exact cohort digest required')
            gate.digest(value[7:])
        else:
            gate.digest(value)
    return selected


def validate_metadata(selection, run, artifact, jobs):
    selected = selection['artifact']
    gate.require(run['id'] == int(selection['run_id']) and run['run_attempt'] == int(selection['run_attempt']) and
                 run['status'] == 'completed' and run['event'] == 'workflow_dispatch' and
                 run['head_sha'] == selection['workflow_commit'] and run['path'] == WORKFLOW and
                 run['repository']['full_name'] == REPOSITORY and
                 run['head_repository']['full_name'] == REPOSITORY, 'Completed selected producer run differs')
    gate.require(artifact['id'] == selected['id'] and artifact['name'] == selected['name'] and
                 artifact['expired'] is False and artifact['size_in_bytes'] == selected['size'] and
                 artifact['digest'] == 'sha256:' + selected['sha256'] and
                 artifact['workflow_run']['id'] == int(selection['run_id']) and
                 artifact['workflow_run']['head_sha'] == selection['workflow_commit'],
                 'GitHub artifact metadata differs from explicit selection')
    native = [job for job in jobs if job['name'] == 'native' and job['run_attempt'] == int(selection['run_attempt'])]
    gate.require(len(native) == 1 and native[0]['status'] == 'completed', 'Exact completed native job required')
    steps = native[0]['steps']
    for name in REQUIRED_STEPS:
        found = [step for step in steps if step['name'] == name]
        gate.require(len(found) == 1 and found[0]['status'] == 'completed' and found[0]['conclusion'] == 'success',
                     'Native build, SDK closure or capsule retention did not complete successfully')
    return {'workflow_path': WORKFLOW, 'event': run['event'], 'status': run['status'],
            'conclusion': run['conclusion'], 'job_id': native[0]['id'], 'job_name': 'native',
            'job_conclusion': native[0]['conclusion'], 'successful_steps': list(REQUIRED_STEPS)}


def member_name(info):
    name = info.filename
    gate.require(name == info.orig_filename and name and not name.startswith('/') and
                 '\\' not in name and ':' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                 'Unsafe archive name')
    name = name[:-1] if name.endswith('/') else name
    parts = name.split('/')
    gate.require(all(p not in ('', '.', '..') for p in parts) and PurePosixPath(name).as_posix() == name,
                 'Unsafe archive path')
    mode = (info.external_attr >> 16) & 0xffff
    kind = stat.S_IFMT(mode)
    gate.require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and
                 (kind != stat.S_IFDIR or info.is_dir()) and
                 (kind != stat.S_IFREG or not info.is_dir()) and not (info.flag_bits & 1),
                 'Linked, special or encrypted archive entry refused')
    return name


def extract_zip(archive, output, expected_sha256, expected_size):
    archive = regular(archive)
    gate.require(0 < expected_size <= MAX_ZIP and archive.stat().st_size == expected_size and
                 gate.sha(archive) == gate.digest(expected_sha256), 'Downloaded archive bytes differ')
    output = gate.fresh(output, (archive, gate.ROOT))
    with zipfile.ZipFile(archive) as stream:
        infos = stream.infolist()
        gate.require(0 < len(infos) <= MAX_FILES and sum(i.file_size for i in infos) <= MAX_EXPANDED,
                     'Archive size or member count exceeds bound')
        planned, portable = {}, set()
        for info in infos:
            name = member_name(info)
            key = unicodedata.normalize('NFC', name).casefold()
            gate.require(name not in planned and key not in portable, 'Duplicate or colliding archive member')
            gate.require(info.file_size <= MAX_ZIP, 'Archive member exceeds bound')
            planned[name] = info; portable.add(key)
        for name, info in planned.items():
            for parent in PurePosixPath(name).parents:
                if str(parent) != '.' and str(parent) in planned:
                    gate.require(planned[str(parent)].is_dir(), 'Archive file/directory overlap')
            path = output / name
            if info.is_dir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with stream.open(info) as source, path.open('xb') as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
                gate.require(path.stat().st_size == info.file_size, 'Extracted member size differs')
                path.chmod(0o644)
    gate.require(gate.sha(archive) == expected_sha256, 'Archive changed during extraction')
    for path in output.rglob('*'):
        if path.is_dir(): path.chmod(0o700)
    return inventory(output)


def inventory(root):
    root = gate.safe(root)
    gate.require(root.is_dir(), 'Capsule directory absent')
    rows = []
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        gate.require(not path.is_symlink() and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
                     'Linked or special capsule member')
        if path.is_file():
            regular(path)
            rows.append({'path': path.relative_to(root).as_posix(), 'size': info.st_size,
                         'mode': stat.S_IMODE(info.st_mode), 'sha256': gate.sha(path), 'kind': 'file'})
        else:
            rows.append({'path': path.relative_to(root).as_posix(), 'mode': stat.S_IMODE(info.st_mode), 'kind': 'directory'})
    gate.require(any(row['kind'] == 'file' for row in rows), 'Empty capsule refused')
    return {'entries': rows, 'sha256': sha(canonical(rows))}


def verify_transport(root, proof_path, selection, selection_sha256):
    proof_path = regular(proof_path)
    gate.require(proof_path.stat().st_size <= 16 * 1024 * 1024, 'Transport evidence exceeds bound')
    proof = gate.read(proof_path)
    gate.require(proof['protocol'] == PROTOCOL and proof['selection_sha256'] == gate.digest(selection_sha256) and
                 all(proof[k] == selection[k] for k in ('repository', 'profile', 'run_id', 'run_attempt', 'workflow_commit', 'artifact')) and
                 proof['github_observation']['workflow_path'] == WORKFLOW and
                 proof['github_observation']['event'] == 'workflow_dispatch' and
                 proof['github_observation']['status'] == 'completed' and
                 proof['github_observation']['successful_steps'] == list(REQUIRED_STEPS) and
                 proof['publisher_trust_accepted'] is False and proof['publication_authorized'] is False,
                 'Selected transport proof differs')
    gate.require(inventory(root) == proof['inventory'], 'Extracted capsule inventory changed')
    return proof


def gh_json(executable, endpoint, env):
    result = subprocess.run([str(executable), 'api', '--hostname', 'github.com', endpoint],
                            env=env, capture_output=True, timeout=90)
    gate.require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
                 'Bounded GitHub metadata request failed')
    return json.loads(result.stdout)


def transport_environment(output, gh):
    gh = regular(Path(gh).resolve())
    token = os.environ.get('GH_TOKEN')
    gate.require(isinstance(token, str) and token, 'Read-only GitHub Actions token is required')
    home = output / 'transport-home'; home.mkdir(mode=0o700)
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
           'GH_TOKEN': token, 'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1', 'NO_COLOR': '1'}
    return gh, env


def download_zip(gh, endpoint, env, archive, expected_size):
    gate.require(type(expected_size) is int and 0 < expected_size <= MAX_ZIP, 'Selected download exceeds bound')
    with archive.open('xb') as stream:
        archive.chmod(0o600)
        result = subprocess.run([str(gh), 'api', '--hostname', 'github.com', endpoint],
                                env=env, stdout=stream, stderr=subprocess.PIPE, timeout=600,
                                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE,
                                    (expected_size, expected_size)))
    gate.require(result.returncode == 0, 'Selected artifact download failed')


def fetch(selection_path, selection_sha256, output, gh):
    selection = validate_selection(selection_path, selection_sha256)
    output = gate.fresh(output, (selection_path, gate.ROOT))
    gh, env = transport_environment(output, gh)
    base = 'repos/' + REPOSITORY + '/actions'
    run = gh_json(gh, base + '/runs/' + selection['run_id'] + '/attempts/' + selection['run_attempt'], env)
    artifact = gh_json(gh, base + '/artifacts/' + str(selection['artifact']['id']), env)
    jobs = []
    for page in range(1, 5):
        response = gh_json(gh, base + '/runs/' + selection['run_id'] + '/attempts/' + selection['run_attempt'] +
                           '/jobs?per_page=100&page=' + str(page), env)
        jobs.extend(response['jobs'])
        if len(jobs) >= response['total_count']:
            break
    else:
        raise ValueError('Producer job enumeration exceeds bound')
    observation = validate_metadata(selection, run, artifact, jobs)
    archive = output / 'capsule.zip'
    download_zip(gh, base + '/artifacts/' + str(artifact['id']) + '/zip', env, archive, selection['artifact']['size'])
    contents = extract_zip(archive, output / 'capsule', selection['artifact']['sha256'], selection['artifact']['size'])
    gate.require(gate.sha(selection_path) == selection_sha256, 'Selection changed during retrieval')
    proof = {'protocol': PROTOCOL, 'selection_sha256': selection_sha256,
             **{k: selection[k] for k in ('repository', 'profile', 'run_id', 'run_attempt', 'workflow_commit', 'artifact')},
             'github_observation': observation, 'inventory': contents, 'transport_executable_sha256': gate.sha(gh),
             'publisher_trust_accepted': False, 'publication_authorized': False}
    gate.write(output / 'transport-proof.json', proof)
    verify_transport(output / 'capsule', output / 'transport-proof.json', selection, selection_sha256)
    return proof


def fetch_generated(artifact_id, expected_digest, profile, output, gh):
    """Retrieve this hosted run's exact completed wrapper-producer artifact."""
    gate.digest(expected_digest)
    gate.require(positive(artifact_id) and profile in gate.PROFILES and
                 os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and os.environ.get('GITHUB_ACTIONS') == 'true',
                 'Explicit hosted generated-artifact selection required')
    run_id, attempt, commit = (os.environ.get(k, '') for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA'))
    gate.require(positive(run_id, string=True) and positive(attempt, string=True) and re.fullmatch('[0-9a-f]{40}', commit),
                 'Current hosted producer identity absent')
    output = gate.fresh(output, (gate.ROOT,)); gh, env = transport_environment(output, gh)
    base = 'repos/' + REPOSITORY + '/actions'
    artifact = gh_json(gh, base + '/artifacts/' + str(artifact_id), env)
    gate.require(artifact['id'] == artifact_id and artifact['expired'] is False and
                 artifact['name'] == f'd10-rewrapped-{profile}-{attempt}' and
                 artifact['digest'] == 'sha256:' + expected_digest and
                 artifact['workflow_run']['id'] == int(run_id) and artifact['workflow_run']['head_sha'] == commit,
                 'Generated artifact is not the selected output of this run')
    jobs = gh_json(gh, base + '/runs/' + run_id + '/attempts/' + attempt + '/jobs?per_page=100', env)
    gate.require(jobs['total_count'] <= 100, 'Current job enumeration exceeds bound')
    producer = [j for j in jobs['jobs'] if j['name'] == 'rewrap' and j['run_attempt'] == int(attempt)]
    gate.require(len(producer) == 1 and producer[0]['status'] == 'completed' and producer[0]['conclusion'] == 'success',
                 'Matching wrapper producer has not completed successfully')
    archive = output / 'rewrapped.zip'
    download_zip(gh, base + '/artifacts/' + str(artifact_id) + '/zip', env, archive, artifact['size_in_bytes'])
    contents = extract_zip(archive, output / 'artifact', expected_digest, artifact['size_in_bytes'])
    proof = {'protocol': 'symphony.distribution.generated-wrapper-transport.v1', 'repository': REPOSITORY,
             'run_id': run_id, 'run_attempt': attempt, 'workflow_commit': commit, 'artifact_id': artifact_id,
             'artifact_sha256': expected_digest, 'size': artifact['size_in_bytes'], 'profile': profile,
             'producer_job_id': producer[0]['id'], 'inventory_sha256': contents['sha256'],
             'publisher_trust_accepted': False, 'publication_authorized': False}
    gate.write(output / 'transport-proof.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gh', type=Path, required=True)
    args = parser.parse_args()
    result = fetch(args.selection, args.selection_sha256, args.output, args.gh)
    print(json.dumps({'state': 'selected_capsule_retrieved_and_verified', 'inventory_sha256': result['inventory']['sha256']}))


if __name__ == '__main__':
    main()
