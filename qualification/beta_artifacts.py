#!/usr/bin/env python3
"""Retrieve exact successful qualification outputs without changing their scope."""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_artifacts as native
from qualification import primary_artifacts as transport

gate = transport.gate
REPOSITORY = 'QuanuX/symphony-distribution'
PROTOCOL = 'symphony.distribution.beta-artifact-selection.v1'
PROOF = 'symphony.distribution.beta-artifact-transport.v1'
ROLES = {
    'package': ('.github/workflows/d12-native-rewrap.yml', 'd10-rewrapped-'),
    'client': ('.github/workflows/d13-primary-client.yml', 'd13-primary-client-'),
    'consumer': ('.github/workflows/d12-native-rewrap.yml', 'd12-native-rewrap-consumer-'),
    'maintenance': ('.github/workflows/d13-native-maintenance.yml', 'd13-native-maintenance-'),
    'beta': ('.github/workflows/d14-beta-assembly.yml', 'd14-beta-assembly-'),
    'native_pkg': ('.github/workflows/d14-native-pkg.yml', 'd14-native-pkg-'),
}


def validate_selection(path, expected):
    selected = native.read_document(path, expected, 262144)
    gate.require(set(selected) == {'protocol', 'repository', 'profile', 'artifacts'} and
        selected['protocol'] == PROTOCOL and selected['repository'] == REPOSITORY and
        selected['profile'] in gate.PROFILES, 'Selected beta artifact source differs')
    rows = selected['artifacts']
    gate.require(type(rows) is dict and rows and set(rows) <= ROLES.keys(), 'Unselected artifact roles')
    gate.require('native_pkg' not in rows or selected['profile'] == 'macos15-arm64', 'Native PKG qualification is Apple ARM only')
    ids = set()
    for role, row in rows.items():
        gate.require(set(row) == {'run_id', 'run_attempt', 'workflow_commit', 'workflow_path', 'artifact', 'result_sha256'} and
            transport.positive(row['run_id']) and transport.positive(row['run_attempt']) and
            re.fullmatch('[0-9a-f]{40}', row['workflow_commit']) and row['workflow_path'] == ROLES[role][0],
            'Exact qualified workflow identity required')
        art = row['artifact']
        gate.require(set(art) == {'id', 'name', 'size', 'sha256'} and transport.positive(art['id']) and
            art['id'] not in ids and type(art['size']) is int and 0 < art['size'] <= transport.MAX_ZIP and
            art['name'] == ROLES[role][1] + selected['profile'] + '-' + str(row['run_attempt']),
            'Exact completed artifact identity required')
        ids.add(art['id']); gate.digest(art['sha256']); gate.digest(row['result_sha256'])
    return selected


def validate_metadata(row, run, artifact):
    gate.require(run['id'] == row['run_id'] and run['run_attempt'] == row['run_attempt'] and
        run['status'] == 'completed' and run['conclusion'] == 'success' and run['event'] == 'workflow_dispatch' and
        run['head_sha'] == row['workflow_commit'] and run['path'] == row['workflow_path'] and
        run['repository']['full_name'] == REPOSITORY and run['head_repository']['full_name'] == REPOSITORY,
        'Selected completed successful qualification run differs')
    art = row['artifact']
    gate.require(artifact['id'] == art['id'] and artifact['name'] == art['name'] and
        artifact['expired'] is False and artifact['size_in_bytes'] == art['size'] and
        artifact['digest'] == 'sha256:' + art['sha256'] and artifact['workflow_run']['id'] == row['run_id'] and
        artifact['workflow_run']['head_sha'] == row['workflow_commit'], 'Selected GitHub artifact differs')
    return {'run_id': row['run_id'], 'run_attempt': row['run_attempt'], 'workflow_commit': row['workflow_commit'],
        'workflow_path': row['workflow_path'], 'event': 'workflow_dispatch', 'conclusion': 'success',
        'artifact_id': art['id'], 'artifact_sha256': art['sha256'], 'artifact_size': art['size']}


def result_identity(directory, profile, role, digest):
    result_name = {'consumer': 'd12-consumer/result.json', 'maintenance': 'd13-maintenance/result.json', 'native_pkg': 'd14-pkg-public/result.json'}.get(role, 'result.json')
    record = native.read_document(directory / result_name, digest)
    if role == 'consumer':
        gate.require(record['state'] == 'primary_shell_install_refusals_and_named_removal_passed',
            'Fresh consumer qualification incomplete')
    elif role == 'client':
        gate.require(record['state'] == 'primary_client_engineering_checks_passed' and
            record['actual_codex_cases'] == 22 and record['client_executed_from_verified_package'] is True and
            record['package_is_original_git_tree'] is False, 'Primary client qualification incomplete')
    elif role == 'package':
        gate.require(record['state'] == 'inherited_native_and_sdk_new_carriers_and_wrappers_audited',
            'Selected wrapper assembly incomplete')
    elif role == 'native_pkg':
        gate.require(profile == 'macos15-arm64' and record['state'] == 'native_pkg_install_and_named_carrier_removal_passed' and
            record['native_pkg_executed'] is True and record['all_named_carriers_removed'] is True and
            record['original_inputs_unchanged'] is True, 'Native PKG qualification incomplete')
    # Maintenance and final beta bodies are admitted by their owner-specific verifier.
    gate.require(record['profile'] == profile, 'Artifact result belongs to another platform')
    return record


def admit(root, selection, expected):
    selected = validate_selection(selection, expected)
    root = gate.safe(root)
    proof = native.read_document(root / 'transport-proof.json')
    gate.require(proof['protocol'] == PROOF and proof['selection_sha256'] == expected and
        proof['selection'] == selected and set(proof['artifacts']) == set(selected['artifacts']),
        'Exact selected artifact transport proof required')
    for role, row in selected['artifacts'].items():
        folder = root / 'artifacts' / role
        archive = transport.regular(root / 'downloads' / (role + '.zip'))
        gate.require(archive.stat().st_size == row['artifact']['size'] and
            gate.sha(archive) == row['artifact']['sha256'] and
            transport.inventory(folder) == proof['artifacts'][role]['inventory'], 'Retained artifact bytes changed')
        wanted = {'run_id': row['run_id'], 'run_attempt': row['run_attempt'], 'workflow_commit': row['workflow_commit'],
            'workflow_path': row['workflow_path'], 'event': 'workflow_dispatch', 'conclusion': 'success',
            'artifact_id': row['artifact']['id'], 'artifact_sha256': row['artifact']['sha256'], 'artifact_size': row['artifact']['size']}
        gate.require(proof['artifacts'][role]['github_observation'] == wanted, 'Hosted artifact observation differs')
        result_identity(folder, selected['profile'], role, row['result_sha256'])
    return proof


def fetch(selection, expected, output, gh):
    selected = validate_selection(selection, expected)
    output = gate.fresh(output, (gate.safe(selection), ROOT))
    (output / 'downloads').mkdir(mode=0o700); (output / 'artifacts').mkdir(mode=0o700)
    gh, env = transport.transport_environment(output, gh); gh_sha = gate.sha(gh)
    base = 'repos/' + REPOSITORY + '/actions'; records = {}
    for role, row in selected['artifacts'].items():
        run = transport.gh_json(gh, base + f"/runs/{row['run_id']}/attempts/{row['run_attempt']}", env)
        artifact = transport.gh_json(gh, base + '/artifacts/' + str(row['artifact']['id']), env)
        observed = validate_metadata(row, run, artifact)
        archive = output / 'downloads' / (role + '.zip')
        transport.download_zip(gh, base + '/artifacts/' + str(row['artifact']['id']) + '/zip', env, archive, row['artifact']['size'])
        inventory = transport.extract_zip(archive, output / 'artifacts' / role, row['artifact']['sha256'], row['artifact']['size'])
        result_identity(output / 'artifacts' / role, selected['profile'], role, row['result_sha256'])
        records[role] = {'github_observation': observed, 'inventory': inventory}
    gate.require(gate.sha(gh) == gh_sha and validate_selection(selection, expected) == selected,
        'Selected transport or artifact request changed')
    proof = {'protocol': PROOF, 'selection_sha256': expected, 'selection': selected, 'artifacts': records,
        'transport_executable_sha256': gh_sha, 'scope': 'successful hosted artifact custody; owner-specific admission remains required'}
    gate.write(output / 'transport-proof.json', proof)
    admit(output, selection, expected)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['fetch', 'admit'])
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gh', type=Path)
    args = parser.parse_args()
    if args.command == 'fetch':
        gate.require(args.gh is not None, 'GitHub transport required')
        result = fetch(args.selection, args.selection_sha256, args.output, args.gh)
    else: result = admit(args.output, args.selection, args.selection_sha256)
    print(json.dumps({'profile': result['selection']['profile'], 'roles': sorted(result['artifacts']), 'state': 'exact_successful_artifacts_admitted'}))


if __name__ == '__main__': main()
