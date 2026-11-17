#!/usr/bin/env python3
"""Validate dossier bindings and prevent fixture evidence becoming acceptance."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {'macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64'}
UNITS = {'secure-identity-access-governance', 'stav-append-authority', 'accordare-stav-producer',
         'qxctl', 'sov-ssh-adapter', 'sov-stdio-adapter', 'sov-transport-profile-admin'}
CORE_DOCUMENTS = {'tests/public-beta/dossier.json', 'tests/public-beta/capability-groups.json',
    'tests/public-beta/package-plan.json', 'tests/public-beta/owners.json', 'tests/public-beta/paper-criteria.json',
    'tests/public-beta/acceptance-mapping.json', 'tests/public-beta/execution/W12-REVIEW.md',
    'tests/public-beta/execution/w12-review/requirements.json', 'cmake/mvp-dependencies.json',
    'cmake/mvp-release-identities.json', 'cmake/mvp-platform-profiles.json', 'cmake/mvp-go-owner-closure.json'}


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate document field')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def path_under(root, name):
    p = PurePosixPath(name)
    require(name == str(p) and not p.is_absolute() and '..' not in p.parts and '\\' not in name,
            'unsafe evidence path')
    target = root / name
    require(target.is_file() and not any(q.is_symlink() for q in (target, *target.parents) if q != root.parent),
            'evidence must be an existing regular non-symlink path')
    return target


def validate_document(data, root=ROOT, source=None, require_rebuild=False, require_source_export=False, require_hosted_status=False):
    require(data.get('protocol') == 'symphony.distribution.s08-dossier.v1', 'dossier protocol differs')
    for field in ('release_acceptance_complete', 'publication_authorized'):
        require(data.get(field) is False, 'dossier cannot grant release acceptance or publication')
    require(data.get('supported_profiles') == [], 'unaccepted platform advertised as supported')
    require(data['feature_freeze'] == {'in_force': True, 'new_features_authorized': False, 'core_changed_by_S08': False},
            'feature freeze or core isolation changed')
    binding = read(root / 'source-binding.json')
    require(data['core_source'] == {k: binding[k] for k in ('source_commit', 'source_tree', 'binding_digest')}, 'core binding differs')
    require(len(data['source_documents']) == len(CORE_DOCUMENTS) and {r['path'] for r in data['source_documents']} == CORE_DOCUMENTS,
            'required core dossier/map reference removed or duplicated')
    local = data['distribution_inputs']
    require(len({r['path'] for r in local}) == len(local), 'duplicate evidence input')
    required_inputs = {'source-binding.json', 'go-owner-catalog.json', 'evidence/s06-local-qualification.json',
        'evidence/go-candidate-closure.json', 'evidence/s07-conda-local-qualification.json',
        'evidence/s07-native-local-qualification.json', 'evidence/s07-local-platform.json', 'dossier/d05-requirements.json'}
    require({r['path'] for r in local} == required_inputs, 'required evidence input removed or changed')
    for row in local:
        require(sha(path_under(root, row['path']).read_bytes()) == row['sha256'], 'distribution evidence hash differs: ' + row['path'])
    catalog = read(root / 'go-owner-catalog.json')
    require(catalog['source_commit'] == binding['source_commit'] and catalog['source_tree'] == binding['source_tree'], 'owner catalog source differs')
    units = data['go_delivery_units']
    require(len(units) == 7 and {r['component_id'] for r in units} == UNITS, 'seven-owner coverage differs')
    for row in units:
        expected = next(x for x in catalog['units'] if x['component_id'] == row['component_id'])
        for key in ('binary_name', 'native_version', 'conda_name', 'conda_version', 'source_root', 'owner_contract',
                    'runtime_owner_kind', 'selection_owner', 'runtime_receipt', 'definition_digest', 'owner_invocation_implemented'):
            require(row[key] == expected[key], 'owner identity or contract substituted')
        require(row['payload_files'] == [row['binary_name'], 'artifact-identity.json', 'LICENSE-AGPL-3.0', 'carrier-manifest.json'],
                'inert carrier content differs')
        require(row['runtime_dependencies'] == [] and row['supported_profiles'] == [], 'unqualified dependency or platform claim')
        for key in ('runtime_python_required', 'automatic_activation', 'automatic_privilege', 'system_removal_qualified', 'live_raw_cleanup_supported'):
            require(row[key] is False, 'unsupported automatic/live/system behavior claimed')
    profiles = data['platforms']
    require(len(profiles) == 4 and {p['id'] for p in profiles} == PROFILES, 'four-profile coverage differs')
    for row in profiles:
        require(row['release_supported'] is False and row['fresh_host_acceptance'] == row['installed_manager_acceptance'] == 'incomplete',
                'inventory or fixture evidence promoted to host acceptance')
    hosted_status = data.get('hosted_status_report')
    require(not require_hosted_status or hosted_status is not None, 'hosted CI snapshot binding required')
    if hosted_status:
        path = path_under(root, hosted_status['path'])
        require(sha(path.read_bytes()) == hosted_status['sha256'], 'hosted CI snapshot hash differs')
        snapshot = read(path)
        require(snapshot.get('protocol') == 'symphony.distribution.s07-hosted-status.v1', 'hosted CI snapshot protocol differs')
        require(snapshot['core_source_commit'] == binding['source_commit'] and snapshot['core_source_tree'] == binding['source_tree'],
                'hosted CI core source differs')
        require(snapshot['distribution_commit'] == '8d9474e89b4974ecbf139ca7e95c60772e7127de', 'hosted evidence silently relabelled to another distribution head')
        require(snapshot['publication_authorized'] is False and snapshot['release_acceptance_complete'] is False and
                all(run['head_sha'] == snapshot['distribution_commit'] for run in snapshot['runs']),
                'hosted snapshot grants acceptance or mixes source heads')
        rows = snapshot['profiles']
        require(len(rows) == 4 and {r['profile'] for r in rows} == PROFILES, 'hosted CI profile coverage differs')
        for row in profiles:
            observation = next(r for r in rows if r['profile'] == row['id'])
            require(row['hosted_evidence_in_this_dossier'] == observation, 'hosted CI observation differs from bound snapshot')
            require(observation['conclusion'] in ('success', 'failure', 'cancelled', 'timed_out') and
                    observation['native_step_conclusion'] in ('success', 'failure', 'cancelled', 'skipped') and
                    observation['conda_step_conclusion'] in ('success', 'failure', 'cancelled', 'skipped', 'skipped_after_native_failure'), 'unknown hosted CI outcome')
            require(observation['job_url'].startswith('https://github.com/QuanuX/symphony-distribution/actions/runs/'), 'hosted CI job provenance differs')
            require(observation['final_host_acceptance'] is False, 'hosted job success promoted to final-host acceptance')
    else:
        require(all(r['hosted_evidence_in_this_dossier'] == 'not_collected' for r in profiles), 'unbound hosted CI claim')
    supplemental = data['supplemental_platform']
    require(supplemental['id'] == 'local-macos-amd64-fixture' and supplemental['not_a_substitute_for_core_profiles'] is True and
            supplemental['final_host_acceptance'] == 'incomplete', 'supplemental host promoted to core acceptance')
    native = read(root / 'evidence/s07-native-local-qualification.json')
    conda = read(root / 'evidence/s07-conda-local-qualification.json')
    for report in (native, conda):
        require(report['source_commit'] == binding['source_commit'] and report['source_tree'] == binding['source_tree'] and
                report['source_binding_digest'] == binding['binding_digest'] and report['status'] == 'passed', 'S07 source or result differs')
    require(native['evidence_level'] == 'E1' and not native['fresh_host_accepted'] and not native['live_removal_accepted'] and
            native['skip_count'] == 0 and conda['tests']['skipped'] == 0 and conda['host_acceptance'] == 'not_run', 'S07 evidence boundary differs')
    accepted = data['d05_safety_acceptance']
    requirements = read(root / 'dossier/d05-requirements.json')['requirements']
    require(len(accepted) == 30 and {r['id'] for r in accepted} == {f'D05-S{i:02}' for i in range(1, 31)}, 'D05 safety requirement omitted or duplicated')
    real_cases = {(s['id'], c['test']): c for s in native['suites'] for c in s['cases']}
    lost_cases = {r['id']: r for r in native['completed_native_response_loss']}
    for row in accepted:
        original = next(r for r in requirements if r['id'] == row['id'])
        require(all(row[k] == v for k, v in original.items()), 'D05 requirement changed')
        require(row['final_acceptance'] == 'incomplete' and row['remaining_limit'], 'D05 requirement silently accepted')
        for ref in row['evidence_refs']:
            if ref['evidence'] == 'evidence/s07-native-local-qualification.json':
                case = real_cases.get((ref.get('suite'), ref.get('test'))) if 'test' in ref else lost_cases.get(ref.get('case'))
                require(case is not None and row['id'] in case['acceptance'] and ref['expected'] == case['expected'], 'native test misattributed to acceptance cell')
            else:
                require(ref['evidence'] == 'evidence/s07-conda-local-qualification.json' and int(row['id'][-2:]) in {9, 15, 16, 26, 28},
                        'Conda carrier evidence misattributed to native acceptance')
    beta = data['retained_beta_requirements']
    require(len(set(beta['core_cell_ids'])) == len(beta['core_cell_ids']) == 36 and
            len(set(beta['paper_criterion_ids'])) == len(beta['paper_criterion_ids']) == 58 and
            len(set(beta['supplemental_ids'])) == len(beta['supplemental_ids']) == 31,
            'retained beta coverage narrowed or duplicated')
    require(beta['replaced_by_D05_supplement'] is False and beta['scores_assessed'] is False and beta['final_acceptance'] == 'incomplete',
            'historical beta acceptance promoted')
    require(data['trust']['publisher_signing_identity'] is None and data['trust']['independent_public_trust_policy'] is None and
            data['trust']['final_retrieval_verified'] is False and data['trust']['signing_or_publication_performed'] is False,
            'unprovided trust or retrieval acceptance invented')
    require(all(r['new_assignment_made'] is False for r in data['roles']), 'unassigned role silently appointed')
    carried = data['capability_baseline']
    require(len(carried) == len({r['id'] for r in carried}) == 26 and
            all(r['s08_disposition'] == 'carried_forward_not_waived_or_requalified' and r['final_acceptance'] == 'incomplete' for r in carried),
            'capability inventory narrowed or accepted')
    rebuild = data['candidate_rebuild_report']
    require(not require_rebuild or rebuild is not None, 'candidate rebuild binding required')
    if rebuild:
        path = path_under(root, rebuild['path'])
        require(sha(path.read_bytes()) == rebuild['sha256'], 'candidate rebuild report hash differs')
        report = read(path)
        require(report.get('protocol', report.get('schema')) == 'symphony.distribution.s08-candidate-rebuild.v1' and report['status'] == 'passed', 'candidate reconstruction not passed')
        require(report['core_source']['commit'] == binding['source_commit'] and report['core_source']['tree'] == binding['source_tree'] and
                report['core_source']['binding_digest'] == binding['binding_digest'], 'rebuilt candidate source substituted')
        require(report['native_binaries_rebuilt'] is False, 'packaging-only increment relabelled as native rebuild')
        require(all(report[k] is False for k in ('fresh_host_accepted', 'publisher_trust_accepted', 'release_acceptance_complete',
                                                 'publication_authorized', 'two_native_versions')),
                'candidate fixture promoted to release or distinct-version acceptance')
        require(report['binary_closure'] == read(root / 'evidence/go-candidate-closure.json'), 'candidate binary/module closure differs')
        required_tools = {'source-binding.json', 'go-owner-catalog.json', 'lifecycle/conda_transaction.py', 'lifecycle/go_delivery.py',
                          'owner-catalog/native_owners.py', 'recipes/build_go_carriers.py', 'recipes/go_generate.py',
                          'recipes/stage_payload.py', 'tests/conda_journeys.py'}
        require(set(report['tool_files_sha256']) == required_tools, 'candidate preparation tool coverage differs')
        for name, expected_hash in report['tool_files_sha256'].items():
            require(sha(path_under(root, name).read_bytes()) == expected_hash, 'candidate preparation tool changed after qualification')
        require(len(report['archives']) == report['archive_count'] == 14 and
                {(r['component_id'], r['build_number']) for r in report['archives']} == {(u, b) for u in UNITS for b in (0, 1)},
                'rebuilt archive cohort incomplete')
        for row in report['archives']:
            expected = next(x for x in catalog['units'] if x['component_id'] == row['component_id'])
            binary = next(x for x in report['binary_closure']['units'] if x['component_id'] == row['component_id'])
            require(row['native_version'] == expected['native_version'] and row['payload_equal_to_original'] is True,
                    'candidate bytes or native version differ from reviewed closure')
            require(row['source_commit'] == binding['source_commit'] and row['source_tree'] == binding['source_tree'] and
                    row['definition_digest'] == expected['definition_digest'] and row['owner_contract'] == expected['owner_contract'] and
                    row['native_executable_sha256'] == binary['executable_sha256'] and row['artifact_identity_sha256'] == binary['artifact_identity_sha256'],
                    'archive owner/source/executable identity differs')
            require(row['audit_passed'] is True and row['payload_file_count'] == 4 and row['lifecycle_hooks'] == [] and
                    row['runtime_dependencies'] == [] and row['recipe_included'] is False and row['host_state_absent'] is True and row['personal_paths_absent'] is True,
                    'archive audit or inert/private payload boundary differs')
            require(all(row[k] is False for k in ('fresh_host_accepted', 'publisher_trust_accepted', 'publication_authorized')),
                    'archive audit promoted to final trust or host acceptance')
    source_export = data['source_export_report']
    require(not require_source_export or source_export is not None, 'source export binding required')
    if source_export:
        path = path_under(root, source_export['path'])
        require(sha(path.read_bytes()) == source_export['sha256'], 'source export report hash differs')
        report = read(path)
        require(report.get('protocol') == 'symphony.distribution.s08-source-export.v1' and report['status'] == 'verified', 'source export not verified')
        for key in ('source_commit', 'source_tree'):
            require(report[key] == binding[key], 'source export core identity differs')
        require(report['source_binding_digest'] == binding['binding_digest'], 'source export binding differs')
        require(report['release_acceptance_complete'] is False and report['publication_authorized'] is False and
                report['all_source_roots_build_tested'] is False, 'selected export build promoted to complete acceptance')
        require(report['final_host_acceptance'] is False and report['publisher_trust_accepted'] is False and
                report['archive_is_original_git_tree'] is False and report['privacy_policy_bundled'] is False,
                'derived export relabelled or trust/private-policy boundary changed')
        require(report['repeat_archive_identical'] is True and report['selected_source_build']['status'] == 'passed', 'source export reproducibility/build not established')
        require(report['tool_sha256'].removeprefix('sha256:') == sha(path_under(root, 'source-export/export_source.py').read_bytes()),
                'source export tool changed after qualification')
        source_map = report['source_map']
        expected_map = next((r for r in data['source_documents'] if r['path'] == source_map['path']), None)
        require(expected_map and source_map['original_sha256'] == expected_map['sha256'], 'derived map original source differs')
        for digest in (report['archive']['sha256'], report['manifest_sha256'], report['derived_export_digest'],
                       report['tool_sha256'], report['privacy_policy_digest'], source_map['export_sha256']):
            require(isinstance(digest, str) and len(digest.removeprefix('sha256:')) == 64 and
                    all(c in '0123456789abcdef' for c in digest.removeprefix('sha256:')), 'source export digest missing or malformed')
        selected = report['selected_source_build']
        selected_path = path_under(root, selected['path'])
        require(sha(selected_path.read_bytes()) == selected['sha256'], 'selected source build report hash differs')
        built = read(selected_path)
        require(built['protocol'] == 'symphony.distribution.derived-go-source-build.v1' and built['status'] == 'passed',
                'selected derived-source build not passed')
        require(built['source_commit'] == binding['source_commit'] and built['source_tree'] == binding['source_tree'] and
                built['source_archive_sha256'] == report['archive']['sha256'] and built['derived_export_digest'] == report['derived_export_digest'],
                'selected build belongs to another source export')
        require(built['recipe_sha256'] == sha(path_under(root, 'source-export/check_go_source.py').read_bytes()),
                'selected source build recipe changed after qualification')
        require(built['toolchain'] == 'go1.26.5' and built['os'] == 'darwin' and built['architecture'] == 'amd64' and
                built['fresh_build_cache'] is True and built['private_build_home'] is True,
                'selected source build host/toolchain/isolation differs')
        require(all(built[k] is False for k in ('all_source_roots_build_tested', 'core_checkout_used_as_build_input',
                    'host_acceptance', 'publication_authorized', 'qxctl_rebuilt', 'release_acceptance_complete', 'source_replacements')),
                'selected source build promoted to broad acceptance or hidden source substituted')
        commands = built['go_commands']
        require(len(commands) == selected['commands_built'] == 6 and {c['component_id'] for c in commands} == UNITS - {'qxctl'},
                'selected source build coverage missing or substituted')
        require(selected['candidate_bytes_equal'] is True and selected['fresh_build_cache'] is True and
                selected['qxctl_rebuilt'] is False and selected['all_source_roots_build_tested'] is False,
                'selected source build summary differs')
        closure = read(root / 'evidence/go-candidate-closure.json')
        for row in commands:
            expected = next(c for c in closure['units'] if c['component_id'] == row['component_id'])
            require(row['native_version'] == expected['native_version'] and row['executable_sha256'] == expected['executable_sha256'] and
                    row['candidate_identity_sha256'] == expected['artifact_identity_sha256'] and row['candidate_bytes_equal'] is True and
                    row['module_cache_verified'] is True and row['private_path_scan_passed'] is True,
                    'derived source output differs from exact verified candidate')
    if source:
        def git(*args):
            return subprocess.check_output(['git', '--no-replace-objects', '-C', str(source), *args], timeout=30)
        require(git('rev-parse', 'HEAD').decode().strip() == binding['source_commit'] and
                git('rev-parse', 'HEAD^{tree}').decode().strip() == binding['source_tree'], 'exact core source required')
        require(not git('status', '--porcelain=v1', '--untracked-files=all').strip(), 'core source is dirty')
        documents = {}
        for row in data['source_documents']:
            actual = git('show', binding['source_commit'] + ':' + row['path'])
            require(sha(actual) == row['sha256'] and sha(path_under(source, row['path']).read_bytes()) == row['sha256'], 'core dossier/map source drift')
            documents[row['path']] = actual
        history = json.loads(documents['tests/public-beta/dossier.json'])
        require(data['historical_core_dossier']['declared_source_commit'] == history['source_commit'] and
                data['historical_core_dossier']['declared_source_tree'] == history['source_tree'], 'historical dossier relabelled as current source')
        groups = json.loads(documents['tests/public-beta/capability-groups.json'])['groups']
        carried = data['capability_baseline']
        require(len(carried) == len(groups) == 26 and {r['id'] for r in carried} == {r['id'] for r in groups}, 'capability inventory narrowed')
        for row in carried:
            expected = next(r for r in groups if r['id'] == row['id'])
            require(row['component_roots'] == expected['component_roots'] and row['historical_implementation_statement'] == expected['implementation_state'] and
                    row['s08_disposition'] == 'carried_forward_not_waived_or_requalified' and row['final_acceptance'] == 'incomplete', 'historical capability silently changed or accepted')
        baseline = json.loads(documents['tests/public-beta/acceptance-mapping.json'])
        require(beta['core_cell_ids'] == [r['id'] for r in baseline['core_cells']] and beta['paper_criterion_ids'] == [r['criterion_id'] for r in baseline['paper_criteria']], 'beta requirement identity substituted')
        supplemental = json.loads(documents['tests/public-beta/execution/w12-review/requirements.json'])['supplemental']
        require(beta['supplemental_ids'] == sorted(supplemental), 'supplemental requirement identity substituted')
        owner_roles = json.loads(documents['tests/public-beta/owners.json'])['roles']
        require(len(data['roles']) == len(owner_roles) and {r['id'] for r in data['roles']} == {r['id'] for r in owner_roles}, 'role coverage differs')
        for row in data['roles']:
            expected = next(r for r in owner_roles if r['id'] == row['id'])
            require(row['assignment_state'] == expected['assignment_state'] and row['responsibility'] == expected['responsibility'],
                    'role assignment or responsibility invented')
    return {'protocol': 'symphony.distribution.s08-dossier-validation.v1', 'status': 'bindings_consistent',
            'core_source_checked': source is not None, 'candidate_rebuild_bound': rebuild is not None,
            'source_export_bound': source_export is not None,
            'hosted_status_bound': hosted_status is not None,
            'core_profiles': 4, 'go_units': 7, 'd05_requirements': 30,
            'retained_beta_cells': 36, 'retained_paper_criteria': 58, 'retained_supplemental_requirements': 31,
            'release_acceptance_complete': False, 'publication_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dossier', type=Path, default=ROOT / 'dossier/s08-dossier.json')
    parser.add_argument('--require-rebuild', action='store_true')
    parser.add_argument('--require-source-export', action='store_true')
    parser.add_argument('--require-hosted-status', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(validate_document(read(args.dossier), source=args.source, require_rebuild=args.require_rebuild,
                                          require_source_export=args.require_source_export,
                                          require_hosted_status=args.require_hosted_status), sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Dossier validation refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
