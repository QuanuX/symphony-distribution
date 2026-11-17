#!/usr/bin/env python3
"""Refresh the external S08 dossier from exact core and distribution evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE_PATHS = (
    'tests/public-beta/dossier.json', 'tests/public-beta/capability-groups.json',
    'tests/public-beta/package-plan.json', 'tests/public-beta/owners.json',
    'tests/public-beta/paper-criteria.json', 'tests/public-beta/acceptance-mapping.json',
    'tests/public-beta/execution/W12-REVIEW.md',
    'tests/public-beta/execution/w12-review/requirements.json',
    'cmake/mvp-dependencies.json', 'cmake/mvp-release-identities.json',
    'cmake/mvp-platform-profiles.json', 'cmake/mvp-go-owner-closure.json',
)
LOCAL_PATHS = ('source-binding.json', 'go-owner-catalog.json',
    'evidence/s06-local-qualification.json', 'evidence/go-candidate-closure.json',
    'evidence/s07-conda-local-qualification.json', 'evidence/s07-native-local-qualification.json',
    'evidence/s07-local-platform.json', 'dossier/d05-requirements.json')
CORE_PROFILES = ('macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64')
LIMITS = {
    1: 'Canonical scope source exists; this supplement does not rerun the complete native/Go parity matrix.',
    2: 'Direct native scope enforcement remains source-bound; final delivered-owner acceptance is open.',
    3: 'Unrelated profile effects remain outside authorization; final complete user-profile journeys are open.',
    4: 'Exact effect identity must survive replanning; fresh-host progression remains unaccepted.',
    5: 'Unapproved dependencies remain blockers; no automatic authorization or selection.',
    6: 'Unknown/adopted/shared ownership remains blocked; fixture evidence is bounded.',
    7: 'Scoped effect completion is not full profile convergence or selection.',
    8: 'Legacy and incompatible reader/recovery paths remain distinct; no new universal compatibility claim.',
    9: 'Private creator/process and whole-execution lease evidence does not cover arbitrary existing Conda clients.',
    10: 'Covered real-child leases do not establish shutdown for every actual supervisor or raw consumer.',
    11: 'Restart injection at each reference-scan, stop-completion and first-delete boundary remains incomplete.',
    12: 'Uncontrolled/legacy launch paths cannot acquire managed custody by inference.',
    13: 'Actual stale/reused process identity and inaccessible user-domain behavior need supported-host evidence.',
    14: 'Detached/escaped descendant lifetime is not qualified; uncertain use retains bytes.',
    15: 'Completed native response loss is observed; mid-operation response loss and every actual native stop/delete crash point remain open.',
    16: 'Damaged/replaced custody safely refuses; refusal is not a universal repair or successful removal claim.',
    17: 'Complete foreign-claim release and real process release are independent prerequisites.',
    18: 'Executing/recovery/audit substrates remain protected; unresolved Accordare audit recovery is open.',
    19: 'Three exact native dispatch routes exist; remaining C++/raw consumers require their real owners.',
    20: 'Seven Go deliveries are catalogued; unknown owner/version/arguments have no fallback route.',
    21: 'Fresh stopped installations are E1; no enrollment, host activation or fresh-host acceptance is inferred.',
    22: 'Two packaging builds do not constitute two distinct compatible native releases.',
    23: 'Raw executable custody is not a native receipt; future selection does not stop current sessions.',
    24: 'Full final-byte qxctl selection and host-slot rollback journeys remain open.',
    25: 'Conda carries inert administrator bytes; privileged host provisioning and replacement remain separate.',
    26: 'Only fresh private attempts are supported; external/shared prefixes are not adopted.',
    27: 'Distinct-release native upgrade, explicit selection and rollback acceptance remain open.',
    28: 'Sentinel preservation is fixture evidence; all user data on unexamined systems is not accepted.',
    29: 'Hosted fixtures, actual manager/privilege domains and fresh-host acceptance require separate evidence.',
    30: 'S08 candidate binding is preparation; signatures, real retrieval, independent review and publication remain open.',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text())


def build(source, rebuild_report=None, source_export_report=None, hosted_status_report=None, *, fresh_candidate=False):
    binding = load(ROOT / 'source-binding.json')
    if fresh_candidate and any((rebuild_report, source_export_report, hosted_status_report)):
        raise ValueError('Fresh candidate preparation cannot reuse qualification reports')
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-C', str(source), *args], timeout=30)
    if git('rev-parse', 'HEAD').decode().strip() != binding['source_commit'] or git('rev-parse', 'HEAD^{tree}').decode().strip() != binding['source_tree']:
        raise ValueError('exact bound clean core source required')
    if git('status', '--porcelain=v1', '--untracked-files=all').strip():
        raise ValueError('core checkout must be clean')
    core = {p: git('show', binding['source_commit'] + ':' + p) for p in CORE_PATHS}
    old = json.loads(core['tests/public-beta/dossier.json'])
    groups = json.loads(core['tests/public-beta/capability-groups.json'])['groups']
    beta = json.loads(core['tests/public-beta/acceptance-mapping.json'])
    requirements = json.loads(core['tests/public-beta/execution/w12-review/requirements.json'])
    catalog = load(ROOT / 'go-owner-catalog.json')
    native = load(ROOT / 'evidence/s07-native-local-qualification.json')
    conda = load(ROOT / 'evidence/s07-conda-local-qualification.json')
    local_files = [{'path': p, 'sha256': sha((ROOT / p).read_bytes())} for p in LOCAL_PATHS]
    rebuild = None
    if rebuild_report:
        report_path = rebuild_report.resolve(strict=True)
        relative = report_path.relative_to(ROOT.resolve()).as_posix()
        report = load(report_path)
        if report.get('protocol', report.get('schema')) != 'symphony.distribution.s08-candidate-rebuild.v1':
            raise ValueError('unrecognized candidate rebuild report')
        rebuild = {'path': relative, 'sha256': sha(report_path.read_bytes()),
                   'interpretation': 'Exact candidate reconstruction evidence; not final-download, signature, live-owner or release acceptance.'}
    source_export = None
    if source_export_report:
        report_path = source_export_report.resolve(strict=True)
        relative = report_path.relative_to(ROOT.resolve()).as_posix()
        report = load(report_path)
        if report.get('protocol') != 'symphony.distribution.s08-source-export.v1':
            raise ValueError('unrecognized source export report')
        source_export = {'path': relative, 'sha256': sha(report_path.read_bytes()),
                         'interpretation': 'Reviewed derived source export with original-blob verification and explicit map rebindings; no all-root build, publisher-trust or release acceptance.'}
    hosted_status, hosted_profiles = None, {}
    if hosted_status_report:
        report_path = hosted_status_report.resolve(strict=True)
        relative = report_path.relative_to(ROOT.resolve()).as_posix()
        report = load(report_path)
        if report.get('protocol') != 'symphony.distribution.s07-hosted-status.v1':
            raise ValueError('unrecognized hosted status snapshot')
        hosted_status = {'path': relative, 'sha256': sha(report_path.read_bytes()),
                         'interpretation': 'Observed completed S07 CI at the recorded historical head; no later run, final-host or release acceptance inferred.'}
        hosted_profiles = {row['profile']: row for row in report['profiles']}
    acceptance = []
    for row in load(ROOT / 'dossier/d05-requirements.json')['requirements']:
        cases = []
        for suite in native['suites']:
            for case in suite['cases']:
                if row['id'] in case['acceptance']:
                    cases.append({'evidence': 'evidence/s07-native-local-qualification.json',
                                  'suite': suite['id'], 'test': case['test'], 'expected': case['expected']})
        for case in native['completed_native_response_loss']:
            if row['id'] in case['acceptance']:
                cases.append({'evidence': 'evidence/s07-native-local-qualification.json',
                              'case': case['id'], 'expected': case['expected']})
        conda_cells = {9, 15, 16, 26, 28}
        if int(row['id'][-2:]) in conda_cells:
            cases.append({'evidence': 'evidence/s07-conda-local-qualification.json',
                          'scope': 'new_private_attempts_only; real Conda with inert carriers',
                          'expected': 'Exact reviewed carrier effects or safe refusal; unrelated data and uncertain attempts retained.'})
        acceptance.append({**row, 'engineering_evidence': 'bounded_E1_recorded' if cases else 'source_or_prior_increment_not_requalified_by_S07',
                           'evidence_refs': cases, 'final_acceptance': 'incomplete',
                           'remaining_limit': LIMITS[int(row['id'][-2:])]})
    units = []
    for row in catalog['units']:
        units.append({k: row[k] for k in ('component_id', 'binary_name', 'native_version', 'conda_name', 'conda_version',
                     'source_root', 'owner_contract', 'runtime_owner_kind', 'selection_owner', 'runtime_receipt',
                     'definition_digest', 'owner_invocation_implemented')})
        units[-1].update({'payload_files': [row['binary_name'], 'artifact-identity.json', 'LICENSE-AGPL-3.0', 'carrier-manifest.json'],
                         'runtime_dependencies': [], 'runtime_python_required': False,
                         'automatic_activation': False, 'automatic_privilege': False,
                         'system_removal_qualified': False, 'live_raw_cleanup_supported': False,
                         'supported_profiles': []})
    roles = []
    for row in json.loads(core['tests/public-beta/owners.json'])['roles']:
        roles.append({'id': row['id'], 'assignment_state': row['assignment_state'],
                      'assignment_reference': 'tests/public-beta/owners.json#' + row['id'],
                      'responsibility': row['responsibility'], 'new_assignment_made': False})
    result = {
        'protocol': 'symphony.distribution.s08-dossier.v1', 'prepared_on': '2026-11-16',
        'state': 'source_bound_distribution_supplement_release_incomplete',
        'core_source': {k: binding[k] for k in ('source_commit', 'source_tree', 'binding_digest')},
        'historical_core_dossier': {'path': 'tests/public-beta/dossier.json', 'declared_source_commit': old['source_commit'],
             'declared_source_tree': old['source_tree'], 'interpretation': 'Historical W01/W06 preparation. Later explicit user continuation and distribution decisions govern this supplement; original approval/acceptance fields are not rewritten.'},
        'feature_freeze': {'in_force': True, 'new_features_authorized': False, 'core_changed_by_S08': False},
        'release_acceptance_complete': False, 'publication_authorized': False, 'supported_profiles': [],
        'source_documents': [{'path': p, 'sha256': sha(core[p])} for p in CORE_PATHS],
        'distribution_inputs': local_files, 'candidate_rebuild_report': rebuild, 'source_export_report': source_export,
        'hosted_status_report': hosted_status,
        'decisions': {'binary_delivery': 'clean_CI_binaries_selected_local_candidates_are_supplemental',
            'source_sdk_delivery': 'optional_reviewed_source_and_SDK', 'conda_channel': 'QuanuX',
            'downloadable_installer_host': 'Cloudflare_storage_and_website_later',
            'downloadable_installer_formats': ['macOS.pkg', 'Linux.sh'],
            'module_version_policy': 'independent_rolling_versions_no_invented_suite_version',
            'application_selection': 'existing_user_authorized_composition_and_Maestro_contracts; packaging_does_not_select',
            'user_state_policy': 'users_generate_local_state_on_their_own_systems; no_publisher_home_hardware_credentials_or_workflows'},
        'platforms': [{'id': p, 'purpose': 'requested_core_CI_and_final_acceptance_target',
                       'hosted_evidence_in_this_dossier': hosted_profiles.get(p, 'not_collected'), 'fresh_host_acceptance': 'incomplete',
                       'installed_manager_acceptance': 'incomplete', 'release_supported': False} for p in CORE_PROFILES],
        'supplemental_platform': {'id': 'local-macos-amd64-fixture', 'conda_evidence_level': conda['evidence_level'],
            'native_evidence_level': native['evidence_level'], 'final_host_acceptance': 'incomplete',
            'not_a_substitute_for_core_profiles': True},
        'capability_baseline': [{'id': g['id'], 'title': g['title'], 'component_roots': g['component_roots'],
            'historical_implementation_statement': g['implementation_state'],
            'source_reference': 'tests/public-beta/capability-groups.json#' + g['id'],
            's08_disposition': 'carried_forward_not_waived_or_requalified', 'final_acceptance': 'incomplete'} for g in groups],
        'go_delivery_units': units,
        'package_boundary': {'conda_owns': 'four_inert_carrier_files_only',
            'runtime_owns': 'existing_native_or_host_owner; independent_runtime_and_rollback_inodes',
            'tooling_python': 'publisher_and_qualification_only',
            'native_sdk': 'complete_receipt_owned_exports; do_not_split_sealed_receipts_without_owner_review',
            'source_export': 'exact_committed_first_party_source_plus_reviewed_build_install_material; dependency_source_and_rights_separately_reviewed',
            'forbidden_payloads': ['developer_build_trees', 'publisher_home_or_absolute_paths', 'credentials_or_private_keys',
                'user_profiles_or_journals', 'host_bindings_or_custody', 'licensed_vendor_bytes_without_rights', 'automatic_activation_hooks']},
        'trust': {'archive_hash': 'integrity_and_identity_only_not_publisher_authority',
            'publisher_signing_identity': None, 'independent_public_trust_policy': None,
            'native_macos_signing_notarization': 'pending_for_final_pkg_and_applicable_bundles',
            'linux_installer_integrity_and_trust': 'pending_for_final_download',
            'anaconda_upload_rights': 'user_confirmed_organization_owner_or_coowner; no_token_in_repository',
            'redistribution_review': 'pending_actual_runtime_dependency_source_notices_and_vendor_payload_review',
            'credentials_in_git': False, 'final_retrieval_verified': False, 'signing_or_publication_performed': False},
        'roles': roles,
        'retained_beta_requirements': {'core_cell_ids': [c['id'] for c in beta['core_cells']],
            'paper_criterion_ids': [c['criterion_id'] for c in beta['paper_criteria']],
            'supplemental_ids': sorted(requirements['supplemental']),
            'replaced_by_D05_supplement': False, 'scores_assessed': False, 'final_acceptance': 'incomplete'},
        'd05_safety_acceptance': acceptance,
        'completion_boundary': 'S08 documentation/candidate preparation does not close S07 E2, D06 clean CI cohort, D10 final-download or W12 release gates.'}

    if fresh_candidate:
        historical = ROOT / 'dossier/history/s08-beta1.json'
        prior = load(historical)
        result.update(state='fresh_candidate_qualification_pending', prepared_on='2026-11-17',
            evidence_scope={'current_candidate_qualified': False,
                'historical_dossier': {'path': 'dossier/history/s08-beta1.json', 'sha256': sha(historical.read_bytes())},
                'historical_core_source': prior['core_source']},
            completion_boundary='Fresh source binding only. Historical E1 and beta1 evidence do not qualify these new bytes; rebuild, installed-client, maintenance and final-delivery qualification remain pending.')
        for row in result['d05_safety_acceptance']:
            row['engineering_evidence'] = 'historical_only_not_current_candidate_qualification'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--fresh-candidate', action='store_true')
    parser.add_argument('--rebuild-report', type=Path)
    parser.add_argument('--source-export-report', type=Path)
    parser.add_argument('--hosted-status-report', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'dossier/s08-dossier.json')
    args = parser.parse_args()
    args.output.write_text(json.dumps(build(args.source, args.rebuild_report, args.source_export_report, args.hosted_status_report, fresh_candidate=args.fresh_candidate), indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
