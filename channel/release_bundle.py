#!/usr/bin/env python3
"""Assemble a new public beta release from exact completed hosted qualifications.

No upload, signing, installation, source merge or acceptance impersonation is
performed. The private request is never included in the public bundle.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'channel'), str(ROOT/'installer_assembly')]
import beta_publish as publisher
import beta_signing as signing
import beta as assembler
import verify_beta as verifier
from qualification import beta_artifacts as transport

c, fs = publisher.c, signing.base
PROTOCOL = 'symphony.distribution.beta-release-bundle.v1'
REQUEST = 'symphony.distribution.beta-release-request.v1'
LINEAGE = ('profile', 'source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256',
    'build_result_sha256', 'round_sha256', 'payload_inventory_sha256', 'native_capsule_sha256',
    'native_archive_sha256', 'sdk_closure_sha256', 'original_delivery_record_sha256')
UNIT_PASS = ('absent_removal_idempotent', 'aliased_receipt_refused', 'changed_owned_bytes_refused',
    'empty_version_preflight_passed', 'immutable_reinstall_refused', 'interrupted_removal_resumed',
    'managed_root_marker_presence_refused', 'other_package_and_user_bytes_preserved', 'same_candidate_restoration_exact')


def raw(path, expected=None):
    value = c.bounded(fs.regular(Path(path)))[0]
    if expected is not None: c.require(c.sha(value) == c.digest(expected), 'Selected release input changed')
    return value


def doc(path, expected=None): return signing.strict_json(raw(path, expected))


def admit_transport(value, role, profile):
    c.require(type(value) is dict and set(value) == {'root', 'selection', 'selection_sha256'}, 'Exact hosted input selection required')
    root = fs.plain(value['root']); selected = transport.validate_selection(Path(value['selection']), value['selection_sha256'])
    c.require(selected['profile'] == profile and set(selected['artifacts']) == {role}, 'Hosted input profile or role differs')
    proof = transport.admit(root, Path(value['selection']), value['selection_sha256'])
    folder = root/'artifacts'/role; pin = selected['artifacts'][role]['result_sha256']
    name = {'maintenance': 'd13-maintenance/result.json', 'native_pkg': 'd14-pkg-public/result.json'}.get(role, 'result.json')
    value = doc(folder/name, pin)
    return folder, value, {'selection_sha256': proof['selection_sha256'], 'selection': selected,
        'github_observation': proof['artifacts'][role]['github_observation']}


def maintenance(record, beta, cohort, cohort_root, selected):
    c.require(record['protocol'] == 'symphony.distribution.retained-native-maintenance.v1' and
        record['state'] == 'primary_retained_native_disposable_owner_campaign_passed' and
        record['profile'] == beta['profile'] and record['native_unit_count'] == 51 and
        all(record[k] is True for k in ('retained_payload_unchanged', 'original_artifacts_unchanged', 'caller_state_preserved')) and
        all(record['lineage'][key] == beta['original_native_lineage'][key] for key in LINEAGE), 'Native maintenance lineage or completion differs')
    c.require(record['qualification_toolkit']['commit'] == selected['selection']['artifacts']['maintenance']['workflow_commit'],
              'Native maintenance toolkit differs from hosted selection')
    units = record['units']; by_id = {unit['component_id']: unit for unit in units}
    native = [entry for entry in cohort['entries'] if entry['kind'] == 'native_receipt_unit']
    c.require(len(by_id) == len(units) == len(native) == 51 and set(by_id) == {entry['component_id'] for entry in native},
              'Native maintenance owner coverage differs')
    for entry in native:
        unit, _ = c.validate_recipe(cohort_root, entry)
        receipt = next(row for row in unit['files'] if row['path'] ==
            f"share/symphony/receipts/{entry['component_id']}/{entry['native_version']}/install-receipt.json")
        observed = by_id[entry['component_id']]
        c.require(observed['version'] == entry['native_version'] and observed['receipt_sha256'] == receipt['sha256'] and
            all(observed[key] is True for key in UNIT_PASS), 'One native owner campaign or exact receipt differs')


def native_pkg(record, beta, cohort, wrapper, selected):
    pkg = next(row for row in wrapper['wrappers'] if row['format'] == 'pkg')
    c.require(record['protocol'] == 'symphony.distribution.native-pkg-qualification.v1' and
        record['state'] == 'native_pkg_install_and_named_carrier_removal_passed' and
        record['profile'] == beta['profile'] == 'macos15-arm64' and record['carrier_count'] == 59 and
        record['linked_file_count'] == 177 and record['pkg_sha256'] == pkg['sha256'] and
        record['cohort_digest'] == cohort['cohort_digest'] and record['cohort_sha256'] == beta['cohort_sha256'] and
        record['wrapper_result_sha256'] == beta['wrappers_result_sha256'] and
        record.get('account_context') == {'current_user_home': True, 'real_and_effective_uid_match': True,
            'root_execution': False} and
        all(record[key] is True for key in ('native_pkg_executed', 'all_named_carriers_removed',
            'caller_configuration_preserved', 'user_and_outside_sentinels_preserved', 'wrapper_support_files_preserved', 'original_inputs_unchanged')) and
        all(record[key] is False for key in ('system_trust_changed', 'gatekeeper_bypassed', 'apple_developer_id', 'notarized')),
        'Final native PKG qualification differs or is incomplete')
    c.require(record['executing_toolkit']['commit'] == selected['selection']['artifacts']['native_pkg']['workflow_commit'],
              'Native PKG toolkit differs from hosted selection')


def explicit(rows):
    # Conda's selected explicit parser supports #sha256:<64>, with no solver.
    return ('@EXPLICIT\n' + ''.join(publisher.url(row) + '#sha256:' + row['sha256'] + '\n' for row in rows)).encode()


def assemble(request_path, request_sha256, output, openssl):
    helper_sha = fs.digest(Path(__file__))
    verifier_raw = raw(ROOT/'channel/verify_beta.py')
    request_path = fs.regular(request_path); request_raw = raw(request_path, request_sha256)
    request = signing.strict_json(request_raw)
    c.require(set(request) == {'protocol', 'release', 'profiles', 'native_pkg', 'publisher_decision',
        'public_certificate', 'privacy_policy', 'additional_documents'} and
        request['protocol'] == REQUEST and request['release'] == signing.RELEASE and
        set(request['profiles']) == set(publisher.PROFILES), 'Complete four-profile release request required')
    for key in ('publisher_decision', 'public_certificate'):
        c.require(set(request[key]) == {'path', 'sha256'}, 'Explicit release identity input required')
    decision_raw = raw(request['publisher_decision']['path'], signing.DECISION)
    c.require(request['publisher_decision']['sha256'] == signing.DECISION, 'Publisher decision differs')
    decision = signing.strict_json(decision_raw)
    c.require(decision['release_class'] == 'public-beta' and decision['release_version'] == signing.RELEASE and
        set(decision['profiles']) == set(publisher.PROFILES) and
        all(decision[key] is True for key in ('legal_approval', 'publisher_acceptance', 'publication_authorized')) and
        decision['acceptance_basis']['publisher_direct_approval'] is True and
        decision['acceptance_basis']['separate_reviewer_independence_established'] is False,
        'Bound publisher beta acceptance differs')
    certificate_raw = raw(request['public_certificate']['path'], verifier.CERTIFICATE_SHA256)
    c.require(request['public_certificate']['sha256'] == verifier.CERTIFICATE_SHA256, 'Release verifier certificate differs')
    signing.certificate(openssl, Path(request['public_certificate']['path']), verifier.CERTIFICATE_SHA256, verifier.PUBLIC_KEY_SHA256)
    policy = fs.regular(request['privacy_policy']); policy_sha = fs.digest(policy)
    scanner = c.load_module('beta_bundle_privacy', ROOT/'source-export/export_source.py'); scanner.configure_policy(policy)
    admitted = {}
    for profile, inputs in sorted(request['profiles'].items()):
        c.require(set(inputs) == {'beta', 'maintenance'}, 'Complete profile input roles required')
        beta_root, beta, beta_selected = admit_transport(inputs['beta'], 'beta', profile)
        verified, cohort, _ = assembler.admit_candidate(beta_root, beta_selected['selection']['artifacts']['beta']['result_sha256'])
        c.require(beta == verified and beta['publisher_decision_sha256'] == signing.DECISION, 'Final beta owner admission differs')
        maintenance_root, maintained, maintenance_selected = admit_transport(inputs['maintenance'], 'maintenance', profile)
        maintenance(maintained, beta, cohort, beta_root/'carriers', maintenance_selected)
        wrapper = doc(beta_root/'wrappers/result.json', beta['wrappers_result_sha256'])
        admitted[profile] = (beta_root, beta, cohort, wrapper, maintained, beta_selected, maintenance_selected)
    pkg_root, pkg_result, pkg_selected = admit_transport(request['native_pkg'], 'native_pkg', 'macos15-arm64')
    mac = admitted['macos15-arm64']; native_pkg(pkg_result, mac[1], mac[2], mac[3], pkg_selected)
    docs = []
    c.require(type(request['additional_documents']) is list and len(request['additional_documents']) <= 32, 'Invalid extra release documents')
    for item in request['additional_documents']:
        c.require(set(item) == {'source', 'path', 'sha256'}, 'Explicit extra document identity required')
        signing.relative(item['path']); c.require(item['path'].startswith('docs/') and item['path'].endswith(('.md', '.txt', '.json')),
            'Extra documentation must remain under docs')
        docs.append((item['path'], raw(item['source'], item['sha256'])))
    output = fs.plain(output)
    protected = [ROOT, request_path, policy, Path(request['public_certificate']['path']), Path(request['publisher_decision']['path'])]
    protected += [fs.plain(inputs[role]['root']) for inputs in request['profiles'].values() for role in ('beta', 'maintenance')]
    protected += [pkg_root, *[Path(item['source']) for item in request['additional_documents']]]
    c.require(all(output != path and output not in path.parents and path not in output.parents for path in protected),
              'Release output must be separate from source and selected evidence')
    output = fs.new_directory(output); inventory = {}; casefold = set()
    def put(name, data, *, opaque=False):
        signing.relative(name); c.require(name.casefold() not in casefold, 'Duplicate release artifact path')
        c.require(len(inventory) < 1023, 'Public release exceeds signing artifact bound')
        if not opaque: scanner.scan(name, data)
        target = output/name; target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fs.write(target, data, 0o644); casefold.add(name.casefold())
        inventory[name] = {'path': name, 'sha256': c.sha(data), 'size': len(data)}
        return inventory[name]
    def copy(name, path, expected=None, *, opaque=False): return put(name, raw(path, expected), opaque=opaque)
    packages, profiles, gate_counts = [], {}, {}
    put('publisher-decision.json', decision_raw); put('identity/beta-cert.pem', certificate_raw)
    put('verify_beta.py', verifier_raw)
    for name, value in docs: put(name, value)
    for profile, (base, beta, cohort, wrapper, maintained, selected, maintenance_selected) in admitted.items():
        optional = c.document(base/'source/carrier/cohort.json'); c.check_seal(optional)
        c.require(len(optional['archives']) == 1 and optional['base_carrier_cohort_digest'] == cohort['cohort_digest'] and
            optional['cohort_digest'] == beta['optional_source_cohort_digest'], 'Source carrier cohort differs')
        default_rows = []
        for selection, rows, folder in [('default', cohort['archives'], base/'carriers'),
                                       ('optional-source', optional['archives'], base/'source/carrier')]:
            for row in rows:
                name = 'packages/' + profile + '/' + row['filename']
                copied = copy(name, folder/'channel'/row['subdir']/row['filename'], row['sha256'], opaque=True)
                c.require(copied['size'] == row['size'], 'Copied Conda size differs')
                package = {k: row[k] for k in ('name', 'version', 'build', 'build_number', 'subdir', 'filename', 'sha256', 'size')}
                package.update(profile=profile, path=name, selection=selection); packages.append(package)
                if selection == 'default': default_rows.append(package)
                else: put('setup/'+profile+'/optional-source-explicit.txt', explicit([package]))
                put('setup/'+profile+'/units/'+row['name']+'.txt', explicit([package]))
        c.require(len(default_rows) == 59, 'Final default package count differs')
        put('setup/'+profile+'/default-explicit.txt', explicit(default_rows))
        for name in ('symphony-retain.py', 'BOOTSTRAP-INDEX.json', 'COHORT.json'):
            copy('setup/'+profile+'/'+name, base/'setup'/name)
        source = doc(base/'source/source-index.json', beta['source_index_sha256']); source_row = source['archive']
        copy('source/'+profile+'/'+source_row['filename'], base/'source'/source_row['filename'], source_row['sha256'], opaque=True)
        copy('source/'+profile+'/source-index.json', base/'source/source-index.json', beta['source_index_sha256'])
        for row in wrapper['wrappers']:
            copied = copy('installers/'+profile+'/'+row['filename'], base/'wrappers'/row['filename'], row['sha256'], opaque=True)
            c.require(copied['size'] == row['size'], 'Copied installer size differs')
        client_report = doc(base/'provenance/client/result.json', beta['input_artifacts']['client']['result_sha256'])
        journey_report = doc(base/'provenance/carrier-journeys.json', beta['carrier_journeys_sha256'])
        c.require(client_report['actual_codex_cases'] == 22 and journey_report['transaction_count'] == 182 and
            beta['shell_qualification']['state'] == 'installed_refusals_and_named_removal_passed' and
            beta['retention_qualification']['state'] == 'installed_retention_and_read_only_entrypoints_passed' and
            beta['retention_qualification']['retained_after_carrier_removal'] is True,
            'Supported beta gate completion differs')
        gate_counts[profile] = {'default_carrier_packages': len(default_rows), 'optional_source_packages': len(optional['archives']),
            'codex_cases': client_report['actual_codex_cases'], 'native_owner_receipts': maintained['native_unit_count'],
            'carrier_packaging_revision_transactions': journey_report['transaction_count'],
            'shell_install_and_removal_profiles': 1, 'first_run_retention_profiles': 1}
        evidence = 'evidence/'+profile+'/'
        copy(evidence+'beta-qualification.json', base/'result.json', selected['selection']['artifacts']['beta']['result_sha256'])
        copy(evidence+'client-qualification.json', base/'provenance/client/result.json', beta['input_artifacts']['client']['result_sha256'])
        copy(evidence+'carrier-journeys.json', base/'provenance/carrier-journeys.json', beta['carrier_journeys_sha256'])
        copy(evidence+'native-maintenance.json', Path(request['profiles'][profile]['maintenance']['root'])/'artifacts/maintenance/d13-maintenance/result.json',
            maintenance_selected['selection']['artifacts']['maintenance']['result_sha256'])
        put(evidence+'hosted-selections.json', fs.canonical({'beta': selected, 'maintenance': maintenance_selected}))
        profiles[profile] = {'conda_subdir': cohort['conda_subdir'], 'cohort_digest': cohort['cohort_digest'],
            'cohort_sha256': beta['cohort_sha256'], 'beta_result_sha256': selected['selection']['artifacts']['beta']['result_sha256'],
            'client_result_sha256': beta['input_artifacts']['client']['result_sha256'],
            'maintenance_result_sha256': maintenance_selected['selection']['artifacts']['maintenance']['result_sha256'],
            'retention_index_sha256': wrapper['retention_index_sha256'], 'retention_helper_sha256': wrapper['retention_helper_sha256'],
            'default_explicit': 'setup/'+profile+'/default-explicit.txt', 'optional_source_explicit': 'setup/'+profile+'/optional-source-explicit.txt',
            'source_binding': {k: beta['original_native_lineage'][k] for k in ('source_commit', 'source_tree', 'source_export_digest')},
            'client_sources': beta['client_sources']}
    copy('evidence/native-pkg-qualification.json', pkg_root/'d14-pkg-public/result.json',
        pkg_selected['selection']['artifacts']['native_pkg']['result_sha256'])
    put('evidence/native-pkg-selection.json', fs.canonical(pkg_selected))
    c.require(len(packages) == 240 and len(profiles) == 4, 'Incomplete final public package set')
    acceptance = {'scope': 'initial-public-beta', 'engineering_qualification_complete': True,
        'publisher_legal_approval': decision['legal_approval'], 'publisher_acceptance': decision['publisher_acceptance'],
        'publisher_decision_sha256': signing.DECISION, 'separate_reviewer_independence_claimed': False,
        'historical_qualification_records_preserved': True, 'per_profile_supported_gates': gate_counts,
        'supported_gate_counts': {'profiles': len(profiles), 'native_pkg_install_and_removal_profiles': 1,
            **{key: sum(row[key] for row in gate_counts.values()) for key in next(iter(gate_counts.values()))}},
        'recognized_apple_trust_claimed': False, 'distinct_native_version_upgrade_qualified': False,
        'distinct_native_version_rollback_qualified': False}
    index = {'protocol': PROTOCOL, 'release': signing.RELEASE, 'state': 'qualified_public_beta_bundle_prepared',
        'publisher_decision_sha256': signing.DECISION, 'certificate_sha256': verifier.CERTIFICATE_SHA256,
        'public_key_sha256': verifier.PUBLIC_KEY_SHA256, 'profiles': profiles, 'conda_packages': packages,
        'public_downloads': sorted([name for name in inventory if not name.endswith('.conda')] + ['release-index.json'],
            key=lambda name: (0 if name.startswith('source/') else 1 if name.startswith('installers/') else 2, name)),
        'artifacts': sorted(inventory.values(), key=lambda row: row['path']), 'private_request_sha256': request_sha256, 'beta_acceptance': acceptance,
        'bundle_helper_sha256': helper_sha, 'publication_performed': False, 'signature_performed': False,
        'apple_developer_id': False, 'notarized': False, 'independent_separate_reviewer_claimed': False,
        'main_modified': False, 'feature_freeze_preserved': True}
    # Re-admission proves selected artifacts did not change during copies; public
    # reports remain original evidence, never rewritten as new qualifications.
    for profile, inputs in request['profiles'].items():
        for role in ('beta', 'maintenance'): admit_transport(inputs[role], role, profile)
    admit_transport(request['native_pkg'], 'native_pkg', 'macos15-arm64')
    c.require(fs.digest(Path(__file__)) == helper_sha and raw(ROOT/'channel/verify_beta.py') == verifier_raw and
        raw(request_path) == request_raw and fs.digest(policy) == policy_sha and
        raw(request['publisher_decision']['path']) == decision_raw and raw(request['public_certificate']['path']) == certificate_raw,
        'Release selection inputs changed')
    c.require(signing.artifact_rows(output, [output/name for name in inventory]) == sorted(inventory.values(), key=lambda row: row['path']),
        'Copied release bytes changed')
    put('release-index.json', fs.canonical(index))
    return index


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--request', type=Path, required=True); p.add_argument('--request-sha256', required=True)
    p.add_argument('--output', type=Path, required=True); p.add_argument('--openssl', type=Path, required=True)
    a = p.parse_args(); result = assemble(a.request, a.request_sha256, a.output, a.openssl)
    print(json.dumps({'state': result['state'], 'release': result['release'], 'packages': len(result['conda_packages']),
        'public_downloads': len(result['public_downloads'])}))


if __name__ == '__main__': main()
