#!/usr/bin/env python3
"""Bind a review packet; never grant legal, integration, or release approval."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

PROTOCOL = 'symphony.distribution.d09-acceptance-preparation.v1'
DOCUMENTS = {'core_delivery', 'qxctl_source', 'client_packet', 'corresponding_source',
             'wrapper_audit', 'review_manifest', 'pr_snapshot'}
ROLES = ('source_integration_owner', 'redistribution_reviewer', 'independent_payload_reviewer',
         'independent_trust_reviewer', 'independent_acceptance_reviewer', 'backup_reviewer', 'release_approver')
REPOSITORIES = {'core': 'QuanuX/Symphony', 'client': 'QuanuX/symphony-codex-ipc-mcp-and-skills',
                'distribution_toolkit': 'QuanuX/symphony-distribution'}
MAX_DOCUMENT = 32 * 1024 ** 2


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_digest(value, length=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'invalid digest')
    return value


def relative(name):
    require(isinstance(name, str) and name and not PurePosixPath(name).is_absolute() and
            '\\' not in name and all(part not in ('', '.', '..') for part in name.split('/')) and
            all(32 <= ord(c) < 127 for c in name), 'unsafe evidence path')
    return name


def custody(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'linked evidence path')
    return path


def read(path):
    path = custody(path)
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= MAX_DOCUMENT,
            'missing or oversized regular evidence')
    raw = path.read_bytes()
    require(len(raw) <= MAX_DOCUMENT, 'evidence exceeds bound')
    return raw


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def selected_documents(selection, evidence_root):
    require(selection.get('protocol') == 'symphony.distribution.d09-review-selection.v1' and
            set(selection.get('documents', {})) == DOCUMENTS, 'incomplete selected evidence set')
    loaded, bindings = {}, {}
    paths = set()
    for role, row in sorted(selection['documents'].items()):
        require(set(row) == {'path', 'sha256'}, 'invalid selected document binding')
        name = relative(row['path']); require(name not in paths, 'repeated selected evidence path'); paths.add(name)
        raw = read(custody(evidence_root) / name)
        require(sha(raw) == exact_digest(row['sha256']), 'selected evidence digest differs')
        loaded[role] = document(raw)
        bindings[role] = {'path': name, 'sha256': sha(raw), 'size': len(raw)}
    return loaded, bindings


def source_pair(selection, docs):
    expected = {'core_delivery': ('protocol', 'symphony.distribution.d06-delivery-record.v1'),
                'qxctl_source': ('protocol', 'symphony.distribution.qxctl-original-source.v1'),
                'client_packet': ('schema', 'symphony.distribution.client-final-packet.v1'),
                'corresponding_source': ('protocol', 'symphony.distribution.d08-corresponding-source.v1')}
    for role, (key, value) in expected.items():
        require(docs[role].get(key) == value and docs[role].get('publication_authorized') is False,
                'unsupported source evidence or authority claim')
    sources = selection.get('sources', {})
    require(set(sources) == set(REPOSITORIES), 'source pair/toolkit selection incomplete')
    for role, repository in REPOSITORIES.items():
        row = sources[role]
        require(set(row) == {'repository', 'commit', 'tree'} and row['repository'] == repository, 'source repository differs')
        exact_digest(row['commit'], 40); exact_digest(row['tree'], 40)
        actual = docs['corresponding_source']['source_bindings'][role]
        require(all(actual[k] == row[k] for k in ('commit', 'tree')), 'corresponding source identity differs')
    delivery = docs['core_delivery']; source = delivery['source']
    require(source['origin_commit'] == sources['core']['commit'] and source['origin_tree'] == sources['core']['tree'],
            'delivery/core identity differs')
    require(source['mode'] == 'verified_derived_public_export' and source['verification']['verified'] is True,
            'reviewed derived source proof required')
    exact_digest(source['derived_export_digest'])
    client = docs['client_packet']
    require(client['sources']['core'] == sources['core'] and client['sources']['plugin'] == sources['client'],
            'client source pair differs')
    qxctl = docs['qxctl_source']
    require(all(qxctl['original_source'][k] == sources['core'][k] for k in ('commit', 'tree')) and
            qxctl['compiled_input_equivalence']['original_matches_cohort_source'] is True and
            qxctl['cohort_source']['export_digest'] == source['derived_export_digest'] and
            qxctl['cohort_source']['is_original_git_tree'] is False and
            qxctl['state'] == 'reproducible_stamped_original_git_source',
            'original-source qxctl proof differs')
    require(client['original_git_source_proof_sha256'] == 'sha256:' + selection['documents']['qxctl_source']['sha256'] and
            docs['corresponding_source']['qxctl_source_proof_sha256'] == selection['documents']['qxctl_source']['sha256'],
            'qxctl/source/client proof binding differs')
    require(docs['corresponding_source']['inherited_delivery_record_sha256'] == selection['documents']['core_delivery']['sha256'],
            'source/delivery binding differs')
    return {'sources': sources, 'derived_core_export_digest': source['derived_export_digest'],
            'qxctl_source_kind': 'original_git_component_with_equal_compiled_inputs',
            'core_full_export_kind': 'reviewed_derived_source', 'original_full_tree_reconstruction': False}


def integration_graph(selection, snapshot):
    require(snapshot['protocol'] == 'symphony.distribution.pr-stack-snapshot.v1' and
            snapshot['main_mutated'] is False and snapshot['merge_performed'] is False and
            snapshot['complete_required_check_coverage'] is False, 'invalid snapshot scope')
    rows = snapshot['pull_requests']; require(rows and len(rows) <= 100, 'empty or excessive PR graph')
    ids, heads, branches = set(), set(), {}
    for row in rows:
        repository = row['repository']; require(repository in REPOSITORIES.values(), 'unexpected PR repository')
        key = (repository, row['number']); branch = (repository, row['head'])
        require(key not in ids and branch not in branches, 'duplicate PR identity'); ids.add(key); branches[branch] = row
        exact_digest(row['head_sha'], 40); exact_digest(row['base_sha'], 40)
        require(row['url'] == f'https://github.com/{repository}/pull/{row["number"]}', 'PR URL differs')
        heads.add((repository, row['head_sha']))
    edges, pending = [], []
    for row in rows:
        parent = branches.get((row['repository'], row['base']))
        if parent:
            require(parent['head_sha'] == row['base_sha'], 'PR graph base/head mismatch')
            edges.append({'repository': row['repository'], 'before': parent['number'], 'after': row['number']})
        if row.get('local_base_is_ancestor_of_head') is not True:
            pending.append({'repository': row['repository'], 'pr': row['number'], 'gate': 'exact_base_ancestry_not_verified'})
        for run in row['workflow_runs']:
            if run['status'] != 'completed' or run['conclusion'] != 'success':
                pending.append({'repository': row['repository'], 'pr': row['number'], 'gate': 'observed_workflow_not_successful',
                                'run_id': run['id'], 'status': run['status'], 'conclusion': run['conclusion']})
    require(set(selection.get('selected_pr_heads', {})) == set(REPOSITORIES), 'selected review heads absent')
    for role, repository in REPOSITORIES.items():
        head = exact_digest(selection['selected_pr_heads'][role], 40)
        require((repository, head) in heads, 'selected source review head absent from snapshot')
        if role != 'distribution_toolkit':
            require(head == selection['sources'][role]['commit'], 'candidate source and selected PR head differ')
    # A cyclic branch stack must not produce a plausible integration order.
    for start in branches:
        visited, current = set(), start
        while current in branches:
            require(current not in visited, 'cyclic PR graph'); visited.add(current)
            row = branches[current]; current = (row['repository'], row['base'])
    return {'snapshot_observed_at': snapshot['observed_at'], 'selected_pr_heads': selection['selected_pr_heads'],
            'dependency_edges': edges, 'observed_pending_checks': pending, 'merged': False,
            'required_check_coverage_verified': False, 'integration_authorized': False,
            'remaining': ['Refresh exact refs and complete required checks immediately before an authorized decision.',
                          'Select the final integration strategy without rewriting retained candidate identities.',
                          'Rebuild/rebind changed source identities and rerun affected gates after integration.']}


def notice_inventory(docs, notice_root, bootstrap_root, expected_bootstrap_sha):
    rows = docs['core_delivery']['notices']; require(rows, 'core notice inventory absent')
    seen, verified = set(), []
    for row in rows:
        name = relative(row['path']); require(name not in seen, 'duplicate core notice'); seen.add(name)
        raw = read(custody(notice_root) / name)
        require(sha(raw) == exact_digest(row['sha256']) and len(raw) == row['size'], 'core notice bytes differ')
        verified.append({key: row[key] for key in ('path', 'component', 'scope', 'sha256', 'size')})
    bootstrap_raw = read(custody(bootstrap_root) / 'BOOTSTRAP.json')
    require(sha(bootstrap_raw) == exact_digest(expected_bootstrap_sha), 'bootstrap metadata differs')
    bootstrap = document(bootstrap_raw)
    require(bootstrap['notices'] and bootstrap['role'] == 'installer_bootstrap_and_explicit_carrier_maintenance', 'bootstrap notice scope differs')
    require(all(w['bootstrap_sha256'] == bootstrap['executable_sha256'] for w in docs['wrapper_audit']['wrappers']),
            'wrapper/bootstrap executable binding differs')
    bootstrap_notices, third_party = [], None
    for name, digest in sorted(bootstrap['notices'].items()):
        raw = read(custody(bootstrap_root) / 'bootstrap-notices' / relative(name))
        require(sha(raw) == exact_digest(digest), 'bootstrap notice bytes differ')
        bootstrap_notices.append({'path': name, 'sha256': digest, 'size': len(raw)})
        if name == '3rd-party-licenses.json':
            third_party = document(raw)
    require(isinstance(third_party, dict) and third_party, 'bootstrap bundled-license inventory absent')
    components = []
    for name, row in sorted(third_party.items()):
        require(isinstance(name, str) and name and isinstance(row.get('type'), str) and isinstance(row.get('files'), list),
                'invalid bootstrap component notice')
        require(all(isinstance(f.get('text'), str) for f in row['files']), 'bootstrap notice text absent')
        # Original publisher-local paths remain only in the exact upstream file.
        components.append({'component': name, 'upstream_declared_license': row['type'],
                           'notice_text_sha256': [sha(f['text'].encode()) for f in row['files']],
                           'redistribution_review': 'pending'})
    return {'core_notice_count': len(verified), 'core_notices': verified,
            'bootstrap_metadata_sha256': sha(bootstrap_raw), 'bootstrap_package': bootstrap['package'],
            'bootstrap_notices': bootstrap_notices, 'bootstrap_components': components,
            'bootstrap_component_count': len(components), 'notice_bytes_verified': True,
            'license_applicability_or_compliance_approved': False,
            'pending_reviews': ['Exact bootstrap component source/build/offer and license-exception closure.',
                                'Core, Go, SDK, client, toolkit, upstream and OS/TLS redistribution applicability.',
                                'Corresponding-source availability, directions and retention at the actual delivery route.',
                                'Preserved legal attribution, optional/vendor exclusion rights and complete notice delivery.']}


def build_packet(selection, evidence_root, notice_root, bootstrap_root):
    docs, bindings = selected_documents(selection, evidence_root)
    pairing = source_pair(selection, docs)
    graph = integration_graph(selection, docs['pr_snapshot'])
    manifest = docs['review_manifest']; wrapper = docs['wrapper_audit']
    require(manifest['protocol'] == 'symphony.distribution.review-signature.v1' and
            manifest['publication_authorized'] is False and manifest['release_acceptance_complete'] is False and
            manifest['independent_publisher_authentication'] is False, 'review signature is not release approval')
    require(wrapper['state'] == 'unsigned_wrappers_audited' and wrapper['installer_executed'] is False and
            wrapper['publication_authorized'] is False, 'wrapper scope differs')
    artifacts = {relative(r['name']): r for r in manifest['artifacts']}
    require(len(artifacts) == len(manifest['artifacts']), 'duplicate signed artifact')
    for row in artifacts.values():
        exact_digest(row['sha256'])
        require(type(row['size']) is int and row['size'] >= 0, 'invalid signed artifact size')
    for row in wrapper['wrappers']:
        require(row['filename'] in artifacts and all(artifacts[row['filename']][k] == row[k] for k in ('sha256', 'size')),
                'wrapper absent from selected review signature manifest')
    legal = notice_inventory(docs, notice_root, bootstrap_root, selection['bootstrap_metadata_sha256'])
    packet = {'protocol': PROTOCOL, 'state': 'prepared_independent_decisions_pending',
              'selection_sha256': sha(canonical(selection)), 'evidence': bindings, 'source_binding': pairing,
              'integration': graph, 'redistribution': legal, 'reviewed_artifact_count': len(artifacts),
              'reviewed_artifact_inventory_sha256': sha(canonical(manifest['artifacts'])),
              'roles': [{'role': role, 'reviewer': None, 'status': 'unassigned_pending'} for role in ROLES],
              'pending_delivery_gates': ['approved exact-byte staging/retrieval', 'primary-platform and fresh-host acceptance',
                                         'native lifecycle safety and distinct-release rollback', 'provider/fault/backup/support drills',
                                         'independent publisher trust and applicable Apple signing/notarization'],
              'human_approval_authenticated': False, 'legal_approval': False, 'integration_authorized': False,
              'release_acceptance_complete': False, 'publication_authorized': False, 'main_changed': False}
    packet['packet_digest'] = 'sha256:' + sha(canonical(packet))
    return packet


def verify_decisions(packet, decisions):
    """Check handoff binding only. JSON cannot authenticate a human or independence."""
    seen, records = set(), []
    for row in decisions:
        require(set(row) == {'protocol', 'packet_digest', 'role', 'reviewer', 'reviewer_kind', 'decision', 'review_record_sha256'},
                'invalid human handoff shape')
        require(row['protocol'] == 'symphony.distribution.d09-human-review.v1' and row['packet_digest'] == packet['packet_digest'],
                'human handoff targets a different packet')
        require(row['role'] in ROLES and row['role'] not in seen, 'duplicate or unknown reviewer role'); seen.add(row['role'])
        require(row['reviewer_kind'] == 'human' and isinstance(row['reviewer'], str) and
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{1,100}', row['reviewer']) and
                row['reviewer'].lower() not in ('codex', 'assistant', 'chatgpt', 'astra'), 'named human reviewer required')
        require(row['decision'] in ('approved', 'rejected', 'needs_changes'), 'invalid declared review decision')
        exact_digest(row['review_record_sha256'])
        records.append({**row, 'authentication': 'not_established_by_this_tool', 'independence': 'not_established_by_this_tool'})
    return {'structurally_bound_handoffs': records, 'missing_roles': sorted(set(ROLES) - seen),
            'human_approval_authenticated': False, 'legal_approval': False,
            'release_acceptance_complete': False, 'publication_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True, type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--notice-root', required=True, type=Path)
    parser.add_argument('--bootstrap-root', required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--output', type=Path)
    group.add_argument('--verify', type=Path)
    parser.add_argument('--decisions', type=Path)
    args = parser.parse_args()
    packet = build_packet(document(read(args.selection)), args.evidence_root, args.notice_root, args.bootstrap_root)
    if args.verify:
        require(document(read(args.verify)) == packet, 'packet or selected evidence changed')
    else:
        output = custody(args.output)
        protected = [custody(p) for p in (args.selection, args.evidence_root, args.notice_root, args.bootstrap_root)]
        require(output.parent.is_dir() and not output.exists() and
                all(output != p and p not in output.parents and output not in p.parents for p in protected),
                'output must be fresh and separate from selected inputs')
        with output.open('xb') as stream:
            stream.write(json.dumps(packet, indent=2, sort_keys=True).encode() + b'\n')
    result = {'state': packet['state'], 'packet_digest': packet['packet_digest'], 'publication_authorized': False}
    if args.decisions:
        result['handoffs'] = verify_decisions(packet, document(read(args.decisions)))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
