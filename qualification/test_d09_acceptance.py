import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('d09_acceptance', Path(__file__).with_name('d09_acceptance.py'))
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)


class AcceptancePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.evidence = self.root / 'evidence'; self.evidence.mkdir()
        self.notices = self.root / 'delivery'; (self.notices / 'notices').mkdir(parents=True)
        self.bootstrap = self.root / 'bootstrap'; (self.bootstrap / 'bootstrap-notices').mkdir(parents=True)
        self.sources = {role: {'repository': repo, 'commit': str(i) * 40, 'tree': str(i + 3) * 40}
                        for i, (role, repo) in enumerate(a.REPOSITORIES.items(), 1)}
        self.docs = {}
        self.docs['core_delivery'] = {'protocol': 'symphony.distribution.d06-delivery-record.v1',
            'publication_authorized': False, 'source': {'origin_commit': '1' * 40, 'origin_tree': '4' * 40,
                'mode': 'verified_derived_public_export', 'verification': {'verified': True}, 'derived_export_digest': 'd' * 64},
            'notices': [{'path': 'notices/LICENSE', 'sha256': a.sha(b'license bytes'), 'size': 13,
                         'component': 'core', 'scope': 'exact notice'}]}
        (self.notices / 'notices/LICENSE').write_bytes(b'license bytes')
        self.docs['qxctl_source'] = {'protocol': 'symphony.distribution.qxctl-original-source.v1',
            'publication_authorized': False, 'state': 'reproducible_stamped_original_git_source',
            'original_source': {'commit': '1' * 40, 'tree': '4' * 40},
            'compiled_input_equivalence': {'original_matches_cohort_source': True},
            'cohort_source': {'export_digest': 'd' * 64, 'is_original_git_tree': False}}
        qhash = self.write('qxctl_source'); dhash = self.write('core_delivery')
        self.docs['client_packet'] = {'schema': 'symphony.distribution.client-final-packet.v1',
            'publication_authorized': False, 'sources': {'core': self.sources['core'], 'plugin': self.sources['client']},
            'original_git_source_proof_sha256': 'sha256:' + qhash}
        self.docs['corresponding_source'] = {'protocol': 'symphony.distribution.d08-corresponding-source.v1',
            'publication_authorized': False, 'source_bindings': self.sources,
            'qxctl_source_proof_sha256': qhash, 'inherited_delivery_record_sha256': dhash}
        archive = {'name': 'fixture.pkg', 'sha256': 'e' * 64, 'size': 10}
        self.docs['wrapper_audit'] = {'state': 'unsigned_wrappers_audited', 'installer_executed': False,
            'publication_authorized': False, 'wrappers': [{'filename': archive['name'], 'sha256': archive['sha256'],
                'size': archive['size'], 'bootstrap_sha256': 'b' * 64}]}
        self.docs['review_manifest'] = {'protocol': 'symphony.distribution.review-signature.v1',
            'publication_authorized': False, 'release_acceptance_complete': False,
            'independent_publisher_authentication': False, 'artifacts': [archive]}
        rows = []
        for role, source in self.sources.items():
            rows.append({'repository': source['repository'], 'number': 1, 'url': 'https://github.com/' + source['repository'] + '/pull/1',
                'head': 'codex/fixture', 'base': 'main', 'head_sha': source['commit'], 'base_sha': '0' * 40,
                'local_base_is_ancestor_of_head': True,
                'workflow_runs': [{'id': 1, 'status': 'completed', 'conclusion': 'success'}]})
        self.docs['pr_snapshot'] = {'protocol': 'symphony.distribution.pr-stack-snapshot.v1', 'observed_at': '2026-11-16 00:00:00 UTC',
            'main_mutated': False, 'merge_performed': False, 'complete_required_check_coverage': False, 'pull_requests': rows}
        bundled = {'example': {'type': 'GPL-2.0-or-later', 'files': [{'path': '/upstream/build/location', 'text': 'original notice'}]}}
        raw = a.canonical(bundled); (self.bootstrap / 'bootstrap-notices/3rd-party-licenses.json').write_bytes(raw)
        meta = {'role': 'installer_bootstrap_and_explicit_carrier_maintenance', 'executable_sha256': 'b' * 64,
                'notices': {'3rd-party-licenses.json': a.sha(raw)}, 'package': {'version': 'fixture', 'sha256': 'f' * 64}}
        raw = a.canonical(meta); (self.bootstrap / 'BOOTSTRAP.json').write_bytes(raw)
        self.selection = {'protocol': 'symphony.distribution.d09-review-selection.v1', 'sources': self.sources,
            'selected_pr_heads': {role: row['commit'] for role, row in self.sources.items()},
            'bootstrap_metadata_sha256': a.sha(raw), 'documents': {}}
        for role in a.DOCUMENTS:
            self.rebind(role)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, role):
        raw = a.canonical(self.docs[role]); (self.evidence / (role + '.json')).write_bytes(raw); return a.sha(raw)

    def rebind(self, role):
        digest = self.write(role)
        self.selection['documents'][role] = {'path': role + '.json', 'sha256': digest}

    def build(self):
        return a.build_packet(self.selection, self.evidence, self.notices, self.bootstrap)

    def test_complete_material_still_leaves_human_legal_and_release_approval_pending(self):
        packet = self.build()
        self.assertEqual(packet, self.build())
        self.assertEqual(packet['redistribution']['core_notice_count'], 1)
        self.assertEqual(packet['redistribution']['bootstrap_component_count'], 1)
        self.assertTrue(all(r['reviewer'] is None for r in packet['roles']))
        self.assertFalse(packet['publication_authorized']); self.assertFalse(packet['legal_approval'])
        self.assertNotIn('/upstream/build/location', json.dumps(packet))

    def test_changed_selected_document_refuses(self):
        (self.evidence / 'client_packet.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'selected evidence digest'):
            self.build()

    def test_path_traversal_and_link_refuse(self):
        self.selection['documents']['client_packet']['path'] = '../escape'
        with self.assertRaisesRegex(ValueError, 'unsafe evidence path'):
            self.build()
        self.rebind('client_packet'); path = self.evidence / 'client_packet.json'; path.unlink()
        path.symlink_to(self.evidence / 'core_delivery.json')
        with self.assertRaisesRegex(ValueError, 'linked evidence'):
            self.build()

    def test_valid_digest_cannot_hide_source_pair_mismatch(self):
        self.docs['client_packet']['sources']['plugin'] = {**self.sources['client'], 'commit': 'a' * 40}
        self.rebind('client_packet')
        with self.assertRaisesRegex(ValueError, 'client source pair'):
            self.build()

    def test_derived_source_cannot_be_relabelled_original(self):
        self.docs['qxctl_source']['cohort_source']['is_original_git_tree'] = True
        self.rebind('qxctl_source')
        with self.assertRaisesRegex(ValueError, 'original-source qxctl'):
            self.build()

    def test_graph_parent_identity_mismatch_refuses(self):
        child = copy.deepcopy(self.docs['pr_snapshot']['pull_requests'][0]); child.update(number=2, head='codex/child', base='codex/fixture', base_sha='f' * 40, head_sha='e' * 40)
        child['url'] = child['url'].replace('/pull/1', '/pull/2')
        self.docs['pr_snapshot']['pull_requests'].append(child); self.rebind('pr_snapshot')
        with self.assertRaisesRegex(ValueError, 'base/head mismatch'):
            self.build()

    def test_failed_checks_remain_visible_without_rerun_or_merge(self):
        self.docs['pr_snapshot']['pull_requests'][0]['workflow_runs'][0]['conclusion'] = 'failure'; self.rebind('pr_snapshot')
        packet = self.build()
        self.assertEqual(packet['integration']['observed_pending_checks'][0]['gate'], 'observed_workflow_not_successful')
        self.assertFalse(packet['integration']['integration_authorized'])

    def test_missing_core_notice_or_changed_bootstrap_notice_refuses(self):
        (self.notices / 'notices/LICENSE').unlink()
        with self.assertRaisesRegex(ValueError, 'missing or oversized'):
            self.build()
        (self.notices / 'notices/LICENSE').write_bytes(b'license bytes')
        (self.bootstrap / 'bootstrap-notices/3rd-party-licenses.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'bootstrap notice bytes'):
            self.build()

    def test_wrapper_must_be_exactly_bound_in_review_manifest(self):
        self.docs['review_manifest']['artifacts'][0]['sha256'] = 'f' * 64; self.rebind('review_manifest')
        with self.assertRaisesRegex(ValueError, 'wrapper absent'):
            self.build()

    def decision(self, packet):
        return {'protocol': 'symphony.distribution.d09-human-review.v1', 'packet_digest': packet['packet_digest'],
                'role': 'redistribution_reviewer', 'reviewer': 'reviewer-example', 'reviewer_kind': 'human',
                'decision': 'approved', 'review_record_sha256': 'e' * 64}

    def test_bound_human_claim_is_not_authenticated_approval(self):
        packet = self.build(); row = self.decision(packet); result = a.verify_decisions(packet, [row])
        self.assertFalse(result['human_approval_authenticated']); self.assertFalse(result['legal_approval'])
        self.assertEqual(len(result['missing_roles']), len(a.ROLES) - 1)

    def test_wrong_packet_ai_and_duplicate_handoffs_refuse(self):
        packet = self.build(); row = self.decision(packet)
        for mutation in ({'packet_digest': 'sha256:' + 'f' * 64}, {'reviewer_kind': 'model'}, {'reviewer': 'Codex'}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                a.verify_decisions(packet, [{**row, **mutation}])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            a.verify_decisions(packet, [row, row])

    def test_duplicate_json_keys_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            a.document(b'{"source":1,"source":2}')


if __name__ == '__main__':
    unittest.main()
