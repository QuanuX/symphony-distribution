"""A dossier must not relabel source/fixture evidence as release acceptance."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import validate as v


class DossierContracts(unittest.TestCase):
    def setUp(self):
        self.data = copy.deepcopy(v.read(v.ROOT / 'dossier/s08-dossier.json'))

    def refuses(self, phrase):
        with self.assertRaisesRegex(ValueError, phrase):
            v.validate_document(self.data)

    def test_current_local_evidence_consistent_without_host_acceptance(self):
        result = v.validate_document(self.data)
        self.assertEqual(result['status'], 'fresh_candidate_qualification_pending')
        self.assertFalse(result['current_candidate_qualified'])
        self.assertFalse(result['core_source_checked'])
        self.assertFalse(result['release_acceptance_complete'])
        self.assertFalse(result['publication_authorized'])

    def test_missing_rebuild_cannot_satisfy_required_candidate_gate(self):
        self.data['candidate_rebuild_report'] = None
        with self.assertRaisesRegex(ValueError, 'rebuild binding required'):
            v.validate_document(self.data, require_rebuild=True)

    def test_missing_source_export_cannot_satisfy_required_source_gate(self):
        self.data['source_export_report'] = None
        with self.assertRaisesRegex(ValueError, 'source export binding required'):
            v.validate_document(self.data, require_source_export=True)

    def test_missing_hosted_snapshot_cannot_satisfy_observed_status_gate(self):
        self.data['hosted_status_report'] = None
        with self.assertRaisesRegex(ValueError, 'hosted CI snapshot binding required'):
            v.validate_document(self.data, require_hosted_status=True)

    def test_historical_reports_cannot_qualify_new_candidate(self):
        prior = v.read(v.ROOT / 'dossier/history/s08-beta1.json')
        for field in ('candidate_rebuild_report', 'source_export_report', 'hosted_status_report'):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data[field] = prior[field]
                with self.assertRaisesRegex(ValueError, 'cannot promote historical'):
                    v.validate_document(data)

    def test_historical_failure_cannot_be_relabelled_as_new_host_success(self):
        row = self.data['platforms'][0]
        row['hosted_evidence_in_this_dossier'] = {'conclusion': 'success'}
        self.refuses('unbound hosted CI claim')

    def test_historical_scope_and_cases_cannot_claim_new_qualification(self):
        self.data['evidence_scope']['current_candidate_qualified'] = True
        self.refuses('historical evidence scope')
        self.data['evidence_scope']['current_candidate_qualified'] = False
        self.data['d05_safety_acceptance'][0]['engineering_evidence'] = 'bounded_E1_recorded'
        self.refuses('historical tests promoted')

    def test_pending_state_cannot_be_removed_to_bypass_evidence_boundaries(self):
        self.data['state'] = 'source_bound_distribution_supplement_release_incomplete'
        self.refuses('unrecognized dossier qualification state')

    def test_historical_snapshot_must_remain_exact(self):
        self.data['evidence_scope']['historical_dossier']['sha256'] = '0' * 64
        self.refuses('historical evidence scope')

    def test_changed_source_binding_refused(self):
        self.data['core_source']['source_commit'] = '0' * 40
        self.refuses('core binding')

    def test_changed_evidence_hash_refused(self):
        self.data['distribution_inputs'][0]['sha256'] = '0' * 64
        self.refuses('hash differs')

    def test_missing_evidence_refused(self):
        self.data['distribution_inputs'].pop()
        self.refuses('evidence input')

    def test_missing_or_duplicate_core_map_refused(self):
        self.data['source_documents'][-1] = self.data['source_documents'][0]
        self.refuses('core dossier/map')

    def test_raw_carrier_cannot_acquire_native_receipt(self):
        row = next(r for r in self.data['go_delivery_units'] if r['component_id'] == 'qxctl')
        row['runtime_receipt'] = 'symphony.knowledge.install-receipt.v2'
        self.refuses('contract substituted')

    def test_module_version_and_carrier_content_substitution_refused(self):
        for key, value in [('native_version', '99.0'), ('payload_files', ['runtime/bin/unknown'])]:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data['go_delivery_units'][0][key] = value
                with self.assertRaises(ValueError):
                    v.validate_document(data)

    def test_automatic_activation_or_unqualified_profile_refused(self):
        for key, value in [('automatic_activation', True), ('system_removal_qualified', True), ('supported_profiles', ['macos15-arm64'])]:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data['go_delivery_units'][0][key] = value
                with self.assertRaises(ValueError):
                    v.validate_document(data)

    def test_missing_beta_capability_and_acceptance_cell_refused(self):
        for key in ('capability_baseline', 'd05_safety_acceptance'):
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data[key].pop()
                with self.assertRaises(ValueError):
                    v.validate_document(data)
        self.data['retained_beta_requirements']['paper_criterion_ids'].pop()
        self.refuses('beta coverage')

    def test_fixture_cannot_be_promoted_to_release_or_host_acceptance(self):
        for field in ('release_acceptance_complete', 'publication_authorized'):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                data[field] = True
                with self.assertRaises(ValueError):
                    v.validate_document(data)
        self.data['platforms'][0]['fresh_host_acceptance'] = 'accepted'
        self.refuses('host acceptance')

    def test_native_evidence_cannot_be_reattributed(self):
        row = next(r for r in self.data['d05_safety_acceptance'] if r['id'] == 'D05-S10')
        row['evidence_refs'][0]['test'] = 'TestInventedAcceptance'
        self.refuses('misattributed')

    def test_carrier_evidence_cannot_close_process_lifetime(self):
        row = next(r for r in self.data['d05_safety_acceptance'] if r['id'] == 'D05-S14')
        row['evidence_refs'].append({'evidence': 'evidence/s07-conda-local-qualification.json'})
        self.refuses('misattributed')

    def test_missing_trust_or_reviewers_cannot_be_invented(self):
        self.data['trust']['independent_public_trust_policy'] = 'unreviewed-policy'
        self.refuses('trust')
        self.data['trust']['independent_public_trust_policy'] = None
        self.data['roles'][0]['new_assignment_made'] = True
        self.refuses('silently appointed')

    def test_duplicate_json_and_external_paths_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'duplicate.json'
            path.write_text('{"accepted":false,"accepted":true}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                v.read(path)
            for name in ('../escape', '/absolute', 'a/../duplicate.json'):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsafe'):
                    v.path_under(root, name)


if __name__ == '__main__':
    unittest.main()
