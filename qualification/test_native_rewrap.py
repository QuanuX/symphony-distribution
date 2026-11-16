"""Bounded resumption/custody regressions; fixtures are not primary acceptance."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualification import native_rewrap as m


class NativeResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()

    def tearDown(self): self.temp.cleanup()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value) + '\n').encode())
        path.chmod(0o644); return path

    def records(self):
        inputs = {'native': self.root / 'capsule', 'evidence': self.root / 'evidence'}
        selected = {'profile': 'ubuntu24.04-amd64', 'run_id': '12', 'run_attempt': '1', 'workflow_commit': 'a'*40,
            'pins': {'source_commit': 'b'*40, 'source_tree': 'c'*40,
                     'source_export_digest': 'd'*64, 'source_manifest_sha256': 'e'*64}}
        aggregate = {'host': {'scope': 'native_profile_build', 'requested_profile': selected['profile']},
            'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'built_and_sdk_checked',
            'repeated_payload_bytes_equal': True, 'source_commit': 'b'*40, 'source_tree': 'c'*40,
            'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True},
            'rounds': [{'directory': 'round-1'}, {'directory': 'round-2'}],
            'publication_authorized': False, 'acceptance_complete': False}
        aggregate_path = self.put(inputs['evidence'] / 'd06-cohort/result.json', aggregate)
        report = {'protocol': m.retention.PROTOCOL, 'state': 'complete_primary_native_bytes_retained',
            'profile': selected['profile'], 'native_count': 51, 'go_count': 6,
            'producer': m.retention.producer_record('12', '1', 'a'*40), 'selected_payload_round': 'round-1',
            'both_original_payloads_verified': True, 'second_round_payload_retained': False,
            'publication_authorized': False, 'release_acceptance_complete': False, 'wrapper_qualified': False,
            'aggregate_sha256': m.signing.digest(aggregate_path), 'round_sha256': {'round-1': 'f'*64, 'round-2': '0'*64},
            **selected['pins']}
        sdk = {'protocol': 'symphony.distribution.d06-sdk-closure.v1', 'status': 'passed', 'round': 'round-1',
            'cohort_result_sha256': report['aggregate_sha256'], 'round_result_sha256': 'f'*64,
            'source_inventory_sha256': 'd'*64, 'source_commit': 'b'*40, 'source_tree': 'c'*40,
            'original_final_candidate_unchanged': True, 'publication_authorized': False,
            'release_acceptance_complete': False, 'fresh_host_accepted': False}
        delivery = {'protocol': 'symphony.distribution.d06-delivery-record.v1',
            'state': 'inventory_complete_publisher_review_pending',
            'build_result_sha256': report['aggregate_sha256'], 'round_result_sha256': 'f'*64}
        self.put(inputs['native'] / 'capsule.json', report)
        self.put(inputs['native'] / 'native-cohort.tar.gz', b'fixture selected archive')
        self.put(inputs['evidence'] / 'd06-sdk-closure/result.json', sdk)
        self.put(inputs['evidence'] / 'd06-delivery/delivery-record.json', delivery)
        return inputs, selected, report, aggregate, sdk, delivery

    def test_original_records_bind_source_repeated_build_sdk_and_delivery(self):
        inputs, selected, report, aggregate, sdk, delivery = self.records()
        self.assertEqual(m.original_records(inputs, selected), (report, aggregate, sdk, delivery))

    def test_sdk_from_other_bytes_or_unfinished_campaign_refused(self):
        inputs, selected, _, _, sdk, _ = self.records()
        for key, value in [('status', 'incomplete'), ('cohort_result_sha256', '1'*64),
                ('round_result_sha256', '2'*64), ('round', 'round-2'), ('source_inventory_sha256', '3'*64),
                ('original_final_candidate_unchanged', False), ('fresh_host_accepted', True)]:
            with self.subTest(key=key):
                self.put(inputs['evidence'] / 'd06-sdk-closure/result.json', sdk | {key: value})
                with self.assertRaises(ValueError): m.original_records(inputs, selected)

    def test_native_report_scope_source_and_producer_mismatch_refused(self):
        inputs, selected, report, _, _, _ = self.records()
        for key, value in [('native_count', 50), ('second_round_payload_retained', True),
                ('source_commit', '0'*40), ('source_export_digest', '0'*64), ('wrapper_qualified', True),
                ('producer', report['producer'] | {'run_attempt': '2'})]:
            with self.subTest(key=key):
                self.put(inputs['native'] / 'capsule.json', report | {key: value})
                with self.assertRaises(ValueError): m.original_records(inputs, selected)

    def test_original_delivery_failure_or_changed_aggregate_refused(self):
        inputs, selected, _, aggregate, _, delivery = self.records()
        self.put(inputs['evidence'] / 'd06-delivery/delivery-record.json', delivery | {'state': 'failed'})
        with self.assertRaisesRegex(ValueError, 'delivery'): m.original_records(inputs, selected)
        self.put(inputs['evidence'] / 'd06-delivery/delivery-record.json', delivery)
        self.put(inputs['evidence'] / 'd06-cohort/result.json', aggregate | {'added': True})
        with self.assertRaisesRegex(ValueError, 'aggregate'): m.original_records(inputs, selected)

    def test_native_transport_receives_both_distinct_capsules(self):
        selected = {'selected': True}
        with patch.object(m, 'transport') as transport:
            self.assertEqual(m.selected_inputs(self.root, selected, 'a'*64, self.root / 'proof'),
                             {'native': self.root / 'capsule', 'evidence': self.root / 'evidence'})
            transport.return_value.verify_transport.assert_called_once_with(
                self.root / 'capsule', self.root / 'evidence', self.root / 'proof', selected, 'a'*64)
            transport.return_value.verify_transport.side_effect = ValueError('changed input')
            with self.assertRaisesRegex(ValueError, 'changed input'):
                m.selected_inputs(self.root, selected, 'a'*64, self.root / 'proof')

    def lineage_fixture(self):
        root = self.root / 'tools'; root.mkdir()
        names = ['build-cohort/build.py', 'build-cohort/cohort.json', 'source-binding.json',
                 'qualification/native_campaign.py', 'source-export/export_source.py',
                 'qualification/d10_build_retention.py', 'qualification/d06_sdk_closure.py',
                 'qualification/d06_delivery_record.py']
        blobs = {name: ('source ' + name).encode() for name in names}
        hashes = {name: m.c.sha(raw) for name, raw in blobs.items()}
        for name, raw in blobs.items(): self.put(root / name, raw)
        aggregate = {'build_helpers': {'build.py': hashes['build-cohort/build.py']},
            'imported_helpers': {name: hashes[name] for name in names[3:5]}, 'plan_sha256': hashes['build-cohort/cohort.json']}
        report = {'producer': {'commit': 'a'*40}, 'helper_sha256': hashes['qualification/d10_build_retention.py']}
        sdk = {'harness_sha256': hashes['qualification/d06_sdk_closure.py'],
            'extra_helpers_sha256': {name: hashes[name] for name in ('qualification/d06_sdk_closure.py', 'qualification/native_campaign.py')}}
        original_delivery = {'tool_sha256': hashes['qualification/d06_delivery_record.py']}
        restored = self.root / 'restored'
        for name in names[:5]: self.put(restored / 'toolkit' / name, blobs[name])
        return root, blobs, aggregate, report, sdk, original_delivery, restored

    def test_inherited_builders_match_retained_original_git_and_current_source(self):
        root, blobs, aggregate, report, sdk, delivery, restored = self.lineage_fixture()
        with patch.object(m, 'ROOT', root), patch.object(m, 'git_bytes', side_effect=lambda commit, name: blobs[name]), \
             patch.object(m, 'git_tree', return_value='b'*40):
            result = m.helper_lineage(restored, report, aggregate, sdk, delivery)
            self.assertEqual(result['original_toolkit_commit'], 'a'*40)
            self.assertTrue(result['current_builder_and_qualification_helpers_identical'])
            self.assertEqual(set(result['original_helpers_sha256']), set(blobs))

    def test_missing_extra_changed_retained_or_current_helper_refused(self):
        root, blobs, aggregate, report, sdk, delivery, restored = self.lineage_fixture()
        path = restored / 'toolkit/build-cohort/build.py'
        with patch.object(m, 'ROOT', root), patch.object(m, 'git_bytes', side_effect=lambda commit, name: blobs[name]), \
             patch.object(m, 'git_tree', return_value='b'*40):
            self.put(restored / 'toolkit/unselected.py', b'unselected')
            with self.assertRaisesRegex(ValueError, 'membership'): m.helper_lineage(restored, report, aggregate, sdk, delivery)
            (restored / 'toolkit/unselected.py').unlink(); path.unlink()
            with self.assertRaisesRegex(ValueError, 'membership'): m.helper_lineage(restored, report, aggregate, sdk, delivery)
            self.put(path, b'changed')
            with self.assertRaisesRegex(ValueError, 'identity'): m.helper_lineage(restored, report, aggregate, sdk, delivery)
            self.put(path, blobs['build-cohort/build.py']); self.put(root / 'build-cohort/build.py', b'changed')
            with self.assertRaisesRegex(ValueError, 'identity'): m.helper_lineage(restored, report, aggregate, sdk, delivery)

    def test_original_git_or_sdk_imported_helper_mismatch_refused(self):
        root, blobs, aggregate, report, sdk, delivery, restored = self.lineage_fixture()
        with patch.object(m, 'ROOT', root), patch.object(m, 'git_bytes', return_value=b'wrong original source'):
            with self.assertRaisesRegex(ValueError, 'identity'): m.helper_lineage(restored, report, aggregate, sdk, delivery)
        sdk['extra_helpers_sha256'] = {}
        with patch.object(m, 'ROOT', root), patch.object(m, 'git_bytes', side_effect=lambda commit, name: blobs[name]):
            with self.assertRaisesRegex(ValueError, 'imported helper set'): m.helper_lineage(restored, report, aggregate, sdk, delivery)

    def test_missing_consumer_optin_refuses_before_admission_or_process(self):
        with patch.object(m, 'admit_package') as admitted:
            with self.assertRaisesRegex(ValueError, 'opt-in'): m.fresh_user(SimpleNamespace(allow_ephemeral_install=False))
            admitted.assert_not_called()

    def test_consumer_same_job_refuses_before_installation(self):
        producer = {'run_id': '12', 'run_attempt': '1', 'job': 'rewrap'}
        args = SimpleNamespace(allow_ephemeral_install=True, artifact=self.root, result_sha256='a'*64, output=self.root / 'out')
        with patch.object(m, 'admit_package', return_value=({'profile': 'ubuntu24.04-amd64', 'producer': producer}, {}, {})), \
             patch.object(m.reuse, 'custody', return_value=producer), patch.object(m.reuse, 'exercise') as exercise:
            with self.assertRaisesRegex(ValueError, 'separate hosted job'): m.fresh_user(args)
            exercise.assert_not_called()

    def test_consumer_uses_private_snapshot_and_complete_named_removal_exercise(self):
        wrapper = self.put(self.root / 'artifact/wrappers/review.sh', b'bounded wrapper')
        root = self.root / 'artifact'; out = self.root / 'consumer'
        package = {'profile': 'ubuntu24.04-amd64', 'producer': {'run_id': '12', 'run_attempt': '1', 'job': 'rewrap'},
            'executing_helpers': {}, 'lineage': {'original': 'retained'}, 'wrapper_toolkit_source': {'commit': 'a'*40}}
        cohort = {'entries': [{'unit': i} for i in range(58)], 'cohort_digest': 'sha256:'+'b'*64}
        row = {'filename': 'review.sh', 'size': wrapper.stat().st_size, 'sha256': m.signing.digest(wrapper), 'bootstrap_sha256': 'c'*64}
        args = SimpleNamespace(allow_ephemeral_install=True, artifact=root, result_sha256='a'*64,
                               inspection_tools=self.root / 'tools', output=out)
        def files(base, entry):
            i = entry['unit']; return {}, {f'share/symphony/carriers/{i}/{n}': (b'exact', 0o644) for n in range(3)}
        def exercise(path, selected, selected_cohort, expected, output):
            self.assertEqual(path, output / 'selected-wrapper.sh'); self.assertNotEqual(path, wrapper)
            self.assertEqual(path.read_bytes(), wrapper.read_bytes()); self.assertEqual(len(expected), 174)
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            return [{'exit_code': 0, 'log_sha256': 'd'*64}]
        with patch.object(m, 'admit_package', return_value=(package, cohort, row)), \
             patch.object(m.reuse, 'custody', return_value={'run_id': '12', 'run_attempt': '1', 'job': 'fresh-user'}), \
             patch.object(m.reuse, 'inspection_tools', return_value={'selected': True}), patch.object(m, 'helpers', return_value={}), \
             patch.object(m.c, 'validate_recipe', side_effect=files), patch.object(m.construct, 'archive_records', return_value=[]), \
             patch.object(m.construct, 'audit_sh'), patch.object(m.reuse, 'exercise', side_effect=exercise):
            report = m.fresh_user(args)
        self.assertTrue(report['all_named_carriers_removed']); self.assertEqual(report['carrier_count'], 58)
        self.assertTrue(all(report[key] is False for key in m.FALSE_FLAGS))
        self.assertTrue(wrapper.exists()); self.assertTrue((out / 'result.json').is_file())

    def test_restore_wrong_host_refuses_before_output_or_archive_extraction(self):
        args = SimpleNamespace(selection=self.root / 'selection', selection_sha256='a'*64, artifact=self.root,
                               transport_proof=self.root / 'proof', output=self.root / 'out')
        with patch.object(m, 'transport') as api, patch.object(m, 'selected_inputs'), \
             patch.object(m.reuse, 'custody', side_effect=ValueError('wrong native host')), patch.object(m.retention, 'restore') as unpack:
            api.return_value.validate_selection.return_value = {'profile': 'ubuntu24.04-arm64'}
            with self.assertRaisesRegex(ValueError, 'wrong native host'): m.restore(args)
            unpack.assert_not_called(); self.assertFalse(args.output.exists())


if __name__ == '__main__': unittest.main()
