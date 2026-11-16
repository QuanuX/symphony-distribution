import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from qualification import native_artifacts as a


class NativeArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.native, self.evidence = self.root / 'native', self.root / 'evidence'
        self.native.mkdir(); self.evidence.mkdir()
        source = {key: a.frozen_source()[key] for key in ('source_commit', 'source_tree')}
        self.pins = {**source, **{key: 'b' * 64 for key in a.PIN_FIELDS - source.keys()}}
        self.selection = {'protocol': a.SELECTION, 'repository': a.REPOSITORY, 'profile': 'ubuntu24.04-amd64',
            'run_id': '123', 'run_attempt': '2', 'workflow_commit': 'a' * 40, 'pins': self.pins,
            'artifact': {'id': 456, 'name': 'd10-native-recovery-ubuntu24.04-amd64-2', 'size': 1, 'sha256': 'c' * 64},
            'evidence_artifact': {'id': 457, 'name': 'd09-evidence-ubuntu24.04-amd64-2', 'size': 1, 'sha256': 'd' * 64}}
        self.run = {'id': 123, 'run_attempt': 2, 'status': 'completed', 'event': 'workflow_dispatch',
            'head_sha': 'a' * 40, 'path': a.WORKFLOW, 'conclusion': 'failure',
            'repository': {'full_name': a.REPOSITORY}, 'head_repository': {'full_name': a.REPOSITORY}}
        self.jobs = [{'id': 789, 'name': 'native', 'run_attempt': 2, 'status': 'completed', 'conclusion': 'failure',
            'steps': [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in a.REQUIRED_STEPS]}]
        payload = [{'path': 'lib/fixture', 'sha256': '5' * 64, 'size': 3, 'mode': 0o755},
                   {'path': 'lib/fixture-link', 'link': 'fixture'}]
        self.pins['payload_inventory_sha256'] = a.transport.sha(a.transport.canonical(payload))
        self.build = {'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'built_and_sdk_checked', **source,
            'host': {'scope': 'native_profile_build', 'requested_profile': self.selection['profile']},
            'repeated_payload_bytes_equal': True,
            'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True, 'export_digest': 'b' * 64},
            'rounds': [{'directory': 'round-' + str(i), 'result_sha256': self.pins['round' + str(i) + '_result_sha256'],
                        'native_count': 51, 'go_count': 6} for i in (1, 2)],
            'publication_authorized': False, 'acceptance_complete': False}
        self.delivery = {'protocol': 'symphony.distribution.d06-delivery-record.v1',
            'state': 'inventory_complete_publisher_review_pending',
            'source_binding': {'commit': source['source_commit'], 'tree': source['source_tree']},
            'source': {'derived_export_digest': 'b' * 64, 'toolkit_files': [
                {'path': name, 'sha256': 'b' * 64, 'mode': 0o644} for name in
                ('qualification/d06_sdk_closure.py', 'qualification/native_campaign.py',
                 'qualification/d10_build_retention.py', 'qualification/d06_delivery_record.py')],
                'toolkit_snapshot': {'git_baseline_commit': 'a' * 40}},
            'host': self.build['host'], 'round_result_sha256': self.pins['round1_result_sha256'],
            'tool_sha256': 'b' * 64, 'payload_files': payload,
            'publication_authorized': False, 'release_ready': False, 'fresh_host_accepted': False}
        before = {row['path']: {'link': row['link']} if 'link' in row else
                  {'sha256': row['sha256'], 'mode': row['mode']} for row in payload}
        self.sdk = {'protocol': 'symphony.distribution.d06-sdk-closure.v1', 'status': 'passed', **source,
            'source_inventory_sha256': 'b' * 64, 'round': 'round-1',
            'round_result_sha256': self.pins['round1_result_sha256'],
            'original_payload_inventory_sha256': a.transport.sha(a.transport.canonical(before)),
            'original_final_candidate_unchanged': True,
            'core_snv_api_smoke': {'status': 'passed'}, 'source_consumer': {'status': 'passed'},
            'disposable_native_removal': {'status': 'passed', 'native_units': 51},
            'extra_helpers_sha256': {'qualification/d06_sdk_closure.py': 'b' * 64,
                                    'qualification/native_campaign.py': 'b' * 64},
            'harness_sha256': 'b' * 64, 'publication_authorized': False,
            'release_acceptance_complete': False, 'fresh_host_accepted': False}
        self.archive = self.native / 'native-cohort.tar.gz'
        # The transport deliberately does not claim to parse or restore the
        # inner archive. Full TAR validation belongs to retention.restore.
        self.archive.write_bytes(b'opaque native transport fixture')
        self.capsule = {'protocol': 'symphony.distribution.native-build-retention.v1',
            'state': 'complete_primary_native_bytes_retained', 'profile': self.selection['profile'], **source,
            'source_export_digest': 'b' * 64, 'source_manifest_sha256': 'b' * 64,
            'selected_payload_round': 'round-1', 'both_original_payloads_verified': True,
            'second_round_payload_retained': False, 'native_count': 51, 'go_count': 6,
            'producer': {'repository': a.REPOSITORY, 'run_id': '123', 'run_attempt': '2', 'commit': 'a' * 40},
            'round_sha256': {'round-1': self.pins['round1_result_sha256'], 'round-2': self.pins['round2_result_sha256']},
            'payload_inventory_sha256': self.pins['payload_inventory_sha256'], 'helper_sha256': 'b' * 64,
            'publication_authorized': False, 'release_acceptance_complete': False, 'wrapper_qualified': False}
        self.reseal(); self.zip_inputs()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(a.transport.canonical(value) + b'\n'); path.chmod(0o644)
        return a.gate.sha(path)

    def reseal(self):
        self.pins['aggregate_sha256'] = self.put(self.evidence / 'd06-cohort/result.json', self.build)
        self.sdk['cohort_result_sha256'] = self.delivery['build_result_sha256'] = self.capsule['aggregate_sha256'] = self.pins['aggregate_sha256']
        self.pins['sdk_closure_sha256'] = self.put(self.evidence / 'd06-sdk-closure/result.json', self.sdk)
        self.pins['delivery_record_sha256'] = self.put(self.evidence / 'd06-delivery/delivery-record.json', self.delivery)
        self.pins['native_archive_sha256'] = a.gate.sha(self.archive)
        self.capsule['archive'] = {'path': self.archive.name, 'sha256': self.pins['native_archive_sha256'], 'size': self.archive.stat().st_size}
        names = [('cohort/result.json', 'aggregate_sha256'), ('cohort/round-1/result.json', 'round1_result_sha256'),
                 ('cohort/round-2/result.json', 'round2_result_sha256'), ('export/SOURCE-EXPORT.json', 'source_manifest_sha256')]
        self.capsule['files'] = [{'path': n, 'sha256': self.pins[k], 'size': 1, 'mode': 0o644} for n, k in names]
        self.capsule['inventory_sha256'] = a.transport.sha(a.transport.canonical(self.capsule['files']))
        self.pins['capsule_sha256'] = self.put(self.native / 'capsule.json', self.capsule)

    def zip_inputs(self):
        self.zips, self.metadata = {}, {}
        for field, root in (('artifact', self.native), ('evidence_artifact', self.evidence)):
            archive = self.root / (field + '.zip')
            with zipfile.ZipFile(archive, 'w') as bundle:
                for path in sorted(root.rglob('*')):
                    if path.is_file(): bundle.write(path, path.relative_to(root).as_posix())
            row = self.selection[field]; row.update(sha256=a.gate.sha(archive), size=archive.stat().st_size)
            self.zips[row['id']] = archive
            self.metadata[field] = {'id': row['id'], 'name': row['name'], 'expired': False,
                'size_in_bytes': row['size'], 'digest': 'sha256:' + row['sha256'],
                'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}

    def selected(self):
        path = self.root / 'selection.json'; digest = self.put(path, self.selection)
        return path, digest

    def verify(self):
        path, digest = self.selected(); selected = a.validate_selection(path, digest)
        return a.validate_capsule(self.native, selected, self.evidence)

    def test_exact_original_records_bind_without_claiming_restore_or_qualification(self):
        result = self.verify()
        self.assertTrue(result['original_sdk_evidence_bound'])
        for field in ('native_tar_restored', 'native_bytes_requalified', 'carrier_capsule_completed', 'publication_authorized'):
            self.assertFalse(result[field])

    def test_missing_pins_wrong_kind_frozen_source_and_evidence_alias_refused(self):
        original = copy.deepcopy(self.selection)
        changes = [lambda s: s['pins'].pop('sdk_closure_sha256'), lambda s: s['pins'].update(source_tree='f' * 40),
            lambda s: s.update(protocol=a.transport.SELECTION), lambda s: s['artifact'].update(name='d10-carrier-capsule-ubuntu24.04-amd64-2'),
            lambda s: s['evidence_artifact'].update(id=s['artifact']['id']), lambda s: s.update(run_attempt='02'),
            lambda s: s['artifact'].update(id=True), lambda s: s['artifact'].update(size=a.transport.MAX_ZIP + 1)]
        for change in changes:
            self.selection = copy.deepcopy(original); change(self.selection)
            with self.assertRaises(ValueError): a.validate_selection(*self.selected())

    def test_selected_json_digest_duplicates_links_and_hardlinks_refused(self):
        path, digest = self.selected()
        with self.assertRaises(ValueError): a.validate_selection(path, 'f' * 64)
        raw = path.read_bytes(); path.write_bytes(b'{"protocol":"x",' + raw[1:])
        with self.assertRaisesRegex(ValueError, 'Duplicate'): a.validate_selection(path, a.gate.sha(path))
        path.write_bytes(raw); link = self.root / 'linked'; link.symlink_to(path)
        with self.assertRaises(ValueError): a.validate_selection(link, digest)
        link.unlink(); os.link(path, link)
        with self.assertRaises(ValueError): a.validate_selection(path, digest)

    def test_later_packaging_failure_preserves_actual_completed_prerequisites(self):
        result = a.validate_metadata(self.selection, self.run, self.metadata['artifact'], self.metadata['evidence_artifact'], self.jobs)
        self.assertEqual(result['job_conclusion'], 'failure')
        self.assertEqual(result['successful_steps'], list(a.REQUIRED_STEPS))

    def test_every_native_sdk_delivery_and_upload_step_is_required(self):
        for index in range(len(a.REQUIRED_STEPS)):
            jobs = copy.deepcopy(self.jobs); jobs[0]['steps'][index]['conclusion'] = 'skipped'
            with self.assertRaisesRegex(ValueError, 'did not complete'):
                a.validate_metadata(self.selection, self.run, self.metadata['artifact'], self.metadata['evidence_artifact'], jobs)

    def test_unfinished_foreign_wrong_attempt_or_cross_run_evidence_refused(self):
        changes = [lambda r, e, j: r.update(status='in_progress'), lambda r, e, j: r.update(head_sha='f' * 40),
            lambda r, e, j: r['head_repository'].update(full_name='other/fork'), lambda r, e, j: j[0].update(run_attempt=1),
            lambda r, e, j: e.update(expired=True), lambda r, e, j: e['workflow_run'].update(id=999),
            lambda r, e, j: e.update(digest='sha256:' + 'f' * 64), lambda r, e, j: j.append(j[0])]
        for change in changes:
            run, evidence, jobs = copy.deepcopy((self.run, self.metadata['evidence_artifact'], self.jobs)); change(run, evidence, jobs)
            with self.assertRaises(ValueError): a.validate_metadata(self.selection, run, self.metadata['artifact'], evidence, jobs)

    def test_changed_native_tar_or_extra_capsule_member_refused(self):
        self.archive.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'native TAR'): self.verify()
        self.reseal(); (self.native / 'extra').mkdir()
        with self.assertRaisesRegex(ValueError, 'two selected files'): self.verify()

    def test_original_evidence_has_closed_bounded_membership(self):
        extra = self.evidence / 'unlisted'; extra.write_bytes(b'not selected by producer workflow')
        with self.assertRaisesRegex(ValueError, 'Unexpected'): self.verify()
        extra.unlink(); extra.mkdir()
        with self.assertRaisesRegex(ValueError, 'Unexpected'): self.verify()
        extra.rmdir()
        with patch.object(a, 'MAX_DOCUMENT', 3):
            with self.assertRaisesRegex(ValueError, 'exceeds bound'): self.verify()

    def test_matching_outer_digest_does_not_admit_contradictory_native_state(self):
        for field, value in [('producer', {**self.capsule['producer'], 'commit': 'f' * 40}),
                             ('native_count', 50), ('wrapper_qualified', True), ('source_export_digest', 'f' * 64)]:
            original = self.capsule[field]; self.capsule[field] = value; self.reseal()
            with self.assertRaises(ValueError): self.verify()
            self.capsule[field] = original

    def test_original_sdk_must_match_payload_source_and_independent_helper_ledger(self):
        changes = [('original_payload_inventory_sha256', 'f' * 64), ('source_inventory_sha256', 'f' * 64),
                   ('original_final_candidate_unchanged', False), ('harness_sha256', 'f' * 64), ('fresh_host_accepted', True)]
        for field, value in changes:
            original = self.sdk[field]; self.sdk[field] = value; self.reseal()
            with self.assertRaises(ValueError): self.verify()
            self.sdk[field] = original
        self.sdk['extra_helpers_sha256'] = {}; self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_original_delivery_and_two_round_build_must_match(self):
        self.delivery['source']['toolkit_files'][0]['sha256'] = 'f' * 64; self.reseal()
        with self.assertRaisesRegex(ValueError, 'helpers differ'): self.verify()
        self.delivery['source']['toolkit_files'][0]['sha256'] = 'b' * 64
        self.build['repeated_payload_bytes_equal'] = False; self.reseal()
        with self.assertRaisesRegex(ValueError, 'Two completed'): self.verify()

    def fetched(self, output='download', metadata_override=None):
        selection_path, digest = self.selected(); gh = self.root / 'gh'; gh.write_bytes(b'fixture transport executable')
        def metadata(executable, endpoint, env):
            self.assertNotIn('GH_DEBUG', env)
            if '/jobs?' in endpoint: return metadata_override or {'total_count': 1, 'jobs': self.jobs}
            if endpoint.endswith('/artifacts/456'): return self.metadata['artifact']
            if endpoint.endswith('/artifacts/457'): return self.metadata['evidence_artifact']
            return self.run
        def download(executable, endpoint, env, destination, expected_size):
            archive = self.zips[int(endpoint.split('/')[-2])]; self.assertEqual(archive.stat().st_size, expected_size)
            destination.write_bytes(archive.read_bytes())
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-test-token', 'GH_DEBUG': 'api'}), \
             patch.object(a.transport, 'gh_json', side_effect=metadata), patch.object(a.transport, 'download_zip', side_effect=download):
            return a.fetch(selection_path, digest, self.root / output, gh)

    def test_actual_two_zip_transport_uses_scoped_environment_and_no_secret_evidence(self):
        proof = self.fetched(); out = self.root / 'download'
        self.assertNotIn('synthetic-test-token', json.dumps(proof)); self.assertNotIn(str(self.root), json.dumps(proof))
        selected, digest = self.selected()
        a.verify_transport(out / 'capsule', out / 'evidence', out / 'transport-proof.json', self.selection, digest)
        (out / 'evidence/d06-sdk-closure/result.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            a.verify_transport(out / 'capsule', out / 'evidence', out / 'transport-proof.json', self.selection, digest)

    def test_incomplete_jobs_or_existing_output_never_download_or_overwrite(self):
        with self.assertRaises(ValueError): self.fetched(metadata_override={'total_count': 0, 'jobs': []})
        out = self.root / 'occupied'; out.mkdir(); (out / 'keep').write_bytes(b'preserve')
        with self.assertRaises(ValueError): self.fetched(output='occupied')
        self.assertEqual((out / 'keep').read_bytes(), b'preserve')


if __name__ == '__main__': unittest.main()
