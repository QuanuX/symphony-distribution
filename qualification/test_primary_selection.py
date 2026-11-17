import copy
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
import zipfile

from qualification import primary_selection as selection

sys.path.insert(0, str(selection.ROOT / 'qualification'))
from qualification import test_d09_platform as capsule_fixtures


class SelectionTests(unittest.TestCase):
    def setUp(self):
        # Reuse the source/round/SDK fixture with a real Git toolkit tree. Only
        # its Conda codec is adapted; the complete capsule verifier still runs.
        self.fixture = capsule_fixtures.CapsuleTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.archive = self.root / 'capsule.zip'
        self.policy = self.put('policy.json', {'schema': 'symphony.source-privacy-policy.v1',
            'markers': ['PRIVATE_SELECTION_OWNER'], 'document_attributions': {}})
        self.policy.chmod(0o600)
        self.request = {'protocol': selection.REQUEST, 'repository': selection.transport.REPOSITORY,
            'profile': self.fixture.profile, 'run_id': '1234', 'run_attempt': '2', 'workflow_commit': 'e' * 40,
            'artifact': {'id': 5678, 'name': 'd10-carrier-capsule-macos15-arm64-2', 'sha256': '', 'size': 0},
            'source': {key: self.fixture.record[key] for key in selection.SOURCE_FIELDS}}
        self.run = {'id': 1234, 'run_attempt': 2, 'status': 'completed', 'event': 'workflow_dispatch',
            'head_sha': 'e' * 40, 'path': selection.transport.WORKFLOW, 'conclusion': 'failure',
            'repository': {'full_name': selection.transport.REPOSITORY},
            'head_repository': {'full_name': selection.transport.REPOSITORY},
            'head_commit': {'id': 'e' * 40, 'tree_id': self.fixture.record['original_toolkit_tree']},
            'actor': {'login': 'PRIVATE_SELECTION_OWNER'}}
        self.artifact = {'id': 5678, 'name': self.request['artifact']['name'], 'expired': False,
            'size_in_bytes': 0, 'digest': '', 'workflow_run': {'id': 1234, 'head_sha': 'e' * 40}}
        self.jobs = {'total_count': 1, 'jobs': [{'id': 8765, 'name': 'native', 'run_attempt': 2,
            'status': 'completed', 'conclusion': 'failure', 'steps': [
                {'name': name, 'status': 'completed', 'conclusion': 'success'} for name in selection.transport.REQUIRED_STEPS]}]}
        self.zip_capsule()
        self.output = self.root / 'prepared-selection'

    def put(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        return path

    def zip_capsule(self):
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(self.fixture.capsule.rglob('*')):
                if path.is_file(): bundle.write(path, path.relative_to(self.fixture.capsule).as_posix())
        size, digest = self.archive.stat().st_size, selection.gate.sha(self.archive)
        self.request['artifact'].update(size=size, sha256=digest)
        self.artifact.update(size_in_bytes=size, digest='sha256:' + digest)

    def inputs(self):
        request = self.put('request.json', self.request)
        return {'request': request, 'request_sha256': selection.gate.sha(request), 'archive': self.archive,
            'run_metadata': self.put('run.json', self.run), 'artifact_metadata': self.put('artifact.json', self.artifact),
            'jobs_metadata': self.put('jobs.json', self.jobs), 'privacy_policy': self.policy, 'output': self.output}

    def prepare(self, arguments=None):
        args = arguments or self.inputs()
        binding = {key: self.fixture.record[key] for key in ('source_commit', 'source_tree')}
        with patch.object(selection, 'source_binding', return_value=binding), \
             patch.object(selection.gate, 'module', side_effect=self.fixture.load):
            return selection.prepare(**args)

    def no_selection(self):
        self.assertFalse((self.output / 'selection.json').exists())
        self.assertFalse((self.output / 'review.json').exists())

    def test_complete_source_bound_fixture_prepares_existing_selection_schema(self):
        original = self.archive.read_bytes()
        report = self.prepare()
        selected = selection.transport.validate_selection(self.output / 'selection.json', report['selection_sha256'])
        self.assertEqual(selected['profile'], self.fixture.profile)
        self.assertEqual(selected['artifact'], self.request['artifact'])
        self.assertEqual(selected['pins']['primary_result_sha256'], selection.gate.sha(self.fixture.capsule / 'result.json'))
        self.assertEqual(set(selected['pins']), selection.transport.PIN_FIELDS)
        self.assertFalse(report['api_snapshot_authenticated'])
        self.assertTrue(report['authoritative_metadata_refetch_required'])
        self.assertEqual(report['pending_independent_acceptance_cells'], 36)
        self.assertFalse(report['wrapper_qualification_started'])
        self.assertEqual(self.archive.read_bytes(), original)
        self.assertNotIn('PRIVATE_SELECTION_OWNER', (self.output / 'review.json').read_text())
        self.assertNotIn(str(self.root), (self.output / 'review.json').read_text())
        self.assertEqual(report['saved_metadata_observation']['job_conclusion'], 'failure')

    def test_request_digest_and_explicit_fields_cannot_be_derived_from_archive(self):
        args = self.inputs(); args['request_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'selected request'): self.prepare(args)
        self.no_selection()
        self.request['source'].pop('source_manifest_sha256')
        with self.assertRaisesRegex(ValueError, 'source pins'): self.prepare()
        self.no_selection()

    def test_core_source_must_match_frozen_binding_before_extraction(self):
        self.request['source']['source_tree'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'frozen distribution binding'): self.prepare()
        self.assertFalse(self.output.exists())

    def test_reviewed_source_export_and_manifest_are_independently_selected(self):
        for field in ('source_export_digest', 'source_manifest_sha256'):
            old = self.request['source'][field]; self.request['source'][field] = 'f' * 64
            self.output = self.root / ('wrong-' + field)
            with self.assertRaisesRegex(ValueError, 'independently selected source'): self.prepare()
            self.no_selection(); self.request['source'][field] = old

    def test_completed_run_and_native_sdk_retention_steps_required(self):
        self.run['status'] = 'in_progress'
        with self.assertRaisesRegex(ValueError, 'Completed selected producer'): self.prepare()
        self.assertFalse(self.output.exists())
        self.run['status'] = 'completed'; self.jobs['jobs'][0]['steps'][1]['conclusion'] = 'skipped'
        with self.assertRaisesRegex(ValueError, 'did not complete successfully'): self.prepare()
        self.assertFalse(self.output.exists())

    def test_complete_job_snapshot_and_exact_attempt_required(self):
        self.jobs['total_count'] = 2
        with self.assertRaisesRegex(ValueError, 'Complete bounded job'): self.prepare()
        self.jobs['total_count'] = 1; self.jobs['jobs'][0]['run_attempt'] = 1
        with self.assertRaisesRegex(ValueError, 'Exact completed native'): self.prepare()
        self.no_selection()

    def test_wrong_or_expired_api_artifact_refused(self):
        original = copy.deepcopy(self.artifact)
        for key, value in [('expired', True), ('id', 42), ('digest', 'sha256:' + 'f' * 64)]:
            self.artifact[key] = value
            with self.assertRaisesRegex(ValueError, 'GitHub artifact metadata'): self.prepare()
            self.artifact = copy.deepcopy(original)
        self.no_selection()

    def test_archive_bytes_and_size_must_match_explicit_api_pin(self):
        with self.archive.open('ab') as stream: stream.write(b'extra')
        with self.assertRaisesRegex(ValueError, 'Archive differs'): self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_producer_commit_or_profile_refused_even_with_matching_api_snapshot(self):
        for field in ('workflow_commit', 'profile'):
            saved_request, saved_run, saved_artifact = copy.deepcopy((self.request, self.run, self.artifact))
            if field == 'workflow_commit':
                self.request[field] = 'd' * 40; self.run['head_sha'] = 'd' * 40
                self.artifact['workflow_run']['head_sha'] = 'd' * 40
            else:
                self.request[field] = 'ubuntu24.04-amd64'
                self.request['artifact']['name'] = self.artifact['name'] = 'd10-carrier-capsule-ubuntu24.04-amd64-2'
            self.output = self.root / ('wrong-' + field)
            with self.assertRaisesRegex(ValueError, 'selected producer/profile'): self.prepare()
            self.no_selection()
            self.request, self.run, self.artifact = saved_request, saved_run, saved_artifact

    def test_full_capsule_verifier_refuses_changed_sdk_after_outer_zip_reselection(self):
        self.fixture.sdk['harness_sha256'] = 'f' * 64; self.fixture.reseal(); self.zip_capsule()
        # A matching artifact SHA alone cannot make changed original helper
        # provenance valid; this calls the actual complete capsule verifier.
        with self.assertRaisesRegex(ValueError, 'Conflicting original helper'): self.prepare()
        self.no_selection()

    def test_full_capsule_verifier_refuses_changed_original_git_tree(self):
        self.fixture.record['original_toolkit_tree'] = 'f' * 40; self.fixture.reseal(); self.zip_capsule()
        with self.assertRaisesRegex(ValueError, 'source identity'): self.prepare()
        self.no_selection()

    def test_original_toolkit_tree_must_match_saved_producer_commit_observation(self):
        self.run['head_commit']['tree_id'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'saved producer commit observation'): self.prepare()
        self.no_selection()

    def test_existing_output_and_linked_or_aliased_inputs_refused(self):
        self.output.mkdir(); marker = self.output / 'keep'; marker.write_text('existing')
        with self.assertRaisesRegex(ValueError, 'Output must be new'): self.prepare()
        self.assertEqual(marker.read_text(), 'existing')
        self.output = self.root / 'other'
        args = self.inputs(); alias = self.root / 'request-alias'; alias.symlink_to(args['request']); args['request'] = alias
        with self.assertRaisesRegex(ValueError, 'Linked path'): self.prepare(args)
        args = self.inputs(); hardlink = self.root / 'archive-alias'; os.link(self.archive, hardlink)
        with self.assertRaisesRegex(ValueError, 'independent regular'): self.prepare(args)
        self.assertFalse(self.output.exists())

    def test_output_cannot_alias_an_input_or_follow_parent_link(self):
        args = self.inputs(); args['output'] = self.archive
        with self.assertRaisesRegex(ValueError, 'Output must be new'): self.prepare(args)
        parent = self.root / 'parent-link'; parent.symlink_to(self.root, target_is_directory=True)
        args['output'] = parent / 'unused'
        with self.assertRaisesRegex(ValueError, 'Linked path'): self.prepare(args)
        self.assertFalse((self.root / 'unused').exists())

    def test_changed_input_after_nested_verification_emits_no_records(self):
        actual = selection.gate.verify_capsule
        args = self.inputs()
        def changing(root, digest):
            value = actual(root, digest)
            args['run_metadata'].write_bytes(args['run_metadata'].read_bytes() + b' ')
            return value
        with patch.object(selection.gate, 'verify_capsule', side_effect=changing), \
             self.assertRaisesRegex(ValueError, 'input changed'):
            self.prepare(args)
        self.no_selection()

    def test_duplicate_json_and_public_policy_refused(self):
        args = self.inputs(); args['run_metadata'].write_text('{"id":1234,"id":1234}')
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'): self.prepare(args)
        self.policy.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'mode0600'): self.prepare()
        self.no_selection()

    def test_no_network_subprocess_or_installer_is_called(self):
        with patch.object(selection.transport, 'gh_json', side_effect=AssertionError('No network allowed')), \
             patch.object(selection.transport, 'download_zip', side_effect=AssertionError('No network allowed')):
            result = self.prepare()
        self.assertFalse(result['native_build_executed'])
        self.assertFalse(result['installer_executed'])
        self.assertFalse(result['publication_authorized'])


if __name__ == '__main__':
    unittest.main()
