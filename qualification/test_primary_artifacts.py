import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from qualification import primary_artifacts as a


class ArtifactTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.selection = {'protocol': a.SELECTION, 'repository': a.REPOSITORY,
            'profile': 'ubuntu24.04-amd64', 'run_id': '123', 'run_attempt': '2',
            'workflow_commit': 'a' * 40,
            'artifact': {'id': 456, 'name': 'd10-carrier-capsule-ubuntu24.04-amd64-2', 'size': 99, 'sha256': 'b' * 64},
            'pins': {key: ('c' * 40 if key in ('source_commit', 'source_tree') else
                           'sha256:' + 'd' * 64 if key == 'cohort_digest' else 'e' * 64) for key in a.PIN_FIELDS}}
        self.run = {'id': 123, 'run_attempt': 2, 'status': 'completed', 'event': 'workflow_dispatch',
            'head_sha': 'a' * 40, 'path': a.WORKFLOW, 'repository': {'full_name': a.REPOSITORY},
            'head_repository': {'full_name': a.REPOSITORY}, 'conclusion': 'failure'}
        self.artifact = {'id': 456, 'name': self.selection['artifact']['name'], 'expired': False,
            'size_in_bytes': 99, 'digest': 'sha256:' + 'b' * 64,
            'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}
        self.jobs = [{'id': 789, 'name': 'native', 'run_attempt': 2, 'status': 'completed', 'conclusion': 'failure',
            'steps': [{'name': name, 'status': 'completed', 'conclusion': 'success'} for name in a.REQUIRED_STEPS]}]

    def selected_file(self, value=None):
        path = self.root / 'selection.json'
        path.write_bytes(a.canonical(self.selection if value is None else value))
        return path, a.gate.sha(path)

    def archive(self, entries):
        path = self.root / 'capsule.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(path, 'w') as stream:
                for name, body, mode in entries:
                    info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = mode << 16
                    stream.writestr(info, body)
        return path, a.gate.sha(path), path.stat().st_size

    def test_exact_selection_is_required(self):
        path, digest = self.selected_file()
        self.assertEqual(a.validate_selection(path, digest), self.selection)
        with self.assertRaises(ValueError): a.validate_selection(path, 'f' * 64)
        for mutate in (lambda x: x.update(repository='unselected/repository'),
                       lambda x: x.update(profile='local-macos-amd64-fixture'),
                       lambda x: x.update(run_attempt='02'),
                       lambda x: x['artifact'].update(id=True),
                       lambda x: x['artifact'].update(name='../unselected'),
                       lambda x: x['artifact'].update(size=a.MAX_ZIP + 1),
                       lambda x: x['pins'].pop('sdk_closure_sha256')):
            value = copy.deepcopy(self.selection); mutate(value)
            path, digest = self.selected_file(value)
            with self.assertRaises((ValueError, TypeError)): a.validate_selection(path, digest)

    def test_linked_selection_is_refused(self):
        path, digest = self.selected_file(); link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): a.validate_selection(link, digest)

    def test_later_wrapper_failure_does_not_erase_completed_retained_build(self):
        proof = a.validate_metadata(self.selection, self.run, self.artifact, self.jobs)
        self.assertEqual(proof['job_conclusion'], 'failure')
        self.assertEqual(proof['successful_steps'], list(a.REQUIRED_STEPS))

    def test_unfinished_foreign_expired_or_changed_artifact_is_refused(self):
        for mutate in (lambda r, f, j: r.update(status='in_progress'),
                       lambda r, f, j: r.update(head_sha='f' * 40),
                       lambda r, f, j: r.update(path='.github/workflows/unselected.yml'),
                       lambda r, f, j: r['head_repository'].update(full_name='other/fork'),
                       lambda r, f, j: f.update(expired=True),
                       lambda r, f, j: f.update(digest='sha256:' + 'f' * 64),
                       lambda r, f, j: f['workflow_run'].update(id=124),
                       lambda r, f, j: j[0]['steps'][1].update(conclusion='failure'),
                       lambda r, f, j: j[0].update(run_attempt=1)):
            run, artifact, jobs = copy.deepcopy((self.run, self.artifact, self.jobs)); mutate(run, artifact, jobs)
            with self.assertRaises(ValueError): a.validate_metadata(self.selection, run, artifact, jobs)

    def test_safe_archive_extracts_without_executable_permissions(self):
        archive, digest, size = self.archive([('result.json', b'{}', stat.S_IFREG | 0o777),
                                             ('evidence/build.json', b'{}', stat.S_IFREG | 0o600)])
        output = self.root / 'output'; inventory = a.extract_zip(archive, output, digest, size)
        self.assertEqual((output / 'result.json').read_bytes(), b'{}')
        self.assertEqual(stat.S_IMODE((output / 'result.json').stat().st_mode), 0o644)
        self.assertEqual(inventory, a.inventory(output))
        with self.assertRaises(ValueError): a.extract_zip(archive, self.root / 'other', 'f' * 64, size)

    def test_unsafe_archive_members_refuse_without_outside_writes(self):
        cases = [[('../outside', b'bad', stat.S_IFREG | 0o600)],
                 [('/absolute', b'bad', stat.S_IFREG | 0o600)],
                 [('a\\outside', b'bad', stat.S_IFREG | 0o600)],
                 [('link', b'outside', stat.S_IFLNK | 0o777)],
                 [('pipe', b'', stat.S_IFIFO | 0o600)],
                 [('same', b'a', stat.S_IFREG | 0o600), ('same', b'b', stat.S_IFREG | 0o600)],
                 [('Case', b'a', stat.S_IFREG | 0o600), ('case', b'b', stat.S_IFREG | 0o600)],
                 [('parent', b'a', stat.S_IFREG | 0o600), ('parent/child', b'b', stat.S_IFREG | 0o600)]]
        outside = self.root / 'outside'; outside.write_bytes(b'preserve')
        for number, entries in enumerate(cases):
            archive, digest, size = self.archive(entries)
            with self.assertRaises(ValueError): a.extract_zip(archive, self.root / f'out-{number}', digest, size)
            self.assertEqual(outside.read_bytes(), b'preserve')

    def test_transport_inventory_covers_changed_bytes_modes_and_extra_directories(self):
        output = self.root / 'capsule'; output.mkdir(); (output / 'result.json').write_bytes(b'{}')
        _, selected_sha = self.selected_file()
        proof = {'protocol': a.PROTOCOL, 'selection_sha256': selected_sha,
            **{k: self.selection[k] for k in ('repository', 'profile', 'run_id', 'run_attempt', 'workflow_commit', 'artifact')},
            'github_observation': a.validate_metadata(self.selection, self.run, self.artifact, self.jobs),
            'inventory': a.inventory(output), 'publisher_trust_accepted': False, 'publication_authorized': False}
        path = self.root / 'proof.json'; path.write_bytes(a.canonical(proof))
        a.verify_transport(output, path, self.selection, selected_sha)
        (output / 'extra').mkdir()
        with self.assertRaises(ValueError): a.verify_transport(output, path, self.selection, selected_sha)
        (output / 'extra').rmdir(); (output / 'result.json').write_bytes(b'changed')
        with self.assertRaises(ValueError): a.verify_transport(output, path, self.selection, selected_sha)

    def test_links_and_shared_inodes_do_not_become_transport_proof(self):
        output = self.root / 'capsule'; output.mkdir(); (output / 'result.json').write_bytes(b'{}')
        (output / 'linked').symlink_to(output / 'result.json')
        with self.assertRaises(ValueError): a.inventory(output)

    def test_fetch_binds_real_extracted_bytes_without_exporting_token(self):
        archive, digest, size = self.archive([('result.json', b'{}', stat.S_IFREG | 0o644)])
        self.selection['artifact'].update(sha256=digest, size=size)
        self.artifact.update(digest='sha256:' + digest, size_in_bytes=size)
        selected, selection_sha = self.selected_file()
        gh = self.root / 'gh'; gh.write_bytes(b'fixture executable')
        observed = []
        def metadata(executable, endpoint, env):
            observed.append(env)
            if '/jobs?' in endpoint:return {'total_count': 1, 'jobs': self.jobs}
            return self.artifact if '/artifacts/' in endpoint else self.run
        def download(executable, endpoint, env, destination, expected_size):
            self.assertEqual(expected_size, size)
            destination.write_bytes(archive.read_bytes())
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-token', 'GH_DEBUG': 'api'}), \
             patch.object(a, 'gh_json', side_effect=metadata), patch.object(a, 'download_zip', side_effect=download):
            proof = a.fetch(selected, selection_sha, self.root / 'download', gh)
        self.assertEqual(proof['artifact']['sha256'], digest)
        self.assertNotIn('fixture-token', json.dumps(proof))
        self.assertTrue(observed and all('GH_DEBUG' not in env for env in observed))

    def test_generated_handoff_requires_this_run_and_completed_producer(self):
        archive, digest, size = self.archive([('capsule/evidence/record.json', b'{}', stat.S_IFREG | 0o644)])
        gh = self.root / 'gh'; gh.write_bytes(b'fixture executable')
        artifact = {**self.artifact, 'name': 'd10-rewrapped-ubuntu24.04-amd64-2',
                    'size_in_bytes': size, 'digest': 'sha256:' + digest}
        producer = {'id': 321, 'name': 'rewrap', 'run_attempt': 2, 'status': 'completed', 'conclusion': 'success'}
        def metadata(executable, endpoint, env):
            return {'total_count': 1, 'jobs': [producer]} if '/jobs?' in endpoint else artifact
        def download(executable, endpoint, env, destination, expected_size):
            destination.write_bytes(archive.read_bytes())
        env = {'GH_TOKEN': 'fixture-token', 'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': a.REPOSITORY,
               'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': 'a' * 40}
        with patch.dict(os.environ, env), patch.object(a, 'gh_json', side_effect=metadata), \
             patch.object(a, 'download_zip', side_effect=download):
            a.fetch_generated(456, digest, 'ubuntu24.04-amd64', self.root / 'generated', gh)
            for directory in (self.root / 'generated/artifact').rglob('*'):
                if directory.is_dir():self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            producer['conclusion'] = 'failure'
            with self.assertRaises(ValueError):
                a.fetch_generated(456, digest, 'ubuntu24.04-amd64', self.root / 'rejected', gh)


if __name__ == '__main__':
    unittest.main()
