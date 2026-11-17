import hashlib
import importlib.util
import copy
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('corresponding_source_tests', Path(__file__).with_name('corresponding_source.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CorrespondingSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.policy = self.root / 'policy.json'
        value = {'schema': 'symphony.source-privacy-policy.v1', 'markers': ['SYNTHETIC_SOURCE_PUBLISHER'], 'document_attributions': {}}
        self.policy.write_text(json.dumps(value))
        self.policy_digest = hashlib.sha256(m.canonical(value)).hexdigest()
        self.scanner = m.load('corresponding_source_fixture_scanner', m.ROOT / 'source-export/export_source.py')
        self.scanner.configure_policy(self.policy)

    def tearDown(self): self.tmp.cleanup()

    def repository(self, files):
        root = self.root / 'git-source'; root.mkdir()
        for name, raw in files.items():
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        def git(*args):
            return subprocess.check_output(['/usr/bin/git', '-C', str(root), *args], stderr=subprocess.DEVNULL,
                env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'})
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Source Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'source fixture')
        return root, git('rev-parse', 'HEAD').decode().strip()

    def fixture(self):
        for name in ('core', 'client', 'toolkit', 'delivery', 'identity'): (self.root / name).mkdir()
        archive = self.root / 'delivery/corresponding-source.tar'
        compiled = b'package main\n'
        m.write_tar(archive, [('symphony-source/tools/qxctl/main.go', compiled, 0o644)])
        original = archive.read_bytes(); recipe = b'original reviewed recipe\n'
        delivery = {'publication_authorized': False, 'source': {'mode': 'verified_derived_public_export',
            'verification': {'verified': True}, 'origin_commit': '1' * 40, 'origin_tree': '2' * 40,
            'derived_export_digest': '3' * 64, 'corresponding_source_archive': {
                'path': archive.name, 'sha256': m.sha(archive), 'size': archive.stat().st_size}}}
        inputs = [{'path': 'tools/qxctl/main.go', 'sha256': hashlib.sha256(compiled).hexdigest(),
                   'size': len(compiled), 'mode': 0o644}]
        proof = {'protocol': 'symphony.distribution.qxctl-original-source.v1',
            'state': 'reproducible_stamped_original_git_source', 'isolated_builds': 2,
            'publication_authorized': False, 'release_acceptance_complete': False,
            'original_source': {'commit': '1' * 40, 'tree': '2' * 40}, 'cohort_source': {'export_digest': '3' * 64},
            'compiled_input_equivalence': {'original_matches_cohort_source': True, 'inputs': inputs,
                'method': 'native_go_list_deps_compiled_json_CGO0', 'inventory_sha256': hashlib.sha256(m.canonical(inputs)).hexdigest()},
            'recipe': {'sha256': hashlib.sha256(recipe).hexdigest()}, 'privacy': {'policy_digest': self.policy_digest}}
        d, p = self.root / 'delivery/delivery.json', self.root / 'identity/result.json'
        d.write_text(json.dumps(delivery)); p.write_text(json.dumps(proof))
        args = dict(delivery=d, delivery_sha256=m.sha(d), proof=p, proof_sha256=m.sha(p), core=self.root / 'core',
                    client=self.root / 'client', client_commit='5' * 40, toolkit=self.root / 'toolkit', toolkit_commit='6' * 40,
                    policy=self.policy, output=self.root / 'output')
        def git(repository, *values):
            selected = values[1]
            if Path(repository) == args['core']: return recipe
            return (m.ROOT / selected.split(':', 1)[1]).read_bytes()
        def committed(repository, commit, scanner, toolkit=False):
            return [('README.md', b'public source\n', 0o644)], {'commit': commit, 'tree': '7' * 40, 'file_count': 1, 'scanner_exceptions': []}
        return args, git, committed, original

    def test_exact_git_files_ignore_dirty_working_copy(self):
        repository, commit = self.repository({'README.md': b'committed public bytes\n'})
        (repository / 'README.md').write_bytes(b'local changed bytes')
        rows, identity = m.committed_files(repository, commit, self.scanner)
        self.assertEqual(rows, [('README.md', b'committed public bytes\n', 0o644)])
        self.assertEqual(identity['commit'], commit); self.assertEqual(identity['file_count'], 1)

    def test_actual_publisher_contamination_and_private_cache_path_refuse(self):
        repository, commit = self.repository({'go-cache/file': b'otherwise harmless'})
        with self.assertRaisesRegex(ValueError, 'Private evidence/cache'):
            m.committed_files(repository, commit, self.scanner, toolkit=True)
        with self.assertRaises(ValueError): self.scanner.scan('README.md', b'SYNTHETIC_SOURCE_PUBLISHER')

    def test_tar_is_deterministic_neutral_and_never_replaces_output(self):
        rows = [('source/main.go', b'package main\n', 0o644), ('run', b'#!/bin/sh\n', 0o755)]
        first, second = self.root / 'one.tar', self.root / 'two.tar'
        m.write_tar(first, rows); m.write_tar(second, list(reversed(rows)))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            for entry in archive:
                self.assertTrue(entry.isfile()); self.assertEqual((entry.uid, entry.gid, entry.mtime), (0, 0, 0))
                self.assertEqual((entry.uname, entry.gname), ('', ''))
        with self.assertRaises(ValueError): m.write_tar(first, rows)
        with self.assertRaises(ValueError): m.write_tar(self.root / 'escape.tar', [('../outside', b'x', 0o644)])
        with self.assertRaises(ValueError): m.write_tar(self.root / 'duplicates.tar', [rows[0], rows[0]])

    def test_composite_retains_exact_selected_nested_bytes_and_no_original_tree_claim(self):
        args, git, committed, original = self.fixture()
        with patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=committed):
            result = m.prepare(**args)
        self.assertFalse(result['exact_original_full_tree_reconstruction'])
        self.assertFalse(result['publication_authorized']); self.assertFalse(result['release_acceptance_complete'])
        with tarfile.open(args['output'] / result['archive']['name']) as archive:
            self.assertEqual(archive.extractfile('d06/corresponding-source.tar').read(), original)
            self.assertEqual(archive.extractfile('d08/qxctl-original-source-proof.json').read(), args['proof'].read_bytes())
            self.assertEqual(len(archive.getmembers()), 7)

    def test_changed_selected_input_is_refused_before_output_creation(self):
        args, git, committed, _ = self.fixture(); args['proof'].write_bytes(b'{}')
        with patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=committed), self.assertRaises(ValueError):
            m.prepare(**args)
        self.assertFalse(args['output'].exists())

    def test_snapshot_prevents_late_input_change_from_entering_selected_archive(self):
        args, git, committed, original = self.fixture(); proof_bytes = args['proof'].read_bytes()
        def mutate(*a, **kw):
            (args['delivery'].parent / 'corresponding-source.tar').write_bytes(b'changed after selected snapshot')
            args['proof'].write_bytes(b'changed proof after selected snapshot')
            return committed(*a, **kw)
        with patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=mutate): result = m.prepare(**args)
        with tarfile.open(args['output'] / result['archive']['name']) as archive:
            self.assertEqual(archive.extractfile('d06/corresponding-source.tar').read(), original)
            self.assertEqual(archive.extractfile('d08/qxctl-original-source-proof.json').read(), proof_bytes)

    def test_symlink_ancestor_and_input_overlap_are_refused(self):
        args, git, committed, _ = self.fixture(); target = self.root / 'real'; target.mkdir(); alias = self.root / 'alias'; alias.symlink_to(target)
        for output in (alias / 'new', args['core'] / 'new', args['toolkit'] / 'new', args['delivery'].parent / 'new'):
            with self.subTest(output=output), patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=committed), self.assertRaises(ValueError):
                m.prepare(**{**args, 'output': output})
            self.assertFalse(output.exists())

    def test_selected_toolkit_must_contain_current_executing_helper_bytes(self):
        args, git, committed, _ = self.fixture()
        def older(repository, *values):
            return b'older helper' if Path(repository) == args['toolkit'] else git(repository, *values)
        with patch.object(m, 'git', side_effect=older), patch.object(m, 'committed_files', side_effect=committed), self.assertRaisesRegex(ValueError, 'Executing source helper'):
            m.prepare(**args)
        self.assertFalse(args['output'].exists())

    def test_different_or_changed_privacy_policy_is_refused(self):
        args, git, committed, _ = self.fixture()
        original = self.policy.read_bytes(); other = json.loads(original); other['markers'] = ['OTHER_SOURCE_PUBLISHER']
        self.policy.write_text(json.dumps(other))
        with patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=committed), self.assertRaises(ValueError):
            m.prepare(**args)
        self.assertFalse(args['output'].exists()); self.policy.write_bytes(original)
        def mutate(*a, **kw):
            self.policy.write_bytes(original + b'\n')
            return committed(*a, **kw)
        with patch.object(m, 'git', side_effect=git), patch.object(m, 'committed_files', side_effect=mutate), self.assertRaises(ValueError):
            m.prepare(**args)

    def test_compiled_input_ledger_cannot_be_empty_repeated_or_inconsistent(self):
        args, _, _, archive = self.fixture(); proof = json.loads(args['proof'].read_bytes())
        m.verify_compiled_source(archive, proof)
        for change in ('empty', 'duplicate', 'hash', 'method'):
            altered = copy.deepcopy(proof); ledger = altered['compiled_input_equivalence']
            if change == 'empty': ledger['inputs'] = []
            elif change == 'duplicate': ledger['inputs'] *= 2
            elif change == 'hash': ledger['inventory_sha256'] = 'f' * 64
            else: ledger['method'] = 'boolean assertion only'
            with self.subTest(change=change), self.assertRaises(ValueError): m.verify_compiled_source(archive, altered)

    def test_matching_ledger_must_describe_actual_packaged_compiled_source(self):
        args, _, _, archive = self.fixture(); proof = json.loads(args['proof'].read_bytes())
        for field, value in (('sha256', 'f' * 64), ('size', 1), ('mode', 0o755), ('path', 'tools/qxctl/missing.go')):
            altered = copy.deepcopy(proof); ledger = altered['compiled_input_equivalence']; ledger['inputs'][0][field] = value
            ledger['inventory_sha256'] = hashlib.sha256(m.canonical(ledger['inputs'])).hexdigest()
            with self.subTest(field=field), self.assertRaises(ValueError): m.verify_compiled_source(archive, altered)

    def test_repeated_or_linked_compiled_archive_member_refuses(self):
        args, _, _, _ = self.fixture(); proof = json.loads(args['proof'].read_bytes())
        for linked in (False, True):
            blob = io.BytesIO()
            with tarfile.open(fileobj=blob, mode='w') as archive:
                for _ in range(1 if linked else 2):
                    entry = tarfile.TarInfo('symphony-source/tools/qxctl/main.go'); entry.mode = 0o644
                    if linked:
                        entry.type = tarfile.SYMTYPE; entry.linkname = '/outside'; archive.addfile(entry)
                    else:
                        raw = b'package main\n'; entry.size = len(raw); archive.addfile(entry, io.BytesIO(raw))
            with self.subTest(linked=linked), self.assertRaises(ValueError): m.verify_compiled_source(blob.getvalue(), proof)


if __name__ == '__main__': unittest.main()
