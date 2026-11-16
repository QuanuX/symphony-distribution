"""Source, platform, package and privacy boundaries for primary client qualification."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from qualification import primary_client as p


class Scan:
    def scan(self, name, raw):
        if b'PRIVATE-TEST-MARKER' in raw:
            raise ValueError('private test marker')


class PrimaryClientTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.root = Path(self.work.name).resolve()

    def tearDown(self):
        self.work.cleanup()

    def file(self, name, data=b'public', mode=0o644):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(mode)
        return path

    def archive(self, members):
        path = self.root / 'codex.tar.gz'
        with tarfile.open(path, 'w:gz') as out:
            for name, kind, raw in members:
                row = tarfile.TarInfo(name); row.type = kind; row.mode = 0o755; row.size = len(raw)
                if kind == tarfile.SYMTYPE: row.linkname = '/outside'
                out.addfile(row, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
        return path, {'size': path.stat().st_size, 'sha256': p.sha(path), 'member': 'codex-target'}

    def git_source(self, private=False):
        root = self.root / 'git'; root.mkdir()
        subprocess.run(['git', 'init', '-q', root], check=True)
        (root / 'LICENSE').write_text('PRIVATE-TEST-MARKER' if private else 'legal attribution')
        (root / 'script').write_text('code'); (root / 'script').chmod(0o755)
        subprocess.run(['git', '-C', root, 'add', '.'], check=True)
        env = dict(os.environ, GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
                   GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        subprocess.run(['git', '-C', root, 'commit', '-qm', 'fixture'], env=env, check=True)
        selected = dict(p.CLIENT, commit=p.git(root, 'rev-parse', 'HEAD').decode().strip(),
                        tree=p.git(root, 'rev-parse', 'HEAD^{tree}').decode().strip())
        return root, selected

    def derived(self):
        original = self.root / 'source'; original.mkdir()
        files = {}
        for name in sorted(p.DERIVED | {'src/main.cpp'}):
            path = original / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode()); path.chmod(0o644)
            files[name] = {'sha256': p.sha(path), 'mode': 0o644, 'git_blob': 'a' * 40}
        import shutil
        derived = self.root / 'derived'; shutil.copytree(original, derived)
        generated = {name: ('generated ' + name).encode() for name in p.DERIVED}
        for name, raw in generated.items(): (derived / name).write_bytes(raw)
        return original, derived, {'source': p.CLIENT, 'files': files, 'git_archive_sha256': '2' * 64}, generated

    def test_all_primary_assets_have_verified_explicit_release_pins(self):
        assets = set()
        for profile in p.gate.PROFILES:
            lock, row = p.codex_lock(profile)
            self.assertEqual(lock['source_commit'], 'd32063f96c2dff1dc96af839b3952abb6acfeda4')
            self.assertNotIn('/latest/', row['url']); self.assertGreater(row['size'], 100_000_000)
            assets.add(row['sha256'])
        self.assertEqual(len(assets), 3)
        with self.assertRaises(ValueError): p.codex_lock('local-macos-amd64-fixture')

    def test_pinned_single_executable_extracts_without_archive_modes(self):
        archive, row = self.archive([('codex-target', tarfile.REGTYPE, b'executable')])
        selected = p.extract_codex(archive, self.root / 'out', row)
        self.assertEqual(selected.read_bytes(), b'executable')
        self.assertEqual(stat.S_IMODE(selected.stat().st_mode), 0o755)

    def test_wrong_asset_digest_refuses_before_extraction(self):
        archive, row = self.archive([('codex-target', tarfile.REGTYPE, b'executable')])
        row['sha256'] = '0' * 64
        with self.assertRaises(ValueError): p.extract_codex(archive, self.root / 'out', row)
        self.assertFalse((self.root / 'out').exists())

    def test_archive_link_refused(self):
        archive, row = self.archive([('codex-target', tarfile.SYMTYPE, b'')])
        with self.assertRaises(ValueError): p.extract_codex(archive, self.root / 'out', row)

    def test_archive_extra_member_refused(self):
        archive, row = self.archive([('codex-target', tarfile.REGTYPE, b'x'), ('extra', tarfile.REGTYPE, b'y')])
        with self.assertRaises(ValueError): p.extract_codex(archive, self.root / 'out', row)

    def test_archive_path_escape_refused(self):
        archive, row = self.archive([('../codex-target', tarfile.REGTYPE, b'x')])
        with self.assertRaises(ValueError): p.extract_codex(archive, self.root / 'out', row)

    def test_export_actual_git_blobs_and_modes_not_dirty_worktree(self):
        repository, selected = self.git_source()
        (repository / 'LICENSE').write_text('unselected working copy')
        with patch.object(p, 'CLIENT', selected):
            record = p.export_client(repository, self.root / 'export', Scan())
        self.assertEqual((self.root / 'export/LICENSE').read_text(), 'legal attribution')
        self.assertEqual(record['files']['script']['mode'], 0o755)
        p.verify_export(self.root / 'export', record)

    def test_unselected_client_git_commit_refused(self):
        repository, _ = self.git_source()
        with self.assertRaises(ValueError): p.export_client(repository, self.root / 'export', Scan())

    def test_source_privacy_marker_refused(self):
        repository, selected = self.git_source(private=True)
        with patch.object(p, 'CLIENT', selected), self.assertRaises(ValueError):
            p.export_client(repository, self.root / 'export', Scan())

    def test_exact_three_file_derivation_is_honest(self):
        original, derived, record, generated = self.derived()
        proof = p.derivation_proof(original, derived, record, generated, 'macos15-arm64', '1' * 64)
        self.assertFalse(proof['is_original_git_tree'])
        self.assertEqual(proof['origin'], p.CLIENT)
        self.assertEqual(proof['generated_paths'], sorted(p.DERIVED))

    def test_derived_runtime_source_change_refused(self):
        original, derived, record, generated = self.derived()
        (derived / 'src/main.cpp').write_bytes(b'changed runtime')
        with self.assertRaises(ValueError): p.derivation_proof(original, derived, record, generated, 'macos15-arm64', '1' * 64)

    def test_extra_generated_path_refused(self):
        original, derived, record, generated = self.derived()
        generated['src/main.cpp'] = b'runtime edit'
        with self.assertRaises(ValueError): p.derivation_proof(original, derived, record, generated, 'macos15-arm64', '1' * 64)

    def test_derived_source_link_refused(self):
        original, derived, record, generated = self.derived()
        path = derived / 'src/main.cpp'; path.unlink(); path.symlink_to(original / 'src/main.cpp')
        with self.assertRaises(ValueError): p.derivation_proof(original, derived, record, generated, 'macos15-arm64', '1' * 64)

    def test_original_source_tamper_refused(self):
        original, derived, record, generated = self.derived()
        (original / 'src/main.cpp').write_bytes(b'tamper')
        with self.assertRaises(ValueError): p.derivation_proof(original, derived, record, generated, 'macos15-arm64', '1' * 64)

    def test_private_environment_drops_auth_and_inherited_client_profiles(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'fixture', 'GH_TOKEN': 'fixture', 'CODEX_HOME': '/caller', 'CXXFLAGS': 'unsafe'}):
            env = p.clean_environment(self.root, ('/usr/bin/clang++',))
        for key in ('OPENAI_API_KEY', 'GH_TOKEN', 'CODEX_HOME', 'CXXFLAGS'):
            self.assertNotIn(key, env)
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertEqual(env['PYTHONNOUSERSITE'], '1')

    def test_nonzero_command_cannot_pass(self):
        env = p.clean_environment(self.root)
        with self.assertRaisesRegex(ValueError, 'Command failed'):
            p.command(['/bin/sh', '-c', 'exit 1'], env, self.root, 'refusal', 10)

    def test_output_existing_or_symlink_refused(self):
        path = self.file('original', b'original')
        with self.assertRaises(FileExistsError): p.write(path, b'replacement')
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(ValueError): p.write(link, b'replacement')
        self.assertEqual(path.read_bytes(), b'original')

    def test_package_links_and_duplicate_members_refused(self):
        path = self.root / 'package.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            row = zipfile.ZipInfo('catalog/tools.json'); row.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(row, b'/outside')
        with self.assertRaises(ValueError): p.package_inventory(path)

    def test_exact_final_package_extraction_and_tamper_refusal(self):
        path = self.root / 'package.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, raw, mode in [('catalog/tools.json', b'{}', 0o644), ('bin/symphony-mcp', b'binary', 0o755)]:
                row = zipfile.ZipInfo(name); row.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(row, raw)
        inventory = p.package_inventory(path); output = self.root / 'stage'
        p.unpack_package(path, output, inventory)
        p.verify_package_tree(output, inventory)
        (output / 'bin/symphony-mcp').write_bytes(b'tampered')
        with self.assertRaises(ValueError): p.verify_package_tree(output, inventory)

    def test_codex_admitted_executable_must_remain_unchanged(self):
        archive, row = self.archive([('codex-target', tarfile.REGTYPE, b'executable')])
        executable = p.extract_codex(archive, self.root / 'out', row); initial = p.sha(executable)
        p.verify_codex_unchanged(archive, executable, row, initial)
        executable.write_bytes(b'replacement')
        with self.assertRaises(ValueError): p.verify_codex_unchanged(archive, executable, row, initial)

    def test_existing_caller_directory_never_receives_failure_diagnostics(self):
        p.failure_summary(self.root, ValueError('fixture'))
        self.assertFalse((self.root / 'INCOMPLETE.json').exists())

    def test_replaced_owned_directory_never_receives_failure_diagnostics(self):
        output = self.root / 'owned'; output.mkdir()
        info = output.stat(); p.OWNED_OUTPUTS[output] = (info.st_dev, info.st_ino)
        output.rename(self.root / 'retained'); output.mkdir()
        p.failure_summary(output, ValueError('fixture'))
        self.assertFalse((output / 'INCOMPLETE.json').exists())

    def test_owned_failure_diagnostics_are_bounded_and_path_free(self):
        output = self.root / 'owned'; output.mkdir()
        info = output.stat(); p.OWNED_OUTPUTS[output] = (info.st_dev, info.st_ino)
        (output / 'actual-codex.log').write_bytes(b'private original log')
        p.failure_summary(output, ValueError(str(self.root)))
        result = json.loads((output / 'INCOMPLETE.json').read_bytes())
        self.assertEqual(result['last_command'], 'actual-codex')
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertNotIn('private original log', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
