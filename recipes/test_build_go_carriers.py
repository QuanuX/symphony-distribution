"""Self-contained archive-policy tests; Conda installation is not needed here."""
import copy
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

import build_go_carriers as b


class CarrierArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='symphony-conda-policy-')
        self.root = Path(self.tmp.name).resolve()
        self.carrier = self.root / 'carrier'
        self.carrier.mkdir(mode=0o700)
        self.catalog = b.strict_json((b.HERE.parent / 'go-owner-catalog.json').read_bytes())
        binding = b.d.owners.reviewed_binding()
        unit = b.d.owners.OWNERS['stav-append-authority']
        binary = b'synthetic qualification bytes; never executed\n'
        source = {x['path']: x['sha256'] for x in binding['source_evidence']}
        identity = {'protocol': 'symphony.artifact-build-identity.v1', 'component_id': unit['component_id'],
                    'version': unit['native_version'], 'binary_name': unit['binary_name'],
                    'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
                    'source_date_epoch': '1', 'dependency_map_sha256': source['cmake/mvp-dependencies.json'],
                    'release_identity_catalog_sha256': source['cmake/mvp-release-identities.json'],
                    'go_mod_sha256': source[unit['source_root'] + '/go.mod'],
                    'go_sum_sha256': source[unit['source_root'] + '/go.sum'],
                    'build_recipe': 'symphony.go.candidate-build.v1', 'go_version': 'go1.26.5', 'goos': 'darwin', 'goarch': 'amd64',
                    'executable_sha256': b.sha(binary), 'isolated_builds': 1, 'reproducibility': 'not_assessed',
                    'publication_authorized': False}
        for name, data, mode in [(unit['binary_name'], binary, 0o755),
                                  ('artifact-identity.json', b.canonical(identity) + b'\n', 0o644),
                                  ('LICENSE-AGPL-3.0', (b.HERE.parent / 'LICENSE').read_bytes(), 0o644)]:
            path = self.carrier / name
            path.write_bytes(data); path.chmod(mode)
        self.manifest = b.d.make_manifest(self.catalog, self.catalog['catalog_digest'], unit['component_id'], self.carrier,
                                          b.d.owners.FIXTURE_PROFILE, 0, fixture=True)
        (self.carrier / 'carrier-manifest.json').write_bytes(b.canonical(self.manifest) + b'\n')
        (self.carrier / 'carrier-manifest.json').chmod(0o644)
        self.recipe = self.root / 'recipe'
        self.record = b.g.render(self.catalog, self.catalog['catalog_digest'], self.carrier,
                                 self.manifest['manifest_digest'], self.recipe, fixture=True)
        _, _, self.expected = b.validate_recipe(self.recipe, self.manifest['manifest_digest'], fixture=True)
        self.entries = dict(self.expected)
        index = {'arch': 'x86_64', 'platform': 'osx', 'subdir': 'osx-64', 'build': self.record['build_string'],
                 'build_number': 0, 'depends': [], 'license': 'AGPL-3.0-only', 'name': self.manifest['conda_name'],
                 'timestamp': 1, 'version': self.manifest['conda_version']}
        paths = {'paths_version': 1, 'paths': [{'_path': name, 'path_type': 'hardlink', 'sha256': b.sha(data),
                                              'size_in_bytes': len(data)} for name, (data, _) in sorted(self.expected.items())]}
        about = {'channels': [], 'conda_build_version': '26.9.1', 'conda_version': '26.10.0', 'env_vars': {'CIO_TEST': '<not set>'},
                 'identifiers': [], 'keywords': [], 'license': 'AGPL-3.0-only', 'license_file': 'LICENSE-AGPL-3.0', 'root_pkgs': [], 'tags': [],
                 'summary': 'Inert Symphony stav-append-authority payload; explicit owner materialization required',
                 'extra': {'copy_test_source_files': True, 'final': True, 'fixture': True, 'native_version': '0.2.1',
                           'owner_contract': self.manifest['owner_contract'], 'publication_authorized': False,
                           'runtime_activation': False, 'runtime_python_dependency': False, 'target_subdir': 'osx-64'}}
        for name, value in [('info/index.json', index), ('info/paths.json', paths), ('info/about.json', about), ('info/hash_input.json', {})]:
            self.entries[name] = (b.canonical(value), 0o644)
        self.entries['info/files'] = (('\n'.join(sorted(self.expected)) + '\n').encode(), 0o644)
        self.entries['info/git'] = (b'', 0o644)
        self.entries['info/licenses/LICENSE-AGPL-3.0'] = ((b.HERE.parent / 'LICENSE').read_bytes(), 0o644)

    def tearDown(self):
        self.tmp.cleanup()

    def audit(self, entries=None, **kwargs):
        return b.audit_entries(self.entries if entries is None else entries, self.manifest, self.record, self.expected, **kwargs)

    def change_json(self, entries, path, change):
        value = b.strict_json(entries[path][0]); change(value)
        entries[path] = (b.canonical(value), 0o644)

    def test_exact_inert_archive_contract(self):
        result = self.audit()
        self.assertTrue(result['exact_payload_verified'])
        self.assertFalse(result['publication_authorized'])
        self.assertFalse(result['fresh_host_accepted'])
        self.assertEqual(result['runtime_dependencies'], [])
        self.assertIn('include_recipe: false', (self.recipe / 'meta.yaml').read_text())
        self.assertIn('$SYS_PYTHON', (self.recipe / 'meta.yaml').read_text())
        self.assertNotIn('requirements:', (self.recipe / 'meta.yaml').read_text())

    def test_two_packaging_builds_keep_one_native_identity(self):
        other = dict(self.manifest)
        other.pop('manifest_digest'); other['build_number'] = 1
        other = b.d.owners.sealed(other, 'manifest_digest')
        second = b.g.recipe_documents(other)[3]
        self.assertNotEqual(second['build_string'], self.record['build_string'])
        self.assertNotEqual(second['carrier_destination'], self.record['carrier_destination'])
        self.assertEqual(other['native_version'], self.manifest['native_version'])
        self.assertEqual(other['files'], self.manifest['files'])
        self.assertEqual(other['source_commit'], self.manifest['source_commit'])

    def test_hooks_host_state_recipe_and_python_payload_refused(self):
        for name in ['bin/.package-post-link.sh', 'etc/conda/activate.d/start.sh', '.symphony-package-retirement/state',
                     'info/recipe/meta.yaml', 'lib/python3.12/site.py', 'build/cache.o']:
            with self.subTest(name=name):
                entries = dict(self.entries); entries[name] = (b'unselected', 0o644)
                with self.assertRaises(ValueError): self.audit(entries)

    def test_runtime_dependency_and_prefix_replacement_refused(self):
        entries = dict(self.entries)
        self.change_json(entries, 'info/index.json', lambda value: value.update(depends=['python >=3.12']))
        with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries)
        self.change_json(entries, 'info/paths.json', lambda value: value['paths'][0].update(prefix_placeholder='/build/prefix'))
        with self.assertRaises(ValueError): self.audit(entries)

    def test_personal_and_neutral_build_paths_refused(self):
        for marker in [b'/' + b'Users/' + b'synthetic-publisher/private', b'/' + b'home/' + b'fixture/private', b'-----BEGIN PRIVATE KEY-----']:
            with self.subTest(marker=marker):
                entries = dict(self.entries); entries['info/git'] = (marker, 0o644)
                with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries); entries['info/git'] = (b'/private/tmp/selected-build/work', 0o644)
        with self.assertRaises(ValueError): self.audit(entries, forbidden=(b'/private/tmp/selected-build',))

    def test_payload_license_and_metadata_tampering_refused(self):
        for name in [next(iter(self.expected)), 'info/licenses/LICENSE-AGPL-3.0', 'info/git']:
            with self.subTest(name=name):
                entries = dict(self.entries); data, mode = entries[name]; entries[name] = (data + b'changed', mode)
                with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries)
        self.change_json(entries, 'info/index.json', lambda value: value.update(build_number=1))
        with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries)
        self.change_json(entries, 'info/about.json', lambda value: value['extra'].update(runtime_activation=True))
        with self.assertRaises(ValueError): self.audit(entries)

    def test_conda_group_write_only_allowed_before_normalization(self):
        entries = dict(self.entries)
        for name in self.expected:
            data, mode = entries[name]; entries[name] = (data, mode | 0o020)
        with self.assertRaises(ValueError): self.audit(entries)
        self.audit(entries, allow_conda_mode_expansion=True)
        name = next(iter(self.expected)); entries[name] = (entries[name][0], 0o777)
        with self.assertRaises(ValueError): self.audit(entries, allow_conda_mode_expansion=True)

    def test_missing_duplicate_and_wrong_content_inventory_refused(self):
        entries = dict(self.entries); del entries['info/files']
        with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries); entries['info/files'] = (entries['info/files'][0] * 2, 0o644)
        with self.assertRaises(ValueError): self.audit(entries)
        entries = dict(self.entries)
        self.change_json(entries, 'info/paths.json', lambda value: value['paths'][0].update(sha256='0' * 64))
        with self.assertRaises(ValueError): self.audit(entries)

    def test_modified_recipe_and_unreviewed_source_refused(self):
        path = self.recipe / 'meta.yaml'; path.write_bytes(path.read_bytes() + b'\ntest: {}\n')
        with self.assertRaises(ValueError): b.validate_recipe(self.recipe, self.manifest['manifest_digest'], fixture=True)
        manifest = dict(self.manifest); manifest.pop('manifest_digest'); manifest['source_commit'] = '0' * 40
        manifest = b.d.owners.sealed(manifest, 'manifest_digest')
        (self.recipe / 'payload/carrier-manifest.json').write_bytes(b.canonical(manifest) + b'\n')
        with self.assertRaises(ValueError): b.validate_recipe(self.recipe, manifest['manifest_digest'], fixture=True)

    def test_coherent_unreviewed_source_cannot_replace_reviewed_binding(self):
        # Update every dependent self-digest and generated instruction so only
        # the independent reviewed source binding can reject this candidate.
        identity_path = self.recipe / 'payload/artifact-identity.json'
        identity = b.strict_json(identity_path.read_bytes())
        identity['source_commit'] = '0' * 40
        identity_bytes = b.canonical(identity) + b'\n'
        identity_path.write_bytes(identity_bytes)
        manifest = dict(self.manifest); manifest.pop('manifest_digest')
        manifest['source_commit'] = '0' * 40
        manifest['files'] = [dict(row) for row in manifest['files']]
        for row in manifest['files']:
            if row['path'] == 'artifact-identity.json':
                row['sha256'] = b.sha(identity_bytes); row['size'] = len(identity_bytes)
        manifest = b.d.owners.sealed(manifest, 'manifest_digest')
        meta, stage, raw_manifest, record = b.g.recipe_documents(manifest)
        for name, data in [('meta.yaml', meta), ('stage_payload.py', stage),
                           ('recipe-evidence.json', b.canonical(record) + b'\n'), ('payload/carrier-manifest.json', raw_manifest)]:
            (self.recipe / name).write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'source differs'):
            b.validate_recipe(self.recipe, manifest['manifest_digest'], fixture=True)

    def test_fixture_opt_in_and_safe_paths(self):
        with self.assertRaises(ValueError): b.validate_recipe(self.recipe, self.manifest['manifest_digest'])
        for name in ['/absolute', '../parent', 'a/../b', 'a\\b', 'a\nname']:
            with self.assertRaises(ValueError): b.safe_name(name)

    def test_zip_hidden_metadata_is_refused(self):
        def archive(extra=b'', comment=b''):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as zipped:
                for name in ['metadata.json', 'pkg-fixture.tar.zst', 'info-fixture.tar.zst']:
                    member = zipfile.ZipInfo(name); member.extra = extra
                    zipped.writestr(member, b'bounded fixture data')
                zipped.comment = comment
            return output.getvalue()
        raw = archive()
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            b.validate_zip_layout(raw, zipped)
        for unsafe in [b'unreviewed-prefix' + raw, raw + b'unreviewed-tail', archive(comment=b'private-comment'),
                       archive(extra=b'\xfe\xca\x04\x00data')]:
            with zipfile.ZipFile(io.BytesIO(unsafe)) as zipped:
                with self.assertRaises(ValueError): b.validate_zip_layout(unsafe, zipped)

    def test_private_recipe_snapshot_ignores_later_source_edits(self):
        # Retain the already validated values, then alter both source recipe
        # instructions and payload before publisher execution would begin.
        (self.recipe / 'meta.yaml').write_text('build: {script: "unreviewed command"}\n')
        (self.recipe / 'stage_payload.py').write_text('raise RuntimeError("unreviewed script")\n')
        binary = self.recipe / 'payload/symphony-stav-append-authority'
        binary.write_bytes(b'unreviewed replacement bytes')
        path = b.snapshot_recipe(self.manifest, self.record, self.expected, self.root / 'snapshot')
        _, _, actual = b.validate_recipe(path, self.manifest['manifest_digest'], fixture=True)
        self.assertEqual(actual, self.expected)
        self.assertNotIn('unreviewed', (path / 'meta.yaml').read_text())
        changed = dict(self.record); changed['renderer_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            b.snapshot_recipe(self.manifest, changed, self.expected, self.root / 'refused')
        self.assertFalse((self.root / 'refused').exists())

    def test_timeout_kills_term_ignoring_child_with_redirected_output(self):
        ready = self.root / 'child-ready'
        survivor = self.root / 'child-survived'
        script = """import os,signal,time,sys
from pathlib import Path
if os.fork() == 0:
 signal.signal(signal.SIGTERM, signal.SIG_IGN)
 Path(sys.argv[1]).write_text('ready')
 time.sleep(2)
 Path(sys.argv[2]).write_text('survived')
else:
 time.sleep(10)
"""
        with (self.root / 'publisher.log').open('wb') as log:
            with self.assertRaisesRegex(ValueError, 'timed out'):
                b.run_owned([sys.executable, '-c', script, str(ready), str(survivor)], stdout=log, stderr=log, timeout=1)
        self.assertTrue(ready.exists(), 'regression did not establish its ignoring-TERM child')
        time.sleep(1.2)
        self.assertFalse(survivor.exists())

    def test_publisher_timeout_reaps_owned_process(self):
        with self.assertRaisesRegex(ValueError, 'timed out'):
            b.run_owned([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.05)


if __name__ == '__main__':
    unittest.main()
