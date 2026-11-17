import copy
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import qxctl_identity as q


class QxctlIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'source'; self.module = self.source / q.MODULE
        self.module.mkdir(parents=True)
        for name, raw in (('main.go', b'package main\n'), ('schema.json', b'{}'), ('testdata.json', b'private fixture')):
            (self.module / name).write_bytes(raw)

    def tearDown(self): self.tmp.cleanup()

    def package(self):
        return {'ImportPath': q.MODULE_ID + '/cmd/qxctl', 'Dir': str(self.module),
                'Module': {'Main': True, 'Path': q.MODULE_ID}, 'GoFiles': ['main.go'],
                'CompiledGoFiles': [str(self.module / 'main.go')], 'EmbedFiles': ['schema.json']}

    def test_compiler_and_embed_inputs_are_exact_without_test_fixture(self):
        rows = q.compiled_inputs([self.package()], self.source)
        self.assertEqual([r['path'] for r in rows], [q.MODULE + '/main.go', q.MODULE + '/schema.json'])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows, q.compiled_inputs([self.package()], self.source))

    def test_changed_compiler_or_embedded_bytes_refuse_equivalence(self):
        rows = q.compiled_inputs([self.package()], self.source)
        for name in ('main.go', 'schema.json'):
            with self.subTest(name=name):
                path = self.module / name; before = path.read_bytes(); path.write_bytes(before + b'x')
                with self.assertRaises(ValueError): q.equal_inputs(rows, q.compiled_inputs([self.package()], self.source))
                path.write_bytes(before)

    def test_compiler_input_mode_and_selected_membership_are_bound(self):
        rows = q.compiled_inputs([self.package()], self.source)
        changed = copy.deepcopy(rows); changed[0]['mode'] ^= 0o111
        with self.assertRaises(ValueError): q.equal_inputs(rows, changed)
        changed = self.package(); changed['EmbedFiles'] = []
        with self.assertRaises(ValueError): q.equal_inputs(rows, q.compiled_inputs([changed], self.source))

    def test_package_errors_replacements_escape_and_links_refuse(self):
        changes = [{'Error': {}}, {'Incomplete': True}, {'Module': {'Main': True, 'Path': 'other'}},
                   {'Module': {'Main': True, 'Path': q.MODULE_ID, 'Replace': {'Path': 'other'}}},
                   {'GoFiles': ['../outside.go']}, {'Dir': str(self.root)}]
        # A nonempty error record is what Go emits.
        changes[0] = {'Error': {'Err': 'failed'}}
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                q.compiled_inputs([{**self.package(), **change}], self.source)
        (self.module / 'schema.json').unlink(); (self.module / 'schema.json').symlink_to(self.module / 'main.go')
        with self.assertRaises(ValueError): q.compiled_inputs([self.package()], self.source)

    def test_missing_executable_and_duplicate_packages_refuse(self):
        row = self.package(); row['ImportPath'] = q.MODULE_ID + '/internal/example'
        with self.assertRaises(ValueError): q.compiled_inputs([row], self.source)
        with self.assertRaises(ValueError): q.compiled_inputs([self.package(), self.package()], self.source)

    def test_environment_is_local_only_and_discards_ambient_settings(self):
        cache = self.root / 'module cache'; (cache / 'cache/download').mkdir(parents=True)
        with patch.dict(os.environ, {'GOPROXY': 'https://example.invalid,direct', 'GOFLAGS': '-tags=private',
                                    'AWS_SECRET_ACCESS_KEY': 'fixture', 'GOOS': 'other'}):
            env = q.clean_environment(self.root, Path('/selected/go'), Path('/selected/cmake'), cache)
        self.assertEqual(env['GOPROXY'], (cache / 'cache/download').as_uri())
        self.assertNotIn(',', env['GOPROXY']); self.assertNotIn('|', env['GOPROXY'])
        self.assertEqual(env['GOVCS'], '*:off'); self.assertEqual(env['GOAUTH'], 'off')
        self.assertEqual(env['CGO_ENABLED'], '0')
        for name in ('AWS_SECRET_ACCESS_KEY', 'GOFLAGS', 'GOOS', 'GOTOOLDIR'): self.assertNotIn(name, env)

    def test_output_never_adopts_existing_or_overlapping_paths(self):
        for output in (self.source, self.source / 'new', self.root):
            with self.subTest(output=output), self.assertRaises(ValueError): q.fresh(output, [self.source])
        alias = self.root / 'alias'; alias.symlink_to(self.source)
        with self.assertRaises(ValueError): q.fresh(alias / 'new', [])
        self.assertFalse((self.source / 'new').exists())

    def test_graph_requires_full_exact_frozen_selection_and_checksums(self):
        rows = [{'Path': q.MODULE_ID, 'Main': True}, {'Path': 'example.org/a', 'Version': 'v1.2.3', 'Sum': 'h1:exact'}]
        q.graph_matches(rows, rows)
        for key, value in (('Version', 'v2.0.0'), ('Sum', 'h1:changed'), ('Replace', {'Path': 'other'})):
            changed = copy.deepcopy(rows); changed[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): q.graph_matches(changed, rows)
        with self.assertRaises(ValueError): q.graph_matches(rows[:1], rows)

    def test_artifact_cannot_upgrade_derived_inputs_or_skip_reproduction(self):
        expected = {'source_commit': '1' * 40, 'source_tree': '2' * 40, 'build_recipe': q.RECIPE}
        info = {'protocol': 'symphony.qxctl.build-info.v1', 'component_id': 'qxctl', 'version': '0.1.0-dev',
                'source_state': 'stamped', 'executable_sha256': '3' * 64, **expected}
        evidence = {'protocol': 'symphony.artifact-build-identity.v1', 'component_id': 'qxctl', 'version': '0.1.0-dev',
                    'isolated_builds': 2, 'reproducibility': 'verified_on_recorded_profile',
                    'publication_authorized': False, 'executable_sha256': '3' * 64, **expected}
        q.validate_artifact(evidence, info, expected, '3' * 64)
        for changes in ({'source_tree': '4' * 40}, {'build_recipe': 'derived-build'}, {'isolated_builds': 1}, {'publication_authorized': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                q.validate_artifact({**evidence, **changes}, info, expected, '3' * 64)
        with self.assertRaises(ValueError): q.validate_artifact(evidence, {**info, 'source_state': 'unavailable'}, expected, '3' * 64)

    def test_archive_links_and_unselected_members_refuse(self):
        for name, kind in ((q.MODULE + '/link', tarfile.SYMTYPE), ('outside/file', tarfile.REGTYPE)):
            archive = self.root / 'archive.tar'
            with tarfile.open(archive, 'w') as output:
                item = tarfile.TarInfo(name); item.type = kind; item.linkname = '/outside'; output.addfile(item, io.BytesIO())
            destination = self.root / ('out-' + str(kind))
            with self.subTest(name=name), self.assertRaises(ValueError): q.extract(archive, destination)

    def test_raw_source_requires_entire_original_tree_bytes_and_modes(self):
        rows = []
        for record in q.inventory(self.source):
            raw = (self.source / record['path']).read_bytes()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            rows.append(('100644 blob ' + blob + '\t' + record['path']).encode())
        with patch.object(q, 'git', return_value=b'\0'.join(rows) + b'\0'):
            q.raw_source_matches(self.root, self.source, '1' * 40)
            (self.source / 'extra').write_bytes(b'not original')
            with self.assertRaises(ValueError): q.raw_source_matches(self.root, self.source, '1' * 40)
            (self.source / 'extra').unlink(); (self.module / 'testdata.json').write_bytes(b'sanitized')
            with self.assertRaises(ValueError): q.raw_source_matches(self.root, self.source, '1' * 40)


if __name__ == '__main__': unittest.main()
