"""Exact native ownership and opaque carrier regressions; no runtime activation."""
import copy
import io
import importlib.util
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import carriers as c


class CarrierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.prefix = self.root / 'prefix'; self.prefix.mkdir()
        self.rows, native, mapping, go = [], [], [], []
        for i in range(51):
            cid = 'unit-' + str(i); name = 'lib/' + cid + '.a'; raw = ('library ' + cid).encode()
            self.add(name, raw, 0o755 if i == 0 else 0o644)
            body = {'protocol': 'symphony.knowledge.install-receipt.v2', 'format_version': 2,
                    'component_id': cid, 'version': '1.0.0',
                    'files': [{'path': name, 'digest': 'sha256:' + c.sha(raw), 'size': len(raw),
                               'kind': 'executable' if i == 0 else 'regular'}]}
            receipt = {**body, 'receipt_digest': 'sha256:' + c.sha(c.canonical(body))}
            rp = 'share/symphony/receipts/' + cid + '/1.0.0/install-receipt.json'; rr = c.canonical(receipt)
            self.add(rp, rr)
            native.append({'component_id': cid, 'version': '1.0.0', 'receipt_path': rp,
                'receipt_sha256': c.sha(rr), 'files': [name], 'source_root': 'modules/' + cid,
                'external_dependency_refs': ['CURL'] if i == 0 else [], 'build_provenance': {'kind': 'fixture_only'}})
            mapping.append({'component_id': cid, 'path': 'modules/' + cid, 'package_release_version': '1.0.0',
                'dependency_paths_in_build_order': ['modules/unit-0'] if i == 1 else [],
                'exported_packages': [{'package': 'ExampleSDK'}] if i == 1 else []})
        for cid in ('qxctl', 'go1', 'go2', 'go3', 'go4', 'go5'):
            name = 'go/' + cid + '/bin/' + cid; self.add(name, cid.encode(), 0o755)
            go.append({'id': 'go:' + cid, 'path': name, 'version': '1.0.0', 'sha256': c.sha(cid.encode()),
                       'build_provenance': {'kind': 'fixture_only'}, 'linked_modules': []})
        self.add('third-party/lib/libcurl.4.8.0.dylib', b'curl')
        for name, target in [('libcurl.4.dylib', 'libcurl.4.8.0.dylib'), ('libcurl.dylib', 'libcurl.4.dylib')]:
            rel = 'third-party/lib/' + name; (self.prefix / rel).symlink_to(target); self.rows.append({'path': rel, 'link': target})
        self.delivery = {'native_components': native, 'go_artifacts': go,
            'external_dependencies': {'files': [r['path'] for r in self.rows if r['path'].startswith('third-party/')], 'build_selection': {'fixture': True}}}
        self.candidate = {'payload_inventory': self.rows, 'go_commands': [dict(component_id=x['id'][3:], version=x['version'], sha256=x['sha256']) for x in go]}
        self.candidate['qxctl_source_proof_sha256'] = 'a' * 64
        self.candidate['qxctl_original_git_override'] = {'component_id': 'qxctl', 'sha256': c.sha(b'qxctl'),
            'cohort_compiled_inputs_equal': True, 'source_commit': 'b' * 40, 'source_tree': 'c' * 40}
        self.candidate['go_commands'][0].update(source_kind='original_git_recipe_with_equal_cohort_compiled_inputs',
            qxctl_source_proof_sha256='a' * 64)
        self.mapping = {'native_components': mapping}

    def add(self, name, raw, mode=0o644):
        path = self.prefix / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(mode)
        self.rows.append(c.file_row(name, raw, mode))

    def partition(self): return c.partition(self.prefix, self.delivery, self.candidate, self.mapping)

    def test_full_payload_assigned_once_and_sdk_stays_with_owner(self):
        units, assigned, inventory = self.partition()
        self.assertEqual(len(units), 58); self.assertEqual(set(assigned), set(inventory))
        selected = c.dependency_selection(units, ['native:unit-1'])
        self.assertEqual(selected, ['external:curl-zstd', 'native:unit-0', 'native:unit-1'])
        self.assertEqual(len([u for u in units if u['sdk_exports']]), 1)
        external = next(u for u in units if u['kind'] == 'external_inert_runtime_and_sdk')
        self.assertIsNone(external['native_runtime_owner'])

    def test_qxctl_exact_source_override_is_retained_and_required(self):
        units, _, _ = self.partition()
        qxctl = next(u for u in units if u['unit_id'] == 'go:qxctl')
        self.assertEqual(qxctl['provenance']['source_override'], self.candidate['qxctl_original_git_override'])
        self.assertEqual(qxctl['provenance']['qxctl_source_proof_sha256'], 'a' * 64)
        self.candidate['go_commands'][0]['qxctl_source_proof_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'source override'): self.partition()
        del self.candidate['qxctl_original_git_override']
        with self.assertRaises(KeyError): self.partition()

    def test_hidden_member_padding_is_refused(self):
        rows = [c.file_row('a', b'x'), c.file_row('b', b'y')]; p = self.root / 'payload.tar'
        c.write_tar(p, rows, {'a': lambda: b'x', 'b': lambda: b'y'})
        raw = bytearray(p.read_bytes()); raw[513:520] = b'private'; p.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'Noncanonical TAR'): c.audit_tar(p, rows)

    def test_unassigned_payload_and_external_native_overlap_refuse(self):
        self.add('unexpected-user-state', b'not allowed')
        with self.assertRaisesRegex(ValueError, 'Unassigned'): self.partition()
        self.rows.pop(); (self.prefix / 'unexpected-user-state').unlink()
        self.delivery['external_dependencies']['files'].append('lib/unit-0.a')
        with self.assertRaisesRegex(ValueError, 'External inventory'): self.partition()

    def test_native_receipt_missing_file_and_tamper_refuse(self):
        name = self.delivery['native_components'][0]['receipt_path']; p = self.prefix / name
        original = p.read_bytes(); p.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'Payload bytes'): self.partition()
        p.write_bytes(original); self.delivery['native_components'][0]['files'] = []
        with self.assertRaisesRegex(ValueError, 'Receipt file closure'): self.partition()

    def test_changed_modes_and_missing_member_refuse(self):
        path = self.prefix / 'lib/unit-1.a'; path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'Payload bytes or mode'): self.partition()
        path.chmod(0o644); path.unlink()
        with self.assertRaises(OSError): self.partition()

    def test_dependency_missing_and_cycle_refuse(self):
        self.mapping['native_components'][0]['dependency_paths_in_build_order'] = ['modules/absent']
        with self.assertRaises(KeyError): self.partition()
        self.mapping['native_components'][0]['dependency_paths_in_build_order'] = ['modules/unit-1']
        with self.assertRaisesRegex(ValueError, 'Cyclic'): self.partition()

    def test_link_escape_and_unknown_external_link_refuse(self):
        row = next(r for r in self.rows if r.get('link') == 'libcurl.4.dylib')
        row['link'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'Unsafe payload name'): self.partition()

    def test_opaque_tar_keeps_links_receipts_bytes_modes_and_neutral_metadata(self):
        units, _, inv = self.partition(); paths = units[0]['payload_paths'] + self.delivery['external_dependencies']['files']
        rows = [inv[p] for p in paths]
        sources = {r['path']: (lambda r=r: c.read_entry(self.prefix, r)) for r in rows if 'link' not in r}
        path = self.root / 'payload.tar'; c.write_tar(path, rows, sources); c.audit_tar(path, rows)
        with tarfile.open(path) as archive:
            self.assertEqual({x.name for x in archive}, set(paths))
        data = path.read_bytes(); path.write_bytes(data + b'publisher-hidden-tail')
        with self.assertRaisesRegex(ValueError, 'hidden tail'): c.audit_tar(path, rows)

    def test_tar_content_or_mode_changed_refuse(self):
        row = c.file_row('bin/example', b'example', 0o755); p = self.root / 'payload.tar'
        c.write_tar(p, [row], {'bin/example': lambda: b'example'})
        changed = dict(row, mode=0o644)
        with self.assertRaisesRegex(ValueError, 'shape differs'): c.audit_tar(p, [changed])
        changed = dict(row, sha256=c.sha(b'changed'))
        with self.assertRaisesRegex(ValueError, 'content differs'): c.audit_tar(p, [changed])

    def test_recipe_is_inert_exact_and_has_no_prefix_rewrites(self):
        units, _, inv = self.partition(); unit = units[0]
        rows = [inv[p] for p in unit['payload_paths']]
        sources = {r['path']: (lambda r=r: c.read_entry(self.prefix, r)) for r in rows}
        directory = self.root / 'recipes/symphony-unit-0-payload'
        e = c.recipe(unit, directory, rows, sources, 'local-macos-amd64-fixture', {'fixture': True}, None)
        e['recipe_path'] = directory.relative_to(self.root).as_posix()
        parsed, expected = c.validate_recipe(self.root, e)
        self.assertFalse(parsed['native_runtime_install_supported']); self.assertEqual(len(expected), 3)
        changed = dict(e, dependency_units=['native:absent'])
        with self.assertRaisesRegex(ValueError, 'dependency closure'): c.validate_recipe(self.root, changed)
        meta = (directory / 'meta.yaml').read_text()
        self.assertIn('binary_relocation: false', meta); self.assertNotIn('requirements:', meta)
        self.assertNotIn('post-link', meta); self.assertNotIn('activate', meta)
        (directory / 'payload/extra').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'Extra carrier payload'): c.validate_recipe(self.root, e)

    @unittest.skipUnless(importlib.util.find_spec('conda_package_handling'), 'Requires selected CPH publisher tools')
    def test_actual_official_archive_writer_and_tampered_metadata_refusal(self):
        import conda_package_handling.api as package_api
        units, _, inv = self.partition(); unit = units[0]
        rows = [inv[p] for p in unit['payload_paths']]
        sources = {r['path']: (lambda r=r: c.read_entry(self.prefix, r)) for r in rows}
        directory = self.root / 'recipes/symphony-unit-0-payload'
        e = c.recipe(unit, directory, rows, sources, 'local-macos-amd64-fixture', {'fixture': True}, None)
        e['recipe_path'] = directory.relative_to(self.root).as_posix()
        _, expected = c.validate_recipe(self.root, e)
        files = expected | c.metadata_for(e, expected)
        stage = self.root / 'stage'; stage.mkdir(); target = self.root / 'archives'; target.mkdir()
        for name, (raw, mode) in files.items():
            path = stage / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(mode)
        filename = e['conda_name'] + '-' + e['conda_version'] + '-' + e['build_string'] + '.conda'
        package_api.create(str(stage), sorted(files), filename, out_folder=str(target))
        audited = c.audit_archive(target / filename, self.root, e)
        self.assertEqual(audited['depends'], []); self.assertEqual(audited['unit_id'], unit['unit_id'])
        changed = self.root / 'tampered'; changed.mkdir()
        (stage / 'info/index.json').write_bytes(b'{}')
        package_api.create(str(stage), sorted(files), filename, out_folder=str(changed))
        with self.assertRaisesRegex(ValueError, 'metadata differ'): c.audit_archive(changed / filename, self.root, e)

    def test_recipe_fingerprint_and_independent_selection_digest_are_required(self):
        value = c.sealed({'protocol': c.PROTOCOL, 'state': 'prepared'})
        c.check_seal(value); value['state'] = 'archives_audited'
        with self.assertRaisesRegex(ValueError, 'seal differs'): c.check_seal(value)
        with self.assertRaisesRegex(ValueError, 'Unreviewed native version'): c.conda_version('latest')
        self.assertEqual(c.conda_version('0.1.0-dev'), '0.1.0dev0')


if __name__ == '__main__': unittest.main()
