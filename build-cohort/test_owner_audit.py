import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import owner_audit as owner


class OwnerAuditTests(unittest.TestCase):
    def manifest(self):
        return {'installed_go_suites': [
            {'module': 'tools/qxctl', 'package': package, 'tests': sorted(tests)}
            for package, tests in owner.SELECTED.items()]}

    def events(self, names):
        return ([{'Action': 'run', 'Test': name} for name in names] +
                [{'Action': 'pass', 'Test': name} for name in names] + [{'Action': 'pass', 'Package': 'fixture'}])

    def test_selected_fixtures_exist_and_optional_is_explicit(self):
        manifest = self.manifest()
        manifest['installed_go_suites'][0]['tests'].append('TestSNVObserverInstalledConsumer')
        selected, pending = owner.selection(manifest)
        self.assertEqual(sum(len(row['tests']) for row in selected), 6)
        self.assertEqual(len(selected), 3)
        self.assertEqual(selected[0]['tests'], [owner.TAMPER_TEST])
        self.assertEqual(selected[0]['prefix_scope'], 'complete_snv_runtime_receipt_projection')
        self.assertTrue(all(row['prefix_scope'] == 'complete_final_payload' for row in selected[1:]))
        self.assertEqual([row['test'] for row in pending], ['TestSNVObserverInstalledConsumer'])

    def test_missing_manifest_test_refused(self):
        manifest = self.manifest(); manifest['installed_go_suites'][0]['tests'].pop()
        with self.assertRaisesRegex(ValueError, 'missing'): owner.selection(manifest)

    def test_complete_selected_results_pass(self):
        names = {'TestOne', 'TestTwo'}
        self.assertEqual(owner.evaluate(self.events(names), names)['tests'], 2)

    def test_nested_skips_fail(self):
        events = self.events({'TestOne'}) + [{'Action': 'skip', 'Test': 'TestOne/nested'}]
        with self.assertRaisesRegex(ValueError, 'skipped'): owner.evaluate(events, {'TestOne'})

    def test_missing_test_fails_even_with_package_success(self):
        with self.assertRaisesRegex(ValueError, 'missing'): owner.evaluate(self.events({'TestOne'}), {'TestOne', 'TestTwo'})

    def test_unselected_test_fails(self):
        with self.assertRaisesRegex(ValueError, 'unselected'): owner.evaluate(self.events({'TestOther'}), {'TestOne'})

    def test_fail_after_test_success_is_not_pass(self):
        with self.assertRaisesRegex(ValueError, 'failed'): owner.evaluate(self.events({'TestOne'}) + [{'Action': 'fail'}], {'TestOne'})

    def test_prefix_mutation_modes_and_links_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root / 'owner'; file.write_bytes(b'original')
            original = owner.snapshot(root)
            file.write_bytes(b'changed'); self.assertNotEqual(owner.snapshot(root), original)
            file.write_bytes(b'original'); file.chmod(0o700); self.assertNotEqual(owner.snapshot(root), original)
            (root / 'link').symlink_to('owner'); self.assertIn('link', owner.snapshot(root)['link'])


class ReceiptProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source, self.prefix, self.destination = (self.root / name for name in ('source', 'prefix', 'projection'))
        (self.source / 'cmake').mkdir(parents=True)
        self.prefix.mkdir()
        ids = ['knowledge-vector-engine-cpp', 'snv-common-cpp', *sorted(owner.SNV_CORE_IDS)]
        roots = {cid: ('libraries/' if cid in ids[:2] else 'modules/') + cid for cid in ids}
        self.mapping = {'native_components': [], 'native_build_order': [roots[cid] for cid in ids]}
        for index, cid in enumerate(ids):
            dependencies = [] if index == 0 else [roots[ids[0]]]
            if index >= 2: dependencies.append(roots[ids[1]])
            self.mapping['native_components'].append({'path': roots[cid], 'component_id': cid, 'package_release_version': '0.1.0-dev',
                'first_party_sdk_dependencies': [{'path': path, 'scope': 'runtime'} for path in dependencies]})
            payload = 'libexec/' + cid + '/owner'
            file = self.prefix / payload; file.parent.mkdir(parents=True); file.write_bytes(cid.encode()); file.chmod(0o755)
            receipt = {'protocol': 'symphony.knowledge.install-receipt.v2', 'component_id': cid, 'version': '0.1.0-dev',
                'files': [{'path': payload, 'digest': 'sha256:' + owner.sha(file.read_bytes()), 'size': file.stat().st_size, 'kind': 'executable'}]}
            receipt['receipt_digest'] = 'sha256:' + owner.sha(json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode())
            target = self.prefix / 'share/symphony/receipts' / cid / '0.1.0-dev/install-receipt.json'
            target.parent.mkdir(parents=True); target.write_text(json.dumps(receipt)); target.chmod(0o644)
        self.write_map()

    def tearDown(self):
        self.temp.cleanup()

    def write_map(self):
        (self.source / 'cmake/mvp-dependencies.json').write_text(json.dumps(self.mapping))

    def test_complete_seven_receipts_project_without_unrelated_external_symlink(self):
        external = self.prefix / 'third-party/lib'; external.mkdir(parents=True)
        (external / 'libcurl.real').write_bytes(b'external')
        (external / 'libcurl.link').symlink_to('libcurl.real')
        before = owner.snapshot(self.prefix)
        result = owner.project_snv_receipts(self.source, self.prefix, self.destination)
        self.assertEqual({r['component_id'] for r in result['components']}, owner.SNV_CLOSURE_IDS)
        self.assertEqual(result['file_count'], 14)
        self.assertFalse((self.destination / 'third-party').exists())
        self.assertFalse(any(p.is_symlink() for p in self.destination.rglob('*')))
        self.assertEqual(before, owner.snapshot(self.prefix))
        for path in self.destination.rglob('*'):
            if path.is_file():
                original = self.prefix / path.relative_to(self.destination)
                self.assertEqual(path.read_bytes(), original.read_bytes())
                self.assertEqual(path.stat().st_mode & 0o777, original.stat().st_mode & 0o777)

    def test_missing_runtime_dependency_refused(self):
        self.mapping['native_components'][-1]['first_party_sdk_dependencies'].append({'path': 'modules/missing', 'scope': 'runtime'})
        with self.assertRaisesRegex(ValueError, 'missing or cyclic'): owner.snv_runtime_closure(self.mapping)

    def test_optional_observer_cannot_replace_core_owner(self):
        self.mapping['native_components'][-1]['component_id'] = 'snv-local-observer'
        with self.assertRaisesRegex(ValueError, 'five core'): owner.snv_runtime_closure(self.mapping)

    def test_tampered_receipt_owned_bytes_refused(self):
        (self.prefix / 'libexec/sniv-engine/owner').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'owned bytes differ'): owner.project_snv_receipts(self.source, self.prefix, self.destination)

    def test_symlinked_receipt_owned_file_not_silently_dereferenced(self):
        payload = self.prefix / 'libexec/sniv-engine/owner'; payload.unlink()
        outside = self.root / 'outside'; outside.write_bytes(b'sniv-engine'); payload.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlinked'): owner.project_snv_receipts(self.source, self.prefix, self.destination)


if __name__ == '__main__':
    unittest.main()
