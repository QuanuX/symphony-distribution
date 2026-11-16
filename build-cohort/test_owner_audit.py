import copy
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


if __name__ == '__main__':
    unittest.main()
