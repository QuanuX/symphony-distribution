import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import d09_maintenance as m


class D09MaintenanceTests(unittest.TestCase):
    def pair(self):
        old = {'component_id': 'unit', 'version': '1.0.0', 'source_commit': 'a' * 40,
               'receipt_sha256': 'b' * 64, 'artifact_sha256': 'c' * 64}
        new = {'component_id': 'unit', 'version': '2.0.0', 'source_commit': 'd' * 40,
               'receipt_sha256': 'e' * 64, 'artifact_sha256': 'f' * 64}
        return old, new

    def test_same_version_rebuild_is_not_an_upgrade(self):
        old, new = self.pair(); new['version'] = old['version']
        with self.assertRaisesRegex(ValueError, 'distinct releases'): m.distinct_release_pair(old, new)

    def test_relabelled_same_bytes_or_same_source_is_not_new_release(self):
        for key in ('artifact_sha256', 'source_commit', 'receipt_sha256'):
            old, new = self.pair(); new[key] = old[key]
            with self.assertRaisesRegex(ValueError, 'distinct releases'): m.distinct_release_pair(old, new)

    def test_release_pair_requires_matching_owner_and_complete_identity(self):
        old, new = self.pair(); new['component_id'] = 'other'
        with self.assertRaisesRegex(ValueError, 'distinct releases'): m.distinct_release_pair(old, new)
        old, new = self.pair(); del new['receipt_sha256']
        with self.assertRaisesRegex(ValueError, 'Incomplete'): m.distinct_release_pair(old, new)

    def test_distinct_pair_does_not_claim_execution_or_compatibility(self):
        result = m.distinct_release_pair(*self.pair())
        self.assertFalse(result['upgrade_qualified']); self.assertFalse(result['rollback_qualified'])
        self.assertFalse(result['compatibility_and_selection_qualified'])

    def test_exact_recovery_preserves_bytes_mode_and_unrelated_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); old = root / 'retained'; new = root / 'disposable'; old.mkdir(); new.mkdir()
            (old / 'binary').write_bytes(b'original'); (old / 'binary').chmod(0o755)
            (new / 'user-state').write_bytes(b'caller')
            m.restore_files(old, new, ['binary'])
            self.assertEqual((new / 'binary').read_bytes(), b'original')
            self.assertEqual((new / 'binary').stat().st_mode & 0o777, 0o755)
            self.assertEqual((new / 'user-state').read_bytes(), b'caller')

    def test_recovery_refuses_existing_target_before_any_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); old = root / 'retained'; new = root / 'disposable'; old.mkdir(); new.mkdir()
            for name in ('first', 'second'): (old / name).write_bytes(b'original')
            (new / 'second').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError, 'existing'): m.restore_files(old, new, ['first', 'second'])
            self.assertFalse((new / 'first').exists()); self.assertEqual((new / 'second').read_bytes(), b'foreign')

    def test_recovery_refuses_alias_without_touching_outside(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); old = root / 'retained'; new = root / 'disposable'; old.mkdir(); new.mkdir()
            (old / 'binary').write_bytes(b'original'); outside = root / 'outside'; outside.write_bytes(b'caller')
            (new / 'binary').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'aliased'): m.restore_files(old, new, ['binary'])
            self.assertEqual(outside.read_bytes(), b'caller')

    def test_recovery_refuses_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            with self.assertRaisesRegex(ValueError, 'Unsafe payload'): m.restore_files(root, root, ['../outside'])

    def test_controlled_alias_snapshot_does_not_follow_outside(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); prefix = root / 'prefix'; prefix.mkdir()
            outside = root / 'outside'; outside.write_bytes(b'caller')
            alias = prefix / 'receipt'; alias.symlink_to(outside)
            self.assertEqual(m.campaign_snapshot(prefix, (alias, outside)),
                             {'receipt': {'link': str(outside)}})
            self.assertEqual(outside.read_bytes(), b'caller')
            second = prefix / 'unselected'; second.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'Unexpected external'):
                m.campaign_snapshot(prefix, (alias, outside))

    def test_controlled_alias_snapshot_rejects_changed_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); prefix = root / 'prefix'; prefix.mkdir()
            outside = root / 'outside'; outside.write_bytes(b'caller')
            alias = prefix / 'receipt'; alias.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'fixture changed'):
                m.campaign_snapshot(prefix, (alias, root / 'other'))

    def test_source_owner_classification_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); component = root / 'component'; component.mkdir()
            path = component / 'CMakeLists.txt'
            path.write_text('file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake" "content")')
            unit = {'source_root': 'component', 'component_id': 'unrecognized'}
            with self.assertRaisesRegex(ValueError, 'Unclassified'): m.owner_sources(root, unit)
            unit['component_id'] = 'sov-cloudflare-adapter'
            self.assertEqual(m.owner_sources(root, unit)[1], 'component_inline_generated_owner')
            path.write_text('include(SymphonyScvEngine.cmake)')
            paths, form = m.owner_sources(root, unit)
            self.assertEqual(form, 'shared_scv_template_owner')
            self.assertIn('modules/scv-engine/cmake/uninstall.cmake.in', paths)

    def test_selected_tools_preserve_language_driver_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); driver = root / 'clang'; driver.write_bytes(b'driver')
            alias = root / 'clang++'; alias.symlink_to(driver)
            selected = m.selected_tools(SimpleNamespace(cmake=driver, cc=driver, cxx=alias))
            self.assertEqual(selected['cxx'], alias)
            self.assertNotEqual(selected['cxx'], driver)

if __name__ == '__main__': unittest.main()
