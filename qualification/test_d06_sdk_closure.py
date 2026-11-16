import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('d06_sdk_closure', Path(__file__).with_name('d06_sdk_closure.py'))
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class ClosureTests(unittest.TestCase):
    def report(self):
        return {'status': 'passed', 'provider_requests': '0', 'spend_usd': '0',
                'resume_executed': '0', 'external_trials': '2', 'selected_proposal': 'proposal-2',
                'calibration': 'not_verified', 'consumer_cancellation': 'incomplete_and_reaped',
                'signals': 2, 'replay_rows': 15, 'source_stream': {'complete': True},
                'replay_stream': {'complete': True}, 'bundle_stream': {'complete': True}}

    def test_exact_roundtrip_accepts_only_declared_synthetic_result(self):
        result = closure.validate_roundtrip(self.report())
        self.assertEqual(result['calibration'], 'not_verified')
        self.assertNotIn('source', result)

    def test_provider_request_or_spend_not_qualified(self):
        for field in ('provider_requests', 'spend_usd'):
            row = self.report(); row[field] = '1'
            with self.assertRaisesRegex(ValueError, 'incomplete'): closure.validate_roundtrip(row)

    def test_stream_incomplete_refused(self):
        for field in ('source_stream', 'replay_stream', 'bundle_stream'):
            row = self.report(); row[field]['complete'] = False
            with self.assertRaisesRegex(ValueError, 'stream incomplete'): closure.validate_roundtrip(row)

    def test_source_fixture_and_resume_are_required(self):
        for key, value in [('signals', 0), ('replay_rows', 0), ('resume_executed', '2'), ('consumer_cancellation', 'complete')]:
            row = self.report(); row[key] = value
            with self.assertRaises(ValueError): closure.validate_roundtrip(row)

    def test_configured_inventory_is_exact_not_receipt_derived_authority(self):
        closure.compare_inventory(['b', 'a'], ['a', 'b'])
        for wrong in (['a'], ['a', 'b', 'c'], ['a', 'a', 'b']):
            with self.assertRaisesRegex(ValueError, 'exact final'): closure.compare_inventory(wrong, ['a', 'b'])

    def test_unsafe_and_duplicate_native_owned_paths_refused(self):
        for names in (['../outside'], ['/outside'], ['file', 'file']):
            with self.assertRaises(ValueError): closure.owned_paths({'files': [{'path': x} for x in names]}, 'receipt.json')

    def test_native_receipt_itself_is_in_owned_inventory(self):
        self.assertEqual(closure.owned_paths({'files': [{'path': 'bin/owner'}]}, 'share/receipt.json'), ['bin/owner', 'share/receipt.json'])

    def test_disposable_snapshot_tracks_bytes_modes_and_no_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root / 'payload'; file.write_bytes(b'original')
            before = closure.file_snapshot(root)
            file.write_bytes(b'changed'); self.assertNotEqual(closure.file_snapshot(root), before)
            file.write_bytes(b'original'); file.chmod(0o700); self.assertNotEqual(closure.file_snapshot(root), before)
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'escaped'): closure.file_snapshot(root)

    def test_source_copy_refuses_build_products_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.mkdir()
            (source / 'build').mkdir(); (source / 'build/object').write_bytes(b'not source')
            with self.assertRaisesRegex(ValueError, 'build artifacts'): closure.copy_regular_tree(source, root / 'copy')

    def test_census_wrapper_does_not_invoke_full_L20(self):
        self.assertIn('census()', closure.CENSUS_WRAPPER)
        self.assertNotIn('queuedCancel()', closure.CENSUS_WRAPPER)
        self.assertNotIn('durableCompletion()', closure.CENSUS_WRAPPER)
        self.assertIn('existing census function only; not full L20 campaign', closure.CENSUS_WRAPPER)

    def test_timeout_is_not_successful_removal_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = closure.Runner(Path(directory), {}, 10)
            with patch.object(closure, 'bounded_run', return_value=124):
                with self.assertRaisesRegex(ValueError, 'unexpected command result'):
                    runner.run('timeout', ['fixture'], success=False)

    def test_only_cmake_fatal_exit_is_expected_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = closure.Runner(Path(directory), {}, 10)
            with patch.object(closure, 'bounded_run', return_value=1):
                runner.run('fatal', ['fixture'], success=False)

    def test_reviewed_source_cannot_change_after_build(self):
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory); source = cohort / 'source'; source.mkdir()
            path = source / 'file'; path.write_text('source'); path.chmod(0o644)
            digest = closure.hashlib.sha256(closure.canonical(closure.source_inventory(source))).hexdigest()
            summary = {'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True, 'export_digest': digest}}
            self.assertEqual(closure.verify_source(cohort, summary), digest)
            path.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'changed after'): closure.verify_source(cohort, summary)


if __name__ == '__main__':
    unittest.main()
