import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('requalify', Path(__file__).with_name('d06_requalify_retained.py'))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)


class RetainedQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def state(self):
        native = [{'component_id': 'unit-' + str(i)} for i in range(51)]
        profile = {'native_build_order': native, 'go_commands': [{} for _ in range(6)]}
        original = {'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'building', 'rounds': [],
                    'publication_authorized': False, 'acceptance_complete': False, 'source_commit': 'commit', 'source_tree': 'tree'}
        incomplete = {'state': 'incomplete', 'acceptance_complete': False,
                      'reason': 'installed owner tests failed; private output retained'}
        progress = {'completed_native': [r['component_id'] for r in native], 'expected_native': 51, 'acceptance': False}
        return original, incomplete, progress, profile, {'source_commit': 'commit', 'source_tree': 'tree'}

    def test_only_declared_full_static_cohort_and_exact_stop_is_admitted(self):
        values = self.state()
        q.verify_static_state(*values)
        for index, key, value in ((0, 'state', 'built_and_sdk_checked'), (1, 'reason', 'compile failed'),
                                  (2, 'completed_native', ['unit-0']), (0, 'source_tree', 'different')):
            changed = json.loads(json.dumps(values))
            changed[index][key] = value
            with self.assertRaises(ValueError):
                q.verify_static_state(*changed)

    def test_retained_prefix_must_match_original_full_inventory(self):
        prefix = self.root / 'prefix'; prefix.mkdir()
        binary = prefix / 'binary'; binary.write_bytes(b'original')
        original = {'protocol': 'symphony.distribution.d06-owner-audit.v1', 'status': 'incomplete',
                    'input_payload_inventory_sha256': q.digest(json.dumps(q.owner_audit.snapshot(prefix), sort_keys=True, separators=(',', ':')).encode())}
        q.bound_inventory(prefix, original)
        binary.write_bytes(b'replacement')
        with self.assertRaisesRegex(ValueError, 'changed since'):
            q.bound_inventory(prefix, original)

    def test_source_checks_every_byte_mode_and_extra_file(self):
        source = self.root / 'source'; source.mkdir()
        f = source / 'a.cpp'; f.write_bytes(b'source'); f.chmod(0o644)
        entries = [{'path': 'a.cpp', 'export_sha256': q.builder.sha(f), 'export_size': 6, 'mode': '100644'}]
        q.source_inventory(source, entries)
        f.chmod(0o755)
        with self.assertRaises(ValueError): q.source_inventory(source, entries)
        f.chmod(0o644)
        (source / 'extra').write_bytes(b'artifact')
        with self.assertRaises(ValueError): q.source_inventory(source, entries)
        (source / 'extra').unlink(); f.write_bytes(b'change')
        with self.assertRaises(ValueError): q.source_inventory(source, entries)

    def test_source_symlink_is_not_adopted(self):
        source = self.root / 'source'; source.mkdir()
        (source / 'foreign').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            q.source_inventory(source, [])

    def test_comparison_requires_completed_exact_source_platform_and_bytes(self):
        first = {'directory': 'round-1', 'native_count': 51, 'go_count': 6}
        root = self.root / 'second'; (root / 'round-1/relocated-prefix').mkdir(parents=True)
        (root / 'round-1/relocated-prefix/file').write_bytes(b'payload')
        inventory = q.builder.snapshot(root / 'round-1/relocated-prefix')
        round_result = {'state': 'built_and_sdk_checked', 'payload_inventory': inventory, 'native_receipts': []}
        q.builder.dump(root / 'round-1/result.json', round_result)
        first['result_sha256'] = q.builder.sha(root / 'round-1/result.json')
        original = {'source_commit': 'commit', 'source_tree': 'tree', 'source_input': {'proof': 'exact'},
                    'plan_sha256': 'plan', 'host': {'architecture': 'amd64'}}
        summary = {**original, 'state': 'built_and_sdk_checked', 'rounds': [first]}
        q.builder.dump(root / 'result.json', summary)
        with patch.object(q.builder, 'verify_receipts', return_value=[]):
            self.assertTrue(q.verify_comparison(root, original, inventory, [])['source_and_platform_equal'])
            summary['host'] = {'architecture': 'arm64'}; q.builder.dump(root / 'result.json', summary)
            with self.assertRaises(ValueError): q.verify_comparison(root, original, inventory, [])
            summary['host'] = original['host']; q.builder.dump(root / 'result.json', summary)
            (root / 'round-1/relocated-prefix/file').write_bytes(b'different')
            with self.assertRaises(ValueError): q.verify_comparison(root, original, inventory, [])

    def test_completed_owner_report_cannot_claim_a_different_payload(self):
        audit = self.root / 'audit'; audit.mkdir()
        source = self.root / 'source'; (source / 'tests/release-qualification').mkdir(parents=True)
        q.builder.dump(source / 'tests/release-qualification/manifest.json', {})
        q.builder.dump(audit / 'result.json', {'status': 'passed', 'selected_test_count': 6, 'prefix_unchanged': True,
            'projection_unchanged': True, 'go_manifests_unchanged': True,
            'harness_sha256': q.builder.sha(q.ROOT / 'build-cohort/owner_audit.py'),
            'input_payload_inventory_sha256': 'foreign'})
        with patch.object(q.owner_audit, 'selection', return_value=([], [])):
            with self.assertRaisesRegex(ValueError, 'does not bind'):
                q.verify_completed_owner(audit, source, 'expected')


if __name__ == '__main__':
    unittest.main()
