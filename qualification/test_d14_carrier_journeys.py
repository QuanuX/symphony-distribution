"""Exact revision, native-byte preservation and closed transaction admission."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import d14_carrier_journeys as q


class CarrierJourneys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()

    def tearDown(self): self.tmp.cleanup()

    def recipe(self):
        raw = b'untouched native payload\n'; rows = [q.c.file_row('lib/sample.a', raw)]
        unit = {'unit_id': 'native:sample', 'kind': 'native_receipt_unit', 'component_id': 'sample',
            'native_version': '0.1.0-dev', 'dependency_units': [], 'external_dependency_units': [],
            'sdk_exports': [], 'payload_paths': ['lib/sample.a']}
        directory = self.root / 'recipes/sample'
        entry = q.c.recipe(unit, directory, rows, {'lib/sample.a': lambda: raw}, 'ubuntu24.04-amd64', {'source': 'bound'}, None)
        entry['recipe_path'] = 'recipes/sample'
        return entry

    def test_revision_changes_only_useful_packaging_contract(self):
        entry = self.recipe(); old, _ = q.c.validate_recipe(self.root, entry)
        archive = (self.root / entry['recipe_path'] / 'payload/payload.tar').read_bytes()
        revised = q.revise_entry(self.root, entry, 'sha256:' + 'a' * 64)
        current, _ = q.c.validate_recipe(self.root, revised)
        contract = current.pop('maintenance_contract')
        self.assertEqual(current, old); self.assertEqual(contract, q.maintenance_contract(entry, 'sha256:' + 'a' * 64))
        self.assertEqual(revised['payload_sha256'], entry['payload_sha256'])
        self.assertEqual((self.root / entry['recipe_path'] / 'payload/payload.tar').read_bytes(), archive)
        self.assertEqual(revised['build_number'], 1)
        self.assertNotEqual(revised['carrier_manifest_sha256'], entry['carrier_manifest_sha256'])
        self.assertFalse(contract['distinct_native_version_transition_supported'])
        self.assertFalse(contract['live_native_removal_supported'])

    def test_revising_an_existing_revision_refuses(self):
        revised = q.revise_entry(self.root, self.recipe(), 'sha256:' + 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'unrevised'):
            q.revise_entry(self.root, revised, 'sha256:' + 'b' * 64)

    def test_changed_recipe_staging_arguments_refuse(self):
        entry = self.recipe(); path = self.root / entry['recipe_path'] / 'meta.yaml'
        path.write_text(path.read_text().replace('  number: 0\n', '  number: 2\n'))
        entry['recipe_files']['meta.yaml'] = q.gate.sha(path)
        with self.assertRaisesRegex(ValueError, 'occurrence'):
            q.revise_entry(self.root, entry, 'sha256:' + 'a' * 64)

    def test_closed_adapter_rechecks_all_archive_bytes_and_metadata(self):
        identity = {'name': 'selected'}; contents = {'payload': (b'x', 0o644)}
        selected = {'archive.conda': {'identity': identity, 'entries': contents, 'sha256': 'a' * 64, 'size': 10}}
        inspect = q.identity_adapter(selected)
        with patch.object(q.c, 'archive_entries', return_value=(contents, 'a' * 64, 10)):
            self.assertEqual(inspect(Path('archive.conda')), identity)
            with self.assertRaisesRegex(ValueError, 'Unselected'): inspect(Path('other.conda'))
        for changed in [({'payload': (b'y', 0o644)}, 'a' * 64, 10), (contents, 'b' * 64, 10), (contents, 'a' * 64, 11)]:
            with patch.object(q.c, 'archive_entries', return_value=changed), self.assertRaisesRegex(ValueError, 'differs'):
                inspect(Path('archive.conda'))

    def test_missing_opt_in_refuses_before_read_or_output(self):
        with patch.object(q.c, 'safe_root') as safe, self.assertRaisesRegex(ValueError, 'opt-in'):
            q.qualify(self.root, self.root, self.root / 'new', 'a', 'b')
        safe.assert_not_called(); self.assertFalse((self.root / 'new').exists())

    def test_transition_census_independent_replacement_rollback_and_swap(self):
        sentinel = self.root / 'user-state'; sentinel.write_bytes(b'preserve user state\n')
        units = ['go:ssh', 'go:stdio', 'native:sample']; pairs = {}
        for unit, name in zip(units, ['sov-ssh-adapter', 'sov-stdio-adapter', 'sample']):
            for number in (0, 1):
                pairs[(unit, number)] = {'name': 'symphony-' + name + '-payload', 'version': '0.1.0dev0',
                    'build': 'revision_' + str(number), 'sha256': str(number) * 64}
        class Attempt:
            def __init__(self): self.sequence = 0; self.installed = {}
            def transact(self, operation, **args):
                self.sequence += 1
                for row in args['expected_unlink']:
                    assert self.installed.pop(row['name']) == row
                for row in args['expected_link']:
                    assert row['name'] not in self.installed; self.installed[row['name']] = row
                return {'sequence': self.sequence, 'unrelated_files_preserved': True}
            def inventory(self): return self.installed
        result = q.transitions(Attempt(), pairs, units, sentinel)
        self.assertEqual(len(result), 3 * len(units) + 5)
        self.assertEqual(sum(row['operation'] == 'upgrade' for row in result), len(units))
        self.assertEqual(sum(row['operation'] == 'rollback' for row in result), len(units) + 1)
        self.assertEqual(sum(row['operation'] == 'swap' for row in result), 1)

    def test_no_historical_transaction_parser_changes(self):
        before = (q.ROOT / 'lifecycle/conda_transaction.py').read_bytes()
        engine, child = q.transaction_engine({})
        self.assertTrue(issubclass(child, engine.Attempt))
        self.assertEqual(before, (q.ROOT / 'lifecycle/conda_transaction.py').read_bytes())
        with self.assertRaises(ValueError): engine.artifact_identity(Path('unknown.conda'))


if __name__ == '__main__': unittest.main()
