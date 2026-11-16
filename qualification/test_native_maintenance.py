"""Retained-native adapter contracts; synthetic records do not claim a campaign."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualification import native_maintenance as m
from qualification import test_d11_native_maintenance as previous_tests


class NativeMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()

    def tearDown(self): self.temp.cleanup()

    def units(self):
        units = [{'component_id': f'unit-{i}', 'version': '1.0.0', 'exported_packages': [f'Unit{i}']} for i in range(51)]
        receipts = [{'component_id': u['component_id'], 'version': u['version'],
                     'receipt_sha256': 'a'*64, 'owned_file_count': 2} for u in units]
        return units, receipts

    def test_receipt_selection_is_configuration_metadata_without_carrier_claim(self):
        units, receipts = self.units(); rows = m.native_selection_rows(units, receipts)
        self.assertEqual(len(rows), 51)
        self.assertEqual(rows[0], {'component_id': 'unit-0', 'native_version': '1.0.0', 'sdk_exports': ['Unit0']})
        self.assertTrue(all(set(r) == {'component_id', 'native_version', 'sdk_exports'} for r in rows))

    def test_missing_duplicate_wrong_version_or_empty_receipt_refused(self):
        units, receipts = self.units()
        cases = [receipts[:-1], receipts + [receipts[0]], receipts[:-1] + [receipts[0]]]
        for key, value in [('version', '2.0.0'), ('receipt_sha256', 'changed'), ('owned_file_count', 0), ('owned_file_count', True)]:
            altered = copy.deepcopy(receipts); altered[0][key] = value; cases.append(altered)
        for rows in cases:
            with self.subTest(rows=rows[0]), self.assertRaises(ValueError): m.native_selection_rows(units, rows)

    def test_existing_carrier_entrypoint_delegates_exact_selected_owner_rows(self):
        entries = [{'kind': 'native_receipt_unit', 'component_id': 'first'}, {'kind': 'go_command', 'component_id': 'go'}]
        binding = {'commit': 'a'*40, 'tree': 'b'*40}; sentinel = object()
        with patch.object(m.existing, 'source_register_units', return_value=sentinel) as register:
            self.assertIs(m.existing.source_register(self.root, {'entries': entries, 'selected_evidence': {'source_binding': binding}}), sentinel)
            register.assert_called_once_with(self.root, [entries[0]], binding)

    def test_pure_dependency_map_proof_matches_existing_carrier_entrypoint(self):
        fixture = previous_tests.PrimaryMaintenanceTests(); fixture.setUp()
        try:
            source, capsule, manifest, record, _ = fixture.map_fixture()
            actual = m.common.dependency_map_binding(source, capsule, manifest, record)
            direct = m.common.dependency_map_files(source / 'cmake/mvp-dependencies.json',
                capsule / 'evidence/mvp-dependencies.json', manifest, record['dependency_map_sha256'])
            self.assertEqual(actual, direct)
            with self.assertRaises(ValueError):
                m.common.dependency_map_files(source / 'cmake/mvp-dependencies.json',
                    capsule / 'evidence/mvp-dependencies.json', manifest, '0'*64)
        finally: fixture.tearDown()

    def test_owner_configuration_paths_match_original_and_reviewed_inputs(self):
        source = self.root / 'source'; restored = self.root / 'restored'; toolkit = self.root / 'toolkit'
        units, receipts = self.units()
        def put(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            path.chmod(0o644)
        plan = toolkit / 'build-cohort/cohort.json'
        put(plan, {'profiles': {'ubuntu24.04-amd64': {'native_build_order': units}}})
        names = ('cmake/mvp-dependencies.json', 'CMakeLists.txt', 'extra.cmake.in', 'tests/mvp-dependencies/prove-imports.cmake')
        rows = []
        for name in names:
            raw = b'{"native_components":[],"source_inputs":[]}' if name.endswith('.json') else b'original configure input'
            put(source / name, raw); put(restored / 'export/source' / name, raw)
            rows.append({'path': name, 'source_sha256': m.c.sha(raw), 'export_sha256': m.c.sha(raw), 'mode': '100644'})
        lineage = {'profile': 'ubuntu24.04-amd64', 'source_commit': m.existing.COMMIT,
                   'source_tree': m.existing.TREE, 'source_export_digest': 'a'*64}
        manifest = {'origin_commit': m.existing.COMMIT, 'origin_tree': m.existing.TREE,
            'derived_export_digest': 'a'*64, 'source_files': rows, 'excluded_files': [],
            'source_map_rebindings': [], 'source_map_omitted_private_publisher_test_inputs': []}
        put(restored / 'export/SOURCE-EXPORT.json', manifest)
        put(restored / 'cohort/result.json', {'plan_sha256': m.existing.file_sha(plan),
            'source_commit': m.existing.COMMIT, 'source_tree': m.existing.TREE})
        put(restored / 'cohort/round-1/result.json', {'native_receipts': receipts})
        with patch.object(m, 'ROOT', toolkit), patch.object(m.existing, 'source_register_units', return_value=(units, [], {})) as register:
            _, _, hashes, proof = m.source_inputs(source, restored, lineage)
            self.assertEqual(set(hashes), set(names)); self.assertTrue(proof['configuration_projection_unchanged'])
            register.assert_called_once_with(source, m.native_selection_rows(units, receipts),
                {'commit': m.existing.COMMIT, 'tree': m.existing.TREE})
            rows[2]['export_sha256'] = '0'*64; put(restored / 'export/SOURCE-EXPORT.json', manifest)
            with self.assertRaisesRegex(ValueError, 'original or reviewed'):
                m.source_inputs(source, restored, lineage)

    def test_optin_and_timeout_refused_before_admission_or_mutation(self):
        with patch.object(m.transport, 'validate_selection') as admission:
            with self.assertRaisesRegex(ValueError, 'opt-in'): m.run(SimpleNamespace(allow_ephemeral_maintenance=False))
            for timeout in (0, 601, True):
                with self.assertRaisesRegex(ValueError, 'timeout'):
                    m.run(SimpleNamespace(allow_ephemeral_maintenance=True, timeout=timeout))
            admission.assert_not_called()

    def test_wrong_native_host_refuses_before_private_restoration(self):
        args = SimpleNamespace(allow_ephemeral_maintenance=True, timeout=180, selection=self.root / 'selection',
            selection_sha256='a'*64, source=self.root, artifact=self.root, transport_proof=self.root / 'proof', output=self.root / 'out')
        with patch.object(m.transport, 'validate_selection', return_value={'profile': 'ubuntu24.04-arm64'}), \
             patch.object(m.native, 'selected_inputs'), patch.object(m.reuse, 'custody', side_effect=ValueError('wrong native host')), \
             patch.object(m.native, 'restore') as restore:
            with self.assertRaisesRegex(ValueError, 'wrong native host'): m.run(args)
            restore.assert_not_called(); self.assertFalse(args.output.exists())

    def test_final_completion_still_requires_all51_and612_exact_outcomes(self):
        units, _ = self.units()
        with self.assertRaisesRegex(ValueError, 'Complete unique'):
            m.common.validate_completion(units, [], [])
        rows = [{'component_id': u['component_id'], 'version': u['version'],
            **{k: True for k in ('immutable_reinstall_refused', 'managed_root_marker_presence_refused', 'aliased_receipt_refused',
              'changed_owned_bytes_refused', 'interrupted_removal_resumed', 'absent_removal_idempotent',
              'empty_version_preflight_passed', 'same_candidate_restoration_exact', 'other_package_and_user_bytes_preserved')},
            **{k: False for k in ('native_install_execution_qualified', 'different_version_upgrade_qualified', 'rollback_qualified', 'live_retirement_qualified')}} for u in units]
        logs = [{'name': str(i), 'exit_code': 0, 'expected': 'success'} for i in range(612)]
        m.common.validate_completion(units, rows, logs)
        for bad in (logs[:-1], logs[:-1] + [{'name': 'other', 'exit_code': 124, 'expected': 'refusal'}]):
            with self.assertRaisesRegex(ValueError, 'Missing commands'): m.common.validate_completion(units, rows, bad)
        rows[0]['live_retirement_qualified'] = True
        with self.assertRaisesRegex(ValueError, 'scope'): m.common.validate_completion(units, rows, logs)

    def test_alias_compiler_invocation_is_preserved(self):
        cmake = self.root / 'cmake'; cc = self.root / 'clang'; cxx = self.root / 'clang++'
        for path in (cmake, cc): path.write_bytes(b'fixture executable'); path.chmod(0o755)
        cxx.symlink_to(cc.name)
        selected = m.existing.selected_tools(SimpleNamespace(cmake=cmake, cc=cc, cxx=cxx))
        self.assertEqual(selected['cxx'], cxx); self.assertNotEqual(selected['cxx'], cc)


if __name__ == '__main__': unittest.main()
