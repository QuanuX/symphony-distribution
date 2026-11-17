import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualification import d11_native_maintenance as m


class PrimaryMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name).resolve()
    def tearDown(self): self.temporary.cleanup()

    def test_optin_refused_before_read_or_process(self):
        with patch.object(m.transport, 'validate_selection') as selected:
            with self.assertRaisesRegex(ValueError, 'opt-in'):
                m.run(SimpleNamespace(allow_ephemeral_maintenance=False))
            selected.assert_not_called()

    def payload_fixture(self):
        entries, archives, assignment, units, raw = [], [], {}, {}, {}
        for number in range(58):
            uid = 'unit-' + str(number)
            kind = 'native_receipt_unit' if number < 51 else 'go_command' if number < 57 else 'external_inert_runtime_and_sdk'
            entry = {'unit_id': uid, 'kind': kind, 'component_id': uid}
            entries.append(entry); archives.append({'unit_id': uid, 'filename': uid + '.conda'})
            name = 'lib/unit-' + str(number)
            files = [m.c.file_row(name, b'fixture exact bytes', 0o555 if number == 0 else 0o644)]
            raw[name] = b'fixture exact bytes'
            if number == 57:
                base = 'third-party/lib/'
                target = base + 'libcurl.so.4.8.0'; raw[target] = b'fixture curl bytes'
                files = [m.c.file_row(target, raw[target]),
                         {'path': base + 'libcurl.so.4', 'link': 'libcurl.so.4.8.0'},
                         {'path': base + 'libcurl.so', 'link': 'libcurl.so.4'}]
            units[uid] = {'unit_id': uid, 'payload_paths': [row['path'] for row in files], 'files': files}
            for row in files: assignment[row['path']] = uid
        cohort = {'profile': 'ubuntu24.04-amd64', 'conda_subdir': 'linux-64', 'entries': entries,
                  'archives': archives, 'payload_assignment': assignment, 'payload_entry_count': len(assignment)}
        def read_carrier(artifacts, record, entry, row, retained):
            unit = units[entry['unit_id']]; target = retained / (entry['component_id'] + '.tar')
            sources = {r['path']: lambda name=r['path']: raw[name] for r in unit['files'] if 'link' not in r}
            m.c.write_tar(target, unit['files'], sources)
            m.c.audit_tar(target, unit['files'])
            return unit, target
        return cohort, units, raw, read_carrier

    def test_primary58_materializes_all_bytes_modes_and_curl_chain_without_running_payload(self):
        cohort, _, raw, read = self.payload_fixture()
        with patch.object(m.existing, 'read_carrier', side_effect=read), patch.object(m.existing, 'configure') as configure:
            prefix, snapshot = m.materialize(self.root / 'capsule', cohort, self.root)
            configure.assert_not_called()
        self.assertEqual(len(snapshot), cohort['payload_entry_count'])
        self.assertEqual((prefix / 'lib/unit-0').stat().st_mode & 0o777, 0o555)
        self.assertEqual((prefix / 'third-party/lib/libcurl.so').resolve(), prefix / 'third-party/lib/libcurl.so.4.8.0')
        self.assertEqual((prefix / 'third-party/lib/libcurl.so').read_bytes(), b'fixture curl bytes')
        self.assertEqual(m.existing.file_snapshot(prefix), snapshot)

    def test_59client_missing_unit_and_supplemental_scope_refuse_before_materialization(self):
        for mutation in ('59', 'missing', 'supplemental'):
            cohort, _, _, read = self.payload_fixture()
            if mutation == '59': cohort['entries'].append({'kind': 'client'})
            if mutation == 'missing': cohort['entries'].pop()
            if mutation == 'supplemental': cohort['profile'] = 'local-macos-amd64-fixture'
            with patch.object(m.existing, 'read_carrier', side_effect=read) as decoded:
                with self.assertRaisesRegex(ValueError, 'primary58'): m.materialize(self.root, cohort, self.root)
                decoded.assert_not_called()
            self.assertFalse((self.root / 'retained-prefix').exists())

    def test_missing_payload_coverage_refuses_before_prefix_creation(self):
        cohort, _, _, read = self.payload_fixture(); cohort['payload_entry_count'] += 1
        with patch.object(m.existing, 'read_carrier', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'coverage'): m.materialize(self.root / 'capsule', cohort, self.root)
        self.assertFalse((self.root / 'retained-prefix').exists())

    def test_curl_cycles_missing_targets_escaping_links_and_parent_aliases_refuse(self):
        base = 'third-party/lib/'
        normal = {base + 'libcurl.so': {'path': base + 'libcurl.so', 'link': 'libcurl.so.4'},
                  base + 'libcurl.so.4': m.c.file_row(base + 'libcurl.so.4', b'fixture')}
        m.validate_payload_rows(normal)
        cases = [normal | {base + 'libcurl.so.4': {'path': base + 'libcurl.so.4', 'link': 'libcurl.so'}},
                 {base + 'libcurl.so': normal[base + 'libcurl.so']},
                 normal | {base + 'libcurl.so': {'path': base + 'libcurl.so', 'link': '../../outside'}},
                 normal | {base + 'libcurl.so/child': m.c.file_row(base + 'libcurl.so/child', b'fixture')},
                 {'other/link': {'path': 'other/link', 'link': 'libcurl.so.4'}}]
        for rows in cases:
            with self.assertRaises(ValueError): m.validate_payload_rows(rows)
        with self.assertRaisesRegex(ValueError, 'Empty'): m.validate_payload_rows({})

    def test_private_environment_does_not_inherit_ambient_values(self):
        tools = {'cmake': Path('/usr/bin/cmake')}
        env = m.environment(self.root, tools, 'ubuntu24.04-amd64')
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertNotIn('DEVELOPER_DIR', env); self.assertNotIn('SDKROOT', env)
        self.assertNotIn('GH_TOKEN', env); self.assertNotIn('LD_PRELOAD', env)
        self.assertEqual((self.root / 'home/.zshrc').read_bytes(), b'# isolated caller state must survive\n')

    def test_platform_specific_developer_directory_is_explicit(self):
        tools = {'cmake': Path('/usr/bin/cmake')}
        for name, profile, developer in [('linux', 'ubuntu24.04-amd64', self.root), ('mac', 'macos15-arm64', None)]:
            output = self.root / name; output.mkdir()
            with self.assertRaises(ValueError): m.environment(output, tools, profile, developer)

    def completion_fixture(self):
        units = [{'component_id': 'unit-' + str(i), 'version': '1.0.0'} for i in range(51)]
        positive = ('immutable_reinstall_refused', 'managed_root_marker_presence_refused', 'aliased_receipt_refused',
            'changed_owned_bytes_refused', 'interrupted_removal_resumed', 'absent_removal_idempotent',
            'empty_version_preflight_passed', 'same_candidate_restoration_exact', 'other_package_and_user_bytes_preserved')
        negative = ('native_install_execution_qualified', 'different_version_upgrade_qualified', 'rollback_qualified', 'live_retirement_qualified')
        results = [row | {key: True for key in positive} | {key: False for key in negative} for row in units]
        logs = [{'name': 'command-' + str(i), 'expected': 'success', 'exit_code': 0} for i in range(612)]
        return units, results, logs

    def test_complete51_and612commands_required_no_empty_falsepass(self):
        units, results, logs = self.completion_fixture(); m.validate_completion(units, results, logs)
        cases = [(units, [], logs), (units, results[:-1], logs), (units, results, logs[:-1]),
                 (units, results[:-1] + [results[0]], logs), (units, results, logs[:-1] + [logs[0]])]
        for args in cases:
            with self.assertRaises(ValueError): m.validate_completion(*args)

    def test_timeout_wrong_refusal_and_scope_inflation_never_pass(self):
        for code in (-9, 124, 2):
            units, results, logs = self.completion_fixture(); logs[0].update(expected='refusal', exit_code=code)
            with self.assertRaisesRegex(ValueError, 'invalid refusal'): m.validate_completion(units, results, logs)
        units, results, logs = self.completion_fixture(); results[0]['live_retirement_qualified'] = True
        with self.assertRaisesRegex(ValueError, 'changed scope'): m.validate_completion(units, results, logs)

    def test_source_configuration_must_match_original_and_reviewed_export(self):
        source = self.root / 'source'; source.mkdir(); capsule = self.root / 'capsule'; (capsule / 'evidence').mkdir(parents=True)
        toolkit = self.root / 'toolkit'; (toolkit / 'build-cohort').mkdir(parents=True)
        units = [{'component_id': 'fixture'}]
        (toolkit / 'build-cohort/cohort.json').write_text(json.dumps({'profiles': {'ubuntu24.04-amd64': {'native_build_order': units}}}))
        names = ['CMakeLists.txt', 'cmake/mvp-dependencies.json', 'tests/mvp-dependencies/prove-imports.cmake', 'extra.cmake.in']
        rows = []
        for name in names:
            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'{"native_components":[],"source_inputs":[]}' if name == 'cmake/mvp-dependencies.json' else b'fixture original configuration'); path.chmod(0o644)
            rows.append({'path': name, 'source_sha256': m.existing.file_sha(path), 'export_sha256': m.existing.file_sha(path), 'mode': '100644'})
        record = {'source_commit': m.existing.COMMIT, 'source_tree': m.existing.TREE, 'source_export_digest': 'a'*64, 'profile': 'ubuntu24.04-amd64', 'dependency_map_sha256': m.existing.file_sha(source / 'cmake/mvp-dependencies.json')}
        (capsule / 'evidence/mvp-dependencies.json').write_bytes((source / 'cmake/mvp-dependencies.json').read_bytes())
        manifest = {'origin_commit': m.existing.COMMIT, 'origin_tree': m.existing.TREE, 'derived_export_digest': 'a'*64, 'source_files': rows, 'excluded_files': [], 'source_map_rebindings': [], 'source_map_omitted_private_publisher_test_inputs': []}
        (capsule / 'result.json').write_text(json.dumps(record))
        (capsule / 'evidence/source-manifest.json').write_text(json.dumps(manifest))
        (capsule / 'evidence/build-result.json').write_text(json.dumps({'plan_sha256': m.existing.file_sha(toolkit / 'build-cohort/cohort.json')}))
        with patch.object(m, 'ROOT', toolkit), patch.object(m.existing, 'source_register', return_value=(units, [], {})):
            _, _, hashes = m.source_binding(source, capsule, {})
            self.assertEqual(set(hashes), set(names))
            rows[-1]['export_sha256'] = 'f'*64
            (capsule / 'evidence/source-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'original or reviewed'): m.source_binding(source, capsule, {})


    def map_fixture(self):
        source = self.root / 'source'; (source / 'cmake').mkdir(parents=True)
        capsule = self.root / 'capsule'; (capsule / 'evidence').mkdir(parents=True)
        original = {'native_components': [{'component_id': 'unit', 'options': {'enabled': True}}],
                    'source_inputs': [{'path': 'changed.cpp', 'sha256': 'a'*64},
                                      {'path': 'tests/public-beta/dossier.json', 'sha256': 'b'*64}]}
        exported = copy.deepcopy(original); exported['source_inputs'] = [{'path': 'changed.cpp', 'sha256': 'c'*64}]
        original_raw = (json.dumps(original, indent=2) + '\n').encode()
        exported_raw = (json.dumps(exported, indent=2) + '\n').encode()
        (source / 'cmake/mvp-dependencies.json').write_bytes(original_raw)
        (capsule / 'evidence/mvp-dependencies.json').write_bytes(exported_raw)
        manifest = {'source_files': [
            {'path': 'cmake/mvp-dependencies.json', 'source_sha256': m.c.sha(original_raw), 'export_sha256': m.c.sha(exported_raw)},
            {'path': 'changed.cpp', 'source_sha256': 'a'*64, 'export_sha256': 'c'*64}],
            'excluded_files': [{'path': 'tests/public-beta/dossier.json', 'source_sha256': 'b'*64}],
            'source_map_rebindings': [{'path': 'changed.cpp', 'original_sha256': 'a'*64, 'export_sha256': 'c'*64}],
            'source_map_omitted_private_publisher_test_inputs': [dict(original['source_inputs'][1],
                reason='private publisher dossier/test artifact omitted from derived public source')]}
        return source, capsule, manifest, {'dependency_map_sha256': m.c.sha(exported_raw)}, exported

    def test_exact_reviewed_map_rebinding_and_dossier_omission_preserves_owner_configuration(self):
        source, capsule, manifest, record, _ = self.map_fixture()
        evidence = m.dependency_map_binding(source, capsule, manifest, record)
        self.assertTrue(evidence['configuration_projection_unchanged'])
        self.assertEqual(evidence['source_input_rebinding_count'], 1)
        self.assertEqual(evidence['omitted_dossier_input_count'], 1)
        self.assertNotEqual(evidence['original_sha256'], evidence['reviewed_sha256'])
        changed = copy.deepcopy(manifest); changed['source_map_rebindings'] = []
        with self.assertRaisesRegex(ValueError, 'beyond reviewed'):
            m.dependency_map_binding(source, capsule, changed, record)

    def test_changed_owner_projection_is_not_accepted_as_source_rebinding(self):
        source, capsule, manifest, record, exported = self.map_fixture()
        exported['native_components'][0]['options']['enabled'] = False
        raw = (json.dumps(exported, indent=2) + '\n').encode()
        (capsule / 'evidence/mvp-dependencies.json').write_bytes(raw)
        manifest['source_files'][0]['export_sha256'] = record['dependency_map_sha256'] = m.c.sha(raw)
        with self.assertRaisesRegex(ValueError, 'beyond reviewed'):
            m.dependency_map_binding(source, capsule, manifest, record)


if __name__ == '__main__': unittest.main()
