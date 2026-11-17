import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('delivery_record', Path(__file__).with_name('d06_delivery_record.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DeliveryRecordTests(unittest.TestCase):
    def source_scanner(self, root, markers=None):
        spec = importlib.util.spec_from_file_location('delivery_privacy_fixture', d.ROOT / 'source-export/export_source.py')
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        policy = root / 'policy.json'
        policy.write_text(json.dumps({'schema': 'symphony.source-privacy-policy.v1',
            'markers': markers or ['SYNTHETIC_PUBLISHER_IDENTITY'], 'document_attributions': {}}))
        scanner.configure_policy(policy)
        return scanner

    def go_fixture(self):
        checksum = 'h1:' + 'A' * 43 + '='
        module = {'Path': 'example.org/dependency', 'Version': 'v1.2.3', 'Sum': checksum}
        info = {'GoVersion': 'go1.26.5', 'Main': {'Path': 'example.org/main'}, 'Deps': [module],
                'Settings': [{'Key': '-trimpath', 'Value': 'true'}, {'Key': 'CGO_ENABLED', 'Value': '0'}]}
        graph = {'module': 'example.org/main', 'resolved_graph': [dict(module)]}
        return info, graph, {(module['Path'], module['Version']): checksum}

    def test_exact_linked_go_versions_and_sums(self):
        info, graph, sums = self.go_fixture()
        records = d.go_modules(info, graph, sums)
        self.assertEqual(records[0]['version'], 'v1.2.3')
        info['Deps'][0]['Version'] = 'v1.2.4'
        with self.assertRaisesRegex(ValueError, 'frozen source graph'):
            d.go_modules(info, graph, sums)

    def test_missing_sum_replacement_and_dirty_build_refuse(self):
        info, graph, sums = self.go_fixture()
        with self.assertRaisesRegex(ValueError, 'go.sum'):
            d.go_modules(info, graph, {})
        info['Deps'][0]['Replace'] = {'Path': '/developer/module'}
        with self.assertRaisesRegex(ValueError, 'Replaced'):
            d.go_modules(info, graph, sums)
        info, graph, sums = self.go_fixture()
        info['Settings'][1]['Value'] = '1'
        with self.assertRaisesRegex(ValueError, 'non-CGO'):
            d.go_modules(info, graph, sums)

    def test_module_cache_escape_and_notice_link_refusal(self):
        self.assertEqual(d.module_escape('github.com/QuanuX/Module'), 'github.com/!quanu!x/!module')
        with self.assertRaises(ValueError):
            d.module_escape('../other')
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / 'LICENSE').symlink_to('/etc/hosts')
            with self.assertRaisesRegex(ValueError, 'nonlinked'):
                d.legal_files(root)

    def test_final_payload_bytes_and_membership(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload = root / 'executable'
            payload.write_bytes(b'final')
            payload.chmod(0o755)
            inventory = [{'path': 'executable', 'sha256': d.sha(payload), 'size': 5, 'mode': 0o755}]
            self.assertEqual(set(d.verify_inventory(root, inventory)), {'executable'})
            payload.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'Changed'):
                d.verify_inventory(root, inventory)
            payload.write_bytes(b'final')
            (root / 'unowned').write_text('extra')
            with self.assertRaisesRegex(ValueError, 'Uninventoried'):
                d.verify_inventory(root, inventory)

    def test_native_receipt_binds_dependencies_and_complete_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload_name = 'share/licenses/unit/LICENSE'
            payload = root / payload_name
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b'license')
            receipt_name = 'share/symphony/receipts/unit/1.0/install-receipt.json'
            receipt_path = root / receipt_name
            receipt_path.parent.mkdir(parents=True)
            receipt = {'component_id': 'unit', 'version': '1.0', 'files': [
                {'path': payload_name, 'digest': 'sha256:' + d.sha(payload), 'size': 7}]}
            receipt['receipt_digest'] = 'sha256:' + d.digest(d.canonical(receipt))
            receipt_path.write_text(json.dumps(receipt))
            inventory = {payload_name: {'sha256': d.sha(payload), 'size': 7}, receipt_name: {'sha256': d.sha(receipt_path)}}
            unit = {'component_id': 'unit', 'version': '1.0', 'source_root': 'modules/unit',
                    'first_party_sdk_dependencies': [{'target': 'Symphony::Foundation'}], 'external_dependency_refs': []}
            records, owned = d.native_records(root, [unit], inventory)
            self.assertEqual(records[0]['first_party_sdk_dependencies'], unit['first_party_sdk_dependencies'])
            self.assertEqual(set(owned), {payload_name, receipt_name})
            receipt['version'] = 'wrong'
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, 'digest'):
                d.native_records(root, [unit], inventory)

    def test_corresponding_source_tar_is_neutral_and_deterministic(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            source = root / 'source.c'
            source.write_text('int main(void) { return 0; }\n')
            entries = [('symphony-source/source.c', source, 0o644)]
            first = d.safe_archive(root / 'first.tar', entries)
            second = d.safe_archive(root / 'second.tar', entries)
            self.assertEqual(first['sha256'], second['sha256'])
            with tarfile.open(root / 'first.tar') as archive:
                member = archive.getmembers()[0]
                self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, '', ''))
            with self.assertRaisesRegex(ValueError, 'Preserve'):
                d.safe_archive(root / 'first.tar', entries)

    def ssiag_notice_fixture(self, root, component='ssiag-provider-private-store'):
        source, prefix = root / 'source', root / 'prefix'
        unit = {'component_id': component, 'version': '0.1.0-dev',
                'source_root': 'modules/' + component,
                'first_party_sdk_dependencies': [], 'external_dependency_refs': []}
        docs = 'share/doc/symphony/' + component + '/0.1.0-dev/'
        pairs = {docs + 'LICENSE-AGPL-3.0': ('LICENSE', b'exact main license'),
                 docs + 'nlohmann-json-LICENSE.MIT': ('libraries/knowledge-vector-engine-cpp/third_party/nlohmann/LICENSE.MIT', b'exact JSON license')}
        for target, (original, raw) in pairs.items():
            for path in (source / original, prefix / target):
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        (prefix / docs / 'MANIFEST.md').write_bytes(b'ordinary component documentation')
        receipt_name = 'share/symphony/receipts/' + component + '/0.1.0-dev/install-receipt.json'
        def seal():
            inventory = {path.relative_to(prefix).as_posix(): {'sha256': d.sha(path), 'size': path.stat().st_size}
                         for path in prefix.rglob('*') if path.is_file() and path.relative_to(prefix).as_posix() != receipt_name}
            receipt = {'component_id': unit['component_id'], 'version': unit['version'], 'files': [
                {'path': name, 'digest': 'sha256:' + row['sha256'], 'size': row['size']} for name, row in inventory.items()]}
            receipt['receipt_digest'] = 'sha256:' + d.digest(d.canonical(receipt))
            path = prefix / receipt_name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(receipt))
            inventory[receipt_name] = {'sha256': d.sha(path), 'size': path.stat().st_size}
            return inventory
        return source, prefix, unit, pairs, seal

    def test_ssiag_doc_notices_are_exact_source_files_not_arbitrary_docs(self):
        with tempfile.TemporaryDirectory() as raw:
            source, prefix, unit, pairs, seal = self.ssiag_notice_fixture(Path(raw).resolve())
            records, _ = d.native_records(prefix, [unit], seal(), source)
            self.assertEqual(set(records[0]['notice_paths']), set(pairs))
            self.assertEqual({row['source_path'] for row in records[0]['notice_source_bindings']},
                             {'LICENSE', 'libraries/knowledge-vector-engine-cpp/third_party/nlohmann/LICENSE.MIT'})
            (prefix / next(iter(pairs))).write_bytes(b'different but freshly receipted text')
            with self.assertRaisesRegex(ValueError, 'exact built-source legal file'):
                d.native_records(prefix, [unit], seal(), source)

    def test_ssiag_notice_source_binding_and_complete_pair_are_required(self):
        with tempfile.TemporaryDirectory() as raw:
            source, prefix, unit, pairs, seal = self.ssiag_notice_fixture(Path(raw).resolve())
            with self.assertRaisesRegex(ValueError, 'Exact adapter source'):
                d.native_records(prefix, [unit], seal())
            (prefix / next(iter(pairs))).unlink()
            with self.assertRaisesRegex(ValueError, 'source notices are incomplete'):
                d.native_records(prefix, [unit], seal(), source)

    def test_cloudflare_doc_notices_share_only_the_exact_approved_contract(self):
        with tempfile.TemporaryDirectory() as raw:
            source, prefix, unit, pairs, seal = self.ssiag_notice_fixture(Path(raw).resolve(), 'sov-cloudflare-adapter')
            records, _ = d.native_records(prefix, [unit], seal(), source)
            self.assertEqual(set(records[0]['notice_paths']), set(pairs))
            unit['source_root'] = 'modules/unreviewed'
            with self.assertRaisesRegex(ValueError, 'Exact adapter source'):
                d.native_records(prefix, [unit], seal(), source)

    def test_duplicate_json_fields_are_not_accepted(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'record.json'
            path.write_text('{"version":"1", "version":"2"}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                d.read_json(path)

    def test_cache_zip_hash_cannot_differ_from_actual_linked_sum(self):
        info, _, _ = self.go_fixture()
        module = {k.lower(): v for k, v in info['Deps'][0].items()}
        with tempfile.TemporaryDirectory() as raw:
            cache = Path(raw).resolve()
            path = cache / 'cache/download/example.org/dependency/@v/v1.2.3.ziphash'
            path.parent.mkdir(parents=True)
            path.write_text(module['sum'] + '\n')
            d.verify_module_cache_sum(cache, module)
            path.write_text('h1:changed')
            with self.assertRaisesRegex(ValueError, 'checksum differs'):
                d.verify_module_cache_sum(cache, module)

    def test_toolkit_excludes_private_artifact_classes(self):
        self.assertEqual(d.toolkit_path('build-cohort/build.py'), 'build-cohort/build.py')
        for name in ('qualification/__pycache__/x.pyc', 'private-evidence/report.json', '.venv/key', '.DS_Store'):
            with self.assertRaisesRegex(ValueError, 'not corresponding source'):
                d.toolkit_path(name)

    def test_native_toolchain_uses_verified_path_free_configure_observations(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / 'logs').mkdir()
            log = root / 'logs/unit-configure.log'
            log.write_text('-- The CXX compiler identification is AppleClang 21.0.0.21000101\n-- compiler path /private/developer/tool\n')
            result = {'logs': [{'name': log.name, 'sha256': d.sha(log), 'exit_code': 0}],
                      'loader_audit': {'status': 'passed', 'native_binaries': [{'dependencies': [
                          {'dependency': '/usr/lib/libc++.1.dylib'}, {'dependency': '/usr/lib/libSystem.B.dylib'}]}]}}
            observed = d.native_toolchain_observations(root, result, [{'component_id': 'unit'}], {'cxx_runtime': 'libc++.1.dylib'})
            self.assertEqual(observed['native_units_observed'], 1)
            self.assertEqual(observed['cxx_compilers'], [{'compiler_id': 'AppleClang', 'version': '21.0.0.21000101'}])
            self.assertEqual(observed['cxx_standard_library']['observed_loader_library_names'], ['libc++.1.dylib'])
            self.assertIsNone(observed['cxx_standard_library']['exact_standard_library_release'])
            self.assertNotIn('/private', json.dumps(observed))
            log.write_text('-- The CXX compiler identification is AppleClang 22.0\n')
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                d.native_toolchain_observations(root, result, [{'component_id': 'unit'}], {'cxx_runtime': 'libc++.1.dylib'})

    def test_missing_compiler_observation_cannot_be_inferred(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / 'logs').mkdir()
            log = root / 'logs/unit-configure.log'
            log.write_text('-- Configuring done\n')
            result = {'logs': [{'name': log.name, 'sha256': d.sha(log), 'exit_code': 0}],
                      'loader_audit': {'status': 'passed', 'native_binaries': []}}
            with self.assertRaisesRegex(ValueError, 'CXX compiler identity'):
                d.native_toolchain_observations(root, result, [{'component_id': 'unit'}], {'cxx_runtime': 'libstdc++.so.6'})
            with self.assertRaisesRegex(ValueError, 'configure log is absent'):
                d.native_toolchain_observations(root, result, [{'component_id': 'other'}], {'cxx_runtime': 'libstdc++.so.6'})

    def test_actual_os_profile_keeps_supplemental_host_at_e1(self):
        build = {'host': {'requested_profile': 'ubuntu24.04-amd64', 'os': 'linux', 'architecture': 'amd64',
                          'os_release': '24.04', 'scope': 'native_profile_build'}}
        host = {'system': 'linux', 'architecture': 'amd64', 'distribution': 'ubuntu', 'version': '24.04', 'wsl': False}
        observed = d.collection_host_observation(build, host)
        self.assertTrue(observed['profile_matches'])
        self.assertFalse(observed['release_supported'])
        with self.assertRaisesRegex(ValueError, 'exact native OS'):
            d.collection_host_observation(build, {**host, 'distribution': 'debian'})
        build['host'] = {'requested_profile': 'macos15-arm64', 'os': 'macos', 'architecture': 'amd64',
                         'os_release': '26.7.1', 'scope': 'supplemental_local_build'}
        host = {'system': 'darwin', 'architecture': 'amd64', 'distribution': 'macos', 'version': '26.7.1', 'wsl': False}
        observed = d.collection_host_observation(build, host)
        self.assertFalse(observed['profile_matches'])
        self.assertTrue(observed['supplemental'])
        self.assertFalse(observed['fresh_host_accepted'])

    def test_external_tool_report_is_optional_but_exact_and_path_free(self):
        self.assertEqual(d.external_toolchain_observation({}, None)['status'], 'not_provided')
        with tempfile.TemporaryDirectory() as raw:
            report = Path(raw) / 'external-build.json'
            report.write_text(json.dumps({'status': 'built_and_scanned', 'tools': {
                name: {'path': '/private/developer/' + name, 'sha256': str(i) * 64}
                for i, name in enumerate(('cc', 'cxx', 'cmake'))}}))
            build = {'external_evidence_sha256': d.sha(report)}
            observed = d.external_toolchain_observation(build, report)
            self.assertEqual(observed['status'], 'exact_build_input_observed')
            self.assertNotIn('/private', json.dumps(observed))
            report.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'differs'):
                d.external_toolchain_observation(build, report)

    def test_only_exact_scanner_sources_receive_synthetic_marker_exception(self):
        with tempfile.TemporaryDirectory() as raw:
            scanner = self.source_scanner(Path(raw))
            for name, approved in d.TOOLKIT_SCANNER_EXCEPTIONS.items():
                data = (d.ROOT / name).read_bytes()
                result = d.scan_toolkit_source(scanner, name, data)
                self.assertEqual(result['sha256'], approved['sha256'])
                self.assertEqual(result['synthetic_marker_count'], approved['synthetic_marker_count'])
                self.assertFalse(result['archived_source_bytes_changed'])
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    d.scan_toolkit_source(scanner, name, data + b'\n# changed\n')
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    d.scan_toolkit_source(scanner, name, data + b'\n' + b'AKIA' + b'B' * 16)
            with self.assertRaisesRegex(ValueError, 'private marker'):
                d.scan_toolkit_source(scanner, 'unreviewed.py', d.TOOLKIT_SYNTHETIC_MARKER)

    def test_scanner_exception_preserves_actual_privacy_checks(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            # This chosen marker occurs in the exact approved scanner source,
            # independently of its synthetic canary. Its removal is forbidden.
            scanner = self.source_scanner(root, ['PRIVATE_MARKERS'])
            name = 'source-export/export_source.py'
            with self.assertRaisesRegex(ValueError, 'private marker'):
                d.scan_toolkit_source(scanner, name, (d.ROOT / name).read_bytes())
            scanner = self.source_scanner(root)
            with self.assertRaisesRegex(ValueError, 'private marker'):
                d.scan_toolkit_source(scanner, 'other.py', b'SYNTHETIC_PUBLISHER_IDENTITY')
            with self.assertRaisesRegex(ValueError, 'credential'):
                d.scan_toolkit_source(scanner, 'other.txt', b'AKIA' + b'A' * 16)
            with self.assertRaisesRegex(ValueError, 'private key'):
                d.scan_toolkit_source(scanner, 'other.txt', b'-----BEGIN PRIVATE KEY-----\n' + b'A' * 40 + b'\n-----END PRIVATE KEY-----')

    def repair_fixture(self):
        units = [{'component_id': 'unit-' + str(i)} for i in range(51)]
        records = [{'component_id': row['component_id'], 'configure_log_sha256': 'a' * 64,
            'kind': 'rebuilt_from_exact_origin_source' if i < 8 else 'inherited_native_receipt_and_bytes',
            **({} if i < 8 else {'original_log_sealed_by_round': False})} for i, row in enumerate(units)]
        repair = {'origin_tool_commit': sorted(d.REVIEWED_ORIGIN_TOOL_COMMITS)[0],
                  'rebuild_ids': [row['component_id'] for row in units[:8]],
                  'inherited_native_count': 43, 'inherited_go_count': 6}
        build = {'repair_provenance': repair, 'fresh_whole_cohort_build': False,
                 'original_evidence_unchanged': True, 'repeated_payload_bytes_equal': False}
        result = {'fresh_whole_cohort_build': False, 'inherited_native_count': 43,
                  'inherited_go_count': 6, 'repaired_native_count': 8, 'native_unit_provenance': records,
                  'logs': [{'name': row['component_id'] + '-configure.log', 'sha256': 'a' * 64} for row in units],
                  'external_repair': {'changed_paths': ['third-party/lib/libzstd.a']}}
        return build, result, units

    def test_imported_helpers_are_exact_and_rechecked_after_collection(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            imports = {'qualification/native_campaign.py': b'original campaign',
                       'source-export/export_source.py': b'original exporter'}
            for name, content in imports.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            build = {'build_helpers': {}, 'imported_helpers': {name: d.sha(root / name) for name in imports}}
            hashes = d.selected_helpers(build)
            d.verify_selected_helpers(hashes, root)
            (root / 'source-export/export_source.py').write_bytes(b'changed during source collection')
            with self.assertRaisesRegex(ValueError, 'helper changed'):
                d.verify_selected_helpers(hashes, root)
            for incomplete in ({}, {'qualification/native_campaign.py': 'a' * 64}):
                with self.assertRaisesRegex(ValueError, 'imported helper set'):
                    d.selected_helpers({'build_helpers': {}, 'imported_helpers': incomplete})

    def test_repaired_lineage_preserves_inherited_scope_and_log_sealing(self):
        build, result, units = self.repair_fixture()
        observed = d.build_lineage(build, result, units)
        self.assertFalse(observed['fresh_whole_cohort_build'])
        self.assertFalse(observed['repeated_payload_bytes_equal'])
        self.assertEqual(observed['repair_provenance'], build['repair_provenance'])
        self.assertEqual(observed['native_unit_provenance'], result['native_unit_provenance'])
        self.assertFalse(observed['native_unit_provenance'][-1]['original_log_sealed_by_round'])
        self.assertEqual(observed['external_repair'], result['external_repair'])
        result['native_unit_provenance'][-1]['configure_log_sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'observation provenance differs'):
            d.build_lineage(build, result, units)

    def test_repaired_lineage_cannot_be_promoted_or_lose_members(self):
        build, result, units = self.repair_fixture()
        build['fresh_whole_cohort_build'] = True
        with self.assertRaisesRegex(ValueError, 'fresh or repeated'):
            d.build_lineage(build, result, units)
        build, result, units = self.repair_fixture()
        result['native_unit_provenance'].pop()
        with self.assertRaisesRegex(ValueError, 'cover the final cohort'):
            d.build_lineage(build, result, units)
        with self.assertRaisesRegex(ValueError, 'missing its repair provenance'):
            d.build_lineage({'fresh_whole_cohort_build': False}, {}, units)

    def test_original_toolkit_uses_complete_exact_git_tree_not_current_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            scanner = self.source_scanner(root)
            repository = root / 'repository'; repository.mkdir()
            inputs = {'source-binding.json': b'{"fixture":true}\n', 'build-cohort/build.py': b'# original builder\n',
                      'qualification/native_campaign.py': b'# original imported helper\n'}
            inputs.update({name: (d.ROOT / name).read_bytes() for name in d.TOOLKIT_SCANNER_EXCEPTIONS})
            for name, data in inputs.items():
                path = repository / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            def git(*args):
                return d.subprocess.check_output(['/usr/bin/git', '-C', str(repository), *args], stderr=d.subprocess.PIPE)
            git('init'); git('add', '.')
            git('-c', 'user.name=Fixture Author', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'Original toolkit fixture')
            commit = git('rev-parse', 'HEAD').decode().strip()
            (repository / 'build-cohort/build.py').write_bytes(b'# changed current builder\n')
            with patch.object(d, 'REVIEWED_ORIGIN_TOOL_COMMITS', {commit}):
                record, entries = d.original_toolkit_source(commit, root / 'original', scanner, repository)
            self.assertEqual(record['git_commit'], commit)
            self.assertEqual(record['file_count'], len(entries))
            self.assertEqual(len(entries), len(inputs))
            files = {row['path']: row for row in record['files']}
            self.assertTrue({'source-binding.json', 'build-cohort/build.py', 'source-export/export_source.py',
                             'qualification/native_campaign.py'} <= set(files))
            self.assertEqual(files['build-cohort/build.py']['sha256'], d.sha(root / 'original/build-cohort/build.py'))
            self.assertNotEqual(files['build-cohort/build.py']['sha256'], d.sha(repository / 'build-cohort/build.py'))
            self.assertEqual(len(record['scanner_exceptions']), 2)
            self.assertTrue(all(name.startswith('distribution-toolkit-origins/' + commit + '/') for name, _, _ in entries))
            archive = d.safe_archive(root / 'source.tar', entries)
            self.assertEqual(archive['file_count'], record['file_count'])
            with self.assertRaisesRegex(ValueError, 'not reviewed'):
                d.original_toolkit_source('0' * 40, root / 'other', scanner)

    def test_original_toolkit_refuses_unreviewed_blob_bytes_and_private_source(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            scanner = self.source_scanner(root)
            commit = sorted(d.REVIEWED_ORIGIN_TOOL_COMMITS)[0]
            secret_fixture = b'SYNTHETIC_PUBLISHER_IDENTITY'
            blob = d.hashlib.sha1(b'blob ' + str(len(secret_fixture)).encode() + b'\0' + secret_fixture).hexdigest()
            def original_git(argv, **kwargs):
                if 'rev-parse' in argv:
                    return ((commit if argv[-1].endswith('^{commit}') else '1' * 40) + '\n').encode()
                if 'ls-tree' in argv:
                    return ('100644 blob ' + blob + '\tREADME.md\0').encode()
                return secret_fixture
            with patch.object(d.subprocess, 'check_output', side_effect=original_git):
                with self.assertRaisesRegex(ValueError, 'private marker'):
                    d.original_toolkit_source(commit, root / 'private-refused', scanner)
            def changed_blob(argv, **kwargs):
                return b'changed' if 'cat-file' in argv else original_git(argv, **kwargs)
            with patch.object(d.subprocess, 'check_output', side_effect=changed_blob):
                with self.assertRaisesRegex(ValueError, 'blob content differs'):
                    d.original_toolkit_source(commit, root / 'changed-refused', scanner)


if __name__ == '__main__':
    unittest.main()
