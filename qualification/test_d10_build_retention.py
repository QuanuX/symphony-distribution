import copy
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import d10_build_retention as retention


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.policy = self.root / 'private-policy.json'
        self.policy.write_text(json.dumps({'schema': 'symphony.source-privacy-policy.v1',
            'markers': ['PRIVATE_TEST_OWNER'], 'document_attributions': {}}))
        self.policy.chmod(0o600)
        self.privacy = retention.scanner(self.policy)
        self.producer = retention.producer_record('1234', '1', 'a' * 40)
        self.cohort, self.export, self.repository = [self.root / n for n in ('cohort', 'export', 'repository')]
        for path in (self.cohort, self.export, self.repository):
            path.mkdir()
        self.source = self.put(self.cohort / 'source/a.cpp', b'public source\n')
        self.payload = self.put(self.cohort / 'round-1/relocated-prefix/lib/libfixture.so.1', b'final native bytes\n', 0o755)
        self.link = self.payload.with_name('libfixture.so'); self.link.symlink_to(self.payload.name)
        self.aggregate = {'host': {'requested_profile': 'macos15-arm64'}, 'source_commit': 'b' * 40,
            'source_tree': 'c' * 40, 'source_input': {'export_digest': 'd' * 64},
            'rounds': [{'directory': 'round-1', 'result_sha256': '1' * 64},
                       {'directory': 'round-2', 'result_sha256': '2' * 64}]}
        self.aggregate_file = self.put(self.cohort / 'result.json', json.dumps(self.aggregate).encode())
        self.manifest = self.put(self.export / 'SOURCE-EXPORT.json', b'{}\n')
        self.external = self.put(self.root / 'external-build.json', b'{"public":true}\n')
        self.selected = {'cohort/result.json': self.aggregate_file,
                         'cohort/source/a.cpp': self.source,
                         'cohort/round-1/relocated-prefix/lib/libfixture.so.1': self.payload,
                         'cohort/round-1/relocated-prefix/lib/libfixture.so': self.link,
                         'export/SOURCE-EXPORT.json': self.manifest,
                         'external/external-build.json': self.external}
        self.rounds = [{'payload_inventory': [{'path': 'lib/libfixture.so.1', 'sha256': retention.sha(self.payload),
                                               'size': self.payload.stat().st_size, 'mode': 0o755}]}] * 2

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, data, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(mode)
        return path

    def fixture_retention(self, output='retained'):
        # Validate custody with real archive I/O and privacy scanning. Native
        # compilation and qxctl's existing source-proof verifier have their own
        # tests; this bounded fixture is not reported as a native qualification.
        with patch.object(retention, 'inspect_completed', return_value=(self.aggregate, self.rounds, {}, [])), \
             patch.object(retention, 'verify_producer_source'), \
             patch.object(retention, 'select_files', return_value=self.selected):
            result = retention.retain(self.cohort, self.export, self.repository, self.external, self.policy,
                                     self.root / output, producer=self.producer)
        return self.root / output, result

    def restore(self, root, output='restored'):
        return retention.restore(root, self.root / output, retention.sha(root / 'capsule.json'),
                                 retention.sha(root / retention.ARCHIVE), self.policy)

    def test_roundtrip_preserves_bytes_modes_links_and_keeps_scope_honest(self):
        root, report = self.fixture_retention()
        paths = self.restore(root)
        self.assertEqual((paths['cohort'] / 'source/a.cpp').read_bytes(), self.source.read_bytes())
        self.assertEqual((paths['export'] / 'source/a.cpp').read_bytes(), self.source.read_bytes())
        lib = paths['cohort'] / 'round-1/relocated-prefix/lib/libfixture.so.1'
        self.assertEqual(lib.read_bytes(), self.payload.read_bytes())
        self.assertEqual(lib.stat().st_mode & 0o777, 0o755)
        self.assertEqual(os.readlink(lib.with_name('libfixture.so')), 'libfixture.so.1')
        self.assertTrue(report['both_original_payloads_verified'])
        self.assertFalse(report['second_round_payload_retained'])
        self.assertFalse(report['wrapper_qualified'])
        self.assertFalse(report['publication_authorized'])
        self.assertFalse((paths['cohort'] / 'round-2/relocated-prefix').exists())

    def test_repeat_archive_is_equal_and_metadata_neutral(self):
        first, _ = self.fixture_retention('first'); second, _ = self.fixture_retention('second')
        self.assertEqual((first / retention.ARCHIVE).read_bytes(), (second / retention.ARCHIVE).read_bytes())
        with tarfile.open(first / retention.ARCHIVE) as bundle:
            for member in bundle:
                self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, '', ''))

    def test_mutated_selected_bytes_refused_and_prior_inputs_preserved(self):
        original = retention.write_archive
        def change(path, rows, selected):
            original(path, rows, selected)
            self.payload.write_bytes(b'changed after archive')
        with patch.object(retention, 'write_archive', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'changed during retention'):
                self.fixture_retention()
        self.assertFalse((self.root / 'retained/capsule.json').exists())

    def test_private_bytes_never_create_capsule(self):
        self.source.write_text('PRIVATE_TEST_OWNER')
        with self.assertRaisesRegex(ValueError, 'private marker'):
            self.fixture_retention()
        self.assertFalse((self.root / 'retained').exists())

    def test_private_path_and_symlink_target_refused(self):
        selected = {'cohort/source/PRIVATE_TEST_OWNER.txt': self.source}
        with self.assertRaisesRegex(ValueError, 'private marker'):
            retention.file_inventory(selected, self.privacy)
        outside = self.root / 'outside-link'; outside.symlink_to(self.source)
        with self.assertRaises(ValueError):
            retention.file_inventory({'cohort/source/link': outside}, self.privacy)

    def test_actual_linux_and_macos_curl_link_chains_roundtrip(self):
        # These exact two-link shapes occur in all four retained primary
        # round inventories; their payload bytes remain unchanged.
        for label, names in (
                ('linux', ('libcurl.so', 'libcurl.so.4', 'libcurl.so.4.8.0')),
                ('macos', ('libcurl.dylib', 'libcurl.4.dylib', 'libcurl.4.8.0.dylib'))):
            with self.subTest(platform=label):
                directory = self.cohort / 'round-1/relocated-prefix/third-party/lib'
                leaf = self.put(directory / names[2], b'exact public curl fixture', 0o755)
                first, second = directory / names[0], directory / names[1]
                first.symlink_to(names[1]); second.symlink_to(names[2])
                selected = dict(self.selected)
                selected.update({'cohort/round-1/relocated-prefix/third-party/lib/' + name: directory / name for name in names})
                with patch.object(self, 'selected', selected):
                    root, _ = self.fixture_retention('retained-' + label)
                    restored = self.restore(root, 'restored-' + label)
                target = restored['cohort'] / 'round-1/relocated-prefix/third-party/lib'
                self.assertEqual(os.readlink(target / names[0]), names[1])
                self.assertEqual(os.readlink(target / names[1]), names[2])
                self.assertEqual((target / names[0]).read_bytes(), leaf.read_bytes())

    def test_link_chains_refuse_cycles_dangling_absolute_and_escape(self):
        prefix = 'cohort/round-1/relocated-prefix/third-party/lib/'
        regular = {'path': prefix + 'real', 'sha256': 'a' * 64, 'size': 1, 'mode': 0o644}
        cases = [
            [{'path': prefix + 'first', 'link': 'second'}, {'path': prefix + 'second', 'link': 'first'}],
            [{'path': prefix + 'first', 'link': 'second'}, {'path': prefix + 'second', 'link': 'absent'}],
            [{'path': prefix + 'first', 'link': 'second'}, {'path': prefix + 'second', 'link': '/tmp/real'}],
            [{'path': prefix + 'first', 'link': 'second'}, {'path': prefix + 'second', 'link': '../../../../source/a.cpp'},
             {'path': 'cohort/source/a.cpp', 'sha256': 'a' * 64, 'size': 1, 'mode': 0o644}],
            [{'path': prefix + 'first', 'link': '.'}],
        ]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                retention.validate_payload_links(rows + [regular])

    def test_live_cycle_and_directory_target_refused_without_mutation(self):
        self.link.unlink(); self.link.symlink_to('cycle')
        cycle = self.link.with_name('cycle'); cycle.symlink_to(self.link.name)
        selected = {**self.selected, 'cohort/round-1/relocated-prefix/lib/cycle': cycle}
        with self.assertRaisesRegex(ValueError, 'Cyclic'):
            retention.file_inventory(selected, self.privacy)
        cycle.unlink(); cycle.symlink_to('.')
        with self.assertRaisesRegex(ValueError, 'dangling'):
            retention.file_inventory(selected, self.privacy)
        self.assertTrue(self.link.is_symlink()); self.assertTrue(cycle.is_symlink())

    def test_existing_dangling_parent_and_overlapping_output_refused(self):
        selected, _ = self.fixture_retention()
        with self.assertRaises(ValueError): self.fixture_retention()
        dangling = self.root / 'dangling'; dangling.symlink_to(self.root / 'absent')
        with self.assertRaisesRegex(ValueError, 'Linked'):
            retention.fresh(dangling, [])
        parent = self.root / 'parent-link'; parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Linked'):
            retention.fresh(parent / 'new', [])
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            retention.fresh(self.cohort / 'new', [self.cohort])
        self.assertTrue((selected / 'capsule.json').exists())

    def test_independently_selected_digests_required(self):
        root, _ = self.fixture_retention()
        for capsule, archive in [('0' * 64, retention.sha(root / retention.ARCHIVE)),
                                  (retention.sha(root / 'capsule.json'), '0' * 64)]:
            with self.assertRaises(ValueError):
                retention.restore(root, self.root / 'restored', capsule, archive, self.policy)
        self.assertFalse((self.root / 'restored').exists())

    def test_archive_hidden_trailer_refused_even_with_rebound_outer_hash(self):
        root, report = self.fixture_retention()
        archive = root / retention.ARCHIVE
        with archive.open('ab') as stream: stream.write(b'\0' * 64)
        report['archive'].update(sha256=retention.sha(archive), size=archive.stat().st_size)
        (root / 'capsule.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'Noncanonical'):
            self.restore(root)

    def test_restore_accepts_equivalent_compression_without_relaxing_tar_identity(self):
        root, report = self.fixture_retention()
        archive = root / retention.ARCHIVE
        raw = gzip.decompress(archive.read_bytes())
        with archive.open('wb') as stream, gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=0, compresslevel=1) as out:
            out.write(raw)
        report['archive'].update(sha256=retention.sha(archive), size=archive.stat().st_size)
        (root / 'capsule.json').write_text(json.dumps(report))
        self.restore(root)

    def test_archive_nonzero_tar_padding_refused(self):
        root, report = self.fixture_retention()
        archive = root / retention.ARCHIVE
        raw = bytearray(gzip.decompress(archive.read_bytes()))
        first = report['files'][0]
        # First member is the small aggregate regular file, followed by padding.
        self.assertLess(first['size'], 512)
        raw[512 + first['size']] = 1
        with archive.open('wb') as stream, gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=0) as out:
            out.write(raw)
        report['archive'].update(sha256=retention.sha(archive), size=archive.stat().st_size)
        (root / 'capsule.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'Noncanonical archive padding'):
            self.restore(root)

    def test_restore_repeats_private_policy_and_refuses_changed_policy(self):
        root, _ = self.fixture_retention()
        changed = json.loads(self.policy.read_text()); changed['markers'].append('another private fixture')
        self.policy.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'policy differs'):
            self.restore(root)
        self.assertFalse((self.root / 'restored').exists())

    def test_policy_cannot_be_public_or_linked(self):
        self.policy.chmod(0o644)
        with self.assertRaisesRegex(ValueError, '0600'): retention.scanner(self.policy)
        self.policy.chmod(0o600)
        link = self.root / 'policy-link'; link.symlink_to(self.policy)
        with self.assertRaisesRegex(ValueError, 'Linked'): retention.scanner(link)

    def test_hardlinked_file_refused(self):
        alias = self.root / 'alias'; os.link(self.source, alias)
        with self.assertRaisesRegex(ValueError, 'aliased'):
            retention.file_inventory(self.selected, self.privacy)

    def test_producer_identity_and_approval_claim_refused(self):
        for run, attempt, commit in [('1/../2', '1', 'a' * 40), ('1', '0', 'a' * 40), ('1', '1', 'main')]:
            with self.assertRaises(ValueError): retention.producer_record(run, attempt, commit)
        root, report = self.fixture_retention()
        report['publication_authorized'] = True
        (root / 'capsule.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'approval'): self.restore(root)

    def test_archive_admission_refuses_duplicates_traversal_and_special_files(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('source/fifo', tarfile.FIFOTYPE)]:
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as bundle:
                member = tarfile.TarInfo(name); member.type = kind
                bundle.addfile(member)
            raw.seek(0)
            row = {'path': name, 'sha256': hashlib.sha256(b'').hexdigest(), 'size': 0, 'mode': 0o644}
            with tarfile.open(fileobj=raw) as bundle, self.assertRaises(ValueError):
                retention.validate_members(bundle, [row])
        root, report = self.fixture_retention()
        with tarfile.open(root / retention.ARCHIVE) as bundle, self.assertRaisesRegex(ValueError, 'Noncanonical'):
            retention.validate_members(bundle, report['files'] * 2)

    def test_completed_input_admission_rejects_raw_and_supplemental_before_packaging(self):
        valid = {'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'built_and_sdk_checked',
                 'host': {'requested_profile': 'macos15-arm64', 'scope': 'native_profile_build'},
                 'rounds': [{'directory': 'round-1'}, {'directory': 'round-2'}],
                 'repeated_payload_bytes_equal': True, 'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True},
                 'publication_authorized': False, 'acceptance_complete': False}
        for field, value, expected in [('source_input', {'kind': 'exact_committed_source_archive'}, 'Raw Git'),
                                      ('host', {'requested_profile': 'macos15-arm64', 'scope': 'supplemental_local_build'}, 'Supplemental'),
                                      ('repeated_payload_bytes_equal', False, 'Two completed')]:
            altered = copy.deepcopy(valid); altered[field] = value
            self.aggregate_file.write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, expected):
                retention.inspect_completed(self.cohort, self.export, self.repository, self.privacy)

    def completed_native_fixture(self):
        plan_file = retention.ROOT / 'build-cohort/cohort.json'
        plan = json.loads(plan_file.read_text())
        units = plan['profiles']['macos15-arm64']['native_build_order']
        manifest = {'source_files': [{'path': 'a.cpp', 'export_sha256': retention.sha(self.source),
                    'export_size': self.source.stat().st_size, 'mode': '100644'}]}
        self.manifest.write_text(json.dumps(manifest))
        prefix = self.cohort / 'round-1/relocated-prefix'
        # Existing fixture payload is external to receipt ownership; every
        # selected native owner receives its own genuine canonical fixture receipt.
        receipts = []
        for unit in units:
            cid, version = unit['component_id'], unit['version']
            owned = self.put(prefix / ('lib/' + cid + '.fixture'), cid.encode())
            row = {'path': owned.relative_to(prefix).as_posix(), 'digest': 'sha256:' + retention.sha(owned),
                   'size': owned.stat().st_size}
            receipt = {'component_id': cid, 'version': version, 'files': [row]}
            receipt['receipt_digest'] = 'sha256:' + hashlib.sha256(retention.canonical(receipt)).hexdigest()
            path = self.put(prefix / f'share/symphony/receipts/{cid}/{version}/install-receipt.json',
                            json.dumps(receipt).encode())
            receipts.append({'component_id': cid, 'version': version, 'receipt_sha256': retention.sha(path), 'owned_file_count': 1})
        shutil.copytree(prefix, self.cohort / 'round-2/relocated-prefix', symlinks=True)
        selected = {p.relative_to(prefix).as_posix(): p for p in prefix.rglob('*') if not p.is_dir()}
        payload = []
        for name, path in sorted(selected.items()):
            payload.append({'path': name, 'link': os.readlink(path)} if path.is_symlink() else {
                'path': name, 'sha256': retention.sha(path), 'size': path.stat().st_size, 'mode': path.stat().st_mode & 0o777})
        build = {'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'built_and_sdk_checked',
            'source_commit': plan['source_commit'], 'source_tree': plan['source_tree'], 'plan_sha256': retention.sha(plan_file),
            'build_helpers': {p.name: retention.sha(p) for p in (retention.ROOT / 'build-cohort').iterdir()
                              if p.suffix in ('.py', '.cmake') and not p.name.startswith('test_')},
            'imported_helpers': {name: retention.sha(retention.ROOT / name) for name in
                                 ('qualification/native_campaign.py', 'source-export/export_source.py')},
            'host': {'requested_profile': 'macos15-arm64', 'scope': 'native_profile_build'},
            'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True,
                             'export_digest': 'a' * 64, 'archive_sha256': 'b' * 64},
            'rounds': [], 'publication_authorized': False, 'acceptance_complete': False,
            'repeated_payload_bytes_equal': True}
        record = {'state': 'built_and_sdk_checked', 'native_count': 51, 'native_receipts': receipts,
                  'go_commands': [{'component_id': 'qxctl'}] + [{'component_id': 'go-fixture-' + str(n)} for n in range(5)],
                  'publication_authorized': False, 'payload_inventory': payload,
                  **{key: {'status': 'passed'} for key in ('sdk_audit', 'installed_owner_audit', 'loader_audit')}}
        for n in (1, 2):
            path = self.put(self.cohort / f'round-{n}/result.json', json.dumps(record).encode())
            build['rounds'].append({'directory': f'round-{n}', 'result_sha256': retention.sha(path),
                                    'native_count': 51, 'go_count': 6})
        self.aggregate_file.write_text(json.dumps(build))
        return build

    def test_actual_two_stage_inventory_and_all51_receipts_admitted(self):
        build = self.completed_native_fixture()
        privacy = SimpleNamespace(verify=lambda export, repository: build['source_input'])
        # The source transformer and qxctl proof each have independent contract
        # suites. Keep these fixtures scoped to the newly introduced custody gate.
        with patch.object(retention.delivery, 'go_build_provenance') as proof:
            result = retention.inspect_completed(self.cohort, self.export, self.repository, privacy)
        self.assertEqual(len(result[3]), 51)
        self.assertEqual(proof.call_count, 2)
        self.assertEqual(result[1][0]['payload_inventory'], result[1][1]['payload_inventory'])

    def test_actual_second_stage_drift_refused_before_selection(self):
        build = self.completed_native_fixture()
        path = self.cohort / 'round-2/relocated-prefix/lib/libfixture.so.1'
        path.write_bytes(b'drift')
        privacy = SimpleNamespace(verify=lambda export, repository: build['source_input'])
        with patch.object(retention.delivery, 'go_build_provenance'), \
             self.assertRaisesRegex(ValueError, 'Changed final payload'):
            retention.inspect_completed(self.cohort, self.export, self.repository, privacy)

    def test_actual_native_receipt_seal_drift_refused(self):
        build = self.completed_native_fixture()
        receipt = next((self.cohort / 'round-1/relocated-prefix/share/symphony/receipts').rglob('install-receipt.json'))
        data = json.loads(receipt.read_text()); data['receipt_digest'] = 'sha256:' + '0' * 64
        receipt.write_text(json.dumps(data))
        record_file = self.cohort / 'round-1/result.json'; record = json.loads(record_file.read_text())
        row = next(r for r in record['payload_inventory'] if r['path'] == receipt.relative_to(self.cohort / 'round-1/relocated-prefix').as_posix())
        row.update(sha256=retention.sha(receipt), size=receipt.stat().st_size)
        record_file.write_text(json.dumps(record)); build['rounds'][0]['result_sha256'] = retention.sha(record_file)
        self.aggregate_file.write_text(json.dumps(build))
        privacy = SimpleNamespace(verify=lambda export, repository: build['source_input'])
        with patch.object(retention.delivery, 'go_build_provenance'), self.assertRaisesRegex(ValueError, 'receipt canonical hash'):
            retention.inspect_completed(self.cohort, self.export, self.repository, privacy)

    def test_producer_commit_must_match_selected_checkout(self):
        with patch.object(retention.subprocess, 'check_output', return_value=b'b' * 40 + b'\n'), \
             self.assertRaisesRegex(ValueError, 'Producer commit'):
            retention.verify_producer_source(self.producer, {})

    def test_closed_selection_omits_cache_policy_and_private_original_archives(self):
        build = self.completed_native_fixture()
        build['external_evidence_sha256'] = retention.sha(self.external)
        plan = json.loads((retention.ROOT / 'build-cohort/cohort.json').read_text())
        units = plan['profiles']['macos15-arm64']['native_build_order']
        rounds = [json.loads((self.cohort / f'round-{n}/result.json').read_text()) for n in (1, 2)]
        rounds[0]['logs'] = []
        for unit in units:
            name = unit['component_id'] + '-configure.log'
            path = self.put(self.cohort / 'round-1/logs' / name, b'-- The CXX compiler identification is AppleClang 21.0.0\n')
            rounds[0]['logs'].append({'name': name, 'exit_code': 0, 'sha256': retention.sha(path)})
        proof_root = self.cohort / 'round-1/qxctl-identity'
        self.put(proof_root / 'result.json', json.dumps({'compiled_input_equivalence': {
            'inputs': [{'path': 'tools/qxctl/main.go'}]}}).encode())
        names = ['recipe/artifact-identity.json', 'recipe/first-build-info.json', 'recipe/second-build-info.json',
                 'recipe/first/bin/qxctl', 'recipe/second/bin/qxctl', 'recipe/first/tools/qxctl/main.go']
        for name in names: self.put(proof_root / name, b'public fixture')
        self.put(proof_root / 'recipe/source.tar', b'PRIVATE_TEST_OWNER')
        self.put(self.cohort / 'round-1/go-cache/private-cache', b'PRIVATE_TEST_OWNER')
        self.put(self.cohort / 'private-policy.json', self.policy.read_bytes())
        self.put(self.cohort / 'round-1/logs/private-general-build.log', b'PRIVATE_TEST_OWNER')
        self.put(self.export / 'symphony-source.tar', b'public source fixture')
        manifest = json.loads(self.manifest.read_text())
        selected = retention.select_files(self.cohort, self.export, self.external, build, rounds, manifest, units)
        self.assertEqual(sum(name.startswith('cohort/round-1/logs/') for name in selected), 51)
        self.assertEqual({n for n in selected if n.startswith('cohort/round-2/')}, {'cohort/round-2/result.json'})
        for forbidden in ('private-policy', 'go-cache', 'recipe/source.tar', 'private-general-build.log'):
            self.assertFalse(any(forbidden in name for name in selected))
        retention.file_inventory(selected, self.privacy)


if __name__ == '__main__':
    unittest.main()
