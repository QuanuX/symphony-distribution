import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from installer_assembly import cohort as c


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class InstallerCohort(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.base = self.root / 'base'; self.prefix = self.base / 'round-1/relocated-prefix'; self.prefix.mkdir(parents=True)
        self.export = self.root / 'export'; self.source = self.export / 'source'; self.source.mkdir(parents=True)
        self.proof_root = self.root / 'identity'; self.proof_root.mkdir()
        self.delivery_path = self.root / 'delivery/delivery-record.json'
        self.output = self.root / 'new-cohort'
        self.commit, self.tree = '1' * 40, '2' * 40
        self.native = []
        for index in range(51):
            component = 'native-' + str(index)
            path = self.prefix / 'share/symphony/receipts' / component / '1.0/install-receipt.json'
            write(path, {'component_id': component})
            self.native.append({'component_id': component, 'version': '1.0', 'receipt_sha256': c.sha(path)})
        self.go = []
        for component in ('qxctl', 'a', 'b', 'c', 'd', 'e'):
            path = self.prefix / 'go' / component / 'bin' / component; path.parent.mkdir(parents=True)
            path.write_bytes(('old binary ' + component).encode()); path.chmod(0o755)
            self.go.append({'component_id': component, 'version': '0.1.0-dev', 'sha256': c.sha(path)})
        sources = {'cmake/mvp-dependencies.json': b'{"native_components":[]}',
                   'tools/qxctl/main.go': b'package main\n', 'tools/qxctl/go.mod': b'module example\n',
                   'tools/qxctl/go.sum': b'checksums\n', 'tools/qxctl/tests/reproducible_build.cmake': b'original recipe\n'}
        source_rows = []
        for name, raw in sorted(sources.items()):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            h = c.sha(path)
            source_rows.append({'path': name, 'mode': '100644', 'source_sha256': h, 'export_sha256': h,
                                'source_size': len(raw), 'export_size': len(raw)})
        export_digest = hashlib.sha256(c.canonical([{'path': r['path'], 'mode': r['mode'], 'sha256': r['export_sha256']} for r in source_rows])).hexdigest()
        self.manifest = {'protocol': 'symphony.public-source-export.v2', 'is_original_git_tree': False,
            'origin_commit': self.commit, 'origin_tree': self.tree, 'derived_export_digest': export_digest,
            'privacy_policy_digest': '3' * 64, 'source_files': source_rows,
            'release_acceptance_complete': False, 'publication_authorized': False}
        write(self.export / 'SOURCE-EXPORT.json', self.manifest)
        self.round = {'state': 'built_and_sdk_checked', 'native_count': 51, 'native_receipts': self.native,
                      'go_commands': self.go, 'payload_inventory': c.snapshot(self.prefix), 'publication_authorized': False,
                      **{name: {'status': 'passed'} for name in ('sdk_audit', 'installed_owner_audit', 'loader_audit')}}
        write(self.base / 'round-1/result.json', self.round)
        self.aggregate = {'protocol': 'symphony.distribution.clean-cohort.v1', 'state': 'built_and_sdk_checked',
            'source_commit': self.commit, 'source_tree': self.tree, 'acceptance_complete': False, 'publication_authorized': False,
            'host': {'os': 'macos', 'architecture': 'amd64'},
            'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True, 'export_digest': export_digest,
                             'archive_sha256': '4' * 64},
            'rounds': [{'directory': 'round-1', 'result_sha256': c.sha(self.base / 'round-1/result.json'), 'native_count': 51, 'go_count': 6}]}
        write(self.base / 'result.json', self.aggregate)
        notice = self.delivery_path.parent / 'notices/LICENSE'; notice.parent.mkdir(parents=True); notice.write_bytes(b'legal notice\n')
        self.delivery = {'protocol': 'symphony.distribution.d06-delivery-record.v1', 'state': 'inventory_complete_publisher_review_pending',
            'publication_authorized': False, 'release_ready': False, 'fresh_host_accepted': False,
            'build_result_sha256': c.sha(self.base / 'result.json'), 'round_result_sha256': c.sha(self.base / 'round-1/result.json'),
            'source_binding': {'commit': self.commit, 'tree': self.tree}, 'payload_files': self.round['payload_inventory'],
            'source': {'mode': 'verified_derived_public_export', 'matching_build_install_source_prepared': True, 'derived_export_digest': export_digest},
            'notices': [{'path': 'notices/LICENSE', 'sha256': c.sha(notice), 'size': notice.stat().st_size}]}
        write(self.delivery_path, self.delivery)
        binary = self.proof_root / 'recipe/first/bin/qxctl'; binary.parent.mkdir(parents=True); binary.write_bytes(b'new stamped binary'); binary.chmod(0o755)
        info = {'protocol': 'symphony.qxctl.build-info.v1', 'component_id': 'qxctl', 'version': '0.1.0-dev', 'source_state': 'stamped',
                'source_commit': self.commit, 'source_tree': self.tree, 'source_date_epoch': '1234',
                'dependency_map_sha256': c.sha(self.source / 'cmake/mvp-dependencies.json'),
                'build_recipe': 'symphony.qxctl.reproducible-build.v1', 'go_version': 'go1.26.5', 'goos': 'darwin', 'goarch': 'amd64',
                'executable_sha256': c.sha(binary)}
        artifact = {k: v for k, v in info.items() if k not in ('protocol', 'source_state')}
        artifact.update(protocol='symphony.artifact-build-identity.v1', isolated_builds=2, reproducibility='verified_on_recorded_profile',
                        publication_authorized=False, go_mod_sha256=c.sha(self.source / 'tools/qxctl/go.mod'),
                        go_sum_sha256=c.sha(self.source / 'tools/qxctl/go.sum'))
        inputs = [r for r in c.snapshot(self.source) if r['path'] == 'tools/qxctl/main.go']
        self.proof = {'protocol': 'symphony.distribution.qxctl-original-source.v1', 'state': 'reproducible_stamped_original_git_source',
            'component_id': 'qxctl', 'isolated_builds': 2, 'release_acceptance_complete': False, 'publication_authorized': False,
            'original_source': {'commit': self.commit, 'tree': self.tree, 'source_date_epoch': '1234'},
            'recipe': {'id': info['build_recipe'], 'modified': False, 'sha256': c.sha(self.source / 'tools/qxctl/tests/reproducible_build.cmake')},
            'network_policy': 'local_file_proxy_only_no_network_or_VCS_fallback', 'build_info': info, 'artifact_identity': artifact,
            'binary_sha256': c.sha(binary), 'binary': 'recipe/first/bin/qxctl',
            'cohort_source': {'kind': 'verified_reviewed_derived_export', 'is_original_git_tree': False, 'export_digest': export_digest, 'archive_sha256': '4' * 64},
            'compiled_input_equivalence': {'method': 'native_go_list_deps_compiled_json_CGO0', 'original_matches_cohort_source': True,
                'goos': 'darwin', 'goarch': 'amd64', 'inputs': inputs, 'inventory_sha256': hashlib.sha256(c.canonical(inputs)).hexdigest()},
            'privacy': {'private_build_paths_absent': True, 'publisher_policy_scanned': True, 'policy_digest': '3' * 64,
                        'private_original_fixture_archive_distributable': False}}
        write(self.proof_root / 'result.json', self.proof)
        self.kwargs = dict(expected_base_result_sha256=c.sha(self.base / 'result.json'), expected_round_result_sha256=c.sha(self.base / 'round-1/result.json'),
                           expected_delivery_sha256=c.sha(self.delivery_path), expected_qxctl_proof_sha256=c.sha(self.proof_root / 'result.json'))

    def tearDown(self): self.tmp.cleanup()

    def prepare(self):
        return c.prepare_cohort(self.base, self.delivery_path, self.proof_root, self.export, self.output, **self.kwargs)

    def test_only_qxctl_changes_with_independent_copies_and_retained_notices(self):
        before = c.snapshot(self.prefix); record = self.prepare()
        self.assertEqual(record, c.verify_cohort(self.output, c.sha(self.output / 'cohort.json')))
        self.assertEqual(before, c.snapshot(self.prefix)); self.assertEqual(record['inherited_native_count'], 51)
        self.assertEqual(record['inherited_go_count'], 5); self.assertFalse(record['publication_authorized'])
        self.assertEqual((self.output / 'evidence/notices/LICENSE').read_bytes(), b'legal notice\n')
        for row in before:
            self.assertNotEqual((self.prefix / row['path']).stat().st_ino, (self.output / 'prefix' / row['path']).stat().st_ino)

    def test_wrong_selected_digest_refuses_before_output_creation(self):
        self.kwargs['expected_base_result_sha256'] = 'f' * 64
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_changed_retained_native_payload_refuses(self):
        (self.prefix / self.round['payload_inventory'][0]['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_changed_derived_source_refuses(self):
        (self.source / 'tools/qxctl/main.go').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_source_overlap_refuse(self):
        self.output.mkdir()
        with self.assertRaises(ValueError): self.prepare()
        self.output.rmdir(); self.output = self.base / 'new'
        with self.assertRaises(ValueError): self.prepare()

    def test_changed_new_binary_native_bytes_modes_and_membership_refuse(self):
        self.prepare()
        target = self.output / 'prefix' / c.QXCTL; original = target.read_bytes()
        target.write_bytes(b'tamper')
        with self.assertRaises(ValueError): c.verify_cohort(self.output)
        target.write_bytes(original); target.chmod(0o644)
        with self.assertRaises(ValueError): c.verify_cohort(self.output)
        target.chmod(0o755); extra = self.output / 'prefix/extra'; extra.write_bytes(b'extra')
        with self.assertRaises(ValueError): c.verify_cohort(self.output)

    def test_missing_notice_and_unknown_evidence_refuse(self):
        self.prepare(); notice = self.output / 'evidence/notices/LICENSE'; raw = notice.read_bytes(); notice.unlink()
        with self.assertRaises(ValueError): c.verify_cohort(self.output)
        notice.write_bytes(raw); (self.output / 'evidence/private-extra').write_bytes(b'not selected')
        with self.assertRaises(ValueError): c.verify_cohort(self.output)

    def test_self_consistent_relabeling_of_inherited_go_provenance_refuses(self):
        record = self.prepare(); record['go_commands'][1]['sha256'] = 'a' * 64; write(self.output / 'cohort.json', record)
        with self.assertRaises(ValueError): c.verify_cohort(self.output)

    def test_derived_source_cannot_be_stamped_as_original(self):
        for field, value in (('source_state', 'unavailable'), ('dependency_map_sha256', 'f' * 64), ('source_tree', 'f' * 40)):
            proof = copy.deepcopy(self.proof); proof['build_info'][field] = value; proof['artifact_identity'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                c.validate_proof(proof, self.aggregate, self.manifest, c.sha(self.source / 'cmake/mvp-dependencies.json'))

    def test_publication_claim_and_escaping_payload_links_refuse(self):
        record = self.prepare(); record['publication_authorized'] = True; write(self.output / 'cohort.json', record)
        with self.assertRaises(ValueError): c.verify_cohort(self.output)
        (self.output / 'prefix/escape').symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): c.snapshot(self.output / 'prefix')


if __name__ == '__main__': unittest.main()
