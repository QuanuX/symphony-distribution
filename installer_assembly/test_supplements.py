import copy
import io
import hashlib
import json
from pathlib import Path
import stat
import sys
import tarfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).parent))
import supplements as s
c = s.c


class SupplementTests(unittest.TestCase):
    def tar(self, files):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as target:
            for name, raw in sorted(files.items()):
                member = tarfile.TarInfo(name); member.mode = 0o644; member.size = len(raw)
                target.addfile(member, io.BytesIO(raw))
        return stream.getvalue()

    def source(self):
        data = b'source'; git_blob = hashlib.sha1(b'blob 6\0' + data).digest()
        tree_body = b'100644 source.txt\0' + git_blob
        git_tree = hashlib.sha1(b'tree ' + str(len(tree_body)).encode() + b'\0' + tree_body).hexdigest()
        binding = {'commit': 'a' * 40, 'tree': git_tree, 'file_count': 1}
        core = {'commit': 'c' * 40, 'tree': 'd' * 40}
        old = self.tar({'symphony-source/tools/qxctl/main.go': data})
        recipe = b'reproducible recipe'
        inputs = [{'path': 'tools/qxctl/main.go', 'size': len(data), 'sha256': c.sha(data), 'mode': 0o644}]
        proof = {'protocol': 'symphony.distribution.qxctl-original-source.v1', 'state': 'reproducible_stamped_original_git_source',
            'publication_authorized': False, 'release_acceptance_complete': False, 'original_source': core,
            'recipe': {'sha256': c.sha(recipe)}, 'compiled_input_equivalence': {'method': 'native_go_list_deps_compiled_json_CGO0',
                'inputs': inputs, 'inventory_sha256': c.sha(c.canonical(inputs))}}
        delivery = {'source': {'corresponding_source_archive': {'sha256': c.sha(old)},
            'origin_commit': core['commit'], 'origin_tree': core['tree']}}
        scope = {'protocol': 'symphony.distribution.d08-corresponding-source.v1',
            'publication_authorized': False, 'release_acceptance_complete': False,
            'exact_original_full_tree_reconstruction': False,
            'source_bindings': {'core': core, 'client': binding, 'distribution_toolkit': binding},
            'compiled_input_equivalence': {'original_matches_cohort_source': True, 'input_count': len(inputs),
                'inventory_sha256': proof['compiled_input_equivalence']['inventory_sha256']},
            'inherited_reviewed_source_archive_sha256': c.sha(old), 'inherited_delivery_record_sha256': c.sha(c.canonical(delivery)),
            'qxctl_source_proof_sha256': c.sha(c.canonical(proof))}
        files = {'SOURCE-SCOPE.json': c.canonical(scope), 'd06/corresponding-source.tar': old,
            'd06/delivery-record.json': c.canonical(delivery), 'd08/client-source.tar': self.tar({'source.txt': data}),
            'd08/distribution-toolkit-source.tar': self.tar({'source.txt': data}),
            'd08/qxctl-original-source-proof.json': c.canonical(proof), 'd08/reproducible_build.cmake': recipe}
        archive = self.tar(files)
        index = {**scope, 'state': 'prepared_review_only', 'privacy_scan': 'pass',
            'archive': {'sha256': c.sha(archive), 'size': len(archive)},
            'members': [{'path': name, 'sha256': c.sha(raw), 'size': len(raw), 'mode': 0o644} for name, raw in sorted(files.items())]}
        privacy = {'protocol': 'symphony.distribution.d08-source-privacy.v1', 'state': 'pass',
            'archive_sha256': c.sha(archive), 'publication_authorized': False}
        return archive, index, privacy

    def test_exact_source_composite_retains_review_scope(self):
        archive, index, privacy = self.source()
        self.assertEqual(s.validate_source(archive, index, privacy), index['source_bindings'])
        index['exact_original_full_tree_reconstruction'] = True
        with self.assertRaisesRegex(ValueError, 'Source scope'): s.validate_source(archive, index, privacy)

    def test_source_changed_member_and_privacy_mismatch_refused(self):
        archive, index, privacy = self.source(); index['members'][0]['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'member differs'): s.validate_source(archive, index, privacy)
        archive, index, privacy = self.source(); privacy['archive_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'privacy binding'): s.validate_source(archive, index, privacy)

    def test_source_unindexed_member_and_hidden_padding_refused(self):
        archive, index, privacy = self.source(); index['members'] = []
        with self.assertRaisesRegex(ValueError, 'member set'): s.validate_source(archive, index, privacy)
        archive, index, privacy = self.source(); changed = bytearray(archive)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar: first = tar.next()
        changed[first.offset_data + first.size] = 65; archive = bytes(changed)
        index['archive']['sha256'] = privacy['archive_sha256'] = c.sha(archive)
        with self.assertRaisesRegex(ValueError, 'hidden/noncanonical'): s.validate_source(archive, index, privacy)

    def test_embedded_scope_cannot_contradict_index(self):
        archive, index, privacy = self.source(); index['source_bindings']['client']['commit'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'source scope'): s.validate_source(archive, index, privacy)
        archive, index, privacy = self.source(); privacy['publication_authorized'] = True
        with self.assertRaisesRegex(ValueError, 'privacy binding'): s.validate_source(archive, index, privacy)

    def test_inner_source_git_tree_and_mode_are_bound(self):
        raw = self.tar({'source.txt': b'source'})
        with self.assertRaisesRegex(ValueError, 'Git tree'): s.source_tree(raw, {'tree': 'f' * 40, 'file_count': 1})
        with self.assertRaisesRegex(ValueError, 'Git tree'): s.source_tree(raw, {'tree': 'f' * 40, 'file_count': 2})

    def client(self):
        files = {'.claude-plugin/plugin.json': b'{"version":"0.2.0-alpha.1"}', 'LICENSE': b'license',
                 'catalog/tools.json': b'{}', 'bin/symphony-mcp': b'bridge'}
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as target:
            for name, raw in sorted(files.items()):
                member = zipfile.ZipInfo(name); member.create_system = 3
                member.external_attr = (stat.S_IFREG | (0o755 if name.startswith('bin/') else 0o644)) << 16
                target.writestr(member, raw)
        package = stream.getvalue(); source = {'repository': 'example/client', 'commit': 'a' * 40, 'tree': 'b' * 40}
        inventory = {name: 'sha256:' + c.sha(raw) for name, raw in files.items()}
        export = {'source': source, 'files': {name: value for name, value in inventory.items() if name != 'bin/symphony-mcp'}}
        core = {'selected_evidence': {'source_binding': {'commit': 'c' * 40, 'tree': 'd' * 40}}}
        report = {'schema': 'symphony.beta-compatibility.report.v1', 'status': 'engineering_review_ready', 'pending': [],
            'distribution': 'pending', 'release_acceptance_complete': False, 'publication_authorized': False,
            'sources': {'plugin': source, 'core': core['selected_evidence']['source_binding']},
            'bindings': {'package_sha256': 'sha256:' + c.sha(package), 'bridge_sha256': inventory['bin/symphony-mcp'],
                         'catalog_sha256': inventory['catalog/tools.json']}}
        return package, inventory, export, report, core

    def test_client_legacy_pass_exact_package_source_and_prerelease_identity(self):
        args = self.client(); version, members = s.validate_client(*args)
        self.assertEqual(version, '0.2.0-alpha.1'); self.assertEqual(len(members), 4)
        args[3]['status'] = 'incomplete'
        with self.assertRaisesRegex(ValueError, 'Legacy'): s.validate_client(*args)

    def test_client_different_package_or_source_refused(self):
        args = self.client(); args[1]['LICENSE'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(ValueError, 'inventory differs'): s.validate_client(*args)
        args = self.client(); args[2]['files']['LICENSE'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(ValueError, 'source bytes'): s.validate_client(*args)

    def test_client_missing_source_file_or_changed_core_refused(self):
        args = self.client(); args[2]['files']['extra-file'] = 'sha256:' + 'f' * 64
        with self.assertRaisesRegex(ValueError, 'closure differs'): s.validate_client(*args)
        args = self.client(); args[3]['sources']['core'] = {'commit': 'e' * 40, 'tree': 'f' * 40}
        with self.assertRaisesRegex(ValueError, 'source pair'): s.validate_client(*args)

if __name__ == '__main__': unittest.main()
