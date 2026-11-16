import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('delivery_record', Path(__file__).with_name('d06_delivery_record.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DeliveryRecordTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
