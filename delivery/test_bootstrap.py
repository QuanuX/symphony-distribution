import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('retention_test', Path(__file__).with_name('bootstrap.py'))
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


def payload(files):
    rows, stream = [], io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, (raw, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name); info.mode = mode; info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
            rows.append({'path': name, 'sha256': b.sha(raw), 'size': len(raw), 'mode': mode})
    return stream.getvalue(), rows


def client_zip():
    files = {'bin/symphony-mcp': b'exact bridge', 'catalog/tools.json': b'{}',
        'scripts/configure_connection.py': b'# connection', 'scripts/configure_clients.py': b'# client'}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name, raw in files.items():
            info = zipfile.ZipInfo(name); info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if name == 'bin/symphony-mcp' else 0o644)) << 16
            archive.writestr(info, raw)
    return stream.getvalue(), {name: 'sha256:' + b.sha(raw) for name, raw in files.items()}


class Bootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.prefix = self.root / 'installed'; self.prefix.mkdir()
        self.out = self.root / 'retained'; self.entries = []
        self.script = self.prefix / b.SCRIPT_PATH; self.script.parent.mkdir(parents=True)
        self.script.write_bytes(Path(b.__file__).read_bytes())
        for n in range(51):
            component='n'+str(n); name='lib/symphony/'+component+'/1/data'; content=b'native data'
            receipt={'protocol':'symphony.knowledge.install-receipt.v2','component_id':component,'version':'1',
                'files':[{'path':name,'digest':'sha256:'+b.sha(content),'size':len(content)}]}
            receipt['receipt_digest']='sha256:'+b.sha(b.canonical(receipt))
            self.add('native:'+component,'native_receipt_unit',{name:(content,0o644),
                'share/symphony/receipts/'+component+'/1/install-receipt.json':(b.canonical(receipt),0o644)})
        self.add('external:curl-zstd', 'external_inert_runtime_and_sdk', {})
        for name in ('qxctl', 'secure-identity-access-governance', 'stav-append-authority', 'accordare-stav-producer', 'sov-ssh-adapter', 'sov-stdio-adapter'):
            executable = {'qxctl':'qxctl', 'secure-identity-access-governance':'symphony-ssiag',
                'stav-append-authority':'symphony-stav-append-authority', 'accordare-stav-producer':'symphony-accordare-stav-producer'}.get(name, name)
            self.add('go:' + name, 'go_command', {'go/' + name + '/bin/' + executable: (b'exact ' + name.encode(), 0o755),
                'delivery-notices/notices/symphony/LICENSE':(b'shared exact legal text',0o644)})
        raw, inventory = client_zip()
        self.add('client:client', 'client_bridge_bundle', {'client.zip': (raw, 0o644),
            'package-inventory.json': (b.canonical(inventory), 0o644), 'qualification.json': (b'{}', 0o644), 'derivation.json': (b'{}', 0o644)})
        self.index = {'protocol': b.INDEX, 'cohort_digest': 'sha256:' + 'a'*64, 'profile':'macos15-arm64',
            'script_sha256': b.sha(self.script.read_bytes()), 'entries': self.entries, 'python_minimum':'3.11',
            'native_installation_performed':False, 'runtime_activation_changed':False}
        self.pin = self.save_index()

    def add(self, uid, kind, files):
        component = uid.split(':')[1]; dest = 'share/symphony/carriers/' + component + '/1/build'
        directory = self.prefix / dest; directory.mkdir(parents=True)
        raw, rows = payload(files)
        unit = {'unit_id':uid, 'component_id':component, 'kind':kind, 'native_version':'1', 'files':rows,
            'native_runtime_install_supported':False}
        unit_raw = b.canonical(unit)
        manifest = {'protocol':'symphony.distribution.d08-inert-carrier.v1', 'unit_id':uid, 'destination':dest,
            'runtime_install_supported':False, 'files':[{'path':name,'sha256':b.sha(data),'size':len(data)}
                for name,data in [('payload.tar',raw),('unit.json',unit_raw)]]}
        blobs = {'payload.tar':raw, 'unit.json':unit_raw, 'carrier-manifest.json':b.canonical(manifest)}
        for name, data in blobs.items(): (directory/name).write_bytes(data)
        entry = {key:unit[key] for key in ('unit_id','component_id','kind','native_version')}
        entry.update(carrier_destination=dest, carrier_files={name:b.sha(data) for name,data in blobs.items()})
        self.entries.append(entry)

    def save_index(self):
        raw = b.canonical(self.index) + b'\n'; (self.prefix / b.INDEX_PATH).write_bytes(raw); return b.sha(raw)

    def retain(self, **kwargs):
        with patch.object(b.os, 'geteuid', return_value=os.getuid()):
            return b.retain(self.prefix, self.pin, self.out, **kwargs)

    def test_default_retention_is_complete_and_inert(self):
        result = self.retain()
        self.assertEqual(result['selected_units'], sorted(b.DEFAULT))
        self.assertFalse(result['native_installation_performed']); self.assertFalse(result['runtime_activation_changed'])
        self.assertEqual((self.out / result['entrypoints']['qxctl']).read_bytes(), b'exact qxctl')
        self.assertEqual((self.out/'client/bin/symphony-mcp').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.out/'CUSTODY.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)

    def test_owners_are_retained_without_native_installation(self):
        result = self.retain(owners=True)
        self.assertEqual(set(result['selected_units']), b.DEFAULT | b.OWNERS)
        self.assertFalse(result['native_retirement_authority'])
        self.assertFalse(result['client_configuration_changed'])
        notices=list((self.out/'notices').rglob('LICENSE'))
        self.assertEqual(len(notices),4)
        self.assertTrue(all(path.read_bytes()==b'shared exact legal text' for path in notices))

    def test_all_complete_native_receipts_are_candidates_only(self):
        result=self.retain(all_units=True)
        self.assertEqual(len(result['selected_units']),59)
        self.assertEqual(len(list((self.out/'candidate/share/symphony/receipts').rglob('install-receipt.json'))),51)
        self.assertFalse(result['native_installation_performed'])

    def test_external_index_supports_cli_prefix_without_wrapper_extras(self):
        external=self.root/'downloaded-index.json'; external.write_bytes((self.prefix/b.INDEX_PATH).read_bytes())
        (self.prefix/b.INDEX_PATH).unlink(); self.script.unlink()
        result=self.retain(external_index=external)
        self.assertEqual(result['state'],'retained_verified_candidates')
        self.assertNotIn(str(self.root),b.canonical(result).decode())

    def test_input_access_time_may_change_without_false_refusal(self):
        path=self.root/'read'; path.write_bytes(b'unchanged'); now=path.stat().st_mtime_ns
        os.utime(path,ns=(1,now)); fd=b.directory(self.root)
        try: self.assertEqual(b.read_at(fd,'read'),b'unchanged')
        finally: os.close(fd)

    def test_fifo_is_refused_without_waiting_for_writer(self):
        os.mkfifo(self.root/'fifo'); fd=b.directory(self.root)
        try:
            with self.assertRaisesRegex(ValueError,'regular'): b.read_at(fd,'fifo')
        finally: os.close(fd)

    def test_extra_installed_carrier_member_is_refused(self):
        entry=next(row for row in self.entries if row['unit_id']=='go:qxctl')
        (self.prefix/entry['carrier_destination']/'unexpected').write_bytes(b'not a candidate')
        with self.assertRaisesRegex(ValueError,'Unexpected installed carrier member'): self.retain()
        self.assertFalse(self.out.exists())

    def test_untrusted_index_and_script_refuse_before_output(self):
        self.pin = 'f'*64
        with self.assertRaisesRegex(ValueError,'index differs'): self.retain()
        self.assertFalse(self.out.exists())
        self.pin = self.save_index(); self.script.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'helper differs'): self.retain()
        self.assertFalse(self.out.exists())

    def test_payload_tamper_and_source_alias_refuse_before_output(self):
        entry = next(row for row in self.entries if row['unit_id']=='go:qxctl')
        path = self.prefix/entry['carrier_destination']/'payload.tar'; original = path.read_bytes()
        path.write_bytes(original+b'hidden')
        with self.assertRaisesRegex(ValueError,'Installed carrier differs'): self.retain()
        path.unlink(); outside=self.root/'outside'; outside.write_bytes(original); path.symlink_to(outside)
        with self.assertRaises(OSError): self.retain()
        self.assertFalse(self.out.exists())

    def test_existing_destination_and_in_carrier_custody_refused(self):
        self.out.mkdir(); marker=self.out/'user'; marker.write_bytes(b'preserve')
        with self.assertRaises(FileExistsError): self.retain()
        self.assertEqual(marker.read_bytes(),b'preserve')
        self.out=self.prefix/'nested'
        with self.assertRaisesRegex(ValueError,'independent'): self.retain()

    def test_tar_padding_traversal_and_link_escape_refused(self):
        raw, rows=payload({'ok':(b'x',0o644)})
        changed=bytearray(raw); changed[513]=1
        with self.assertRaisesRegex(ValueError,'Noncanonical'): b.tar_members(bytes(changed),rows)
        rows[0]['path']='../outside'
        with self.assertRaisesRegex(ValueError,'Unsafe'): b.tar_members(raw,rows)
        stream=io.BytesIO(); name='third-party/lib/libcurl.dylib'
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            info=tarfile.TarInfo(name); info.type=tarfile.SYMTYPE; info.mode=0o777; info.linkname='../../../../outside'; archive.addfile(info)
        with self.assertRaisesRegex(ValueError,'escapes'): b.tar_members(stream.getvalue(),[{'path':name,'link':'../../../../outside','mode':0o777}])

    def test_client_zip_hash_or_symlink_refused(self):
        raw, inventory=client_zip(); inventory['bin/symphony-mcp']='sha256:'+'f'*64
        with self.assertRaisesRegex(ValueError,'digest'): b.client_members(raw,inventory)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            row=zipfile.ZipInfo('bin/symphony-mcp'); row.create_system=3; row.external_attr=(stat.S_IFLNK|0o777)<<16; archive.writestr(row,'outside')
        with self.assertRaisesRegex(ValueError,'member'): b.client_members(stream.getvalue(),inventory)

    def test_source_mutation_after_snapshot_prevents_success_record(self):
        original=b.write_at
        def mutate(*args):
            result=original(*args)
            self.script.write_bytes(b'changed after capture')
            return result
        with patch.object(b,'write_at',side_effect=mutate):
            with self.assertRaisesRegex(ValueError,'bootstrap changed'): self.retain()
        self.assertFalse((self.out/'CUSTODY.json').exists())

    def test_root_execution_is_refused(self):
        with patch.object(b.os,'geteuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'unprivileged'): b.retain(self.prefix,self.pin,self.out)
        self.assertFalse(self.out.exists())


if __name__ == '__main__': unittest.main()
