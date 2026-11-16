import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import build

class BuildSafety(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
    def tearDown(self):self.tmp.cleanup()
    def test_fresh_refuses_existing_and_overlapping_input(self):
        source=self.root/'source';source.mkdir()
        with self.assertRaises(ValueError):build.fresh(source,[])
        with self.assertRaises(ValueError):build.fresh(source/'output',[source])
        self.assertFalse((source/'output').exists())
    def test_fresh_refuses_symlink_parent(self):
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to(self.root/'actual',target_is_directory=True)
        with self.assertRaises(ValueError):build.fresh(self.root/'alias/output',[])
    def test_native_profile_mismatch_is_not_acceptance(self):
        contract={'os':'macos','architecture':'arm64','os_release':'15'}
        with patch('build.platform.system',return_value='Darwin'),patch('build.platform.machine',return_value='x86_64'),patch('build.platform.mac_ver',return_value=('26.7.1',(),'')):
            with self.assertRaises(ValueError):build.selected_host('macos15-arm64',contract,False)
            observed=build.selected_host('macos15-arm64',contract,True)
            self.assertEqual(observed['scope'],'supplemental_local_build')
            self.assertFalse(observed['primary_profile_accepted'])
    def test_clean_environment_drops_credentials_and_build_overrides(self):
        with patch.dict('os.environ',{'CMAKE_PREFIX_PATH':'/private/dev','DYLD_LIBRARY_PATH':'/private/dev','AWS_SECRET_ACCESS_KEY':'fixture','GOFLAGS':'-mod=mod'}):
            env=build.clean_environment(self.root,Path('/selected/go'),Path('/cache'),Path('/usr/bin/cc'),Path('/usr/bin/c++'))
        for name in ('CMAKE_PREFIX_PATH','DYLD_LIBRARY_PATH','AWS_SECRET_ACCESS_KEY','GOFLAGS'):
            self.assertNotIn(name,env)
        self.assertEqual(env['ZERO_AR_DATE'],'1');self.assertEqual(env['SOURCE_DATE_EPOCH'],'0')
        self.assertEqual(env['GOPROXY'],'off');self.assertEqual(env['GOWORK'],'off')
    def test_static_archive_rejects_local_identity_and_time(self):
        def archive(uid='0',stamp='0'):
            return b'!<arch>\n'+f"{'unit.o/':<16}{stamp:<12}{uid:<6}{'0':<6}{'644':<8}{'2':<10}`\n".encode()+b'ok'
        build.verify_archive_metadata(archive())
        for raw in (archive(uid='501'),archive(stamp='1730000000'),b'!<thin>\n',archive()[:-1]):
            with self.assertRaises(ValueError):build.verify_archive_metadata(raw)
    def receipt(self, files):
        unit={'component_id':'example','version':'1.0'}
        receipt={'component_id':'example','version':'1.0','files':files}
        raw=json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()
        receipt['receipt_digest']='sha256:'+hashlib.sha256(raw).hexdigest()
        path=self.root/'share/symphony/receipts/example/1.0/install-receipt.json';path.parent.mkdir(parents=True)
        path.write_text(json.dumps(receipt));return unit,path
    def test_receipt_refuses_modified_payload(self):
        f=self.root/'binary';f.write_bytes(b'original')
        unit,_=self.receipt([{'path':'binary','size':8,'digest':'sha256:'+build.sha(f)}])
        build.verify_receipts(self.root,[unit]);f.write_bytes(b'tampered')
        with self.assertRaises(ValueError):build.verify_receipts(self.root,[unit])
    def test_receipt_refuses_path_escape(self):
        unit,_=self.receipt([{'path':'../outside','size':0,'digest':'sha256:'+'0'*64}])
        with self.assertRaises(ValueError):build.verify_receipts(self.root,[unit])
    def test_snapshot_refuses_build_path_and_escaping_symlink(self):
        f=self.root/'binary';f.write_bytes(b'path=/private/build/secrets')
        with self.assertRaises(ValueError):build.snapshot(self.root,forbidden=[Path('/private/build')])
        f.unlink();f.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):build.snapshot(self.root)
    def test_snapshot_retains_relative_internal_links(self):
        (self.root/'library').write_bytes(b'payload');(self.root/'alias').symlink_to('library')
        rows=build.snapshot(self.root)
        self.assertEqual(rows[0],{'path':'alias','link':'library'})

if __name__=='__main__':unittest.main()
