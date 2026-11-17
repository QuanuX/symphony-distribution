import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'installer_assembly'))
import beta_signing as b
spec=importlib.util.spec_from_file_location('standalone_beta_verifier',Path(__file__).with_name('verify_beta.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

@unittest.skipUnless(shutil.which('openssl'),'OpenSSL required for real signature tests')
class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name).resolve()
        cls.openssl=Path(shutil.which('openssl')).resolve();cls.key=cls.root/'key'
        identity=b.initialize(cls.key,cls.openssl)
        v.CERTIFICATE_SHA256=identity['certificate_sha256'];v.PUBLIC_KEY_SHA256=identity['public_key_sha256']
        cls.art=cls.root/'art';cls.art.mkdir(); (cls.art/'selected.sh').write_bytes(b'public installer')
        (cls.art/'undownloaded.bin').write_bytes(b'other platform')
        (cls.art/'release-index.json').write_bytes(b.base.canonical({'release':b.RELEASE}))
        decision=Path(__file__).resolve().parents[1]/'evidence/d14-publisher-decision.json'
        (cls.art/'decision.json').write_bytes(decision.read_bytes())
        b.sign(cls.art,list(cls.art.iterdir()),cls.art/'release-index.json',cls.art/'decision.json',cls.key,
               v.CERTIFICATE_SHA256,v.PUBLIC_KEY_SHA256,cls.root/'signature',cls.openssl)
        (cls.art/'undownloaded.bin').unlink()
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def test_selected_download_verified_without_other_platforms(self):
        result=v.verify(self.root/'signature',self.art,['selected.sh'],self.openssl)
        self.assertEqual(result['publisher_signature'],'verified');self.assertFalse(result['notarized'])
    def test_tampered_file_refused(self):
        target=self.art/'selected.sh';raw=target.read_bytes();target.write_bytes(b'changed')
        try:
            with self.assertRaises(ValueError):v.verify(self.root/'signature',self.art,['selected.sh'],self.openssl)
        finally:target.write_bytes(raw)
    def test_unselected_or_unsafe_path_refused(self):
        for path in ('../selected.sh','unlisted.bin'):
            with self.assertRaises(ValueError):v.verify(self.root/'signature',self.art,[path],self.openssl)
    def test_wrong_certificate_pin_refused(self):
        old=v.CERTIFICATE_SHA256;v.CERTIFICATE_SHA256='0'*64
        try:
            with self.assertRaises(ValueError):v.verify(self.root/'signature',self.art,['selected.sh'],self.openssl)
        finally:v.CERTIFICATE_SHA256=old
    def test_tampered_signature_refused(self):
        target=self.root/'signature/beta-manifest.sig';raw=target.read_bytes();target.write_bytes(bytes([raw[0]^1])+raw[1:])
        try:
            with self.assertRaises(ValueError):v.verify(self.root/'signature',self.art,['selected.sh'],self.openssl)
        finally:target.write_bytes(raw)

if __name__=='__main__':unittest.main()
