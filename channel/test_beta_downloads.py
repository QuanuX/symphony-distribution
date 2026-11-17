import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('beta_downloads', Path(__file__).with_name('beta_downloads.py'))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)

class Missing(Exception):
    response = {'Error': {'Code': 'NoSuchKey'}}

class API:
    def __init__(self): self.objects = {}; self.writes = []; self.fail = False
    def get_object(self, Bucket, Key):
        if Key not in self.objects: raise Missing()
        raw = self.objects[Key]
        return {'Body': io.BytesIO(raw), 'ContentLength': len(raw)}
    def put_object(self, **kw):
        self.writes.append(kw)
        assert kw['IfNoneMatch'] == '*'
        assert kw['Key'] not in self.objects
        self.objects[kw['Key']] = kw['Body'].read()
        if self.fail: raise TimeoutError('uncertain')

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.art = self.root / 'art'; self.art.mkdir()
        self.sig = self.root / 'signature'; self.sig.mkdir(); self.api = API(); self.reads = []
        (self.art / 'installer.sh').write_bytes(b'exact-release')
        self.row = {'path':'installer.sh','size':13,'sha256':d.sha(b'exact-release'),'source':'artifacts',
                    'key':d.PREFIX+'installer.sh','url':d.ORIGIN+d.PREFIX+'installer.sh'}
        self.plan = {'protocol':d.PROTOCOL,'release':d.signing.RELEASE,'bucket':d.BUCKET,'manifest_sha256':'a'*64,
                     'objects':[self.row],'overwrite_supported':False,'automatic_mutation_retry':False}
        self.admission=patch.object(d,'prepare',return_value=self.plan);self.admission.start();self.addCleanup(self.admission.stop)
    def run_publish(self):
        return d.publish(self.plan,self.art,self.sig,'cert','key','openssl',self.root/'attempt',self.api,self.reads.append)
    def test_conditional_create_and_public_readback(self):
        result=self.run_publish()
        self.assertEqual(len(self.api.writes),1); self.assertEqual(self.reads,[self.row])
        self.assertEqual(result['state'],'all_selected_public_downloads_verified')
        self.assertTrue((self.root/'attempt/000-intent.json').is_file())
    def test_existing_identical_is_read_only(self):
        self.api.objects[self.row['key']]=b'exact-release'; self.run_publish()
        self.assertEqual(self.api.writes,[])
    def test_existing_different_never_overwritten(self):
        self.api.objects[self.row['key']]=b'wrong-release'
        with self.assertRaises(ValueError): self.run_publish()
        self.assertEqual(self.api.writes,[]); self.assertEqual(self.reads,[])
    def test_changed_local_bytes_refused_before_remote_write(self):
        (self.art/'installer.sh').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.run_publish()
        self.assertEqual(self.api.writes,[])
    def test_unknown_write_is_retained_and_never_automatically_retried(self):
        self.api.fail=True
        with self.assertRaisesRegex(ValueError,'unknown write outcome'): self.run_publish()
        self.assertEqual(len(self.api.writes),1)
        self.assertTrue((self.root/'attempt/000-unknown.json').is_file())
        with self.assertRaises(ValueError): self.run_publish()
        self.assertEqual(len(self.api.writes),1)
        self.assertTrue(d.remote(self.api,self.row))
    def test_wrong_destination_refused(self):
        self.row['key']='another-prefix/installer.sh'
        with self.assertRaises(ValueError): self.run_publish()
        self.assertEqual(self.api.writes,[])
    def test_public_readback_failure_never_claims_complete(self):
        def failure(row): raise ValueError('bad public bytes')
        with self.assertRaises(ValueError):
            d.publish(self.plan,self.art,self.sig,'cert','key','openssl',self.root/'attempt',self.api,failure)
        self.assertFalse((self.root/'attempt/result.json').exists())
        self.assertEqual(len(self.api.writes),1)
    def test_excess_remote_bytes_refused(self):
        with self.assertRaises(ValueError): d.streamed_digest(io.BytesIO(b'longer'),3)
    def test_redirect_refused(self):
        with self.assertRaises(ValueError): d.NoRedirect().redirect_request(None,None,302,'',{},'https://other')
    def test_public_readback_identifies_application_without_account_credentials(self):
        response=io.BytesIO(b'exact-release');response.status=200;response.geturl=lambda:self.row['url']
        opener=Mock();opener.open.return_value=response
        with patch.dict(sys.modules,{'botocore.httpsession':SimpleNamespace(get_cert_path=lambda _:None)}), \
             patch.object(d.urllib.request,'build_opener',return_value=opener):
            d.public_readback(self.row)
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_header('User-agent'),d.USER_AGENT)
        self.assertEqual(request.get_header('Cache-control'),'no-cache')
        self.assertIsNone(request.get_header('Authorization'));self.assertIsNone(request.get_header('Cookie'))

class AdmissionTests(unittest.TestCase):
    def test_replaced_manifest_index_and_signature_refused(self):
        for changed in ('beta-manifest.json', 'beta-manifest.sig', 'release-index.json'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(); art=root/'art'; sig=root/'sig'; art.mkdir();sig.mkdir()
                index=d.signing.base.canonical({'release':d.signing.RELEASE,'public_downloads':['release-index.json']})
                (art/'release-index.json').write_bytes(index)
                manifest=d.signing.base.canonical({'release_index':{'path':'release-index.json'},
                    'artifacts':[{'path':'release-index.json','size':len(index),'sha256':d.sha(index)}]})
                (sig/'beta-manifest.json').write_bytes(manifest);(sig/'beta-manifest.sig').write_bytes(b'signature')
                (sig/'beta-cert.pem').write_bytes(b'certificate')
                def verified(*args):
                    target=(art if changed=='release-index.json' else sig)/changed
                    target.write_bytes(b'changed')
                    return {'release_index_sha256':d.sha(index)}
                with patch.object(d.signing,'verify',side_effect=verified):
                    with self.assertRaises(ValueError):d.prepare(art,sig,d.sha(b'certificate'),'key','openssl')
    def test_unsigned_download_selection_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();art=root/'art';sig=root/'sig';art.mkdir();sig.mkdir()
            index=d.signing.base.canonical({'release':d.signing.RELEASE,'public_downloads':['unlisted.sh']})
            (art/'release-index.json').write_bytes(index)
            (sig/'beta-manifest.json').write_bytes(d.signing.base.canonical({'release_index':{'path':'release-index.json'},'artifacts':[]}))
            (sig/'beta-manifest.sig').write_bytes(b'signature')
            with patch.object(d.signing,'verify',return_value={'release_index_sha256':d.sha(index)}):
                with self.assertRaisesRegex(ValueError,'signed non-Conda'):d.prepare(art,sig,'cert','key','openssl')

if __name__ == '__main__': unittest.main()
