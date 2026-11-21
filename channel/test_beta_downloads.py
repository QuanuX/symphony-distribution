import hashlib
import importlib.util
import io
import json
import os
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


class CredentialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name).resolve() / 'credentials.json'
        self.direct = {'accessKeyId': 'example-access-key', 'secretAccessKey': 'example-direct-secret'}

    def store(self, value):
        self.path.write_text(json.dumps(value))
        self.path.chmod(0o600)
        return self.path

    def test_legacy_token_derives_secret_and_requires_exact_fields(self):
        record = {'id': 'example-id', 'value': 'example-token', 'expires_on': None}
        self.assertEqual(d.credential_parameters(self.store(record)), {
            'aws_access_key_id': 'example-id', 'aws_secret_access_key': hashlib.sha256(b'example-token').hexdigest()})
        for wrong in ({'id': 'example-id', 'value': 'example-token'}, {**record, **self.direct}, {**record, 'sessionToken': 'example-session'}):
            with self.assertRaisesRegex(ValueError, 'format'):
                d.credential_parameters(self.store(wrong))

    def test_direct_pairs_and_session_tokens_pass_through_with_optional_expiry(self):
        for session in ({}, {'sessionToken': 'example-session'}):
            for expiry in ({}, {'expires_on': '2999-01-01T00:00:00Z'}):
                expected = {'aws_access_key_id': 'example-access-key', 'aws_secret_access_key': 'example-direct-secret'}
                if session:
                    expected['aws_session_token'] = session['sessionToken']
                self.assertEqual(d.credential_parameters(self.store({**self.direct, **session, **expiry})), expected)

    def test_invalid_fields_and_expiry_fail_without_reporting_values(self):
        invalid = [[], {**self.direct, 'endpoint': 'https://example.invalid'}, {**self.direct, 'secretAccessKey': ''},
            {**self.direct, 'sessionToken': None}, {**self.direct, 'sessionToken': 'do-not-echo\n'},
            {**self.direct, 'expires_on': 'do-not-echo'}, {**self.direct, 'expires_on': '2000-01-01T00:00:00Z'},
            {**self.direct, 'expires_on': '2999-01-01T00:00:00'}, {**self.direct, 'expires_on': 1}]
        for value in invalid:
            with self.assertRaises(ValueError) as exc:
                d.credential_parameters(self.store(value))
            self.assertNotIn('do-not-echo', str(exc.exception))

    def test_public_or_linked_credentials_refused(self):
        self.store(self.direct).chmod(0o644)
        with self.assertRaises(ValueError):
            d.credential_parameters(self.path)
        self.path.chmod(0o600)
        alias = self.path.with_name('alias')
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            d.credential_parameters(alias)
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            d.credential_parameters(self.path)

    @unittest.skipUnless(importlib.util.find_spec('boto3'), 'requires the selected R2 publisher SDK')
    def test_boto_session_uses_explicit_real_sdk_fields_without_network(self):
        environment = {'AWS_EC2_METADATA_DISABLED': 'true', 'AWS_CONFIG_FILE': os.devnull,
                       'AWS_SHARED_CREDENTIALS_FILE': os.devnull}
        with patch.dict(os.environ, environment, clear=True), patch('socket.socket.connect', side_effect=AssertionError('Unexpected network connection')):
            for session in ({}, {'sessionToken': 'example-session'}):
                api = d.client(self.store({**self.direct, **session}))
                try:
                    creds = api._request_signer._credentials.get_frozen_credentials()
                    self.assertEqual((creds.access_key, creds.secret_key, creds.token),
                                     ('example-access-key', 'example-direct-secret', session.get('sessionToken')))
                    self.assertEqual(api.meta.endpoint_url, f'https://{d.ACCOUNT}.r2.cloudflarestorage.com')
                    self.assertEqual(api.meta.config.signature_version, 's3v4')
                    self.assertEqual(api.meta.config.retries['total_max_attempts'], 1)
                finally:
                    api.close()

if __name__ == '__main__': unittest.main()
