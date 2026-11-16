import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import staging as s


class Missing(Exception): pass


class API:
    def __init__(self, conflict=False, uncertain=False):
        self.calls = []; self.present = {}; self.conflict = conflict; self.uncertain = uncertain
    def distribution(self, owner, name, version, filename):
        if self.conflict: return {'sha256': '0' * 64, 'size': 3, 'labels': ['d09-review-aaaaaaaaaaaa']}
        if filename not in self.present: raise Missing()
        return self.present[filename]
    def package(self, *args): raise Missing()
    def add_package(self, *args, **kwargs): self.calls.append(('package', args, kwargs))
    def release(self, *args): raise Missing()
    def add_release(self, *args): self.calls.append(('release', args))
    def upload(self, owner, name, version, filename, stream, kind, **kwargs):
        self.calls.append(('upload', filename, kwargs))
        if self.uncertain: raise TimeoutError('private account material must not be retained')
        self.present[filename] = {'sha256': hashlib.sha256(stream.read()).hexdigest(), 'size': kwargs['size'], 'labels': kwargs['channels']}


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.delivery = self.root / 'delivery'; (self.delivery / 'artifacts').mkdir(parents=True)
        row = {'name': 'symphony-unit-payload', 'version': '1.0', 'build': 'd08_abc_0', 'build_number': 0,
               'subdir': 'osx-64', 'filename': 'symphony-unit-payload-1.0-d08_abc_0.conda',
               'sha256': hashlib.sha256(b'abc').hexdigest(), 'size': 3, 'selection': 'optional-source'}
        row['url'] = s.package_url({'label': 'd09-review-aaaaaaaaaaaa'}, row)
        self.plan = s.seal({'protocol': s.PROTOCOL, 'organization': 'QuanuX', 'label': 'd09-review-aaaaaaaaaaaa',
            'visibility': 'public-review-only', 'packages': [row], 'corresponding_source_url': row['url'], 'beta_release_authorized': False, 'overwrite_supported': False})
        (self.delivery / 'artifacts' / row['filename']).write_bytes(b'abc')
        errors = types.ModuleType('binstar_client.errors'); errors.NotFound = Missing
        config = types.ModuleType('binstar_client.utils.config'); config.PackageType = types.SimpleNamespace(CONDA='conda')
        self.modules = patch.dict('sys.modules', {'binstar_client.errors': errors, 'binstar_client.utils.config': config})
        self.modules.start()
    def tearDown(self): self.modules.stop(); self.tmp.cleanup()
    def stage(self,*args):
        with patch.object(s,'download',return_value={'state':'fixture_source_retrieval'}) as fetch:
            return s.stage(*args)
    def test_default_main_label_and_release_claim_refused(self):
        for field, value in [('label', 'main'), ('label', 'beta'), ('organization', 'other'), ('beta_release_authorized', True), ('overwrite_supported', True)]:
            plan = copy.deepcopy(self.plan); plan[field] = value; plan = s.seal({k:v for k,v in plan.items() if k != 'plan_sha256'})
            with self.assertRaises(ValueError): s.check_plan(plan)
    def test_tampered_seal_and_duplicate_identity_refused(self):
        changed = copy.deepcopy(self.plan); changed['packages'][0]['size'] = 4
        with self.assertRaises(ValueError): s.check_plan(changed)
        changed['packages'] = [self.plan['packages'][0]] * 2; changed = s.seal({k:v for k,v in changed.items() if k != 'plan_sha256'})
        with self.assertRaises(ValueError): s.check_plan(changed)
    def test_remote_collision_refuses_before_any_write(self):
        api = API(conflict=True)
        with self.assertRaisesRegex(ValueError, 'overwrite refused'): self.stage(self.plan, self.delivery, self.root/'attempt', api)
        self.assertEqual(api.calls, []); self.assertFalse((self.root/'attempt').exists())
    def test_local_tamper_refuses_before_remote_write(self):
        (self.delivery/'artifacts'/self.plan['packages'][0]['filename']).write_bytes(b'changed')
        api = API()
        with self.assertRaises(ValueError): self.stage(self.plan, self.delivery, self.root/'attempt', api)
        self.assertEqual(api.calls, [])
    def test_exact_custom_label_no_overwrite_and_same_bytes_resume_is_read_only(self):
        api = API(); result = self.stage(self.plan, self.delivery, self.root/'attempt', api)
        self.assertEqual(result['state'], 'public_review_staged_metadata_verified')
        self.assertFalse(result['fresh_download_qualified'])
        upload = api.calls[-1]; self.assertEqual(upload[2]['channels'], ['d09-review-aaaaaaaaaaaa'])
        count = len(api.calls); self.stage(self.plan, self.delivery, self.root/'reconcile', api)
        self.assertEqual(len(api.calls), count)
        with self.assertRaises(ValueError): self.stage(self.plan, self.delivery, self.root/'attempt', api)
    def test_upload_uses_verified_snapshot_when_original_changes_during_remote_calls(self):
        api=API(); path=self.delivery/'artifacts'/self.plan['packages'][0]['filename']
        def changed(*args):
            path.write_bytes(b'hostile replacement')
            raise Missing()
        api.package=changed
        result=self.stage(self.plan,self.delivery,self.root/'attempt',api)
        self.assertEqual(result['state'],'public_review_staged_metadata_verified')
        self.assertEqual(next(iter(api.present.values()))['sha256'],self.plan['packages'][0]['sha256'])
    def test_missing_post_upload_metadata_is_uncertain_not_success(self):
        api=API()
        def discard(*args,**kwargs): api.calls.append(('upload',))
        api.upload=discard
        with self.assertRaisesRegex(ValueError,'reconcile'): self.stage(self.plan,self.delivery,self.root/'attempt',api)
        self.assertFalse((self.root/'attempt/staging.json').exists())
    def test_source_retrieval_failure_stops_before_binary_upload(self):
        api=API(); plan=copy.deepcopy(self.plan); binary=copy.deepcopy(plan['packages'][0])
        binary.update(name='symphony-binary-payload',filename='symphony-binary-payload-1.0-d08_abc_0.conda',selection='default-carrier')
        binary['url']=s.package_url(plan,binary); plan['packages'].append(binary)
        plan=s.seal({k:v for k,v in plan.items() if k!='plan_sha256'})
        (self.delivery/'artifacts'/binary['filename']).write_bytes(b'abc')
        with patch.object(s,'download',side_effect=ValueError('source unavailable')):
            with self.assertRaisesRegex(ValueError,'reconcile'): s.stage(plan,self.delivery,self.root/'attempt',api)
        self.assertEqual(sum(x[0]=='upload' for x in api.calls),1)
        self.assertNotIn(binary['subdir']+'/'+binary['filename'],api.present)
    def test_uncertain_write_stops_without_retry_and_records_no_private_error(self):
        api = API(uncertain=True)
        with self.assertRaisesRegex(ValueError, 'reconcile'): self.stage(self.plan, self.delivery, self.root/'attempt', api)
        self.assertEqual(sum(x[0] == 'upload' for x in api.calls), 1)
        raw = (self.root/'attempt/attempt.jsonl').read_text()
        self.assertIn('uncertain_do_not_retry', raw); self.assertNotIn('private account', raw)
    def test_existing_other_label_does_not_silently_relabel(self):
        api=API(); row=self.plan['packages'][0]
        api.present[row['subdir']+'/'+row['filename']]={'sha256': row['sha256'], 'size': row['size'], 'labels':['main']}
        with self.assertRaisesRegex(ValueError, 'no implicit relabel'): self.stage(self.plan,self.delivery,self.root/'attempt',api)
        self.assertEqual(api.calls,[])
    def test_publisher_transport_requires_tls_and_bounds_nonretrying_upload(self):
        sdk=types.ModuleType('binstar_client'); requests=types.ModuleType('requests'); belt=types.ModuleType('requests_toolbelt')
        calls=[]
        class Session:
            verify=True; trust_env=True
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def request(self,*args,**kwargs): calls.append((args,kwargs,self.trust_env))
            def post(self,*args,**kwargs): calls.append((args,kwargs,self.trust_env));return object()
        class Encoder:
            content_type='multipart/form-data; boundary=fixture'
            def __init__(self,body): self.body=body
        requests.Session=Session; belt.MultipartEncoder=Encoder; belt.MultipartEncoderMonitor=Encoder
        with patch.dict('sys.modules',{'binstar_client':sdk,'requests':requests,'requests_toolbelt':belt}):
            api=types.SimpleNamespace(session=Session())
            api.session.verify=False
            with self.assertRaisesRegex(ValueError,'TLS'): s.bound_publisher_transport(api)
            api.session.verify=True;s.bound_publisher_transport(api)
            api.session.request('GET','https://api.anaconda.org/user',timeout=36000)
            sdk.multipart_files_upload('https://binstar-cio-packages-prod.s3.amazonaws.com/',{},verify=True)
            self.assertEqual(calls[0][1]['timeout'],(15,60));self.assertFalse(calls[0][2])
            self.assertEqual(calls[1][1]['timeout'],(15,120));self.assertFalse(calls[1][1]['allow_redirects']);self.assertFalse(calls[1][2])
            with self.assertRaises(ValueError): sdk.multipart_files_upload('https://evil.test/',{})
            self.assertEqual(len(calls),2)
    def test_download_destination_refuses_credentials_http_and_unknown_redirect(self):
        for value in ('http://conda.anaconda.org/a', 'https://user:secret@conda.anaconda.org/a',
                      'https://evil.test/a', 'https://127.0.0.1/a', 'https://conda.anaconda.org:4433/a',
                      'https://conda.anaconda.org/a?token=secret'):
            with self.assertRaises(ValueError): s.destination(value, initial=True)
        self.assertEqual(s.public_url('https://binstar-cio-packages-prod.s3.amazonaws.com/a?sig=private'),
                         'https://binstar-cio-packages-prod.s3.amazonaws.com/a')
    def test_retrieval_truncation_and_tampering_refuse(self):
        row=self.plan['packages'][0]
        class Response(io.BytesIO):
            status=200; headers={}; url=row['url']
        for body in (b'ab',b'abd',b'abcd'):
            with patch('urllib.request.OpenerDirector.open',return_value=Response(body)):
                with self.assertRaises(ValueError): s.download(row,self.root/('download-'+str(len(body))+hashlib.sha256(body).hexdigest()))
    def test_retrieval_records_fresh_bytes_without_credentials(self):
        row=self.plan['packages'][0]
        class Response(io.BytesIO):
            status=200; headers={'Content-Length':'3'}; url=row['url']
        with patch('urllib.request.OpenerDirector.open',return_value=Response(b'abc')) as opened:
            result=s.retrieve(self.plan,self.root/'retrieval')
        self.assertFalse(result['account_credentials_used'])
        request=opened.call_args.args[0]
        self.assertNotIn('Authorization',request.headers)
        self.assertEqual((self.root/'retrieval'/row['filename']).read_bytes(),b'abc')

if __name__=='__main__': unittest.main()
