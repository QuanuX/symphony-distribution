import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import export_source as e

class Configured(unittest.TestCase):
    def setUp(self):
        self.policy_temp=tempfile.TemporaryDirectory()
        p=Path(self.policy_temp.name)/'policy.json'
        p.write_text(json.dumps({'schema':'symphony.source-privacy-policy.v1','markers':['ExamplePublisher','examplepublisher'],'document_attributions':{'ExamplePublisher':'the project owner'}}))
        e.configure_policy(p)
        self.addCleanup(self.policy_temp.cleanup)

class PrivacyTests(Configured):
    def test_canary_in_document_refused(self):
        with self.assertRaisesRegex(ValueError,'private marker'):e.sanitize('README.md',b'SYMPHONY_PRIVATE_CANARY_123')
    def test_unknown_runtime_identity_refused(self):
        with self.assertRaisesRegex(ValueError,'private marker'):e.sanitize('src/main.cpp',b'const char *id="examplepublisher";')
    def test_legal_attribution_not_silently_removed(self):
        with self.assertRaisesRegex(ValueError,'private marker'):e.sanitize('LICENSE.md',b'Copyright ExamplePublisher')
    def test_legal_attribution_in_ordinary_markdown_is_retained_for_review(self):
        for content in (b'Copyright 2026 ExamplePublisher. All rights reserved.',
                        b'Copyright 2026\nExamplePublisher\nAll rights reserved.\n'):
            with self.subTest(content=content):
                with self.assertRaisesRegex(ValueError,'legal attribution'):e.sanitize('README.md',content)
    def test_synthetic_fixture_preserves_descriptor(self):
        d={'descriptors':{'v1':{'protocol':'test','hash':'a'*64}},'observation':{'path':'/Users/ExamplePublisher/project/libexec/symphony/example/1.0/tool'}}
        b,changes=e.sanitize(next(iter(e.FIXTURES)),json.dumps(d).encode());out=json.loads(b)
        self.assertEqual(out['descriptors'],d['descriptors']);self.assertEqual(out['observation']['path'],'/__symphony_fixture__/libexec/symphony/example/1.0/tool');self.assertTrue(changes)
    def test_complete_private_key_refused(self):
        with self.assertRaisesRegex(ValueError,'private key'):e.scan('fixture.txt',b'-----BEGIN PRIVATE KEY-----\n'+b'A'*64+b'\n-----END PRIVATE KEY-----')
    def test_key_parser_header_is_not_key(self):e.scan('parser.cpp',b'find("-----BEGIN PRIVATE KEY-----")')
    def test_credential_shaped_access_key_refused(self):
        with self.assertRaisesRegex(ValueError,'access key'):e.scan('fixture.txt',b'AKIAABCDEFGHIJKLMNOP')
    def test_traversal_path_refused(self):
        for path in ['../bad','/bad','a/../bad','a/./bad','a//bad','a\\b','.git/config','a\nfoo']:
            with self.assertRaises(ValueError):e.safe_path(path)
    def test_private_filename_refused(self):
        with self.assertRaisesRegex(ValueError,'file name'):e.scan('SYMPHONY_PRIVATE_CANARY_123.txt',b'clean contents')
    def test_scnv_fixture_only_known_literal_changed(self):
        b=b'{"source", {{"kind", "user"}, {"id", "examplepublisher"}}}'
        out,changes=e.sanitize('modules/scnv-engine/tests/scnv_test.cpp',b)
        self.assertEqual(out,b.replace(b'examplepublisher',b'synthetic-user'));self.assertTrue(changes)
    def test_scnv_fixture_shape_drift_refused(self):
        with self.assertRaisesRegex(ValueError,'shape drift'):e.sanitize('modules/scnv-engine/tests/scnv_test.cpp',b'changed test')

class ExportIntegrityTests(Configured):
    def setUp(self):
        super().setUp()
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);source=self.root/'source';source.mkdir()
        self.data=b'public source\n';(source/'file.txt').write_bytes(self.data);(source/'file.txt').chmod(0o644)
        entry={'path':'file.txt','mode':'100644','export_sha256':e.digest(self.data),'export_size':len(self.data),'transformations':[]}
        manifest={'privacy_scan':{},'limitations':[],'source_map_rebindings':[],'source_map_omitted_private_publisher_test_inputs':[],'protocol':'symphony.public-source-export.v2','state':'sanitized_source_preparation_not_release','source_repository':'https://github.com/QuanuX/Symphony','is_original_git_tree':False,'public_source_build_tested':False,'source_test_suite_qualified':False,'release_acceptance_complete':False,'publication_authorized':False,'transformation_implementation_sha256':e.digest(Path(e.__file__).read_bytes()),'privacy_policy_digest':e.POLICY_DIGEST,'source_binding_digest':e.BINDING['binding_digest'],'origin_commit':e.EXPECTED_COMMIT,'origin_tree':e.EXPECTED_TREE,'source_files':[entry],'excluded_files':[],'derived_export_digest':e.digest(e.canonical([{'path':'file.txt','mode':'100644','sha256':e.digest(self.data)}]))}
        self.manifest=(json.dumps(manifest)+'\n').encode();(self.root/'SOURCE-EXPORT.json').write_bytes(self.manifest);self.make_tar()
    def tearDown(self):self.temp.cleanup()
    def make_tar(self,uid=0,duplicate=False):
        with tarfile.open(self.root/'symphony-source.tar','w') as t:
            for name,data in [('file.txt',self.data),('SOURCE-EXPORT.json',self.manifest)]+([('file.txt',self.data)] if duplicate else []):
                i=tarfile.TarInfo('symphony-source/'+name);i.size=len(data);i.mode=0o644;i.uid=uid;t.addfile(i,io.BytesIO(data))
    def test_clean_export_verifies(self):self.assertTrue(e.verify(self.root)['verified'])
    def test_forged_origin_commit_refused(self):
        p=self.root/'SOURCE-EXPORT.json';m=json.loads(p.read_bytes());m['origin_commit']='0'*40;p.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,'origin commit'):e.verify(self.root)
    def test_forged_origin_tree_refused(self):
        p=self.root/'SOURCE-EXPORT.json';m=json.loads(p.read_bytes());m['origin_tree']='0'*40;p.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,'origin tree'):e.verify(self.root)
    def test_changed_exported_bytes_refused(self):
        (self.root/'source/file.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'byte drift'):e.verify(self.root)
    def test_extra_file_refused(self):
        (self.root/'source/extra.txt').write_text('extra')
        with self.assertRaisesRegex(ValueError,'extra source'):e.verify(self.root)
    def test_symlink_refused(self):
        (self.root/'source/link').symlink_to('/tmp')
        with self.assertRaisesRegex(ValueError,'symlink'):e.verify(self.root)
    def test_personal_archive_ownership_refused(self):
        self.make_tar(uid=501)
        with self.assertRaisesRegex(ValueError,'personal archive'):e.verify(self.root)
    def test_duplicate_archive_member_refused(self):
        self.make_tar(duplicate=True)
        with self.assertRaisesRegex(ValueError,'duplicate archive'):e.verify(self.root)
    def test_permission_drift_refused(self):
        (self.root/'source/file.txt').chmod(0o666)
        with self.assertRaisesRegex(ValueError,'mode drift'):e.verify(self.root)
    def test_incomplete_output_refused(self):
        (self.root/'INCOMPLETE').write_text('failed')
        with self.assertRaisesRegex(ValueError,'incomplete'):e.verify(self.root)
    def test_canary_detected_even_if_manifest_rehashed(self):
        b=b'SYMPHONY_PRIVATE_CANARY_123';(self.root/'source/file.txt').write_bytes(b)
        path=self.root/'SOURCE-EXPORT.json';manifest=json.loads(path.read_bytes())
        manifest['source_files'][0].update(export_sha256=e.digest(b),export_size=len(b))
        manifest['derived_export_digest']=e.digest(e.canonical([{'path':'file.txt','mode':'100644','sha256':e.digest(b)}]))
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError,'private marker'):e.verify(self.root)


    def test_archive_mode_drift_refused(self):
        with tarfile.open(self.root/'symphony-source.tar','w') as t:
            for name,data in [('file.txt',self.data),('SOURCE-EXPORT.json',self.manifest)]:
                info=tarfile.TarInfo('symphony-source/'+name);info.size=len(data);info.mode=0o777
                t.addfile(info,io.BytesIO(data))
        with self.assertRaisesRegex(ValueError,'archive mode drift'):e.verify(self.root)
    def test_pax_comment_cannot_carry_personal_data(self):
        with tarfile.open(self.root/'symphony-source.tar','w',format=tarfile.PAX_FORMAT) as t:
            for name,data in [('file.txt',self.data),('SOURCE-EXPORT.json',self.manifest)]:
                info=tarfile.TarInfo('symphony-source/'+name);info.size=len(data);info.mode=0o644;info.pax_headers={'comment':'private metadata'}
                t.addfile(info,io.BytesIO(data))
        with self.assertRaisesRegex(ValueError,'extended metadata'):e.verify(self.root)
    def test_changed_privacy_policy_refused(self):
        p=self.root/'SOURCE-EXPORT.json';m=json.loads(p.read_bytes());m['privacy_policy_digest']='0'*64;p.write_text(json.dumps(m))
        with self.assertRaisesRegex(ValueError,'privacy policy differs'):e.verify(self.root)
    def test_canary_in_normalizable_fixture_refused(self):
        with self.assertRaisesRegex(ValueError,'canary'):e.sanitize(next(iter(e.FIXTURES)),b'{"path":"SYMPHONY_PRIVATE_CANARY_123"}')

    def test_hidden_tar_trailer_refused(self):
        with (self.root/'symphony-source.tar').open('ab') as stream:stream.write(b'SYMPHONY_PRIVATE_CANARY_HIDDEN_TRAILER')
        with self.assertRaisesRegex(ValueError,'hidden trailer'):e.verify(self.root)
    def test_manifest_cannot_grant_acceptance_or_substitute_transformer(self):
        original=json.loads(self.manifest)
        for key,value in [('publication_authorized',True),('release_acceptance_complete',True),('protocol','unknown'),('unreviewed_release_support',True),('transformation_implementation_sha256','0'*64)]:
            with self.subTest(key=key):
                manifest=dict(original);manifest[key]=value;self.manifest=(json.dumps(manifest)+'\n').encode()
                (self.root/'SOURCE-EXPORT.json').write_bytes(self.manifest);self.make_tar()
                with self.assertRaises(ValueError):e.verify(self.root)

if __name__=='__main__':unittest.main(verbosity=2)
