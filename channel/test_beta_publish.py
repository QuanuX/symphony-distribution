import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import beta_publish as p


class Missing(Exception): pass


class API:
    def __init__(self):
        self.calls = []; self.files = {}; self.packages = {}; self.releases = set(); self.upload_error = False
    def distribution(self, owner, name, version, filename):
        if (name, version, filename) not in self.files: raise Missing()
        return copy.deepcopy(self.files[name, version, filename])
    def package(self, owner, name):
        if name not in self.packages: raise Missing()
        return copy.deepcopy(self.packages[name])
    def add_package(self, owner, name, **kw):
        self.calls.append(('package', name, kw))
        self.packages[name] = {'public': True, 'summary': kw['summary'], 'home': 'https://example.org', 'custom': {'keep': 1}}
    def update_package(self, owner, name, attrs):
        self.calls.append(('summary', name, copy.deepcopy(attrs)))
        self.packages[name] = {'public': True, **copy.deepcopy(attrs)}
    def release(self, owner, name, version):
        if (name, version) not in self.releases: raise Missing()
        return {'version': version}
    def add_release(self, owner, name, version, requirements, announce, attrs):
        self.calls.append(('release', name, announce, copy.deepcopy(attrs))); self.releases.add((name, version))
    def upload(self, owner, name, version, filename, stream, kind, **kw):
        raw = stream.read(); stream.fileno()
        self.calls.append(('upload', filename, raw, copy.deepcopy(kw)))
        if self.upload_error: raise TimeoutError('PRIVATE-CREDENTIAL-MUST-NOT-LEAK')
        self.files[name, version, filename] = {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw), 'labels': list(kw['channels'])}
    def add_channel(self, label, owner, name, version, filename):
        self.calls.append(('label', label, owner, name, version, filename))
        self.files[name, version, filename]['labels'].append(label)


class BetaPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.artifacts = self.root / 'artifacts'; self.artifacts.mkdir()
        self.signatures = self.root / 'signatures'; self.signatures.mkdir()
        self.rows = []
        for name, selection in [('symphony-corresponding-source-payload', 'optional-source'), ('symphony-qxctl-payload', 'default')]:
            filename = name + '-1.0.0-d08_ab_1.conda'; raw = name.encode()
            row = {'profile': 'macos15-arm64', 'path': 'mac/' + filename, 'name': name, 'version': '1.0.0',
                'build': 'd08_ab_1', 'build_number': 1, 'subdir': 'osx-arm64', 'filename': filename,
                'sha256': p.c.sha(raw), 'size': len(raw), 'selection': selection}
            target = self.artifacts / row['path']; target.parent.mkdir(exist_ok=True); target.write_bytes(raw); self.rows.append(row)
        self.index = {'release': p.b.RELEASE, 'conda_packages': self.rows}
        self.write_index()
        self.pin = 'a' * 64; self.key = 'b' * 64
        self.proof = {'release_index_sha256': p.c.sha((self.artifacts/'release-index.json').read_bytes())}
        errors = types.ModuleType('binstar_client.errors'); errors.NotFound = Missing
        config = types.ModuleType('binstar_client.utils.config'); config.PackageType = types.SimpleNamespace(CONDA='conda')
        self.modules = patch.dict('sys.modules', {'binstar_client.errors': errors, 'binstar_client.utils.config': config}); self.modules.start()
    def tearDown(self): self.modules.stop(); self.temp.cleanup()
    def write_index(self):
        raw = p.fs.canonical(self.index); (self.artifacts/'release-index.json').write_bytes(raw)
        manifest = {'release_index': {'path': 'release-index.json', 'sha256': p.c.sha(raw)},
            'artifacts': [{k: r[k] for k in ('path', 'sha256', 'size')} for r in self.rows]}
        (self.signatures/'beta-manifest.json').write_bytes(p.fs.canonical(manifest))
        self.proof = {'release_index_sha256': p.c.sha(raw)}
    def prepare(self):
        with patch.object(p.b, 'verify', return_value=self.proof), patch.object(p, 'audit_archive'):
            return p.prepare(self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'))
    def download(self, row, path):
        self.downloads.append(row['url']); path.write_bytes(b'fixture')
        return {'filename': row['filename'], 'url': row['url'], 'sha256': row['sha256'], 'size': row['size'], 'account_credentials_used': False}
    def execute(self, api, *, plan=None, output='attempt', **kw):
        plan = plan or self.prepare(); self.downloads = []
        with patch.object(p, 'prepare', return_value=plan), patch.object(p.s, 'download', side_effect=self.download):
            return p.execute(plan, self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'), self.root/output, api, **kw)
    def populate(self, api, labels=None):
        for row in self.rows:
            api.files[p.remote_key(row)] = {'sha256': row['sha256'], 'size': row['size'], 'labels': labels or ['review']}
            api.packages[row['name']] = {'public': True, **p.package_metadata.overview(row['name']), 'custom': {'keep': True}}
            api.releases.add((row['name'], row['version']))
    def archive_entries(self, row):
        prefix = 'share/symphony/carriers/unit/1.0.0/d08_ab_1'
        unit = {'unit_id': 'source:unit', 'kind': 'optional_corresponding_source'}
        payload = {prefix+'/payload.tar': (b'bounded source fixture', 0o644),
                   prefix+'/unit.json': (p.c.canonical(unit)+b'\n', 0o644)}
        manifest = {'destination': prefix, 'unit_id': unit['unit_id'],
            'files': [p.c.file_row(n, payload[prefix+'/'+n][0]) for n in ('payload.tar', 'unit.json')],
            **{target: row[source] for source, target in [('name','conda_name'),('version','conda_version'),
                ('build','build'),('build_number','build_number'),('subdir','subdir')]}}
        payload[prefix+'/carrier-manifest.json'] = (p.c.canonical(manifest)+b'\n',0o644)
        entry = {target: row[source] for source, target in [('name','conda_name'),('version','conda_version'),
            ('build','build_string'),('build_number','build_number'),('subdir','conda_subdir')]}
        return payload | p.c.metadata_for(entry,payload)
    def test_archive_admission_rejects_hooks_false_source_and_changed_metadata(self):
        row=self.rows[0]; entries=self.archive_entries(row)
        with patch.object(p.c,'archive_entries',return_value=(entries,row['sha256'],row['size'])):
            p.audit_archive(self.artifacts/row['path'],row)
            with self.assertRaisesRegex(ValueError,'source selection'):
                p.audit_archive(self.artifacts/row['path'],dict(row,selection='default'))
        for name in ('info/has_prefix','bin/.unit-post-link.sh'):
            altered={**entries,name:(b'forbidden',0o644)}
            with patch.object(p.c,'archive_entries',return_value=(altered,row['sha256'],row['size'])):
                with self.assertRaises(ValueError): p.audit_archive(self.artifacts/row['path'],row)
        changed=copy.deepcopy(entries); index=json.loads(changed['info/index.json'][0]); index['depends']=['external']
        changed['info/index.json']=(p.c.canonical(index)+b'\n',0o644)
        with patch.object(p.c,'archive_entries',return_value=(changed,row['sha256'],row['size'])):
            with self.assertRaisesRegex(ValueError,'metadata'):
                p.audit_archive(self.artifacts/row['path'],row)
    def test_archive_digest_mutation_after_signature_is_refused(self):
        row=self.rows[0]; entries=self.archive_entries(row)
        with patch.object(p.c,'archive_entries',return_value=(entries,'0'*64,row['size'])):
            with self.assertRaisesRegex(ValueError,'changed during admission'):
                p.audit_archive(self.artifacts/row['path'],row)
    def test_signature_failure_stops_before_archive_or_remote_admission(self):
        with patch.object(p.b, 'verify', side_effect=ValueError('invalid signature')), patch.object(p, 'audit_archive') as audit:
            with self.assertRaisesRegex(ValueError, 'invalid signature'):
                p.prepare(self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'))
            audit.assert_not_called()
    def test_signed_index_requires_exact_paths_source_and_signed_closure(self):
        for change in ('escape', 'source', 'unsigned'):
            rows = copy.deepcopy(self.rows)
            if change == 'escape': self.rows[0]['path'] = '../escape.conda'
            elif change == 'source': self.rows[0]['selection'] = 'default'
            else: self.rows.pop()
            self.write_index()
            if change == 'unsigned':
                manifest = json.loads((self.signatures/'beta-manifest.json').read_bytes())
                manifest['artifacts'].append({k: rows[-1][k] for k in ('path', 'sha256', 'size')})
                (self.signatures/'beta-manifest.json').write_bytes(p.fs.canonical(manifest))
            with self.assertRaises(ValueError): self.prepare()
            self.rows[:] = rows; self.write_index()
    def test_same_remote_build_different_profile_bytes_refused(self):
        for row in self.rows: row.update(profile='ubuntu24.04-amd64', subdir='linux-64')
        other = [dict(row, profile='ubuntu26.04-amd64', path='other/'+row['filename'], sha256='0'*64) for row in self.rows]
        self.rows.extend(other); self.write_index()
        with self.assertRaisesRegex(ValueError, 'collide'): self.prepare()
    def test_conflict_refuses_before_any_write_or_attempt(self):
        api = API(); self.populate(api); api.files[p.remote_key(self.rows[1])]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'overwrite refused'): self.execute(api)
        self.assertEqual(api.calls, []); self.assertFalse((self.root/'attempt').exists())
    def test_source_public_readbacks_precede_binary_upload(self):
        api = API(); original = api.upload
        def upload(*a, **kw):
            if a[1] == self.rows[1]['name']: self.assertEqual(len(self.downloads), 2)
            return original(*a, **kw)
        api.upload = upload; result = self.execute(api)
        self.assertEqual(result['state'], 'public_beta_packages_freshly_verified')
        self.assertEqual(len(result['packages']), 2)
        self.assertEqual(len(self.downloads), 3)
        for call in api.calls:
            if call[0] == 'upload': self.assertEqual(call[3]['channels'][0], 'beta'); self.assertNotIn('main', call[3]['channels'])
            if call[0] == 'release': self.assertEqual(call[2], '')
    def test_source_download_failure_stops_before_binary_mutations(self):
        api = API(); plan = self.prepare()
        with patch.object(p, 'prepare', return_value=plan), patch.object(p.s, 'download', side_effect=ValueError('unavailable')):
            with self.assertRaisesRegex(ValueError, 'reconcile'):
                p.execute(plan, self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'), self.root/'attempt', api)
        self.assertEqual(len([call for call in api.calls if call[0] == 'upload']), 1)
        self.assertNotIn(self.rows[1]['name'], api.packages)
    def test_existing_exact_build_gains_only_exact_labels_without_upload(self):
        api = API(); self.populate(api); self.execute(api, require_catalog=True)
        self.assertTrue(api.calls); self.assertTrue(all(call[0] == 'label' for call in api.calls))
        for call in api.calls:
            self.assertEqual(call[2], 'QuanuX'); self.assertTrue(call[5].endswith('.conda')); self.assertEqual(len(call), 6)
        count = len(api.calls); self.execute(api, output='second', require_catalog=True)
        self.assertEqual(count, len(api.calls))
    def test_uncertain_upload_is_not_retried_and_journal_is_sanitized(self):
        api = API(); api.upload_error = True
        with self.assertRaisesRegex(ValueError, 'reconcile'): self.execute(api)
        self.assertEqual(len([call for call in api.calls if call[0] == 'upload']), 1)
        raw = (self.root/'attempt/attempt.jsonl').read_text()
        self.assertIn('mutation_pending', raw); self.assertIn('uncertain_do_not_retry', raw)
        self.assertNotIn('PRIVATE-CREDENTIAL', raw); self.assertFalse((self.root/'attempt/publication.json').exists())
        with self.assertRaises(ValueError): self.execute(api)
        self.assertEqual(len([call for call in api.calls if call[0] == 'upload']), 1)
    def test_upload_uses_snapshot_when_original_changes_during_catalog_calls(self):
        api = API(); original = api.package
        def package(owner, name):
            (self.artifacts/self.rows[0]['path']).write_bytes(b'changed')
            return original(owner, name)
        api.package = package
        self.execute(api)
        first = next(call for call in api.calls if call[0] == 'upload')
        self.assertEqual(p.c.sha(first[2]), self.rows[0]['sha256'])
    def test_parallel_profile_mode_requires_catalog_and_does_not_create(self):
        api = API()
        with self.assertRaisesRegex(ValueError, 'reconcile'): self.execute(api, require_catalog=True)
        self.assertEqual(api.calls, [])
    def test_serial_catalog_preserves_public_attributes_and_never_uploads(self):
        api = API()
        for row in self.rows:
            api.packages[row['name']] = {'public': True, 'summary': 'Old review summary', 'home': 'https://example.org',
                'custom': {'preserve': ['all', 'values']}, 'files': [{'server': True}], 'watchers': 8}
        result = self.execute(api, catalog_only=True)
        self.assertEqual(result['state'], 'catalog_prepared'); self.assertFalse(self.downloads)
        for row in self.rows:
            value = api.packages[row['name']]
            self.assertEqual(value['custom'], {'preserve': ['all', 'values']}); self.assertEqual(value['summary'], p.package_metadata.overview(row['name'])['summary'])
        self.assertFalse(any(call[0] in ('upload', 'label') for call in api.calls))
    def test_reused_native_version_gets_maintained_overview_without_changing_build_source_links(self):
        api = API(); self.populate(api)
        for row in self.rows:
            api.packages[row['name']]['description'] = 'Review-only carrier. Exact reviewed corresponding source: https://example.org/old-source'
            api.packages[row['name']]['home'] = 'https://example.org/preserved'
            api.files[p.remote_key(row)]['description'] = 'Immutable build source: https://example.org/exact-old-build-source'
        before_files = copy.deepcopy(api.files); before_releases = copy.deepcopy(api.releases)
        result = self.execute(api, catalog_only=True)
        self.assertEqual(result['state'], 'catalog_prepared')
        self.assertEqual(api.files, before_files); self.assertEqual(api.releases, before_releases)
        self.assertTrue(api.calls); self.assertTrue(all(call[0] == 'summary' for call in api.calls))
        for name, value in api.packages.items():
            self.assertEqual(value['description'], p.package_metadata.overview(name)['description'])
            self.assertEqual(value['home'], p.package_metadata.HOME); self.assertEqual(value['custom'], {'keep': True})
            self.assertNotIn('Review-only', value['description'])
            self.assertEqual('Historical corresponding source for Symphony 0.2.0-beta.1:' in value['description'],
                             name in p.package_metadata.BETA1_SOURCE_NAMES)
            self.assertNotIn('beta.2', value['description'])
            self.assertIn('https://github.com/QuanuX/symphony-distribution/releases', value['description'])

    def test_parallel_publication_refuses_stale_overview_before_mutation(self):
        api = API(); self.populate(api)
        for value in api.packages.values(): value['description'] = 'review-only source from another build'
        with self.assertRaisesRegex(ValueError, 'reconcile'): self.execute(api, require_catalog=True)
        self.assertEqual(api.calls, [])

    def test_new_build_description_keeps_its_exact_source_after_generic_catalog_preparation(self):
        api = API(); plan = self.prepare(); self.execute(api, plan=plan)
        for call in api.calls:
            if call[0] == 'upload':
                self.assertIn(plan['corresponding_source_urls']['macos15-arm64'], call[3]['description'])
                self.assertTrue(all(call[3]['description'] != p.package_metadata.overview(row['name'])['description'] for row in self.rows))
        for name, value in api.packages.items():
            self.assertEqual(value['description'], p.package_metadata.overview(name)['description'])

    def test_release_creation_resets_metadata_then_catalog_restores_selected_values(self):
        api=API()
        for row in self.rows:
            api.packages[row['name']]={'public':True,'summary':'prior','home':'https://example.org','custom':{'keep':1}}
        original=api.add_release
        def create(owner,name,version,requirements,announce,attrs):
            original(owner,name,version,requirements,announce,attrs)
            api.packages[name]={'public':True,'summary':'','home':'','description':attrs['description']}
        api.add_release=create
        self.execute(api,catalog_only=True)
        for name, value in api.packages.items():
            expected = p.package_metadata.overview(name)
            self.assertEqual({key: value[key] for key in expected}, expected)
            self.assertEqual(value['custom'], {'keep': 1})
            release, = [call for call in api.calls if call[0] == 'release' and call[1] == name]
            self.assertEqual(release[3], expected)
        self.execute(api,output='after-catalog',require_catalog=True)
        self.assertEqual(len(self.downloads),3)
    def test_missing_post_upload_metadata_never_succeeds(self):
        api = API()
        def upload(*args, **kw): api.calls.append(('upload',))
        api.upload = upload
        with self.assertRaisesRegex(ValueError, 'reconcile'): self.execute(api)
        self.assertFalse((self.root/'attempt/publication.json').exists())
    def test_changed_plan_and_output_overlap_refused_before_api(self):
        plan = self.prepare(); changed = dict(plan, labels=['main']); api = API()
        with patch.object(p, 'prepare', return_value=plan):
            with self.assertRaisesRegex(ValueError, 'Exact current'):
                p.execute(changed, self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'), self.root/'attempt', api)
            with self.assertRaisesRegex(ValueError, 'separate'):
                p.execute(plan, self.artifacts, self.signatures, self.pin, self.key, Path('/openssl'), self.artifacts/'attempt', api)
        self.assertEqual(api.calls, [])


if __name__ == '__main__': unittest.main()
