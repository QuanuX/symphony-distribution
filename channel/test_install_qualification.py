import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('install_qualification', Path(__file__).with_name('install_qualification.py'))
q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)


def plan_fixture():
    rows = []
    for i in range(60):
        name = 'symphony-fixture-' + str(i)
        filename = name + '-1.0-d09_0.conda'
        rows.append({'name': name, 'version': '1.0', 'build': 'd09_0', 'build_number': 0, 'filename': filename,
            'subdir': 'osx-64', 'selection': 'optional-source' if i == 0 else 'default-carrier',
            'url': 'https://conda.anaconda.org/QuanuX/label/d09-review-aaaaaaaaaaaa/osx-64/' + filename,
            'sha256': hashlib.sha256(b'abc').hexdigest(), 'size': 3})
    plan = {'protocol': 'symphony.distribution.d09-public-review-stage.v1', 'organization': 'QuanuX',
        'label': 'd09-review-aaaaaaaaaaaa', 'visibility': 'public-review-only', 'overwrite_supported': False,
        'beta_release_authorized': False, 'native_install_or_activation': False, 'packages': rows}
    plan['plan_sha256'] = q.c.sha(q.c.canonical(plan))
    stage = {'protocol': plan['protocol'], 'plan_sha256': plan['plan_sha256'],
        'state': 'public_review_staged_metadata_verified', 'beta_release_authorized': False,
        'packages': [r['filename'] for r in rows]}
    return plan, stage


class PublicInstallQualificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_exact_completed_public_stage_is_admitted(self):
        plan, stage = plan_fixture()
        self.assertEqual(len(q.validate_plan(plan, plan['plan_sha256'], stage)), 60)
        explicit = q.explicit_urls(plan)
        self.assertTrue(explicit.startswith('@EXPLICIT\n'))
        self.assertEqual(len(explicit.splitlines()), 61)
        self.assertTrue(all(line.endswith('#' + row['sha256']) for line, row in zip(explicit.splitlines()[1:], plan['packages'])))

    def test_incomplete_or_other_plan_stage_refuses(self):
        plan, stage = plan_fixture()
        for mutation in ({'state': 'incomplete'}, {'plan_sha256': 'f' * 64}, {'packages': stage['packages'][:-1]}):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'stage has not completed'):
                q.validate_plan(plan, plan['plan_sha256'], stage | mutation)

    def test_wrong_seal_and_foreign_or_credential_url_refuse(self):
        plan, stage = plan_fixture(); plan['packages'][0]['size'] = 4
        with self.assertRaisesRegex(ValueError, 'staging plan differs'):
            q.validate_plan(plan, plan['plan_sha256'], stage)
        for url in ('file:///unreviewed/package.conda', 'https://user:token@conda.anaconda.org/unsafe',
                    'https://other.example/package.conda'):
            plan, stage = plan_fixture(); plan['packages'][0]['url'] = url
            plan['plan_sha256'] = q.c.sha(q.c.canonical({k:v for k,v in plan.items() if k != 'plan_sha256'}))
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, 'package URL'):
                q.validate_plan(plan, plan['plan_sha256'], stage)

    def test_fresh_environment_has_no_account_credentials_or_inherited_proxy(self):
        with patch.dict(os.environ, {'ANACONDA_API_TOKEN': 'never-inherit', 'HTTPS_PROXY': 'https://private.example'}):
            env = q.isolated_env(self.root, Path('/selected/bin/python'), 'osx-64')
        self.assertNotIn('ANACONDA_API_TOKEN', env); self.assertNotIn('HTTPS_PROXY', env)
        self.assertEqual(env['CONDA_ADD_ANACONDA_TOKEN'], 'false')
        self.assertEqual(env['CONDA_SSL_VERIFY'], 'true')
        self.assertEqual(env['CONDA_REMOTE_MAX_RETRIES'], '0')
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertEqual(list((self.root / 'pkgs').iterdir()), [])

    def carrier_fixture(self):
        destination = 'share/symphony/carriers/fixture/1.0/d09_0'
        payload = {destination + '/' + name: (raw, 0o644) for name, raw in
                   [('payload.tar', b'opaque retained archive'), ('unit.json', b'{"unit":"fixture"}'), ('carrier-manifest.json', b'{}')]}
        entry = {'carrier_destination': destination, 'conda_name': 'symphony-fixture', 'conda_version': '1.0',
                 'build_string': 'd09_0', 'build_number': 0, 'conda_subdir': 'osx-64',
                 'payload_size': len(payload[destination + '/payload.tar'][0])}
        for name, key in (('payload.tar', 'payload_sha256'), ('unit.json', 'unit_manifest_sha256'), ('carrier-manifest.json', 'carrier_manifest_sha256')):
            entry[key] = q.c.sha(payload[destination + '/' + name][0])
        entries = payload | q.c.metadata_for(entry, payload)
        row = json.loads(entries['info/index.json'][0])
        return entry, row, payload, entries

    def test_only_three_exact_opaque_carrier_files_can_link(self):
        entry, row, payload, entries = self.carrier_fixture()
        self.assertEqual(q.expected_carrier(entries, entry, row), payload)
        for name in ('bin/.fixture-post-link.sh', 'info/has_prefix', 'extra'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                q.expected_carrier(entries | {name: (b'unexpected', 0o755)}, entry, row)

    def test_payload_tamper_and_mode_change_refuse(self):
        entry, row, payload, entries = self.carrier_fixture(); name = next(iter(payload))
        for value in ((b'changed', 0o644), (payload[name][0], 0o755)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                q.expected_carrier(entries | {name: value}, entry, row)

    def installed_fixture(self):
        plan, _ = plan_fixture(); row = plan['packages'][0]
        prefix, cache = self.root / 'prefix', self.root / 'cache'
        (prefix / 'conda-meta').mkdir(parents=True); cache.mkdir()
        (prefix / 'payload').write_bytes(b'linked'); (prefix / 'payload').chmod(0o644)
        metadata = {k:row[k] for k in ('name','version','build','build_number','subdir','sha256','url')}
        (prefix / 'conda-meta/fixture.json').write_text(json.dumps(metadata))
        (cache / row['filename']).write_bytes(b'abc')
        return row, prefix, cache, {'payload': (b'linked', 0o644)}

    def test_actual_download_and_installed_records_match_selected_bytes(self):
        row, prefix, cache, expected = self.installed_fixture()
        count, records = q.downloaded_and_linked(prefix, cache, [row], expected)
        self.assertEqual(count, 1); self.assertEqual(records[0]['sha256'], row['sha256'])

    def test_changed_cache_or_extra_package_refuses(self):
        row, prefix, cache, expected = self.installed_fixture()
        (cache / row['filename']).write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'download bytes'):
            q.downloaded_and_linked(prefix, cache, [row], expected)
        (cache / row['filename']).write_bytes(b'abc'); (cache / 'unselected.conda').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'cache package selection'):
            q.downloaded_and_linked(prefix, cache, [row], expected)

    def test_installed_wrong_source_or_package_digest_refuses(self):
        row, prefix, cache, expected = self.installed_fixture(); path = prefix / 'conda-meta/fixture.json'
        original = json.loads(path.read_bytes())
        for mutation in ({'url': 'https://other.example/fixture.conda'}, {'sha256': 'f' * 64}):
            path.write_text(json.dumps(original | mutation))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                q.downloaded_and_linked(prefix, cache, [row], expected)


if __name__ == '__main__': unittest.main()
