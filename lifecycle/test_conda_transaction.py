"""Real classic-solver/same-object tests using disposable inert .conda carriers."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

import conda_transaction as c

SUBDIR = {'Darwin': {'arm64': 'osx-arm64', 'x86_64': 'osx-64'},
          'Linux': {'aarch64': 'linux-aarch64', 'x86_64': 'linux-64'}}[platform.system()][platform.machine()]


def package(channel, work, name, version='1.0', build='b0', depends=(), extra=None):
    from conda_package_handling.api import create
    prefix = work / (name + '-' + version + '-' + build)
    prefix.mkdir()
    base = f'share/symphony/carriers/{name}/{version}/{build}'
    payload = base + '/' + name
    files = {payload: (f'INERT-FIXTURE:{name}:{version}:{build}\n'.encode(), 0o755),
             base + '/artifact-identity.json': (b'{"fixture":true}\n', 0o644),
             base + '/LICENSE-AGPL-3.0': (b'fixture license sentinel\n', 0o644)}
    manifest = {'schema': 'symphony.distribution.go-carrier.v2', 'format_version': 2,
        'conda_name': name, 'conda_version': version, 'conda_subdir': SUBDIR, 'build_number': int(build[1:]),
        'component_id': name, 'native_version': version, 'fixture': True,
        'files': [{'path': p.rsplit('/', 1)[1], 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': mode}
                  for p, (data, mode) in sorted(files.items())]}
    manifest['manifest_digest'] = 'sha256:' + hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    files[base + '/carrier-manifest.json'] = (c.canonical(manifest), 0o644)
    if extra:
        files.update(extra)
    paths = []
    for rel, (data, mode) in files.items():
        target = prefix / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)
        paths.append({'_path': rel, 'path_type': 'hardlink', 'sha256': hashlib.sha256(data).hexdigest(), 'size_in_bytes': len(data)})
    info = prefix / 'info'
    info.mkdir()
    index = {'name': name, 'version': version, 'build': build, 'build_number': int(build[1:]),
             'subdir': SUBDIR, 'depends': list(depends)}
    (info / 'index.json').write_text(json.dumps(index))
    (info / 'paths.json').write_text(json.dumps({'paths_version': 1, 'paths': paths}))
    (info / 'files').write_text(''.join(p + '\n' for p in sorted(files)))
    filename = f'{name}-{version}-{build}.conda'
    create(str(prefix), [p.relative_to(prefix).as_posix() for p in prefix.rglob('*') if p.is_file()], filename, str(channel / SUBDIR))
    archive = channel / SUBDIR / filename
    index.update({'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'md5': hashlib.md5(archive.read_bytes(), usedforsecurity=False).hexdigest(), 'size': archive.stat().st_size})
    return archive, index


def index_channel(channel, records):
    for subdir in (SUBDIR, 'noarch'):
        (channel / subdir / 'repodata.json').write_text(json.dumps({'info': {'subdir': subdir}, 'packages': {},
            'packages.conda': records if subdir == SUBDIR else {}, 'repodata_version': 1}))


def spec(row):
    return f"{row['name']}={row['version']}={row['build']}"


class Transactions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s06-conda-', dir='/private/tmp' if Path('/private/tmp').is_dir() else None)
        self.root = Path(self.temp.name).resolve()
        self.channel = self.root / 'channel'
        self.work = self.root / 'work'
        self.work.mkdir()
        for s in (SUBDIR, 'noarch'):
            (self.channel / s).mkdir(parents=True)
        self.records = {}
        self.a = self.add('test-alpha')
        self.a1 = self.add('test-alpha', build='b1')
        self.b = self.add('test-beta')
        self.sentinel = self.add('test-sentinel')

    def tearDown(self):
        self.temp.cleanup()

    def add(self, name, **kw):
        archive, record = package(self.channel, self.work, name, **kw)
        self.records[archive.name] = record
        index_channel(self.channel, self.records)
        return c.artifact_identity(archive)

    def attempt(self, name='attempt'):
        return c.Attempt.create(self.root / name, self.channel, SUBDIR)

    def install(self, attempt, *rows):
        return attempt.transact('install', add_specs=[spec(r) for r in rows], expected_link=list(rows))

    def test_real_install_update_swap_rollback_remove_preserves_sentinels(self):
        old_home = os.environ.get('HOME')
        with self.attempt() as attempt:
            foreign = attempt.prefix / 'foreign-user-data'
            foreign.write_bytes(b'owned by somebody else\n')
            self.install(attempt, self.a, self.sentinel)
            sentinel_before = {p: c._hash_file(attempt.prefix / p) for p in self.sentinel['files']}
            self.assertEqual(os.environ.get('HOME'), old_home)
            attempt.transact('update', add_specs=[spec(self.a1)], expected_link=[self.a1], expected_unlink=[self.a])
            attempt.transact('rollback', add_specs=[spec(self.a)], expected_link=[self.a], expected_unlink=[self.a1])
            attempt.transact('swap', add_specs=[spec(self.b)], remove_names=['test-alpha'], expected_link=[self.b], expected_unlink=[self.a])
            attempt.transact('rollback', add_specs=[spec(self.a)], remove_names=['test-beta'], expected_link=[self.a], expected_unlink=[self.b])
            attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            self.assertEqual(set(attempt.inventory()), {'test-sentinel'})
            self.assertEqual(foreign.read_bytes(), b'owned by somebody else\n')
            self.assertEqual(sentinel_before, {p: c._hash_file(attempt.prefix / p) for p in self.sentinel['files']})
            self.assertEqual(len(list((attempt.root / 'evidence').glob('*/result.json'))), 6)
            for p in self.sentinel['files']:
                self.assertEqual((attempt.prefix / p).stat().st_nlink, 1)

    def test_existing_attempt_and_symlink_refused_without_touching_sentinel(self):
        existing = self.root / 'existing'
        existing.mkdir()
        (existing / 'sentinel').write_bytes(b'preserve')
        with self.assertRaisesRegex(c.Refused, 'Existing'):
            c.Attempt.create(existing, self.channel, SUBDIR)
        alias = self.root / 'alias'
        alias.symlink_to(existing, target_is_directory=True)
        with self.assertRaisesRegex(c.Refused, 'Symlink'):
            c.Attempt.create(alias / 'new', self.channel, SUBDIR)
        self.assertEqual((existing / 'sentinel').read_bytes(), b'preserve')

    def test_unreviewed_dependency_delta_refused_before_execution(self):
        dependent = self.add('test-dependent', depends=['test-beta ==1.0 b0'])
        with self.attempt() as attempt:
            with self.assertRaisesRegex(c.Refused, 'Complete solver'):
                self.install(attempt, dependent)
            self.assertFalse(list(attempt.prefix.glob('share/**/*')))
            self.assertFalse(list((attempt.root / 'evidence').glob('*/execution-started.json')))
            with self.assertRaisesRegex(c.Refused, 'replayed'):
                self.install(attempt, self.a)

    def test_archive_hook_and_escape_refused_before_extraction(self):
        for i, rel in enumerate(('bin/.test-hook-post-link.sh', '../escape')):
            channel = self.root / f'unsafe-{i}'
            for s in (SUBDIR, 'noarch'):
                (channel / s).mkdir(parents=True)
            archive, _ = package(channel, self.work, f'test-hook{i}', extra={rel: (b'#!/bin/sh\nexit 0\n', 0o755)})
            with self.assertRaises(c.Refused):
                c.artifact_identity(archive)

    def test_repodata_hash_tamper_refused_and_evidence_retained(self):
        self.records[self.a['filename']]['sha256'] = '0' * 64
        index_channel(self.channel, self.records)
        with self.assertRaisesRegex(c.Refused, 'hash differs'):
            self.attempt()
        self.assertTrue((self.root / 'attempt/evidence/create-failed.json').is_file())

    def test_missing_expected_unlink_and_foreign_collision_refused(self):
        with self.attempt() as attempt:
            self.install(attempt, self.a)
            with self.assertRaisesRegex(c.Refused, 'exact old'):
                attempt.transact('update', add_specs=[spec(self.a1)], expected_link=[self.a1])
        with self.attempt('collision') as attempt:
            p = attempt.prefix / next(iter(self.a['files']))
            p.parent.mkdir(parents=True)
            p.write_bytes(b'foreign file')
            with self.assertRaisesRegex(c.Refused, 'collides'):
                self.install(attempt, self.a)
            self.assertEqual(p.read_bytes(), b'foreign file')

    def test_prepared_extra_action_refused_before_execute(self):
        from conda.core.link import UnlinkLinkTransaction, ActionGroup
        original = UnlinkLinkTransaction.prepare
        def injected(transaction):
            original(transaction)
            groups = next(iter(transaction.prefix_action_groups.values()))
            groups.final_action_groups = [ActionGroup('final', None, (object(),), str(attempt.prefix))]
        with self.attempt() as attempt, patch.object(UnlinkLinkTransaction, 'prepare', injected):
            with self.assertRaisesRegex(c.Refused, 'plugin actions'):
                self.install(attempt, self.a)
            self.assertFalse(list((attempt.root / 'evidence').glob('*/execution-started.json')))

    def test_execution_lost_outcome_retained_and_never_retried(self):
        from conda.core.link import UnlinkLinkTransaction
        original = UnlinkLinkTransaction.execute
        calls = []
        def lost(transaction):
            calls.append(1)
            original(transaction)
            raise RuntimeError('lost acknowledgement after real transaction')
        with self.attempt() as attempt, patch.object(UnlinkLinkTransaction, 'execute', lost):
            sentinel = attempt.prefix / 'sentinel'
            sentinel.write_bytes(b'preserve')
            with self.assertRaisesRegex(RuntimeError, 'lost acknowledgement'):
                self.install(attempt, self.a)
            failure = json.loads((attempt.root / 'evidence/0001/failure.json').read_text())
            self.assertEqual(failure['status'], 'uncertain-retained')
            self.assertTrue(list(attempt.prefix.glob('conda-meta/test-alpha*.json')))
            self.assertEqual(sentinel.read_bytes(), b'preserve')
            with self.assertRaisesRegex(c.Refused, 'replayed'):
                self.install(attempt, self.a)
            self.assertEqual(calls, [1])

    def test_real_cache_cleanup_keeps_retained_copy_and_foreign_sentinels(self):
        with self.attempt() as attempt:
            foreign = attempt.prefix / 'foreign.c~'
            foreign.write_bytes(b'prefix tempfile-looking sentinel must remain')
            self.install(attempt, self.a)
            retained = self.root / 'retained-owner'
            original = attempt.prefix / next(p for p in self.a['files'] if p.endswith('/test-alpha'))
            shutil.copyfile(original, retained)
            retained.chmod(0o755)
            retained_before = c._hash_file(retained)
            attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            cache = attempt.root / 'cache'
            self.assertTrue(list(cache.glob('*.conda')))
            cache_sentinel = cache / 'foreign-cache-sentinel'
            cache_sentinel.write_bytes(b'outside selected cache entries')
            cache_temp = cache / 'selected.c~'
            cache_temp.write_bytes(b'owned disposable temporary file')
            before_home = os.environ.get('HOME')
            result = attempt.clean_cache()
            self.assertEqual(result['status'], 'observed-complete')
            self.assertGreater(result['removed_file_count'], 0)
            self.assertFalse(result['force_pkgs_dirs'])
            self.assertTrue(result['normal_conda_clean_all'])
            self.assertFalse(list(cache.glob('*.conda')))
            self.assertFalse(cache_temp.exists())
            self.assertEqual(cache_sentinel.read_bytes(), b'outside selected cache entries')
            self.assertEqual(foreign.read_bytes(), b'prefix tempfile-looking sentinel must remain')
            self.assertEqual(c._hash_file(retained), retained_before)
            self.assertEqual(retained.stat().st_nlink, 1)
            self.assertEqual(os.environ.get('HOME'), before_home)
            self.assertFalse(attempt.inventory())

    def test_cache_cleanup_refuses_installed_package_and_external_cache(self):
        with self.attempt() as attempt:
            self.install(attempt, self.a)
            with self.assertRaisesRegex(c.Refused, 'empty owned delivery'):
                attempt.clean_cache()
            self.assertTrue(list((attempt.root / 'cache').glob('*.conda')))
        from conda.cli import main_clean
        with self.attempt('external-cache') as attempt:
            self.install(attempt, self.a)
            attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            with patch.object(main_clean, 'find_pkgs_dirs', return_value=[str(attempt.root / 'cache'), str(self.root / 'foreign-cache')]):
                with self.assertRaisesRegex(c.Refused, 'external package cache'):
                    attempt.clean_cache()
            self.assertFalse((attempt.root / 'evidence/0003/execution-started.json').exists())
            with self.assertRaisesRegex(c.Refused, 'replayed'):
                attempt.clean_cache()

    def test_cache_cleanup_lost_acknowledgement_never_retries(self):
        from conda.cli import main_clean
        original = main_clean.execute
        calls = []
        with self.attempt() as attempt:
            self.install(attempt, self.a)
            attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            def lost(args, parser):
                calls.append(1)
                original(args, parser)
                raise RuntimeError('lost cleanup acknowledgement')
            with patch.object(main_clean, 'execute', lost):
                with self.assertRaisesRegex(RuntimeError, 'lost cleanup'):
                    attempt.clean_cache()
            failure = json.loads((attempt.root / 'evidence/0003/failure.json').read_text())
            self.assertEqual(failure['status'], 'uncertain-retained')
            self.assertFalse(list((attempt.root / 'cache').glob('*.conda')))
            with self.assertRaisesRegex(c.Refused, 'replayed'):
                attempt.clean_cache()
            self.assertEqual(calls, [1])

    def test_foreign_destination_hook_preserved_but_never_executed(self):
        with self.attempt() as attempt:
            marker = self.root / 'must-not-exist'
            hook = attempt.prefix / 'bin/.test-alpha-post-link.sh'
            hook.parent.mkdir()
            hook.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
            hook.chmod(0o755)
            with self.assertRaisesRegex(c.Refused, 'Existing lifecycle hook'):
                self.install(attempt, self.a)
            self.assertTrue(hook.is_file())
            self.assertFalse(marker.exists())
            self.assertFalse(list((attempt.root / 'evidence').glob('*/execution-started.json')))

    def test_full_delta_cannot_authorize_runtime_dependency_or_prepared_metadata_change(self):
        dependent = self.add('test-dependent', depends=['test-beta ==1.0 b0'])
        with self.attempt() as attempt:
            with self.assertRaisesRegex(c.Refused, 'Runtime dependencies'):
                self.install(attempt, dependent, self.b)
        from conda.core.link import UnlinkLinkTransaction
        original = UnlinkLinkTransaction.prepare
        with self.attempt('metadata-change') as attempt:
            self.install(attempt, self.a)
            def changed(transaction):
                original(transaction)
                record = next((attempt.prefix / 'conda-meta').glob('test-alpha*.json'))
                value = json.loads(record.read_text())
                value['unreviewed_field'] = 'changed after solve'
                record.write_text(json.dumps(value))
            with patch.object(UnlinkLinkTransaction, 'prepare', changed):
                with self.assertRaisesRegex(c.Refused, 'Prefix changed during preparation'):
                    attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            self.assertFalse((attempt.root / 'evidence/0002/execution-started.json').exists())

    def test_carrier_source_deletion_and_private_channel_tamper(self):
        with self.attempt() as attempt:
            (self.channel / SUBDIR / self.a['filename']).unlink()
            self.install(attempt, self.a)
            private_archive = attempt.channel / SUBDIR / self.a['filename']
            private_archive.write_bytes(b'changed')
            with self.assertRaisesRegex(c.Refused, 'channel changed'):
                attempt.transact('remove', remove_names=['test-alpha'], expected_unlink=[self.a])
            for rel, row in self.a['files'].items():
                self.assertEqual(c._hash_file(attempt.prefix / rel), row)


if __name__ == '__main__':
    unittest.main()
