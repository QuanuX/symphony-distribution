import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('d06_prepare_go', Path(__file__).with_name('d06_prepare_go.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

SUM = 'h1:' + 'A' * 43 + '='
MOD_SUM = 'h1:' + 'B' * 43 + '='
OTHER_SUM = 'h1:' + 'C' * 43 + '='


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        self.work, self.cache = self.root / 'work', self.root / 'modules'
        self.go = self.root / 'go'; self.go.write_bytes(b'exact-tool-fixture')
        self.main = {'Path': 'example.invalid/owner', 'Main': True, 'GoVersion': '1.26.5'}
        self.dep = {'Path': 'example.invalid/dependency', 'Version': 'v1.2.3', 'Sum': SUM, 'GoModSum': MOD_SUM}
        self.lazy = {'Path': 'example.invalid/graph-only', 'Version': 'v2.0.0', 'GoModSum': MOD_SUM}
        self.module = {'path': 'tools/owner', 'module': self.main['Path'], 'go': '1.26.5',
                       'module_replacements': [], 'resolved_graph': [self.main, self.dep, self.lazy]}
        (self.source / 'cmake').mkdir(); (self.source / 'tools/owner').mkdir(parents=True)
        self.mod = b'module example.invalid/owner\n\ngo 1.26.5\n'
        self.sums = (self.dep['Path'] + ' v1.2.3 ' + SUM + '\n' + self.dep['Path'] + ' v1.2.3/go.mod ' + MOD_SUM + '\n').encode()
        (self.source / 'tools/owner/go.mod').write_bytes(self.mod)
        (self.source / 'tools/owner/go.sum').write_bytes(self.sums)
        self.write_mapping()
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def write_mapping(self):
        (self.source / 'cmake/mvp-dependencies.json').write_text(json.dumps({'go_modules': [self.module]}))

    def downloaded(self):
        return [self.dep, {**self.lazy, 'Sum': OTHER_SUM}]

    def response(self, go, args, cwd, env, work, label, logs, **kwargs):
        self.calls.append((args, cwd, dict(env), kwargs))
        if args == ['env', 'GOVERSION']:
            return b'go1.26.5\n'
        if args == ['mod', 'download', '-json', 'all']:
            (cwd / 'go.sum').write_bytes(self.sums + (self.lazy['Path'] + ' v2.0.0 ' + OTHER_SUM + '\n' +
                                                    self.lazy['Path'] + ' v2.0.0/go.mod ' + MOD_SUM + '\n').encode())
            return '\n'.join(json.dumps(row) for row in self.downloaded()).encode()
        if args == ['list', '-mod=readonly', '-m', '-json', 'all']:
            return '\n'.join(json.dumps(row) for row in [self.main, *self.downloaded()]).encode()
        if args == ['mod', 'verify']:
            return b'all modules verified\n'
        self.fail('Unexpected Go invocation')

    def test_full_graph_hydration_then_original_manifest_offline_preflight(self):
        with patch.object(p, 'command', side_effect=self.response):
            report = p.prepare(self.source, self.work, self.go, self.cache)
        self.assertEqual(report['status'], 'full_graph_cached_and_offline_verified')
        self.assertTrue(report['source_manifests_unchanged'])
        self.assertEqual((self.source / 'tools/owner/go.sum').read_bytes(), self.sums)
        self.assertEqual(report['modules'][0]['private_checksum_additions'], 2)
        rows = report['modules'][0]['downloaded']
        self.assertEqual(rows[1]['Sum_authority'], 'public_sum_golang_org')
        download = self.calls[1]; closure = self.calls[2]; verify = self.calls[3]
        self.assertNotEqual(download[1], self.source / 'tools/owner')
        self.assertEqual(download[2]['GOSUMDB'], 'sum.golang.org')
        self.assertTrue(download[3]['network_retry'])
        self.assertEqual(closure[1], self.source / 'tools/owner')
        self.assertEqual(closure[2]['GOPROXY'], 'off')
        self.assertEqual(verify[2]['GOPROXY'], 'off')
        self.assertNotIn('network_retry', closure[3])

    def test_missing_graph_input_fails_before_build_and_preserves_source(self):
        def missing(*args, **kwargs):
            if args[1][0] == 'list':
                raise ValueError('offline cache incomplete')
            return self.response(*args, **kwargs)
        with patch.object(p, 'command', side_effect=missing):
            with self.assertRaisesRegex(ValueError, 'offline cache incomplete'):
                p.prepare(self.source, self.work, self.go, self.cache)
        report = json.loads((self.work / 'result.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertTrue(report['source_manifests_unchanged'])
        self.assertEqual(report['modules'], [])

    def test_frozen_archive_and_metadata_hashes_cannot_be_overridden(self):
        sums = p.read_sums(self.sums)
        for field in ('Sum', 'GoModSum'):
            rows = self.downloaded(); rows[0] = {**rows[0], field: OTHER_SUM}
            with self.assertRaisesRegex(ValueError, 'differs from frozen source'):
                p.verify_download(self.module, rows, sums)
        rows = self.downloaded(); rows[1] = {**rows[1], 'Sum': None}
        with self.assertRaisesRegex(ValueError, 'verified checksum'):
            p.verify_download(self.module, rows, sums)

    def test_missing_extra_duplicate_and_replaced_graph_members_refused(self):
        rows = self.downloaded()
        for changed in (rows[:1], [*rows, rows[0]], [rows[0], {**rows[1], 'Version': 'v2.1.0'}]):
            with self.assertRaisesRegex(ValueError, 'graph differs'):
                p.verify_download(self.module, changed, {})
        with self.assertRaisesRegex(ValueError, 'replaced'):
            p.verify_download(self.module, [{**rows[0], 'Replace': {'Dir': '/tmp/other'}}, rows[1]], {})
        with self.assertRaisesRegex(ValueError, 'replacement'):
            p.verify_graph(self.module, [self.main, {**rows[0], 'Replace': {}}, rows[1], {'Error': 'missing'}])

    def test_offline_graph_drift_and_checksum_drift_refused(self):
        with self.assertRaisesRegex(ValueError, 'Offline graph differs'):
            p.verify_graph(self.module, [self.main, self.dep])
        with self.assertRaisesRegex(ValueError, 'Offline checksum differs'):
            p.verify_graph(self.module, [self.main, {**self.dep, 'Sum': OTHER_SUM}, self.lazy])

    def test_public_network_policy_ignores_ambient_credentials_and_replacements(self):
        with patch.dict(os.environ, {'GOPROXY': 'https://credential.invalid', 'GOSUMDB': 'off',
                                     'GONOSUMDB': '*', 'GOPRIVATE': '*', 'GOFLAGS': '-modfile=/private/source',
                                     'GIT_SSH_COMMAND': 'unexpected', 'AWS_SECRET_ACCESS_KEY': 'fixture'}):
            env = p.clean_env(self.go, self.work, self.cache, online=True)
        self.assertEqual(env['GOPROXY'], 'https://proxy.golang.org')
        self.assertEqual(env['GOSUMDB'], 'sum.golang.org')
        self.assertEqual(env['GONOSUMDB'], '')
        self.assertEqual(env['GOAUTH'], 'off')
        self.assertEqual(env['GOVCS'], '*:off')
        self.assertFalse({'GOFLAGS', 'GIT_SSH_COMMAND', 'AWS_SECRET_ACCESS_KEY'} & env.keys())

    def command_work(self):
        self.work.mkdir(); (self.work / 'logs').mkdir()

    def test_only_transient_preparation_failures_are_retried(self):
        self.command_work(); logs = []
        failed = subprocess.CompletedProcess([], 1, b'', b'i/o timeout')
        okay = subprocess.CompletedProcess([], 0, b'{}', b'')
        with patch.object(p.subprocess, 'run', side_effect=[failed, okay]) as run, patch.object(p.time, 'sleep'):
            self.assertEqual(p.command(self.go, ['mod', 'download', 'all'], self.root, {}, self.work, 'online', logs,
                                       network_retry=True), b'{}')
        self.assertEqual(run.call_count, 2)
        with patch.object(p.subprocess, 'run', return_value=failed) as run:
            with self.assertRaisesRegex(ValueError, 'step failed'):
                p.command(self.go, ['list'], self.root, {}, self.work, 'offline', [])
        self.assertEqual(run.call_count, 1)
        corrupted = subprocess.CompletedProcess([], 1, b'', b'checksum mismatch SECURITY ERROR timeout')
        with patch.object(p.subprocess, 'run', return_value=corrupted) as run:
            with self.assertRaises(ValueError):
                p.command(self.go, ['mod', 'download', 'all'], self.root, {}, self.work, 'corrupt', [], network_retry=True)
        self.assertEqual(run.call_count, 1)

    def test_timeout_retries_are_bounded_to_three_attempts(self):
        self.command_work()
        with patch.object(p.subprocess, 'run', side_effect=subprocess.TimeoutExpired('go', 300)) as run, patch.object(p.time, 'sleep'):
            with self.assertRaises(ValueError):
                p.command(self.go, ['mod', 'download', 'all'], self.root, {}, self.work, 'timeout', [], network_retry=True)
        self.assertEqual(run.call_count, 3)

    def test_existing_or_linked_cache_is_not_adopted(self):
        self.cache.mkdir(); (self.cache / 'sentinel').write_bytes(b'preserved')
        with self.assertRaisesRegex(ValueError, 'must be new'):
            p.prepare(self.source, self.work, self.go, self.cache)
        self.assertEqual((self.cache / 'sentinel').read_bytes(), b'preserved')
        link = self.root / 'linked'; link.symlink_to(self.cache)
        with self.assertRaisesRegex(ValueError, 'must be new'):
            p.fresh_directory(link)

    def test_unfrozen_toolchain_replacement_and_path_escape_refused(self):
        for key, value in (('go', '1.27'), ('module_replacements', [{'new': 'elsewhere'}]), ('path', '../outside')):
            old = self.module[key]; self.module[key] = value; self.write_mapping()
            with self.assertRaises(ValueError):
                p.prepare(self.source, self.work, self.go, self.cache)
            self.module[key] = old
        self.assertFalse(self.work.exists())

    def test_original_manifest_drift_is_failure_even_after_commands_succeed(self):
        def mutate(*args, **kwargs):
            result = self.response(*args, **kwargs)
            if args[1] == ['mod', 'verify']:
                (self.source / 'tools/owner/go.sum').write_bytes(b'changed\n')
            return result
        with patch.object(p, 'command', side_effect=mutate):
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                p.prepare(self.source, self.work, self.go, self.cache)
        report = json.loads((self.work / 'result.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['source_manifests_unchanged'])


if __name__ == '__main__':
    unittest.main()
