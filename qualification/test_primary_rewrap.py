import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualification import primary_rewrap as m
from qualification import primary_artifacts as transport


class RewrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_optin_refuses_before_any_artifact_or_process(self):
        with patch.object(m, 'admit_rewrap') as admission:
            with self.assertRaisesRegex(ValueError, 'opt-in'):
                m.fresh_user(SimpleNamespace(allow_ephemeral_install=False))
            admission.assert_not_called()

    def test_copy_preserves_exact_members_bytes_and_executable_modes(self):
        original = self.root / 'original'; original.mkdir()
        path = original / 'nested/executable'; path.parent.mkdir(); path.write_bytes(b'exact source')
        path.chmod(0o755)
        (original / 'empty').mkdir(mode=0o700); path.parent.chmod(0o700)
        before = m.copy_tree(original, self.root / 'copy')
        self.assertEqual(before, m.tree_inventory(original))
        self.assertEqual(before, m.tree_inventory(self.root / 'copy'))
        self.assertEqual(transport.inventory(original)['entries'], before)
        self.assertEqual(transport.inventory(original), transport.inventory(self.root / 'copy'))
        self.assertEqual((self.root / 'copy/nested/executable').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / 'copy/empty').stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / 'copy/nested').stat().st_mode & 0o777, 0o700)
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'changed'): m.records_equal(original, before)
        self.assertEqual((self.root / 'copy/nested/executable').read_bytes(), b'exact source')

    def test_artifact_tree_refuses_links_shared_files_and_existing_output(self):
        source = self.root / 'source'; source.mkdir()
        target = source / 'file'; target.write_bytes(b'original')
        alias = source / 'alias'; alias.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'Linked'): m.tree_inventory(source)
        alias.unlink(); os.link(target, alias)
        with self.assertRaisesRegex(ValueError, 'shared'): m.tree_inventory(source)
        alias.unlink()
        with self.assertRaisesRegex(ValueError, 'new'): m.copy_tree(source, source)

    def selection_fixture(self):
        keys = ('source_export_digest', 'source_manifest_sha256', 'build_result_sha256', 'round_result_sha256',
                'sdk_closure_sha256', 'delivery_record_sha256', 'fresh_host_requirements_sha256')
        pins = {key: str(i + 1) * 64 for i, key in enumerate(keys)}
        pins.update(source_commit='a'*40, source_tree='b'*40, cohort_digest='sha256:'+'c'*64,
                    primary_result_sha256='d'*64)
        selected = {'profile': 'ubuntu24.04-amd64', 'workflow_commit': 'e'*40, 'pins': pins}
        record = {key: value for key, value in pins.items() if key != 'primary_result_sha256'}
        record.update(profile=selected['profile'], original_toolkit_commit=selected['workflow_commit'])
        return selected, record

    def test_every_independent_original_evidence_pin_and_workflow_identity_is_required(self):
        selected, record = self.selection_fixture()
        with patch.object(transport, 'verify_transport') as verified, \
             patch.object(m.platform_gate, 'verify_capsule', return_value=record, create=True):
            self.assertEqual(m.selected_capsule(self.root, selected, 'f'*64, self.root / 'proof'), record)
            verified.assert_called_once_with(self.root, self.root / 'proof', selected, 'f'*64)
            for key in selected['pins']:
                if key == 'primary_result_sha256': continue
                bad = copy.deepcopy(selected); bad['pins'][key] = 'changed'
                with self.assertRaisesRegex(ValueError, 'selection differs'):
                    m.selected_capsule(self.root, bad, 'f'*64, self.root / 'proof')
            bad = selected | {'workflow_commit': 'f'*40}
            with self.assertRaisesRegex(ValueError, 'toolkit identity'):
                m.selected_capsule(self.root, bad, 'f'*64, self.root / 'proof')

    def test_capsule_incomplete_or_transport_refusal_is_not_bypassed(self):
        selected, record = self.selection_fixture()
        with patch.object(transport, 'verify_transport', side_effect=ValueError('transport refused')), \
             patch.object(m.platform_gate, 'verify_capsule', return_value=record, create=True) as checked:
            with self.assertRaisesRegex(ValueError, 'transport refused'):
                m.selected_capsule(self.root, selected, 'f'*64, self.root / 'proof')
            checked.assert_not_called()
        with patch.object(transport, 'verify_transport'), \
             patch.object(m.platform_gate, 'verify_capsule', side_effect=ValueError('incomplete capsule'), create=True):
            with self.assertRaisesRegex(ValueError, 'incomplete capsule'):
                m.selected_capsule(self.root, selected, 'f'*64, self.root / 'proof')

    def wrappers(self, profile='ubuntu24.04-amd64'):
        subdir = 'osx-arm64' if profile == 'macos15-arm64' else 'linux-64'
        rows = [{'unit_id': str(i), 'filename': f'package-{i}-1-build.conda', 'sha256': 'a'*64, 'md5': 'b'*32,
                 'size': 1, 'name': f'package-{i}', 'version': '1', 'build': 'build', 'build_number': 0,
                 'subdir': subdir, 'depends': []} for i in range(58)]
        cohort = {'state': 'archives_audited', 'archives': rows, 'entries': [{}]*58, 'conda_subdir': subdir,
                  'profile': profile, 'cohort_digest': 'sha256:'+'c'*64}
        wrapper = {'protocol': m.construct.SCHEMA, 'state': 'unsigned_wrappers_audited', 'profile': profile,
                   'cohort_digest': cohort['cohort_digest'], 'archives': rows, 'publication_authorized': False,
                   'release_acceptance_complete': False, 'runtime_activated': False,
                   'wrappers': [{'format': 'sh', 'archive_count': 58, 'filename': 'review.sh', 'sha256': 'd'*64,
                                 'bootstrap_sha256': 'e'*64, 'size': 12}]}
        if profile == 'macos15-arm64':
            wrapper['wrappers'].append(wrapper['wrappers'][0] | {'format': 'pkg', 'filename': 'review.pkg'})
        return cohort, wrapper

    def test_exact58_primary_and_native_formats_required(self):
        for profile in ('ubuntu24.04-amd64', 'macos15-arm64'):
            cohort, wrapper = self.wrappers(profile)
            self.assertEqual(m.wrapper_selection(cohort, wrapper)['filename'], 'review.sh')
            for altered in (wrapper | {'wrappers': []}, wrapper | {'wrappers': wrapper['wrappers'] * 2},
                            wrapper | {'runtime_activated': True}, wrapper | {'profile': 'ubuntu26.04-amd64'}):
                with self.assertRaises(ValueError): m.wrapper_selection(cohort, altered)
            bad = copy.deepcopy(wrapper); bad['archives'][0]['sha256'] = 'f'*64
            with self.assertRaises(ValueError): m.wrapper_selection(cohort, bad)
        cohort, wrapper = self.wrappers(); cohort['entries'] = [{}]*59
        with self.assertRaises(ValueError): m.wrapper_selection(cohort, wrapper)
        cohort, wrapper = self.wrappers(); cohort['profile'] = 'local-macos-amd64-fixture'
        with self.assertRaises(ValueError): m.wrapper_selection(cohort, wrapper)

    def test_wrapper_identity_traversal_size_and_bootstrap_refused(self):
        for key, value in [('filename', '../review.sh'), ('size', 0), ('size', m.construct.MAX_WRAPPER + 1),
                           ('bootstrap_sha256', 'unselected'), ('archive_count', 59)]:
            cohort, wrapper = self.wrappers(); wrapper['wrappers'][0][key] = value
            with self.assertRaises(ValueError): m.wrapper_selection(cohort, wrapper)

    def test_private_readonly_execution_copy_survives_original_mutation(self):
        source = self.root / 'wrapper.sh'; source.write_bytes(b'exact wrapper bytes')
        out = self.root / 'output'; out.mkdir()
        row = {'sha256': m.signing.digest(source), 'size': source.stat().st_size}
        result = m.snapshot_wrapper(source, row, out)
        self.assertEqual(result.stat().st_mode & 0o777, 0o400)
        source.write_bytes(b'changed original')
        self.assertEqual(result.read_bytes(), b'exact wrapper bytes')
        with self.assertRaises(ValueError): m.snapshot_wrapper(source, row, self.root)

    def test_snapshot_refuses_alias_digest_mismatch_and_existing_destination(self):
        source = self.root / 'wrapper'; source.write_bytes(b'wrapper')
        row = {'sha256': m.signing.digest(source), 'size': 7}
        alias = self.root / 'alias'; alias.symlink_to(source)
        with self.assertRaises(ValueError): m.snapshot_wrapper(alias, row, self.root)
        with self.assertRaisesRegex(ValueError, 'differs'):
            m.snapshot_wrapper(source, row | {'sha256': 'f'*64}, self.root)
        # Failed snapshot is retained and cannot be silently reused/replaced.
        with self.assertRaises(FileExistsError): m.snapshot_wrapper(source, row, self.root)

    def test_consumer_custody_requires_native_host_and_explicit_job_identity(self):
        with patch.object(m.platform_gate, 'hosted_custody', return_value={'system': 'linux'}), \
             patch.dict(os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_JOB': 'fresh-user'}, clear=True):
            self.assertEqual(m.custody('ubuntu24.04-amd64', self.root)['job'], 'fresh-user')
            os.environ['GITHUB_JOB'] = '../unselected'
            with self.assertRaisesRegex(ValueError, 'job identity'): m.custody('ubuntu24.04-amd64', self.root)

    def test_same_job_and_changed_consumer_helpers_refuse_before_execution(self):
        artifact = self.root / 'artifact'; artifact.mkdir(); (artifact / 'fixture').write_bytes(b'input')
        host = {'run_id': '11', 'run_attempt': '1', 'job': 'rewrap'}
        result = {'profile': 'ubuntu24.04-amd64', 'producer': host, 'executing_helpers': {'selected': 'a'*64}}
        args = SimpleNamespace(artifact=artifact, result_sha256='b'*64,
                               output=self.root / 'new', inspection_tools=self.root / 'tools', allow_ephemeral_install=True)
        with patch.object(m, 'admit_rewrap', return_value=(result, {}, {})), \
             patch.object(m, 'custody', return_value=host), patch.object(m, 'exercise') as execute:
            with self.assertRaisesRegex(ValueError, 'separate disposable'): m.fresh_user(args)
            execute.assert_not_called()
        with patch.object(m, 'admit_rewrap', return_value=(result, {}, {})), \
             patch.object(m, 'custody', return_value=host | {'job': 'consumer'}), \
             patch.object(m, 'helper_hashes', return_value={'selected': 'c'*64}), \
             patch.object(m, 'inspection_tools', return_value={}), patch.object(m, 'exercise') as execute:
            with self.assertRaisesRegex(ValueError, 'Consumer helpers differ'): m.fresh_user(args)
            execute.assert_not_called()
        self.assertFalse(args.output.exists())

    def test_partial_new_toolkit_helper_claim_refused_before_source_admission(self):
        archive = self.root / 'WRAPPER-TOOLKIT-SOURCE.tar'; archive.write_bytes(b'fixture source')
        identity = {'commit': 'a'*40, 'tree': 'b'*40, 'file_count': 1}
        index = {'protocol': m.source_capture.SOURCE, 'source': identity, 'privacy_scan': 'pass',
                 'publication_authorized': False, 'executing_helpers': {}, 'archive_sha256': m.signing.digest(archive)}
        (self.root / 'WRAPPER-TOOLKIT-SOURCE.json').write_text(json.dumps(index))
        with patch.object(m.supplements, 'source_tree') as verify:
            with self.assertRaisesRegex(ValueError, 'source/helper binding'): m.verify_toolkit(self.root, {}, identity)
            verify.assert_not_called()

    def tools_fixture(self):
        root = self.root / 'tools'; root.mkdir(); (root / 'publisher').mkdir()
        (root / 'publisher.explicit.txt').write_bytes(b'@EXPLICIT\nfixture-only\n')
        record = {'protocol': 'symphony.distribution.d09-publisher-tools.v1', 'profile': 'ubuntu24.04-amd64',
                  'publication_authorized': False, 'resolved_transitive_closure_preapproved': False,
                  'helper_sha256': m.signing.digest(m.ROOT / 'qualification/d09_platform_tools.py'),
                  'resolved_tool_closure_sha256': m.signing.digest(root / 'publisher.explicit.txt')}
        (root / 'result.json').write_text(json.dumps(record))
        return root, record

    def test_inspection_tools_bind_profile_helper_and_resolved_closure(self):
        root, record = self.tools_fixture()
        with patch.object(m, 'inspection_runtime', return_value={'observed': 'fixture'}) as runtime:
            evidence = m.inspection_tools(root, 'ubuntu24.04-amd64')
            self.assertEqual(evidence['resolved_tool_closure_sha256'], record['resolved_tool_closure_sha256'])
            runtime.assert_called_once_with(root / 'publisher')
            with self.assertRaises(ValueError): m.inspection_tools(root, 'ubuntu26.04-amd64')
            for key, value in [('helper_sha256', 'f'*64), ('publication_authorized', True),
                               ('resolved_transitive_closure_preapproved', True)]:
                (root / 'result.json').write_text(json.dumps(record | {key: value}))
                with self.assertRaises(ValueError): m.inspection_tools(root, 'ubuntu24.04-amd64')
            (root / 'result.json').write_text(json.dumps(record))
            (root / 'publisher.explicit.txt').write_bytes(b'changed')
            with self.assertRaises(ValueError): m.inspection_tools(root, 'ubuntu24.04-amd64')

    def test_system_interpreter_cannot_impersonate_private_inspection_prefix(self):
        prefix = self.root / 'publisher'; (prefix / 'bin').mkdir(parents=True)
        (prefix / 'bin/python').symlink_to(Path(m.sys.executable).resolve())
        with self.assertRaisesRegex(ValueError, 'selected private Python'):
            m.inspection_runtime(prefix)

    def test_native_decoder_bytes_are_bound_and_external_library_refused(self):
        publisher = self.root / 'publisher'; publisher.mkdir()
        extension = publisher / '_zstd.so'; extension.write_bytes(b'original decoder fixture')
        module = SimpleNamespace(__file__=str(extension))
        with patch.object(m.importlib.metadata, 'version', return_value='fixture-version'):
            before = m.inspection_module(publisher, module, 'backports.zstd')
            extension.write_bytes(b'changed decoder fixture')
            self.assertNotEqual(before, m.inspection_module(publisher, module, 'backports.zstd'))
            outside = self.root / 'outside.so'; outside.write_bytes(b'outside fixture')
            with self.assertRaisesRegex(ValueError, 'outside selected tool prefix'):
                m.inspection_module(publisher, SimpleNamespace(__file__=str(outside)), 'backports.zstd')

    def exercise_fixture(self, *, mutate_refusal=False, leave_carrier=False):
        cohort, _ = self.wrappers()
        # A small behavioral fixture exercises the exact real orchestration,
        # without pretending to be native Conda or a completed58 carrier build.
        cohort['archives'] = cohort['archives'][:1]
        bootstrap_raw = b'exact selected fixture bootstrap'
        row = {'bootstrap_sha256': m.c.sha(bootstrap_raw)}
        expected = {'share/symphony/carriers/module/1/build/payload.tar': (b'opaque carrier', 0o644)}
        seen = []
        def invoke(command, env, log, *, expected=0):
            seen.append((command, env.copy(), expected))
            self.assertNotIn('CONDA_SOLVER', env)
            prefix = self.root / 'prefix'
            if log.name == 'install.log':
                for name, (raw, mode) in payload.items():
                    path = prefix / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(mode)
                (prefix / '_conda').write_bytes(bootstrap_raw)
                (prefix / 'share/symphony/installer').mkdir()
                (prefix / 'share/symphony/installer/NOTICE').write_bytes(b'notice')
                (prefix / 'conda-meta').mkdir()
                (prefix / 'conda-meta/unit.json').write_text(json.dumps(cohort['archives'][0]))
            elif log.name == 'remove.log':
                self.assertEqual(command[1:8], ['remove', '--prefix', prefix, '--offline', '--yes', '--solver', 'classic'])
                self.assertEqual(command[8:], [cohort['archives'][0]['name']])
                if not leave_carrier: shutil.rmtree(prefix / 'share/symphony/carriers')
                (prefix / 'conda-meta/unit.json').unlink()
            elif mutate_refusal:
                (prefix / 'user-state.txt').write_bytes(b'changed')
            return {'name': log.name, 'sha256': 'a'*64, 'exit_code': expected}
        payload = expected
        return cohort, row, expected, seen, invoke

    def test_real_orchestrator_uses_private_snapshot_named_removal_and_preserves_state(self):
        cohort, row, expected, seen, invoke = self.exercise_fixture()
        execution = self.root / 'private-verified.sh'
        with patch.object(m.consumer, 'invoke', side_effect=invoke):
            logs = m.exercise(execution, row, cohort, expected, self.root)
        self.assertEqual([r['name'] for r in logs], ['install.log', 'existing.log', 'force.log', 'upgrade.log', 'dangling.log', 'remove.log'])
        self.assertTrue(all(command[1] == execution for command, _, _ in seen[:5]))
        self.assertEqual((self.root / 'prefix/user-state.txt').read_bytes(), b'caller state survives removal\n')
        self.assertEqual((self.root / 'home/.zshrc').read_bytes(), b'# isolated caller state must survive\n')
        self.assertEqual(seen[0][1]['CONDA_SUBDIR'], 'linux-64')

    def test_refusal_mutation_and_partial_named_removal_fail(self):
        for name, options in (('refusal', {'mutate_refusal': True}), ('removal', {'leave_carrier': True})):
            with self.subTest(name=name):
                directory = self.root / name; directory.mkdir(); original = self.root; self.root = directory
                try:
                    cohort, row, expected, _, invoke = self.exercise_fixture(**options)
                    with patch.object(m.consumer, 'invoke', side_effect=invoke):
                        with self.assertRaises(ValueError): m.exercise(directory / 'private.sh', row, cohort, expected, directory)
                finally: self.root = original

    def test_optional_retention_probe_runs_after_admission_before_removal(self):
        cohort,row,expected,seen,invoke=self.exercise_fixture(); called=[]
        def retain(prefix, env):
            self.assertEqual(m.consumer.carrier_namespace(prefix),expected)
            self.assertEqual(len(seen),1)
            called.append(prefix)
        with patch.object(m.consumer,'invoke',side_effect=invoke):
            m.exercise(self.root/'private.sh',row,cohort,expected,self.root,after_install=retain)
        self.assertEqual(called,[self.root/'prefix'])
        self.assertEqual(m.consumer.carrier_namespace(self.root/'prefix'),{})

    def test_retention_probe_cannot_mutate_original_installed_prefix(self):
        cohort,row,expected,seen,invoke=self.exercise_fixture()
        def mutate(prefix, env): (prefix/'unexpected').write_bytes(b'change')
        with patch.object(m.consumer,'invoke',side_effect=invoke),self.assertRaisesRegex(ValueError,'retention probe changed'):
            m.exercise(self.root/'private.sh',row,cohort,expected,self.root,after_install=mutate)
        self.assertEqual(len(seen),1)


if __name__ == '__main__': unittest.main()
