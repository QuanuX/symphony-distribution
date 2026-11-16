import copy
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import d09_platform as gate
import d09_platform_tools as tool


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.build = {'state': 'built_and_sdk_checked', 'repeated_payload_bytes_equal': True,
                      'host': {'scope': 'native_profile_build', 'requested_profile': 'macos15-arm64'},
                      'rounds': [{'directory': 'round-1'}, {'directory': 'round-2'}],
                      'source_input': {'kind': 'verified_reviewed_derived_export', 'verified': True},
                      'publication_authorized': False, 'acceptance_complete': False}

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_primary_and_two_round_contract(self):
        gate.primary_build(self.build, 'macos15-arm64')
        for field, value in [('repeated_payload_bytes_equal', False), ('rounds', [{'directory': 'round-1'}]),
                             ('publication_authorized', True)]:
            bad = copy.deepcopy(self.build); bad[field] = value
            with self.assertRaises(ValueError): gate.primary_build(bad, 'macos15-arm64')

    def test_raw_git_never_promoted(self):
        self.build['source_input'] = {'kind': 'exact_committed_source_archive', 'verified': True}
        with self.assertRaisesRegex(ValueError, 'Raw Git'): gate.primary_build(self.build, 'macos15-arm64')

    def test_supplemental_and_wrong_platform_refused(self):
        for profile in ('local-macos-amd64-fixture', 'ubuntu24.04-amd64'):
            with self.assertRaises(ValueError): gate.primary_build(self.build, profile)
        self.build['host']['scope'] = 'supplemental_local_build'
        with self.assertRaises(ValueError): gate.primary_build(self.build, 'macos15-arm64')

    def test_selected_source_checks_both_pins_and_full_export_verifier(self):
        export = self.root / 'export'; export.mkdir()
        manifest = export / 'SOURCE-EXPORT.json'; manifest.write_text('{}')
        seen = []
        fake = SimpleNamespace(configure_policy=lambda p: seen.append(p),
                               verify=lambda e, r: {'export_digest': 'a' * 64, 'verified': True})
        with patch.object(gate, 'module', return_value=fake):
            gate.check_source(export, self.root, 'private-policy', 'a' * 64, gate.sha(manifest))
            self.assertEqual(seen, ['private-policy'])
            for ed, md in [('b' * 64, gate.sha(manifest)), ('a' * 64, 'b' * 64)]:
                with self.assertRaises(ValueError): gate.check_source(export, self.root, 'private-policy', ed, md)

    def test_private_policy_permissions_refused_before_export(self):
        policy = self.root / 'policy'; policy.write_text('{}'); policy.chmod(0o644)
        with self.assertRaisesRegex(ValueError, '0600'):
            gate.prepare_source(self.root, policy, self.root / 'export', 'a' * 64, 'b' * 64)

    def test_private_policy_exclusive0600_under_permissive_umask(self):
        path = self.root / 'policy.json'
        original_umask = os.umask(0)
        try:
            self.assertEqual(gate.write_private_policy(path, '{"private":"fixture-only"}'), path)
        finally:
            os.umask(original_umask)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_text(), '{"private":"fixture-only"}')
        with self.assertRaises(FileExistsError): gate.write_private_policy(path, 'replacement')
        self.assertEqual(path.read_text(), '{"private":"fixture-only"}')

    def test_private_policy_missing_or_linked_input_refuses_without_mutation(self):
        absent = self.root / 'absent'
        for raw in ('', None, 'x' * 65537):
            with self.assertRaises(ValueError): gate.write_private_policy(absent, raw)
            self.assertFalse(absent.exists())
        linked = self.root / 'linked'; linked.symlink_to(absent)
        with self.assertRaises(ValueError): gate.write_private_policy(linked, 'fixture')
        self.assertTrue(linked.is_symlink()); self.assertFalse(absent.exists())
        directory = self.root / 'directory'; directory.mkdir()
        parent = self.root / 'linked-parent'; parent.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(ValueError): gate.write_private_policy(parent / 'policy', 'fixture')
        self.assertEqual(list(directory.iterdir()), [])

    def test_actual_workflow_source_step_creates_private_policy_before_export_invocation(self):
        workflow = (gate.ROOT / '.github/workflows/d09-platform.yml').read_text()
        step = workflow.split('      - name: Reproduce only the independently selected reviewed source export\n', 1)[1]
        step = step.split('      - name:', 1)[0]
        match = re.search(r"python3 - <<'PYCODE'\n(.*?)\n          PYCODE", step, re.S)
        self.assertIsNotNone(match)
        program = textwrap.dedent(match.group(1))
        output = io.StringIO()
        environment = {'RUNNER_TEMP': str(self.root), 'PRIVATE_SOURCE_POLICY': '{"private":"fixture-only"}',
                       'EXPECTED_EXPORT': 'a' * 64, 'EXPECTED_MANIFEST': 'b' * 64}
        with patch.dict(os.environ, environment, clear=True), patch.object(subprocess, 'run') as child, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exec(compile(program, '<actual-d09-workflow-source-step>', 'exec'), {})
            self.assertNotIn('PRIVATE_SOURCE_POLICY', os.environ)
        policy = self.root / 'd09-source-policy.json'
        self.assertEqual(policy.stat().st_mode & 0o777, 0o600)
        self.assertEqual(policy.read_text(), environment['PRIVATE_SOURCE_POLICY'])
        command = child.call_args.args[0]
        self.assertEqual(command[1:4], ['-B', 'qualification/d09_platform.py', 'source'])
        self.assertEqual(command[command.index('--policy') + 1], str(policy))
        self.assertEqual(command[command.index('--export-digest') + 1], 'a' * 64)
        self.assertEqual(command[command.index('--manifest-sha256') + 1], 'b' * 64)
        self.assertEqual(output.getvalue(), '')

    def test_new_output_custody(self):
        source = self.root / 'input'; source.mkdir()
        linked = self.root / 'linked'; linked.symlink_to(source, target_is_directory=True)
        for output in (source / 'nested', linked / 'child', source, self.root):
            with self.assertRaises(ValueError): gate.fresh(output, [source])
        out = gate.fresh(self.root / 'safe', [source])
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)

    def environment(self):
        return {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_REPOSITORY': gate.REPOSITORY, 'GITHUB_RUN_ID': '12',
                'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_TEMP': str(self.root)}

    def test_local_self_hosted_foreign_runs_never_execute(self):
        for key, value in [('GITHUB_ACTIONS', ''), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                           ('GITHUB_REPOSITORY', 'foreign/repository'), ('GITHUB_RUN_ID', 'bad')]:
            env = self.environment(); env[key] = value
            with self.assertRaises(ValueError): gate.hosted_custody('macos15-arm64', self.root / 'new', env)

    def test_ephemeral_host_must_match_and_stay_in_runner_temp(self):
        host = {'system': 'darwin', 'architecture': 'arm64', 'distribution': 'macos', 'version': '15.7', 'wsl': False}
        fake = SimpleNamespace(observe_host=lambda: host, profile_matches=lambda p, h: p == 'macos15-arm64')
        with patch.object(gate, 'module', return_value=fake):
            self.assertEqual(gate.hosted_custody('macos15-arm64', self.root / 'new', self.environment()), host)
            with self.assertRaises(ValueError): gate.hosted_custody('ubuntu24.04-amd64', self.root / 'new', self.environment())
            with self.assertRaises(ValueError): gate.hosted_custody('macos15-arm64', self.root.parent / 'outside', self.environment())

    def test_missing_opt_in_refuses_before_custody(self):
        with self.assertRaisesRegex(ValueError, 'opt-in'):
            gate.fresh_user(SimpleNamespace(allow_ephemeral_install=False))

    def test_carrier_bytes_modes_extra_files_links_and_activation_refused(self):
        prefix = self.root / 'prefix'; carrier = prefix / 'share/symphony/carriers/module/1/build/payload.tar'
        carrier.parent.mkdir(parents=True); carrier.write_bytes(b'exact'); carrier.chmod(0o644)
        expected = {str(carrier.relative_to(prefix)): (b'exact', 0o644)}
        self.assertEqual(gate.verify_wrapper_link(prefix, expected), 1)
        carrier.chmod(0o755)
        with self.assertRaises(ValueError): gate.verify_wrapper_link(prefix, expected)
        carrier.chmod(0o644); extra = carrier.parent / 'extra'; extra.write_bytes(b'unselected')
        with self.assertRaises(ValueError): gate.verify_wrapper_link(prefix, expected)
        extra.unlink(); (prefix / 'bin').mkdir()
        with self.assertRaises(ValueError): gate.verify_wrapper_link(prefix, expected)

    def test_user_state_snapshot_detects_content_mode_and_membership_changes(self):
        file = self.root / 'sentinel'; file.write_bytes(b'original'); file.chmod(0o644)
        before = gate.inventory(self.root)
        file.write_bytes(b'changed'); self.assertNotEqual(gate.inventory(self.root), before)
        file.write_bytes(b'original'); file.chmod(0o600); self.assertNotEqual(gate.inventory(self.root), before)
        file.chmod(0o644); self.assertEqual(gate.inventory(self.root), before)

    def test_timeout_or_signal_is_not_successful_refusal(self):
        fake = SimpleNamespace(returncode=124)
        with patch.object(gate.subprocess, 'run', return_value=fake):
            with self.assertRaises(ValueError): gate.invoke(['false'], {}, self.root / 'log', expected=1)

    def test_primary_tools_cover_exact_profiles(self):
        self.assertEqual(set(tool.TARGETS), set(gate.PROFILES))
        self.assertEqual(tool.TARGETS['ubuntu24.04-amd64'][1], tool.TARGETS['ubuntu26.04-amd64'][1])
        for _, _, _, sha in tool.TARGETS.values(): gate.digest(sha)

    def test_duplicate_record_fields_refused(self):
        path = self.root / 'duplicate.json'; path.write_text('{"state":"pending","state":"passed"}')
        with self.assertRaises(ValueError): gate.read(path)

    def test_failure_evidence_is_bounded_and_does_not_export_private_policy_or_raw_log(self):
        work = gate.fresh(self.root / 'work', [])
        (work / 'install.log').write_text('private-person compiler error\nTOKEN=private-value\n' + str(work) + '/file.cpp\n')
        policy = self.root / 'policy.json'; policy.write_text(json.dumps({'markers': ['private-person']}))
        gate.failure_summary(work, ValueError('install failed'), policy)
        report = gate.read(work / 'failure.json')
        rendered = json.dumps(report)
        self.assertNotIn('private-person', rendered)
        self.assertNotIn('private-value', rendered)
        self.assertNotIn(str(work), rendered)
        self.assertEqual(report['selected_log']['sha256'], gate.sha(work / 'install.log'))
        self.assertEqual(report['state'], 'incomplete')

    def test_refused_existing_output_never_receives_failure_metadata(self):
        gate.failure_summary(self.root, ValueError('existing output refused'))
        self.assertFalse((self.root / 'failure.json').exists())

    def test_acceptance_packet_preserves_all36_pending_cells_and_two_routes(self):
        source = self.root / 'tests/launch-acceptance'; source.mkdir(parents=True)
        plan = {'required_profiles': list(gate.PROFILES), 'required_scenarios': ['scenario-' + str(i) for i in range(9)],
                'required_inputs': ['independent_signer_policy', 'named_acceptance_reviewer']}
        (source / 'plan.json').write_text(json.dumps(plan))
        record = gate.acceptance_packet(self.root, 'a' * 40, 'macos15-arm64', 'sha256:' + 'b' * 64)
        self.assertEqual(len(record['cells']), 36)
        self.assertTrue(all(r['state'] == 'pending' and r['routes'] == {'cli': 'pending', 'standalone': 'pending'}
                            for r in record['cells']))
        self.assertFalse(record['release_acceptance_complete'])
        plan['required_scenarios'].append('new-scope'); (source / 'plan.json').write_text(json.dumps(plan))
        with self.assertRaises(ValueError): gate.acceptance_packet(self.root, 'a' * 40, 'macos15-arm64', 'sha256:' + 'b' * 64)

    def test_fresh_user_orchestration_executes_disposable_fixture_and_checks_all_refusals(self):
        # This is a small executable fixture, not a native installer or host
        # acceptance. Only external archive/tool adapters are replaced. The
        # actual subprocess, mode/byte checks, snapshots and refusals run.
        artifact = self.root / 'artifact'; wrappers = artifact / 'wrappers'
        wrappers.mkdir(parents=True); (artifact / 'carriers').mkdir()
        script = wrappers / 'fixture.sh'
        script.write_text(textwrap.dedent('''\
            #!/bin/bash
            set -eu
            prefix=''
            while [ "$#" -gt 0 ]; do
              case "$1" in
                -b) shift ;;
                -p) prefix="$2"; shift 2 ;;
                -f|-u) exit 1 ;;
                *) exit 2 ;;
              esac
            done
            if [ -e "$prefix" ] || [ -L "$prefix" ]; then exit 1; fi
            mkdir -p "$prefix/share/symphony/carriers/fixture/1/build" "$prefix/conda-meta"
            printf 'payload' > "$prefix/share/symphony/carriers/fixture/1/build/payload.tar"
            chmod 644 "$prefix/share/symphony/carriers/fixture/1/build/payload.tar"
            printf '{"name":"fixture","version":"1","build":"build"}' > "$prefix/conda-meta/fixture.json"
            '''))
        row = {'filename': script.name, 'sha256': gate.sha(script), 'size': script.stat().st_size,
               'bootstrap_sha256': 'c' * 64}
        cohort = {'profile': 'macos15-arm64', 'cohort_digest': 'sha256:' + 'a' * 64,
                  'archives': [{'name': 'fixture', 'version': '1', 'build': 'build'}], 'entries': [{}]}
        gate.write(wrappers / 'result.json', {'state': 'unsigned_wrappers_audited', 'wrappers': [row]})
        gate.write(artifact / 'fresh-host-requirements.json', {'state': 'pending'})
        selected = {'state': 'primary_review_wrappers_audited', 'profile': 'macos15-arm64', 'archive_count': 58,
                    'publication_authorized': False, 'cohort_digest': cohort['cohort_digest'],
                    'wrapper_result_sha256': gate.sha(wrappers / 'result.json'),
                    'fresh_host_requirements_sha256': gate.sha(artifact / 'fresh-host-requirements.json')}
        gate.write(artifact / 'result.json', selected)
        expected = {'share/symphony/carriers/fixture/1/build/payload.tar': (b'payload', 0o644)}
        adapters = {
            'installer_assembly/carriers.py': SimpleNamespace(audit_cohort=lambda p: cohort,
                                                               validate_recipe=lambda p, e: (None, expected)),
            'installer_assembly/construct.py': SimpleNamespace(audit_sh=lambda *a: None,
                                                                archive_records=lambda c: c['archives']),
            'installer_assembly/link_qualification.py': SimpleNamespace(qualify=lambda *a, **k: {'state': 'passed'}),
        }
        interpreter = self.root / 'tools/bin/python'; interpreter.parent.mkdir(parents=True)
        args = SimpleNamespace(allow_ephemeral_install=True, profile='macos15-arm64',
                               output=self.root / 'fresh', artifact=artifact, python=interpreter,
                               result_sha256=gate.sha(artifact / 'result.json'))
        with patch.object(gate, 'module', side_effect=lambda n, p: adapters[p]), \
             patch.object(gate, 'hosted_custody', return_value={'fixture': True}), \
             patch.dict(os.environ, self.environment()):
            result = gate.fresh_user(args)
        self.assertEqual(result['state'], 'passed')
        self.assertEqual(len(result['fresh_prefix_refusals']), 4)
        self.assertEqual(result['installed_carrier_file_count'], 1)
        self.assertTrue(result['user_state_unchanged'])
        self.assertFalse(result['independent_fresh_host_acceptance'])
        self.assertFalse(result['native_runtime_owner_invoked'])
        self.assertEqual(gate.read(args.output / 'result.json'), result)


if __name__ == '__main__':
    unittest.main()
