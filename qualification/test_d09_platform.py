import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import textwrap
import tarfile
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


class CapsuleTests(unittest.TestCase):
    """Use the existing real D06/cohort fixture; mock only the Conda codec."""
    def setUp(self):
        self.fixture = gate.module('capsule_fixture', 'installer_assembly/test_cohort.py').InstallerCohort()
        self.fixture.setUp(); self.addCleanup(self.fixture.tearDown)
        f = self.fixture; self.root = f.root
        self.real_module = gate.module
        self.c = gate.module('capsule_test_carriers', 'installer_assembly/carriers.py')
        self.source = gate.module('capsule_test_source', 'installer_assembly/corresponding_source.py')
        self.profile = 'macos15-arm64'
        self.contents = {name: ('fixture source ' + name).encode() for name in
            set(gate.CAPSULE_HELPERS) | {'build-cohort/build.py', 'build-cohort/qxctl_identity.py',
                'build-cohort/cohort.json', 'qualification/native_campaign.py', 'qualification/d06_sdk_closure.py'}}
        self.helpers = {name: self.c.sha(self.contents[name]) for name in gate.CAPSULE_HELPERS}
        plan = {'required_profiles': list(gate.PROFILES), 'required_scenarios': ['scenario-' + str(i) for i in range(9)],
                'required_inputs': ['independent_review']}
        path = f.source / 'tests/launch-acceptance/plan.json'; path.parent.mkdir(parents=True)
        self.put(path, plan)
        f.manifest['source_files'].append({'path': 'tests/launch-acceptance/plan.json', 'mode': '100644',
            'source_sha256': gate.sha(path), 'export_sha256': gate.sha(path),
            'source_size': path.stat().st_size, 'export_size': path.stat().st_size})
        f.manifest['source_files'].sort(key=lambda r: r['path'])
        export_digest = self.c.sha(json.dumps([{'path': r['path'], 'mode': r['mode'], 'sha256': r['export_sha256']}
            for r in f.manifest['source_files']], sort_keys=True, separators=(',', ':')).encode())
        f.manifest['derived_export_digest'] = export_digest
        f.aggregate['source_input']['export_digest'] = export_digest
        f.aggregate['host'].update(scope='native_profile_build', requested_profile=self.profile, architecture='arm64')
        f.aggregate['repeated_payload_bytes_equal'] = True
        f.aggregate['build_helpers'] = {Path(name).name: self.c.sha(raw) for name, raw in self.contents.items()
                                       if name.startswith('build-cohort/') and name.endswith('.py')}
        f.aggregate['builder_sha256'] = f.aggregate['build_helpers']['build.py']
        f.aggregate['plan_sha256'] = self.c.sha(self.contents['build-cohort/cohort.json'])
        f.aggregate['imported_helpers'] = {name: self.c.sha(self.contents[name]) for name in
                                          ('qualification/native_campaign.py', 'source-export/export_source.py')}
        f.aggregate['rounds'].append({**f.aggregate['rounds'][0], 'directory': 'round-2'})
        f.proof['helper_sha256'] = self.c.sha(self.contents['build-cohort/qxctl_identity.py'])
        f.proof['cohort_source']['export_digest'] = export_digest
        for field in ('build_info', 'artifact_identity', 'compiled_input_equivalence'): f.proof[field]['goarch'] = 'arm64'
        f.delivery['source']['derived_export_digest'] = export_digest
        f.delivery['source']['toolkit_files'] = [{'path': name, 'sha256': self.c.sha(raw), 'mode': 0o644}
                                                for name, raw in sorted(self.contents.items())]
        f.delivery['tool_sha256'] = self.c.sha(self.contents['qualification/d06_delivery_record.py'])
        self.put(f.export / 'SOURCE-EXPORT.json', f.manifest); self.put(f.proof_root / 'result.json', f.proof)
        self.put(f.base / 'round-2/result.json', f.round); self.put(f.base / 'result.json', f.aggregate)
        f.delivery['build_result_sha256'] = gate.sha(f.base / 'result.json'); self.put(f.delivery_path, f.delivery)
        f.kwargs.update(expected_base_result_sha256=gate.sha(f.base / 'result.json'),
                        expected_delivery_sha256=gate.sha(f.delivery_path), expected_qxctl_proof_sha256=gate.sha(f.proof_root / 'result.json'))
        self.candidate = f.prepare()
        self.sdk = {'protocol': 'symphony.distribution.d06-sdk-closure.v1', 'status': 'passed',
            'source_commit': f.commit, 'source_tree': f.tree, 'round': 'round-1',
            'source_inventory_sha256': export_digest,
            'cohort_result_sha256': gate.sha(f.base / 'result.json'), 'round_result_sha256': gate.sha(f.base / 'round-1/result.json'),
            'harness_sha256': self.c.sha(self.contents['qualification/d06_sdk_closure.py']),
            'extra_helpers_sha256': {name: self.c.sha(self.contents[name]) for name in
                ('qualification/d06_sdk_closure.py', 'qualification/native_campaign.py')},
            'publication_authorized': False, 'release_acceptance_complete': False, 'fresh_host_accepted': False}
        self.candidate['helper_sha256'] = self.helpers['installer_assembly/cohort.py']
        self.capsule = self.root / 'capsule'; evidence = self.capsule / 'evidence'; evidence.mkdir(parents=True)
        (self.capsule / 'carriers').mkdir()
        self.documents = {'build-result.json': f.aggregate, 'round-result.json': f.round, 'round-2-result.json': f.round,
            'delivery-record.json': f.delivery, 'sdk-closure.json': self.sdk, 'source-manifest.json': f.manifest,
            'qxctl-source-proof.json': f.proof, 'input-cohort.json': self.candidate,
            'mvp-dependencies.json': json.loads((f.source / 'cmake/mvp-dependencies.json').read_text()),
            'source-acceptance-plan.json': plan}
        rows = [(name, raw, 0o644) for name, raw in sorted(self.contents.items())]
        files = self.source.write_tar(evidence / 'TOOLKIT-SOURCE.tar', rows)
        # Git itself supplies the independent fixture tree identity.
        git_root = self.root / 'toolkit'; git_root.mkdir()
        for name, raw in self.contents.items():
            p = git_root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
        for command in (['init', '--quiet'], ['add', '.']):
            subprocess.run(['/usr/bin/git', '-C', str(git_root), *command], check=True, capture_output=True)
        tree = subprocess.check_output(['/usr/bin/git', '-C', str(git_root), 'write-tree'], text=True).strip()
        self.documents['TOOLKIT-SOURCE.json'] = {'protocol': gate.CAPSULE_SOURCE,
            'source': {'commit': 'e' * 40, 'tree': tree, 'file_count': len(rows)}, 'files': files,
            'archive_sha256': gate.sha(evidence / 'TOOLKIT-SOURCE.tar'), 'executing_helpers': self.helpers,
            'privacy_scan': 'pass', 'publication_authorized': False}
        self.cohort = {'profile': self.profile, 'cohort_digest': 'sha256:' + 'b' * 64, 'conda_subdir': 'osx-arm64',
                      'archives': [{'filename': 'fixture-' + str(i) + '.conda'} for i in range(58)],
                      'entries': [{'index': i, 'recipe_path': 'recipes/fixture-' + str(i)} for i in range(58)]}
        carrier_root = self.capsule / 'carriers'; (carrier_root / 'cohort.json').write_bytes(b'fixture codec')
        for i in range(58):
            names = ['channel/osx-arm64/fixture-' + str(i) + '.conda'] + ['recipes/fixture-' + str(i) + '/' + name
                for name in ('meta.yaml', 'stage_payload.py', 'payload/payload.tar', 'payload/unit.json', 'payload/carrier-manifest.json')]
            for name in names:
                p = carrier_root / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b'fixture codec')
        packet = gate.acceptance_packet(f.source, f.commit, self.profile, self.cohort['cohort_digest'])
        self.put(self.capsule / 'fresh-host-requirements.json', packet)
        self.record = {'protocol': gate.CAPSULE_PROTOCOL, 'state': 'primary_carriers_audited', 'profile': self.profile,
            'source_commit': f.commit, 'source_tree': f.tree, 'source_export_digest': export_digest,
            'archive_count': 58, 'cohort_digest': self.cohort['cohort_digest'],
            'original_toolkit_commit': 'e' * 40, 'original_toolkit_tree': tree, 'helper_sha256': self.helpers,
            'fresh_host_requirements_sha256': gate.sha(self.capsule / 'fresh-host-requirements.json'),
            **{key: False for key in ('client_included', 'wrappers_built', 'publication_authorized',
                'publisher_trust_accepted', 'independent_fresh_host_acceptance', 'release_acceptance_complete')}}
        self.reseal()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

    def reseal(self):
        for name, value in self.documents.items(): self.put(self.capsule / 'evidence' / name, value)
        shutil.copyfile(self.fixture.source / 'cmake/mvp-dependencies.json', self.capsule / 'evidence/mvp-dependencies.json')
        for name, field in gate.CAPSULE_EVIDENCE.items(): self.record[field] = gate.sha(self.capsule / 'evidence' / name)
        self.cohort['selected_evidence'] = {'input_cohort_sha256': self.record['input_cohort_sha256'],
            'source_binding': self.candidate['source_binding'], 'base_d06': self.candidate['base_d06'],
            'qxctl_source_proof_sha256': self.record['qxctl_source_proof_sha256']}
        self.put(self.capsule / 'result.json', self.record)
        return gate.sha(self.capsule / 'result.json')

    def verify(self, expected=None):
        with patch.object(gate, 'module', side_effect=self.load):
            return gate.verify_capsule(self.capsule, expected or gate.sha(self.capsule / 'result.json'))

    def load(self, name, relative):
        value = self.real_module(name, relative)
        if relative == 'installer_assembly/carriers.py':
            value.audit_cohort = lambda p: self.cohort
            value.validate_recipe = lambda p, entry: ({'payload_paths': [r['path'] for r in self.candidate['payload_inventory']]
                if entry['index'] == 0 else [], 'files': self.candidate['payload_inventory'] if entry['index'] == 0 else []}, {})
        return value

    def test_complete_retained_evidence_passes_without_current_helper_equality_or_wrapper_claim(self):
        result = self.verify()
        self.assertEqual(result, self.record); self.assertFalse(result['wrappers_built'])
        self.assertNotEqual(result['helper_sha256']['qualification/d09_platform.py'], gate.sha(gate.__file__))

    def test_independent_result_digest_extra_evidence_and_links_refused(self):
        with self.assertRaisesRegex(ValueError, 'Selected capsule'): self.verify('f' * 64)
        extra = self.capsule / 'evidence/extra'; extra.write_bytes(b'unselected')
        with self.assertRaisesRegex(ValueError, 'evidence set'): self.verify()
        extra.unlink(); selected = self.capsule / 'evidence/sdk-closure.json'
        saved = self.root / 'sdk'; selected.rename(saved); selected.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, 'Linked path'): self.verify()

    def test_wrapper_approval_and_carrier_rebinding_refused(self):
        for name in ('wrappers_built', 'publication_authorized', 'independent_fresh_host_acceptance'):
            self.record[name] = True; self.reseal()
            with self.assertRaisesRegex(ValueError, 'acceptance claim'): self.verify()
            self.record[name] = False
        self.reseal(); self.cohort['selected_evidence']['input_cohort_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'Carrier capsule binding'): self.verify()

    def test_source_tree_and_partial_producer_helpers_refused(self):
        self.record['original_toolkit_tree'] = 'f' * 40; self.reseal()
        with self.assertRaisesRegex(ValueError, 'source identity'): self.verify()
        self.record['original_toolkit_tree'] = self.documents['TOOLKIT-SOURCE.json']['source']['tree']
        self.record['helper_sha256'] = {}; self.documents['TOOLKIT-SOURCE.json']['executing_helpers'] = {}; self.reseal()
        with self.assertRaisesRegex(ValueError, 'helper closure'): self.verify()

    def test_original_sdk_helper_identity_refused_even_when_evidence_rehashed(self):
        self.sdk['harness_sha256'] = 'f' * 64; self.reseal()
        with self.assertRaisesRegex(ValueError, 'Conflicting original helper'): self.verify()

    def test_evidence_file_mutation_and_acceptance_promotion_refused(self):
        path = self.capsule / 'evidence/sdk-closure.json'; path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'evidence differs'): self.verify()
        self.reseal(); path = self.capsule / 'fresh-host-requirements.json'; packet = json.loads(path.read_text())
        packet['cells'][0]['state'] = 'passed'; self.put(path, packet)
        self.record['fresh_host_requirements_sha256'] = gate.sha(path); self.reseal()
        with self.assertRaisesRegex(ValueError, 'pending independent'): self.verify()

    def test_sdk_source_inventory_partial_helpers_and_unselected_carrier_files_refused(self):
        self.sdk['source_inventory_sha256'] = 'f' * 64; self.reseal()
        with self.assertRaisesRegex(ValueError, 'SDK closure'): self.verify()
        self.sdk['source_inventory_sha256'] = self.record['source_export_digest']
        saved = self.sdk['extra_helpers_sha256']; self.sdk['extra_helpers_sha256'] = {}; self.reseal()
        with self.assertRaisesRegex(ValueError, 'helper closure is incomplete'): self.verify()
        self.sdk['extra_helpers_sha256'] = saved; self.reseal()
        (self.capsule / 'carriers/private-extra').write_bytes(b'unselected')
        with self.assertRaisesRegex(ValueError, 'Unselected carrier checkpoint'): self.verify()

    def retention_args(self, output):
        f = self.fixture
        self.put(f.base / 'round-1/qxctl-identity/result.json', f.proof)
        self.put(self.root / 'sdk/result.json', self.sdk)
        return SimpleNamespace(build_root=f.base, delivery=f.delivery_path.parent, sdk_closure=self.root / 'sdk',
            export=f.export, repository=f.source, privacy_policy=self.root / 'policy',
            export_digest=f.manifest['derived_export_digest'], manifest_sha256=gate.sha(f.export / 'SOURCE-EXPORT.json'),
            profile=self.profile, output=output, python=Path('/selected/python'),
            standalone=Path('/selected/standalone'), standalone_archive=Path('/selected/standalone.conda'))

    def test_retention_is_independent_copy_atomic_and_existing_checkpoint_refused(self):
        out = self.root / 'package'; out.mkdir(); args = self.retention_args(out)
        shutil.copytree(self.capsule / 'carriers', out / 'carriers')
        self.put(out / 'input-cohort/cohort.json', self.candidate)
        real_root = gate.ROOT
        def load(name, relative):
            if relative == 'source-export/export_source.py':
                return SimpleNamespace(configure_policy=lambda p: None, scan=lambda n, raw: None)
            with patch.object(gate, 'ROOT', real_root): return self.load(name, relative)
        def toolkit(evidence, policy, helpers):
            self.assertEqual(helpers, self.helpers)
            for name in ('TOOLKIT-SOURCE.tar', 'TOOLKIT-SOURCE.json'):
                shutil.copyfile(self.capsule / 'evidence' / name, evidence / name)
            return self.documents['TOOLKIT-SOURCE.json']
        with patch.object(gate, 'ROOT', self.root / 'toolkit'), patch.object(gate, 'module', side_effect=load), \
             patch.object(gate, 'capsule_toolkit', side_effect=toolkit):
            result = gate.retain_capsule(args, out, self.fixture.aggregate, self.cohort)
            self.assertFalse((out / '.carrier-capsule-preparing').exists())
            self.assertEqual(gate.read(out / 'carrier-capsule/result.json'), result)
            original = out / 'carriers/cohort.json'; copied = out / 'carrier-capsule/carriers/cohort.json'
            self.assertNotEqual(original.stat().st_ino, copied.stat().st_ino)
            original.write_bytes(b'publisher later failed or changed')
            self.assertEqual(copied.read_bytes(), b'fixture codec')
            with self.assertRaisesRegex(ValueError, 'Existing carrier checkpoint'):
                gate.retain_capsule(args, out, self.fixture.aggregate, self.cohort)

    def test_constructor_failure_keeps_completed_capsule_and_no_wrapper_success_result(self):
        args = self.retention_args(self.root / 'package-fails'); events = []
        def retain(args, out, aggregate, archives):
            events.append('retain'); (out / 'carrier-capsule').mkdir()
            gate.write(out / 'carrier-capsule/result.json', {'state': 'primary_carriers_audited'})
        def assemble(*a, **k):
            events.append('constructor')
            self.assertTrue((args.output / 'carrier-capsule/result.json').is_file())
            raise ValueError('fixture constructor failure')
        adapters = {
            'installer_assembly/cohort.py': SimpleNamespace(prepare_cohort=lambda *a, **k:
                self.put(args.output / 'input-cohort/cohort.json', self.candidate)),
            'installer_assembly/carriers.py': SimpleNamespace(prepare=lambda *a, **k: self.cohort,
                build_cohort=lambda *a: self.cohort),
            'installer_assembly/construct.py': SimpleNamespace(assemble=assemble)}
        with patch.object(gate, 'check_source', return_value={'verified': True, 'export_digest': args.export_digest}), \
             patch.object(gate, 'module', side_effect=lambda n, p: adapters[p]), patch.object(gate, 'retain_capsule', side_effect=retain):
            with self.assertRaisesRegex(ValueError, 'constructor failure'): gate.package(args)
        self.assertEqual(events, ['retain', 'constructor']); self.assertFalse((args.output / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
