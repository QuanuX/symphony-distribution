"""Beta authorization, exact derived client closure and immutable packaging gates."""
import copy
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).parent))
import beta as b
from test_construct import cohort


class BetaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else b.signing.canonical(value)); path.chmod(0o644)
        return path

    def decision(self):
        value = json.loads((b.ROOT / 'evidence/d14-publisher-decision.json').read_bytes())
        return self.put(self.root / 'decision.json', value), value

    def review_decision(self):
        value = {'protocol': 'symphony.distribution.beta-candidate-authorization.v1',
            'release_class': 'beta-review-candidate', 'release_version': '0.2.0-beta.2',
            'candidate_assembly_authorized': True, 'publication_authorized': False,
            'release_acceptance_complete': False,
            'source_binding': {'core_commit': 'a' * 40, 'client_commit': b.client_gate.CLIENT['commit']},
            'profiles': ['macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64'],
            'trust': {'mode': 'unsigned-review', 'apple_developer_id': False,
                'notarization': False, 'os_trust_store_change_authorized': False},
            'preserved_constraints': {key: True for key in ('feature_freeze', 'main_unchanged',
                'no_automatic_runtime_or_provider_activation', 'no_private_publisher_state_in_distribution')}}
        return self.put(self.root / 'publisher-decision.json', value), value

    def test_review_candidate_requires_no_publication_or_legal_approval(self):
        path, _ = self.review_decision()
        auth = b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')
        scope = b.construct.beta_delivery_scope(auth)
        self.assertFalse(scope['publication_authorized'])
        self.assertEqual(scope['trust_status'], 'unsigned_review_candidate')
        config = b.construct.configuration(cohort(), self.root, ['pkg', 'sh'], beta=auth)
        plain = b.construct.configuration(cohort(), self.root, ['pkg', 'sh'])
        self.assertEqual(config['version'], '0.2.0-beta.2')
        self.assertEqual(config['name'], 'SymphonyReview')
        self.assertEqual(config['default_prefix'], '${HOME}/symphony-beta2-review')
        self.assertEqual(config['channels_remap'][0]['dest'], b.construct.REVIEW_CHANNEL)
        self.assertIn('not approved for public distribution', config['readme_text'])
        self.assertIn('unsigned and not notarized', config['readme_text'])
        self.assertIn({'symphony-retain.py': 'share/symphony/installer/symphony-retain.py'}, config['extra_files'])
        for key in ('initialize_conda', 'initialize_by_default', 'register_envs', 'menu_packages',
                    'write_condarc', 'keep_pkgs', 'script_env_variables', 'pkg_domains', 'specs'):
            self.assertEqual(config[key], plain[key])

    def test_review_candidate_cannot_invent_publication_acceptance_or_trust(self):
        path, value = self.review_decision()
        changes = [{'publication_authorized': True}, {'candidate_assembly_authorized': False},
            {'release_acceptance_complete': True}, {'release_class': 'public-beta'},
            {'release_version': '0.2.0-beta.1'}, {'release_version': '0.2.0-beta.3'},
            {'legal_approval': True}, {'publisher_acceptance': True}, {'legal_approval': 'true'},
            {'profiles': value['profiles'] + ['local-macos-amd64-fixture']},
            {'source_binding': value['source_binding'] | {'core_commit': 'main'}},
            {'trust': value['trust'] | {'mode': 'publisher-pinned-self-signed-detached-manifest'}},
            {'trust': value['trust'] | {'apple_developer_id': True}}]
        for change in changes:
            with self.subTest(change=change):
                self.put(path, value | change)
                with self.assertRaises(ValueError):
                    b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')

    def test_review_result_cannot_be_promoted_or_relabelled(self):
        path, _ = self.review_decision()
        result = {'protocol': b.PROTOCOL, 'profile': 'macos15-arm64',
            'publisher_decision_sha256': b.gate.sha(path), 'release_version': '0.2.0-beta.2',
            'state': 'beta_review_candidate_wrappers_and_shell_qualified',
            'carrier_count': 59, 'original_core_archives_unchanged': True,
            'native_payloads_and_receipts_changed': False, 'final_packaging_revision': 1,
            'native_or_client_recompiled': False, 'runtime_activated': False,
            'publication_authorized': False, 'release_acceptance_complete': False}
        b.admit_delivery_authority(self.root, result)
        for change in ({'publication_authorized': True}, {'state': 'beta_wrappers_and_shell_qualified'},
                       {'release_version': '0.2.0-beta.1'}, {'release_acceptance_complete': True},
                       {'native_or_client_recompiled': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                b.admit_delivery_authority(self.root, result | change)

    def test_beta1_publication_decision_cannot_authorize_beta2(self):
        path, value = self.decision()
        self.put(path, value | {'release_version': '0.2.0-beta.2'})
        with self.assertRaises(ValueError):
            b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')

    def test_explicit_authorization_changes_only_delivery_presentation(self):
        path, decision = self.decision()
        auth = b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')
        old = b.construct.configuration(cohort(), self.root, ['pkg', 'sh'])
        new = b.construct.configuration(cohort(), self.root, ['pkg', 'sh'], beta=auth)
        self.assertEqual(new['version'], '0.2.0-beta.1'); self.assertEqual(new['name'], 'Symphony')
        self.assertIn('not approved', old['readme_text']); self.assertNotIn('not approved', new['readme_text'])
        self.assertIn('unsigned and not notarized', new['readme_text'])
        for key in ('initialize_conda', 'initialize_by_default', 'register_envs', 'menu_packages', 'write_condarc',
                    'keep_pkgs', 'script_env_variables', 'pkg_domains', 'specs'):
            self.assertEqual(new[key], old[key])
        self.assertEqual(new['extra_files'][:len(old['extra_files'])],old['extra_files'])
        self.assertIn({'symphony-retain.py':'share/symphony/installer/symphony-retain.py'},new['extra_files'])
        self.assertIn('Python 3.11',new['readme_text'])

    def test_unapproved_or_changed_decision_refused(self):
        path, value = self.decision(); pin = b.gate.sha(path)
        self.put(path, value | {'legal_approval': False})
        with self.assertRaises(ValueError): b.construct.beta_authorization(path, pin, 'macos15-arm64')
        with self.assertRaises(ValueError): b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')

    def test_trust_or_source_scope_cannot_be_invented(self):
        path, value = self.decision()
        for key in ('apple_developer_id', 'notarization', 'os_trust_store_change_authorized'):
            changed = copy.deepcopy(value); changed['trust'][key] = True; self.put(path, changed)
            with self.assertRaises(ValueError): b.construct.beta_authorization(path, b.gate.sha(path), 'macos15-arm64')
        self.put(path, value)
        with self.assertRaises(ValueError): b.construct.beta_authorization(path, b.gate.sha(path), 'local-macos-amd64-fixture')

    def test_linked_authorization_refused(self):
        path, _ = self.decision(); link = self.root / 'linked'; link.symlink_to(path)
        with self.assertRaises(ValueError): b.construct.beta_authorization(link, b.gate.sha(path), 'macos15-arm64')

    def client(self):
        root = self.root / 'client'; root.mkdir()
        core = {'commit': 'c'*40, 'tree': 'd'*40}
        profile = 'ubuntu24.04-amd64'; proof = {'build_info': {'executable_sha256': 'sha256:' + 'a'*64,
            'source_commit': core['commit'], 'source_tree': core['tree']}, 'original_source': dict(core),
            'binary_sha256': 'a'*64, 'compiled_input_equivalence': {'inputs': [{'path': 'source'}]},
            'cohort_source': {'export_digest': 'e'*64}, 'isolated_builds': 2}
        proof_path = self.put(self.root / 'proof.json', proof)
        original_meta = {'core': {'repository': 'QuanuX/Symphony', 'commit': '1'*40, 'tree': '2'*40},
            'qxctl_build': {'executable_sha256': 'sha256:' + 'b'*64}, 'client_dependency': {},
            'observed_registry_digest': 'old', 'catalog_sha256': 'old', 'original_git_source_binding': {'method': 'retained'}}
        originals = {'README.md': (b'readme', 0o644), 'src/main.cpp': (b'unchanged bridge source', 0o644),
            '.claude-plugin/plugin.json': (b'{"version":"0.2.0-alpha.1"}', 0o644),
            'catalog/tools.json': (b.signing.canonical({'tools': [], 'source_registry_digest': 'old'}), 0o644),
            'catalog/beta-source.json': (b.signing.canonical(original_meta), 0o644),
            'catalog/stamped-owner-delta.json': (b.signing.canonical({'scope': 'old'}), 0o644)}
        files = dict(originals); files['bin/symphony-mcp'] = (b'qualified bridge', 0o755)
        files['catalog/tools.json'] = (b.signing.canonical({'tools': [], 'source_registry_digest': 'observed'}), 0o644)
        metadata = original_meta | {'core': original_meta['core'] | core,
            'qxctl_build': proof['build_info'], 'client_dependency': b.client_gate.CLIENT,
            'observed_registry_digest': 'observed', 'catalog_sha256': 'sha256:' + b.c.sha(files['catalog/tools.json'][0]),
            'original_git_source_binding': {'method': 'retained', 'proof_sha256': 'sha256:' + b.gate.sha(proof_path),
                'compiled_input_count': 1, 'derived_source_export_digest': 'e'*64, 'isolated_builds': 2}}
        files['catalog/beta-source.json'] = (b.signing.canonical(metadata), 0o644)
        files['catalog/stamped-owner-delta.json'] = (b.signing.canonical({'base_client_commit': b.client_gate.CLIENT['commit'],
            'old_qxctl_sha256': 'sha256:'+'b'*64, 'new_qxctl_sha256': 'a'*64,
            'scope': 'Primary platform artifact binding only; command records and tool descriptors unchanged'}), 0o644)
        self.zip(root / 'symphony-client.zip', files)
        inventory = {name: 'sha256:' + b.c.sha(raw) for name, (raw, mode) in files.items()}
        self.put(root / 'package-inventory.json', inventory)
        derivation = {'protocol': 'symphony.distribution.primary-client-derivation.v1', 'origin': b.client_gate.CLIENT,
            'profile': profile, 'is_original_git_tree': False, 'native_command_contracts_unchanged': True,
            'generated_paths': sorted(b.client_gate.DERIVED), 'publication_authorized': False,
            'qxctl_source_proof_sha256': b.gate.sha(proof_path),
            'files': {name: {'original_sha256': b.c.sha(raw), 'derived_sha256': b.c.sha(files[name][0]), 'mode': mode}
                for name, (raw, mode) in originals.items()}}
        self.put(root / 'derivation.json', derivation)
        lineage = {key: 'a'*64 for key in ('source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256',
            'build_result_sha256', 'round_sha256', 'payload_inventory_sha256', 'sdk_closure_sha256')}
        binding = {'qxctl_sha256': 'sha256:'+'a'*64, 'package_sha256': 'sha256:'+b.gate.sha(root/'symphony-client.zip'),
            'bridge_sha256': inventory['bin/symphony-mcp'], 'catalog_sha256': inventory['catalog/tools.json'],
            'observed_registry_digest': 'observed'}
        lock, asset = b.client_gate.codex_lock(profile)
        report = {'protocol': b.client_gate.PROTOCOL, 'state': 'primary_client_engineering_checks_passed', 'profile': profile,
            'sources': {'plugin': b.client_gate.CLIENT, 'core': core}, 'client_source_kind': 'explicit_derived_catalog_package',
            'package_is_original_git_tree': False, 'client_executed_from_verified_package': True, 'actual_codex_cases': 22,
            'connection_modes': ['stdio', 'same_user_ipc'], 'real_client_qualification': ['Codex'],
            'fixture_suites': sorted(b.client_gate.REQUIRED_SUITES), 'independent_finalized_bridge_builds_equal': True,
            'repeated_package_bytes_equal': True, 'native_inputs_unchanged': True, 'native_payload_rebuilt': False,
            'publication_authorized': False, 'release_acceptance_complete': False, 'original_native_lineage': lineage,
            'derivation_sha256': b.gate.sha(root/'derivation.json'), 'package_inventory_sha256': b.gate.sha(root/'package-inventory.json'),
            'bindings': binding, 'codex': {'version': lock['version'], 'source_commit': lock['source_commit'], 'asset': asset}}
        report['legacy_verifier'] = {'schema': 'symphony.beta-compatibility.report.v1', 'status': 'engineering_review_ready',
            'pending': [], 'sources': report['sources'], 'bindings': binding, 'distribution': 'pending',
            'publication_authorized': False, 'release_acceptance_complete': False}
        self.put(root/'result.json', report)
        return root, {'profile': profile, 'selected_evidence': {'source_binding': core}, 'entries': [{'unit_id': 'go:qxctl'}]}, {'lineage': lineage}, originals, proof_path

    def zip(self, path, files):
        with zipfile.ZipFile(path, 'w') as target:
            for name, (raw, mode) in sorted(files.items()):
                info=zipfile.ZipInfo(name); info.create_system=3; info.external_attr=(stat.S_IFREG|mode)<<16
                target.writestr(info, raw)

    def validate(self, args):
        root, base, original, sources, proof = args
        with patch.object(b.c, 'validate_recipe', return_value=({'provenance': {'source_override': {'sha256': 'a'*64}}}, {})):
            return b.validate_client(root, base, self.root, original, sources, proof_path=proof)

    def test_exact_qualified_derived_client_is_admitted(self):
        args = self.client(); result = self.validate(args)
        self.assertEqual(result[0]['actual_codex_cases'],22); self.assertEqual(len(result[3]),7)

    def test_unfinished_or_relabelled_client_refused(self):
        args=self.client(); root=args[0]; original=b.c.document(root/'result.json')
        for key,value in [('actual_codex_cases',21),('package_is_original_git_tree',True),('native_payload_rebuilt',True),
                          ('fixture_suites',[]),('publication_authorized',True)]:
            self.put(root/'result.json', original|{key:value})
            with self.assertRaises(ValueError): self.validate(args)

    def test_other_native_payload_lineage_refused(self):
        args=self.client(); args[2]['lineage']['payload_inventory_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'different core'): self.validate(args)

    def test_changed_legacy_assertion_or_pending_gate_refused(self):
        args=self.client(); report=b.c.document(args[0]/'result.json'); report['legacy_verifier']['pending']=['client']
        self.put(args[0]/'result.json',report)
        with self.assertRaisesRegex(ValueError,'legacy'): self.validate(args)

    def test_derived_source_cannot_change_runtime_code(self):
        args=self.client(); root=args[0]; derivation=b.c.document(root/'derivation.json')
        derivation['files']['src/main.cpp']['derived_sha256']='f'*64; self.put(root/'derivation.json',derivation)
        report=b.c.document(root/'result.json'); report['derivation_sha256']=b.gate.sha(root/'derivation.json'); self.put(root/'result.json',report)
        with self.assertRaisesRegex(ValueError,'Runtime source'): self.validate(args)

    def test_packaged_unknown_source_or_changed_mode_refused(self):
        args=self.client(); path=args[0]/'symphony-client.zip'; files=b.zip_files(path)
        files['unselected']=(b'x',0o644); self.zip(path,files)
        with self.assertRaisesRegex(ValueError,'member closure'): self.validate(args)
        files.pop('unselected'); files['src/main.cpp']=(files['src/main.cpp'][0],0o755); self.zip(path,files)
        with self.assertRaisesRegex(ValueError,'ZIP member'): self.validate(args)

    def test_catalog_binding_requires_actual_qxctl_source_proof(self):
        args=self.client(); proof=b.c.document(args[4]); proof['isolated_builds']=1; self.put(args[4],proof)
        with self.assertRaisesRegex(ValueError,'qxctl proof'): self.validate(args)

    def rebind_client_metadata(self, args, metadata):
        root = args[0]; files = b.zip_files(root/'symphony-client.zip')
        files['catalog/beta-source.json'] = (b.signing.canonical(metadata), 0o644)
        self.zip(root/'symphony-client.zip', files)
        self.put(root/'package-inventory.json', {name: 'sha256:' + b.c.sha(raw) for name, (raw, _) in files.items()})
        derivation = b.c.document(root/'derivation.json')
        derivation['files']['catalog/beta-source.json']['derived_sha256'] = b.c.sha(files['catalog/beta-source.json'][0])
        derivation['qxctl_source_proof_sha256'] = b.gate.sha(args[4])
        self.put(root/'derivation.json', derivation)
        report = b.c.document(root/'result.json')
        report.update(derivation_sha256=b.gate.sha(root/'derivation.json'), package_inventory_sha256=b.gate.sha(root/'package-inventory.json'))
        report['bindings']['package_sha256'] = 'sha256:' + b.gate.sha(root/'symphony-client.zip')
        report['legacy_verifier']['bindings'] = report['bindings']
        self.put(root/'result.json', report)

    def test_derived_core_binding_cannot_change_beyond_selected_commit_and_tree(self):
        args = self.client(); metadata = b.supplements.parse(b.zip_files(args[0]/'symphony-client.zip')['catalog/beta-source.json'][0])
        for change in ({'commit': '1'*40}, {'tree': '2'*40}, {'repository': 'another/repository'}, {'extra': 'unreviewed'}):
            with self.subTest(change=change):
                self.rebind_client_metadata(args, metadata | {'core': metadata['core'] | change})
                with self.assertRaisesRegex(ValueError, 'qxctl proof'): self.validate(args)

    def test_matching_client_metadata_cannot_rebind_proof_to_another_core(self):
        args = self.client(); proof = b.c.document(args[4])
        proof['build_info']['source_commit'] = 'f'*40
        proof['original_source']['commit'] = 'f'*40
        self.put(args[4], proof)
        metadata = b.supplements.parse(b.zip_files(args[0]/'symphony-client.zip')['catalog/beta-source.json'][0])
        metadata['qxctl_build'] = proof['build_info']; metadata['core']['commit'] = 'f'*40
        metadata['original_git_source_binding']['proof_sha256'] = 'sha256:' + b.gate.sha(args[4])
        self.rebind_client_metadata(args, metadata)
        with self.assertRaisesRegex(ValueError, 'qxctl proof'): self.validate(args)

    def test_zip_symlink_or_duplicate_member_refused(self):
        path=self.root/'bad.zip'
        with zipfile.ZipFile(path,'w') as archive:
            row=zipfile.ZipInfo('link'); row.external_attr=(stat.S_IFLNK|0o777)<<16; archive.writestr(row,b'target')
        with self.assertRaisesRegex(ValueError,'ZIP member'): b.zip_files(path)

    def test_source_tree_hash_and_canonical_stream_required(self):
        path=self.root/'source.tar'; b.source_builder.write_tar(path,[('source',b'bytes',0o644)])
        with self.assertRaisesRegex(ValueError,'Git tree'): b.source_files(path.read_bytes(),{'tree':'f'*40,'file_count':1})

    def test_beta_workflow_recollects_source_without_building_native_or_client(self):
        text=(b.ROOT/'.github/workflows/d14-beta-assembly.yml').read_text()
        self.assertIn('qualification/d06_delivery_record.py',text)
        self.assertIn('installer_assembly/beta.py',text)
        for forbidden in ('build-cohort/build.py','cmake --build','primary_client.py qualify','go build'):
            self.assertNotIn(forbidden,text)
        self.assertNotIn('PRIVATE_SOURCE_POLICY:',text[text.index('- name: Retain completed'):])

    def test_beta_workflow_selects_committed_authority_without_publishing(self):
        text = (b.ROOT / '.github/workflows/d14-beta-assembly.yml').read_text()
        self.assertIn('default: evidence/d14-publisher-decision.json', text)
        self.assertIn('evidence/beta2-candidate.json', text)
        self.assertIn("os.environ['GITHUB_SHA'] + ':' + authority", text)
        self.assertIn("(accepted['protocol'], accepted['release_version']) == expected[authority]", text)
        self.assertIn('--publisher-decision "$GITHUB_WORKSPACE/$AUTHORIZATION"', text)
        for forbidden in ('anaconda upload', 'wrangler r2', 'gh release create', 'beta_signing.py sign'):
            self.assertNotIn(forbidden, text)

    def test_portable_envelope_matches_retrieval_without_changing_archive(self):
        path=self.put(self.root/'envelope/channel/payload.tar',b'unchanged native archive'); path.chmod(0o600)
        root=self.root/'envelope'; (root/'channel').chmod(0o755)
        b.portable_modes(root)
        self.assertEqual(path.read_bytes(),b'unchanged native archive')
        self.assertEqual(path.stat().st_mode&0o777,0o644)
        self.assertEqual((root/'channel').stat().st_mode&0o777,0o700)

    def retention(self, *, wrong_binary=False, changed_version=False, enabled_write=False):
        prefix=self.root/'installed'; script=self.put(prefix/'share/symphony/installer/symphony-retain.py',b'fixture helper')
        index=self.put(prefix/'share/symphony/installer/BOOTSTRAP-INDEX.json',{'fixture':True})
        wrapper={'retention_helper_sha256':b.gate.sha(script),'retention_index_sha256':b.gate.sha(index)}
        report={'bindings':{'qxctl_sha256':'sha256:'+b.c.sha(b'qxctl'), 'bridge_sha256':'sha256:'+b.c.sha(b'bridge'),
                            'observed_registry_digest':'registry'}}
        proof=self.put(self.root/'proof.json',{'build_info':{'source_state':'stamped'}}); seen=[]
        def invoke(command,env,log,expected=0):
            seen.append(command)
            if log.name=='retain.log':
                retained=Path(command[command.index('--output')+1])
                self.put(retained/'candidate/go/qxctl/bin/qxctl',b'wrong' if wrong_binary else b'qxctl').chmod(0o755)
                self.put(retained/'client/bin/symphony-mcp',b'bridge').chmod(0o755)
                self.put(retained/'CUSTODY.json',{'protocol':'symphony.distribution.retained-candidates.v1',
                    'state':'retained_verified_candidates','native_installation_performed':False,'runtime_activation_changed':False})
                self.put(log,b'retained fixture')
            elif log.name=='qxctl-version.json': self.put(log,{'source_state':'wrong' if changed_version else 'stamped'})
            elif log.name=='qxctl-manifest.json': self.put(log,{'registry_digest':'registry'})
            elif log.name=='configure-connection.log':
                qxctl=Path(command[command.index('--qxctl')+1]); profile=Path(command[command.index('--output')+1])
                self.put(profile,{'schema':'symphony.agent.connection.v1','qxctl':str(qxctl),'qxctl_sha256':report['bindings']['qxctl_sha256'],
                    'working_directory':env['HOME'],'registry_digest':'registry','enabled_nonread_commands':['write'] if enabled_write else [],
                    'inherit_environment':['HOME','TMPDIR'],'environment':{},'timeout_ms':30000,'max_output_bytes':524288}).chmod(0o600)
                self.put(log,b'private profile fixture')
            elif log.name=='configure-codex.log':
                binary=str(command[command.index('--binary')+1]); config=str(command[command.index('--config')+1])
                catalog=str(command[command.index('--tool-catalog')+1]); fragment=Path(command[command.index('--output')+1])
                text='[mcp_servers.symphony]\ncommand = '+json.dumps(binary)+'\nargs = '+json.dumps(['--config',config,'--tool-catalog',catalog])+'\nstartup_timeout_sec = 70\ntool_timeout_sec = 70\ndefault_tools_approval_mode = "writes"\n'
                self.put(fragment,text.encode()).chmod(0o600); self.put(log,b'private fragment fixture')
            else: self.put(log,b'help fixture')
            return {'name':log.name,'sha256':b.gate.sha(log),'exit_code':0}
        with patch.object(b.reuse.consumer,'invoke',side_effect=invoke):
            result=b.qualify_retention(prefix,{'HOME':str(self.root)},self.root/'probe',wrapper,Path(sys.executable),report,proof)
        return result,seen

    def test_installed_retention_binds_exact_candidates_before_read_only_probes(self):
        (record,retained,before),seen=self.retention()
        self.assertEqual(len(seen),6); self.assertIn('--owners',seen[0]); self.assertIn('-I',seen[0])
        self.assertEqual(record['state'],'installed_retention_and_read_only_entrypoints_passed')
        self.assertTrue(record['private_default_deny_profile_and_codex_fragment_passed'])
        self.assertEqual(b.artifact_inventory(retained),before)

    def test_retention_wrong_binary_or_version_refuses(self):
        with self.assertRaisesRegex(ValueError,'entrypoints differ'): self.retention(wrong_binary=True)
        # A distinct attempt preserves the failed custody and all logs.
        old=self.root; self.root=self.root/'second'; self.root.mkdir()
        try:
            with self.assertRaisesRegex(ValueError,'read-only entrypoint'): self.retention(changed_version=True)
        finally: self.root=old

    def test_first_run_profile_cannot_enable_a_write(self):
        with self.assertRaisesRegex(ValueError,'default-deny'): self.retention(enabled_write=True)


if __name__ == '__main__': unittest.main()
