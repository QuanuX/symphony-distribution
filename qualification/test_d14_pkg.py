"""Native PKG boundary tests; no system installer or root mutation executes."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from qualification import d14_pkg as m


class NativePkgContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def layout(self):
        (self.root / 'Distribution').write_text('<installer-gui-script><domains enable_anywhere="false" '
            'enable_currentUserHome="true" enable_localSystem="false"/></installer-gui-script>')
        for name, scripts in [('prepare_installation', ('preinstall', 'postinstall')), ('run_installation', ('postinstall',))]:
            package = self.root / (name + '.pkg'); (package / 'Scripts').mkdir(parents=True)
            (package / 'PackageInfo').write_text('<pkg-info auth="root" relocatable="false" '
                'identifier="org.quanux.symphony.beta.pkg.' + name + '"/>')
            for script in scripts: (package / 'Scripts' / script).write_text('#!/bin/bash\nPREFIX="$2/symphonybeta"\n')
        return self.root

    def selected(self):
        archives = [{'filename': 'selected.conda', 'sha256': 'a' * 64}]
        cohort = {'profile': m.PROFILE, 'cohort_digest': 'sha256:' + 'b' * 64, 'archives': archives}
        row = {'format': 'pkg', 'filename': 'SymphonyBeta.pkg', 'sha256': 'c' * 64,
               'archive_count': 1, 'nested_archives_sha256': {'selected.conda': 'a' * 64}}
        audit = dict(cohort, wrappers=[row])
        return cohort, audit, row

    def test_exact_current_home_domain_and_two_package_scripts(self):
        result = m.package_layout(self.layout())
        self.assertEqual(result['target_domain'], 'CurrentUserHomeDirectory')
        self.assertEqual(result['prefix_basename'], 'symphonybeta')
        self.assertEqual(len(result['package_identifiers']), 2)

    def test_system_volume_domain_refuses(self):
        self.layout(); path = self.root / 'Distribution'
        path.write_text(path.read_text().replace('enable_localSystem="false"', 'enable_localSystem="true"'))
        with self.assertRaisesRegex(ValueError, 'current user home'): m.package_layout(self.root)

    def test_absolute_parent_or_conflicting_script_prefix_refuses(self):
        self.layout(); path = self.root / 'prepare_installation.pkg/Scripts/preinstall'
        for raw in ('PREFIX="/Library/Symphony"', 'PREFIX="$2/../escape"', 'PREFIX="$2/other"'):
            with self.subTest(raw=raw):
                path.write_text(raw + '\n')
                with self.assertRaises(ValueError): m.package_layout(self.root)

    def test_extra_component_or_script_refuses(self):
        self.layout(); extra = self.root / 'other.pkg'; extra.mkdir()
        with self.assertRaisesRegex(ValueError, 'component'): m.package_layout(self.root)
        extra.rmdir(); (self.root / 'run_installation.pkg/Scripts/extra').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'script'): m.package_layout(self.root)

    def test_explicit_install_location_and_xml_entity_refuse(self):
        self.layout(); path = self.root / 'prepare_installation.pkg/PackageInfo'; original = path.read_text()
        path.write_text(original.replace('auth=', 'install-location="/Applications" auth='))
        with self.assertRaisesRegex(ValueError, 'destination'): m.package_layout(self.root)
        path.write_text('<!DOCTYPE pkg-info [<!ENTITY e SYSTEM "file:///etc/passwd">]>' + original)
        with self.assertRaisesRegex(ValueError, 'XML'): m.package_layout(self.root)

    def test_selected_wrapper_matches_exact_cohort_and_hash(self):
        cohort, audit, row = self.selected()
        self.assertEqual(m.select_pkg(cohort, audit, row['sha256']), row)
        for key, value in [('profile', 'ubuntu24.04-amd64'), ('cohort_digest', 'sha256:' + 'd' * 64)]:
            altered = copy.deepcopy(audit); altered[key] = value
            with self.assertRaises(ValueError): m.select_pkg(cohort, altered, row['sha256'])
        with self.assertRaises(ValueError): m.select_pkg(cohort, audit, '0' * 64)

    def test_duplicate_or_hidden_archive_binding_refuses(self):
        cohort, audit, row = self.selected(); audit['wrappers'].append(dict(row))
        with self.assertRaises(ValueError): m.select_pkg(cohort, audit, row['sha256'])
        audit['wrappers'].pop(); row['nested_archives_sha256']['other.conda'] = 'e' * 64
        with self.assertRaises(ValueError): m.select_pkg(cohort, audit, row['sha256'])

    def test_optin_host_and_root_refuse_before_archive_reads(self):
        with patch.object(m.reuse, 'custody') as custody, patch.object(m.c, 'audit_cohort') as audit:
            with self.assertRaisesRegex(ValueError, 'opt-in'):
                m.qualify(SimpleNamespace(allow_ephemeral_install=False))
            custody.assert_not_called(); audit.assert_not_called()
        with patch.object(m.reuse, 'custody', side_effect=ValueError('host refused')), patch.object(m.c, 'audit_cohort') as audit:
            with self.assertRaisesRegex(ValueError, 'host refused'):
                m.qualify(SimpleNamespace(allow_ephemeral_install=True, output=self.root / 'out'))
            audit.assert_not_called()
        with patch.object(m.reuse, 'custody'), patch.object(m.os, 'getuid', return_value=0), patch.object(m.os, 'geteuid', return_value=0), patch.object(m.c, 'audit_cohort') as audit:
            with self.assertRaisesRegex(ValueError, 'unelevated'):
                m.qualify(SimpleNamespace(allow_ephemeral_install=True, output=self.root / 'out'))
            audit.assert_not_called()

    def test_current_account_rejects_root_and_mismatched_effective_uid(self):
        for uid, effective in ((0,0),(501,0),(501,502)):
            with self.subTest(uid=uid,effective=effective), patch.object(m.os,'getuid',return_value=uid), patch.object(m.os,'geteuid',return_value=effective), patch.object(m.pwd,'getpwuid') as account:
                with self.assertRaisesRegex(ValueError,'unelevated'):m.current_account()
                account.assert_not_called()

    def test_current_account_requires_owned_exact_runner_home(self):
        account=SimpleNamespace(pw_name='runner',pw_dir='/Users/runner')
        home=Mock();home.stat.return_value=SimpleNamespace(st_uid=501)
        with patch.object(m.os,'getuid',return_value=501), patch.object(m.os,'geteuid',return_value=501), patch.object(m.pwd,'getpwuid',return_value=account), patch.dict(os.environ,{'HOME':'/Users/runner'}), patch.object(m.c,'safe_root',return_value=home) as safe:
            self.assertEqual(m.current_account(),(home,'runner'));safe.assert_called_once_with(Path('/Users/runner'))
            with patch.dict(os.environ,{'HOME':'/other'}):
                with self.assertRaisesRegex(ValueError,'HOME'):m.current_account()
            home.stat.return_value=SimpleNamespace(st_uid=502)
            with self.assertRaisesRegex(ValueError,'owned'):m.current_account()
            account.pw_name='another-account'
            with self.assertRaisesRegex(ValueError,'runner account'):m.current_account()

    def test_current_home_prefix_is_new_and_confined(self):
        with patch.object(m,'current_account',return_value=(self.root,'runner')):
            self.assertEqual(m.current_home_prefix('symphonybeta'),(self.root,self.root/'symphonybeta'))
            with self.assertRaisesRegex(ValueError,'Unsafe'):m.current_home_prefix('../escape')
            (self.root/'symphonybeta').mkdir()
            with self.assertRaisesRegex(ValueError,'existing'):m.current_home_prefix('symphonybeta')
            (self.root/'alias').symlink_to(self.root/'missing')
            with self.assertRaisesRegex(ValueError,'existing'):m.current_home_prefix('alias')

    def test_timeout_diagnostics_keep_error_and_remove_credentials_and_paths(self):
        out=m.gate.fresh(self.root/'attempt',())
        m.progress(out,'native_pkg_install')
        (out/'native-install.log').write_text('PackageKit error 42: permission denied at /Users/runner/symphony\nAuthorization: Bearer example-private-token\ninstaller:%75.0\n')
        m.retain_failure(out,m.subprocess.TimeoutExpired(['unpublished command'],1200))
        data=json.loads((out/'diagnostics.json').read_bytes());raw=json.dumps(data)
        self.assertTrue(data['command_timeout_observed']);self.assertTrue(data['installer_command_attempted'])
        self.assertEqual(data['phase'],'native_pkg_install')
        self.assertIn('error 42',raw);self.assertNotIn('example-private-token',raw);self.assertNotIn('/Users/runner',raw)
        self.assertFalse(data['logs']['native-install.log']['raw_text_retained_publicly'])
        record=json.loads((out/'INCOMPLETE.json').read_bytes())
        self.assertEqual(record['diagnostics_sha256'],m.signing.digest(out/'diagnostics.json'))
        self.assertFalse((out/'result.json').exists())

    def test_diagnostics_refuse_linked_log_and_bound_tail(self):
        source=self.root/'log';source.write_text('line\n'*10000+'error 73: refused\n')
        report=m.sanitized_log_tail(source)
        self.assertLessEqual(len(report['tail']),40);self.assertIn('error 73',report['tail'][-1])
        alias=self.root/'alias';alias.symlink_to(source)
        self.assertEqual(m.sanitized_log_tail(alias)['state'],'unavailable_or_changed')

    def test_caller_snapshot_detects_changes_and_refuses_links(self):
        expected = m.caller_files(self.root)
        path = self.root / '.condarc'; path.write_text('selected state')
        self.assertNotEqual(m.caller_files(self.root), expected)
        path.unlink(); path.symlink_to('/dev/null')
        with self.assertRaisesRegex(ValueError, 'Aliased'): m.caller_files(self.root)

    def test_foreign_owned_input_refuses_strict_reader_but_private_copy_passes(self):
        from lifecycle import go_delivery as strict
        source=self.root/'runner-input';source.mkdir(mode=0o700)
        original=source/'selected.conda';original.write_bytes(b'exact selected archive');original.chmod(0o644)
        source_stat=original.stat(); source_key=(source_stat.st_dev,source_stat.st_ino)
        actual_fstat=os.fstat
        class ForeignOwner:
            def __init__(self,value):self.value=value
            def __getattr__(self,name):
                return os.geteuid()+10000 if name=='st_uid' else getattr(self.value,name)
        def owner_boundary(fd):
            value=actual_fstat(fd)
            return ForeignOwner(value) if (value.st_dev,value.st_ino)==source_key else value
        # Simulate only the kernel UID on the original runner-owned inode. The
        # production strict reader and actual copy/open/write operations run.
        with patch.object(os,'fstat',side_effect=owner_boundary):
            with self.assertRaisesRegex(ValueError,'ownership'):strict.regular(original)
            before=m.private_input_snapshot(source,self.root/'private-copy')
            self.assertEqual(strict.regular(self.root/'private-copy/selected.conda'),(b'exact selected archive',0o644))
            with self.assertRaisesRegex(ValueError,'ownership'):strict.regular(original)
        self.assertEqual(original.stat().st_uid,source_stat.st_uid)
        self.assertEqual(original.stat().st_ino,source_stat.st_ino)
        self.assertNotEqual(original.stat().st_ino,(self.root/'private-copy/selected.conda').stat().st_ino)
        m.reuse.records_equal(source,before)

    def test_private_snapshot_rejects_alias_overlap_and_detects_modified_copy(self):
        source=self.root/'source';source.mkdir();(source/'file').write_bytes(b'exact')
        with self.assertRaisesRegex(ValueError,'overlaps'):m.private_input_snapshot(source,source/'nested')
        target=self.root/'snapshot';before=m.private_input_snapshot(source,target)
        (target/'file').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'changed'):m.verify_private_snapshot(target,before)
        (source/'alias').symlink_to(source/'file')
        with self.assertRaisesRegex(ValueError,'Linked'):m.private_input_snapshot(source,self.root/'linked-snapshot')

    def test_early_admission_failure_retains_bounded_attempt_before_audit(self):
        source=self.root/'cohort';source.mkdir();(source/'cohort.json').write_text('{}')
        wrappers=self.root/'wrappers';wrappers.mkdir();(wrappers/'result.json').write_text('{}')
        tools=self.root/'tools';tools.mkdir();out=self.root/'attempt'
        args=SimpleNamespace(allow_ephemeral_install=True,output=out,cohort_root=source,wrapper_root=wrappers,
            inspection_tools=tools,cohort_sha256='0'*64,wrapper_result_sha256='0'*64,pkg_sha256='0'*64)
        with patch.object(m.reuse,'custody',return_value={}),patch.object(m,'current_account',return_value=(self.root,'runner')),             patch.object(m.c,'audit_cohort') as audit,patch.object(m,'exercise') as exercise:
            with self.assertRaisesRegex(ValueError,'evidence selection'):m.qualify(args)
            audit.assert_not_called();exercise.assert_not_called()
        record=json.loads((out/'INCOMPLETE.json').read_bytes())
        self.assertEqual(record['error_type'],'ValueError');self.assertFalse(record['publication_authorized'])
        self.assertFalse((out/'result.json').exists())

    def test_both_full_audits_and_execution_use_private_snapshots_only(self):
        cohort,audit,row=self.selected();cohort['entries']=[]
        row['sha256']=m.c.sha(b'exact pkg');audit['wrappers']=[row]
        source=self.root/'cohort';source.mkdir();(source/'cohort.json').write_bytes(m.signing.canonical(cohort))
        wrappers=self.root/'wrappers';wrappers.mkdir();(wrappers/'result.json').write_bytes(m.signing.canonical(audit))
        (wrappers/row['filename']).write_bytes(b'exact pkg');tools=self.root/'tools';tools.mkdir()
        out=m.gate.fresh(self.root/'attempt',(source,wrappers,tools))
        args=SimpleNamespace(cohort_root=source,wrapper_root=wrappers,inspection_tools=tools,
            cohort_sha256=m.signing.digest(source/'cohort.json'),wrapper_result_sha256=m.signing.digest(wrappers/'result.json'),
            pkg_sha256=row['sha256'])
        with patch.object(m.c,'audit_cohort',return_value=cohort) as full_audit,             patch.object(m.reuse,'inspection_tools',return_value={}),patch.object(m,'helper_identity',return_value={}),             patch.object(m,'exercise',return_value={'native_pkg_executed':False}) as exercise:
            result=m.qualify_selected(args,{},out)
        self.assertEqual([call.args[0] for call in full_audit.call_args_list],[out/'input-snapshots/cohort']*2)
        self.assertEqual(exercise.call_args.args[0],out/'input-snapshots/wrappers'/row['filename'])
        self.assertTrue(result['original_inputs_unchanged'])
        self.assertEqual(result['input_snapshots']['cohort']['file_count'],1)
        self.assertFalse(result['input_snapshots']['cohort']['original_ownership_changed'])

    def test_changed_original_after_private_execution_refuses_completion(self):
        source=self.root/'source';source.mkdir();(source/'file').write_bytes(b'original')
        before=m.private_input_snapshot(source,self.root/'snapshot')
        (source/'file').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'changed'):m.reuse.records_equal(source,before)
        m.verify_private_snapshot(self.root/'snapshot',before)

    def test_default_conda_cache_hardlinks_are_confined_to_new_prefix(self):
        prefix = self.root / 'prefix'; cache = prefix / 'pkgs/cache/source'
        cache.parent.mkdir(parents=True); cache.write_bytes(b'exact carrier'); cache.chmod(0o644)
        target = prefix / 'share/symphony/carriers/unit/payload.tar'; target.parent.mkdir(parents=True)
        os.link(cache, target)
        self.assertEqual(m.installed_carriers(prefix),
                         {'share/symphony/carriers/unit/payload.tar': (b'exact carrier', 0o644)})
        os.link(cache, self.root / 'outside-link')
        with self.assertRaisesRegex(ValueError, 'outside the private prefix'): m.installed_carriers(prefix)

    def test_installed_symlink_is_not_a_conda_hardlink(self):
        prefix = self.root / 'prefix'; target = prefix / 'share/symphony/carriers/unit/payload.tar'
        target.parent.mkdir(parents=True); target.symlink_to('/dev/null')
        with self.assertRaisesRegex(ValueError, 'alias or special'): m.installed_carriers(prefix)


if __name__ == '__main__': unittest.main()
