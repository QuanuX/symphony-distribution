"""Native PKG boundary tests; no system installer or root mutation executes."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        with patch.object(m.reuse, 'custody'), patch.object(m.os, 'geteuid', return_value=501), patch.object(m.c, 'audit_cohort') as audit:
            with self.assertRaisesRegex(ValueError, 'root account'):
                m.qualify(SimpleNamespace(allow_ephemeral_install=True, output=self.root / 'out'))
            audit.assert_not_called()

    def test_root_prefix_never_accepts_a_nonroot_identity(self):
        with patch.object(m.os, 'geteuid', return_value=501), patch.object(m.pwd, 'getpwuid') as account:
            with self.assertRaisesRegex(ValueError, 'root account'): m.root_prefix('symphonybeta')
            account.assert_not_called()

    def test_caller_snapshot_detects_changes_and_refuses_links(self):
        expected = m.caller_files(self.root)
        path = self.root / '.condarc'; path.write_text('selected state')
        self.assertNotEqual(m.caller_files(self.root), expected)
        path.unlink(); path.symlink_to('/dev/null')
        with self.assertRaisesRegex(ValueError, 'Aliased'): m.caller_files(self.root)

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
