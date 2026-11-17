"""Platform labels never substitute for observed host or manager evidence."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('s07_platform', Path(__file__).with_name('host_platform.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def host(system='linux', arch='amd64', distro='ubuntu', version='24.04', wsl=False):
    return {'system': system, 'architecture': arch, 'distribution': distro, 'version': version, 'wsl': wsl}


class Platforms(unittest.TestCase):
    def test_all_core_profiles_and_supplement_are_exact(self):
        for profile, value in p.PROFILES.items():
            with self.subTest(profile=profile):
                observed = host(*value[:3], version=value[3] or '14.7')
                self.assertTrue(p.profile_matches(profile, observed))
                self.assertFalse(p.profile_matches(profile, {**observed, 'architecture': 'unknown'}))
                self.assertFalse(p.profile_matches(profile, {**observed, 'wsl': True}))
        self.assertFalse(p.profile_matches('ubuntu24.04-amd64', host(version='26.04')))
        self.assertFalse(p.profile_matches('ubuntu24.04-amd64', host(distro='debian')))
        self.assertTrue(p.profile_matches('macos15-arm64', host('darwin', 'arm64', 'macos', '15.7.1')))
        self.assertFalse(p.profile_matches('macos15-arm64', host('darwin', 'arm64', 'macos', '26.0')))

    def test_os_release_reads_only_data_and_missing_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'os-release'
            self.assertEqual(p.os_release(path), {})
            path.write_text('ID="ubuntu"\nVERSION_ID="24.04"\nPRIVATE_NAME=private\nCOMMAND=$(false)\n')
            self.assertEqual(p.os_release(path), {'ID': 'ubuntu', 'VERSION_ID': '24.04'})

    def test_observed_host_uses_actual_distribution_version_without_hostname(self):
        observed = os.uname_result(('Linux', 'private-hostname', '6.0-microsoft-standard', 'private-build', 'aarch64'))
        with patch.object(p.os, 'uname', return_value=observed), \
             patch.object(p, 'os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}):
            value = p.observe_host()
        self.assertEqual(value, host(arch='arm64', wsl=True))
        self.assertNotIn('private', str(value))

    def test_failed_macos_version_probe_never_infers_requested_profile(self):
        observed = os.uname_result(('Darwin', 'private-hostname', '25.0.0', 'private-build', 'arm64'))
        with patch.object(p.os, 'uname', return_value=observed), \
             patch.object(p.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sw_vers', 5)):
            value = p.observe_host()
        self.assertEqual(value['version'], 'unknown')
        self.assertFalse(p.profile_matches('macos15-arm64', value))

    def test_missing_manager_is_incomplete_without_subprocess(self):
        with patch.object(p.shutil, 'which', return_value=None), patch.object(p.subprocess, 'run') as run:
            value = p.manager_inventory(host())
        run.assert_not_called()
        self.assertEqual(value['availability'], 'incomplete')
        self.assertEqual({r['state'] for r in value['scopes']}, {'missing'})
        self.assertEqual(value['acceptance'], 'not_run')

    def test_inaccessible_user_manager_does_not_pass_with_system_manager(self):
        with patch.object(p.shutil, 'which', return_value='/usr/bin/systemctl'), \
             patch.object(p.subprocess, 'run', side_effect=[subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]) as run:
            value = p.manager_inventory(host())
        self.assertEqual(value['availability'], 'incomplete')
        self.assertEqual([r['state'] for r in value['scopes']], ['inaccessible', 'accessible'])
        self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/systemctl', '--user', 'show', '--property=Version', '--value'])
        self.assertEqual(run.call_args_list[0].kwargs['stdout'], subprocess.DEVNULL)

    def test_manager_timeout_and_os_error_are_incomplete(self):
        for error, state in [(subprocess.TimeoutExpired('systemctl', 5), 'timeout'), (PermissionError(), 'inaccessible')]:
            with self.subTest(state=state), patch.object(p.subprocess, 'run', side_effect=error):
                self.assertEqual(p.probe(['/usr/bin/systemctl'])['state'], state)

    def test_launchd_queries_only_existing_domains_without_retaining_identity(self):
        with patch.object(p.shutil, 'which', return_value='/bin/launchctl'), patch.object(p.os, 'getuid', return_value=123456), \
             patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as run:
            value = p.manager_inventory(host('darwin', 'arm64', 'macos', '15.7'))
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/bin/launchctl', 'print', 'user/123456'], ['/bin/launchctl', 'print', 'gui/123456'], ['/bin/launchctl', 'print', 'system']])
        self.assertNotIn('123456', str(value))
        self.assertFalse(value['activation_performed'])
        self.assertEqual(value['acceptance'], 'not_run')

    def test_inventory_does_not_promote_availability_to_acceptance(self):
        with patch.object(p, 'observe_host', return_value=host()), \
             patch.object(p.shutil, 'which', return_value='/usr/bin/systemctl'), \
             patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            value = p.profile_inventory('ubuntu24.04-amd64')
        self.assertTrue(value['profile_matches'])
        self.assertEqual(value['service_manager']['availability'], 'observed')
        self.assertEqual(value['fresh_host_acceptance'], 'incomplete')
        self.assertFalse(value['physical_hardware_qualified'])
        self.assertFalse(value['host_activation_performed'])

    def test_unknown_host_manager_is_incomplete(self):
        self.assertEqual(p.manager_inventory(host(system='unknown'))['availability'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
