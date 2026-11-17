import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


c = module('constructor_assembly', HERE / 'construct.py')
r = module('constructor_adapter', HERE / 'constructor_runner.py')


def cohort(payload=b'inert-conda-bytes'):
    name = 'symphony-example-payload'
    row = {'unit_id': 'example', 'filename': name + '-0.1.0-review1.conda',
           'name': name, 'version': '0.1.0', 'build': 'review1', 'build_number': 0,
           'sha256': c.sha(payload), 'md5': hashlib.md5(payload).hexdigest(),
           'size': len(payload), 'subdir': 'osx-64', 'depends': []}
    return {'state': 'archives_audited', 'profile': 'local-macos-amd64-fixture',
            'conda_subdir': 'osx-64', 'cohort_digest': 'sha256:' + 'a' * 64, 'archives': [row]}


def tar_bytes(members, *, neutral=True):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, data in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            if not neutral:
                member.uid = 501
                member.uname = 'publisher'
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def shell_bytes(payload, *, extra=None, neutral=True, bootstrap=b'bootstrap'):
    row = cohort(payload)['archives'][0]
    members = [('pkgs/' + row['filename'], payload)]
    if extra:
        members += extra
    raw = tar_bytes(members, neutral=neutral)
    header = (f'#!/bin/sh\nboundary1=$(( boundary0 + {len(bootstrap)} ))\n'
              'boundary2=$(( boundary1 + 0 ))\n'
              f'boundary3=$(( boundary2 + {len(raw)} ))\n'
              'CONDA_REGISTER_ENVS="false"\n'
              "export CONDA_REPORT_ERRORS='false'\nexport CONDA_NO_PLUGINS='true'\n"
              'export CONDARC=/dev/null\nexport CONDA_RESTRICT_RC_SEARCH_PATH=1\n'
              + (r.CONSTRUCTOR_COMMAND + ' --extract-tarball\n') * 4 +
              'if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then\nexit 1\nfi\n@@END_HEADER@@\n').encode()
    return header + bootstrap + raw


class BootstrapContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / 'standalone.conda'
        self.executable = self.root / 'conda.exe'
        self.executable.write_bytes(b'exact-bootstrap')
        self.pin = {'version': '26.9.4.post1', 'build': 'fixture_0',
                    'url': 'https://conda.anaconda.org/conda-forge/osx-64/'
                           'conda-standalone-26.9.4.post1-fixture_0.conda'}
        self.stem = 'conda-standalone-26.9.4.post1-fixture_0'
        self.members = {
            'metadata.json': b'{"conda_pkg_format_version":2}',
            f'pkg-{self.stem}.tar.zst': tar_bytes([('standalone_conda/conda.exe', b'exact-bootstrap')]),
            f'info-{self.stem}.tar.zst': tar_bytes([('info/licenses/LICENSE.txt', b'upstream-notice')])}
        self.calls = []
        self.write_archive()

    def write_archive(self, entries=None):
        with zipfile.ZipFile(self.archive, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, raw in (self.members.items() if entries is None else entries):
                archive.writestr(name, raw)
        self.pin['sha256'] = c.file_sha(self.archive)

    def fake_stream(self, filename, *, component, zf):
        self.calls.append((filename, component))
        # Reproduce the library's filename-based component lookup. These fixture
        # members are uncompressed TARs; the separate codec test uses real zstd.
        name = f'{component}-{Path(filename).stem}.tar.zst'
        with tarfile.open(fileobj=io.BytesIO(zf.read(name))) as stream:
            for member in stream:
                yield stream, member

    def proof(self, stream=None):
        reader = SimpleNamespace(stream_conda_component=stream or self.fake_stream)
        with patch.dict(sys.modules, {'conda_package_streaming': SimpleNamespace(),
                                      'conda_package_streaming.package_streaming': reader}):
            return c.bootstrap_proof(self.archive, self.executable, self.pin)

    def test_generic_download_name_uses_selected_component_identity(self):
        before = self.archive.read_bytes()
        binary, notices = self.proof()
        self.assertEqual(binary, c.sha(b'exact-bootstrap'))
        self.assertEqual(notices, {'LICENSE.txt': b'upstream-notice'})
        self.assertEqual(self.calls, [(self.stem + '.conda', 'pkg'), (self.stem + '.conda', 'info')])
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertFalse((self.root / (self.stem + '.conda')).exists())

    def test_archive_hash_and_executable_mismatch_refuse(self):
        self.pin['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'exact tool pin'):
            self.proof()
        self.assertEqual(self.calls, [])
        self.pin['sha256'] = c.file_sha(self.archive)
        self.executable.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'executable differs'):
            self.proof()

    def test_mismatched_ambiguous_or_unsafe_components_refuse_before_streaming(self):
        pkg = f'pkg-{self.stem}.tar.zst'
        for extra in ('pkg-other.tar.zst', pkg + '.extra', '../escape', 'metadata.json'):
            with self.subTest(extra=extra):
                entries = [(name, raw) for name, raw in self.members.items() if name != pkg]
                entries.append((extra, self.members[pkg]))
                if extra == 'metadata.json':
                    # ZipFile correctly warns when constructing this hostile fixture.
                    import warnings
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        self.write_archive(entries)
                else:
                    self.write_archive(entries)
                with self.assertRaisesRegex(ValueError, 'components differ'):
                    self.proof()
        self.assertEqual(self.calls, [])

    def test_unknown_or_duplicate_metadata_refuses(self):
        for raw in (b'{"conda_pkg_format_version":1}', b'{"conda_pkg_format_version":2.0}',
                    b'{"conda_pkg_format_version":2,"conda_pkg_format_version":2}',
                    b'{"conda_pkg_format_version":2,"extra":true}'):
            with self.subTest(raw=raw):
                self.members['metadata.json'] = raw
                self.write_archive()
                with self.assertRaisesRegex(ValueError, 'package metadata'):
                    self.proof()
        self.assertEqual(self.calls, [])

    def test_selected_pin_url_and_identity_must_agree(self):
        self.pin['build'] = 'different_0'
        with self.assertRaisesRegex(ValueError, 'URL differs'):
            self.proof()
        self.pin['build'] = '../escape'
        with self.assertRaisesRegex(ValueError, 'invalid standalone'):
            self.proof()
        self.assertEqual(self.calls, [])

    def test_symlink_component_refuses(self):
        name = f'pkg-{self.stem}.tar.zst'
        linked = zipfile.ZipInfo(name)
        linked.external_attr = 0o120777 << 16
        self.write_archive([(linked if key == name else key, raw) for key, raw in self.members.items()])
        with self.assertRaisesRegex(ValueError, 'unsupported standalone ZIP'):
            self.proof()
        self.assertEqual(self.calls, [])

    def test_mutation_during_inspection_refuses(self):
        def changing_stream(filename, *, component, zf):
            yield from self.fake_stream(filename, component=component, zf=zf)
            if component == 'info':
                with self.archive.open('ab') as output:
                    output.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'changed during inspection'):
            self.proof(changing_stream)

    def test_real_streaming_library_reads_renamed_archive(self):
        try:
            from conda_package_streaming import package_streaming as streaming
        except ImportError:
            self.skipTest('real Conda codec is exercised with the pinned publisher interpreter')
        if streaming.zstd is None:
            self.skipTest('real Conda codec is unavailable in this interpreter')
        for name in list(self.members):
            if name.endswith('.tar.zst'):
                self.members[name] = streaming.zstd.compress(self.members[name])
        self.write_archive()
        with zipfile.ZipFile(self.archive) as archive:
            with self.assertRaisesRegex(LookupError, 'pkg-standalone'):
                list(streaming.stream_conda_component(self.archive, component='pkg', zf=archive))
        binary, notices = c.bootstrap_proof(self.archive, self.executable, self.pin)
        self.assertEqual(binary, c.sha(b'exact-bootstrap'))
        self.assertEqual(notices, {'LICENSE.txt': b'upstream-notice'})
        self.assertEqual(c.file_sha(self.archive), self.pin['sha256'])


class ConstructorContracts(unittest.TestCase):
    def test_closed_inert_configuration(self):
        config = c.configuration(cohort(), '/tmp/review-channel', ['pkg', 'sh'])
        for key in ('initialize_conda', 'initialize_by_default', 'register_envs', 'write_condarc', 'ignore_duplicate_files'):
            self.assertIs(config[key], False)
        self.assertEqual(config['menu_packages'], [])
        self.assertEqual(config['pkg_domains'], {'enable_anywhere': False, 'enable_currentUserHome': True, 'enable_localSystem': False})
        for forbidden in ('pre_install', 'post_install', 'pre_uninstall', 'signing_identity_name', 'notarization_identity_name', 'environment', 'environment_file', 'extra_envs'):
            self.assertNotIn(forbidden, config)
        self.assertEqual(config['channels_remap'][0]['dest'], c.REVIEW_CHANNEL)
        self.assertNotIn('conda', config['specs'])
        self.assertNotIn('python', config['specs'])

    def test_recipe_only_cohort_refuses(self):
        value = cohort(); value['state'] = 'prepared'
        with self.assertRaisesRegex(ValueError, 'completed archive audit'):
            c.configuration(value, '/tmp/channel', ['sh'])

    def test_solver_dependency_or_duplicate_refuses(self):
        value = cohort(); value['archives'][0]['depends'] = ['python']
        with self.assertRaisesRegex(ValueError, 'inert dependency'):
            c.archive_records(value)
        value = cohort(); value['archives'] *= 2
        with self.assertRaisesRegex(ValueError, 'repeated'):
            c.archive_records(value)

    def test_native_route_does_not_claim_cross_platform(self):
        c.native_route('ubuntu24.04-arm64', 'linux-aarch64', ['sh'], system='Linux', machine='aarch64')
        with self.assertRaisesRegex(ValueError, 'matching native host'):
            c.native_route('ubuntu24.04-arm64', 'linux-aarch64', ['sh'], system='Darwin', machine='arm64')
        with self.assertRaisesRegex(ValueError, 'PKG requires'):
            c.native_route('ubuntu24.04-amd64', 'linux-64', ['pkg'], system='Linux', machine='x86_64')
        with self.assertRaisesRegex(ValueError, 'supplemental'):
            c.native_route('local-macos-amd64-fixture', 'osx-64', ['pkg'], system='Darwin', machine='x86_64')

    def test_metadata_adapter_keeps_payload_identity(self):
        info = tarfile.TarInfo('payload/example.conda'); info.size = 91; info.mode = 0o755
        info.uid = 501; info.gid = 20; info.uname = 'publisher'; info.gname = 'staff'; info.mtime = 11223344
        info.pax_headers = {'mtime': '11223344.12', 'path': info.name}
        result = r.normalized_tarinfo(info)
        self.assertEqual((result.size, result.mode, result.name), (91, 0o755, 'payload/example.conda'))
        self.assertEqual((result.uid, result.gid, result.uname, result.gname, result.mtime), (0, 0, '', '', 0))
        self.assertEqual(result.pax_headers, {'path': result.name})

    def test_pkg_adapter_is_narrow_and_rejects_vendor_drift(self):
        self.assertEqual(r.pkgbuild_command(['pkgbuild', '--ownership', 'preserve', 'review.pkg']),
                         ['/usr/bin/pkgbuild', '--ownership', 'recommended', 'review.pkg'])
        self.assertEqual(r.pkgbuild_command(['/usr/bin/productbuild', 'review.pkg']), ['/usr/bin/productbuild', 'review.pkg'])
        with self.assertRaisesRegex(ValueError, 'ownership policy drift'):
            r.pkgbuild_command(['pkgbuild', '--ownership', 'recommended'])

    def test_public_metadata_has_no_host_inventory(self):
        record = r.public_build_info('osx-64', {'constructor': '3.17.3', 'conda': '26.10.0', 'python': '3.12.16'})
        self.assertIs(record['host_inventory_included'], False)
        self.assertEqual(record['target_subdir'], 'osx-64')
        self.assertNotIn('platform_full', record)
        self.assertNotIn('machine', record)

    def test_builtin_scripts_disable_reporting_and_external_plugins(self):
        script = '#!/bin/bash\nset -eu\necho "inert"\n'
        changed = r.inactive_script(script)
        self.assertEqual(changed, '#!/bin/bash\nexport CONDA_REPORT_ERRORS=false\nexport CONDA_NO_PLUGINS=true\n'
                         'export CONDA_RESTRICT_RC_SEARCH_PATH=1\nexport CONDARC=/dev/null\nset -eu\necho "inert"\n')
        with self.assertRaisesRegex(ValueError, 'shebang drift'):
            r.inactive_script('#!/bin/zsh\necho unsafe\n')

    def test_native_adapter_preserves_only_selected_prefix_ownership(self):
        selected = 'chown -R "${USER}" "$PREFIX"\n'
        script = '#!/bin/bash\nunset CONDARC\n' + selected + r.AMBIENT_CONDA_OWNERSHIP + '\nexit 0\n'
        result = r.scope_native_script('run_installation.sh', script)
        self.assertIn(selected, result)
        self.assertNotIn('${HOME}/.conda', result)
        self.assertNotIn('CONDA_DIR=', result)
        with self.assertRaisesRegex(ValueError, 'ownership block drift'):
            r.scope_native_script('run_installation.sh', script.replace('WARNING:', 'NOTICE:'))

    def test_native_prefix_guard_rejects_dangling_link(self):
        result = r.scope_native_script('checks_before_install.sh', '#!/bin/bash\nif [[ -e "$PREFIX" ]]; then\nexit 1\nfi\n')
        self.assertIn('if [[ -e "$PREFIX" || -L "$PREFIX" ]]; then', result)

    def test_shell_update_and_force_do_not_bypass_fresh_prefix(self):
        header = ('-f           no error if install prefix already exists\n-u           update an existing installation\n'
                  '        f)\n            FORCE=1\n            ;;\n'
                  '        u)\n            FORCE=1\n            ;;\n'
                  'if [ "$FORCE" = "0" ] && [ -e "$PREFIX" ]; then\n    exit 1\n'
                  'elif [ "$FORCE" = "1" ] && [ -e "$PREFIX" ]; then\n    REINSTALL=1\nfi\n')
        result = r.fresh_shell_header(header)
        self.assertNotIn('FORCE=1', result)
        self.assertNotIn('REINSTALL=1', result)
        self.assertIn('if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then', result)
        self.assertEqual(result.count('Existing-prefix replacement is unavailable'), 2)

    def test_constructor_override_is_command_local_and_keeps_install_denied(self):
        script = '#!/bin/bash\nunset CONDARC\n"$CONDA_EXEC" constructor --extract-conda-pkgs\n"$CONDA_EXEC" install --offline\n'
        result = r.scope_native_script('prepare_installation.sh', script)
        self.assertEqual(r.CONSTRUCTOR_COMMAND.encode(), c.CONSTRUCTOR_COMMAND)
        self.assertIn('export CONDA_NO_PLUGINS=true\n', result)
        self.assertIn(r.CONSTRUCTOR_COMMAND + ' --extract-conda-pkgs', result)
        self.assertIn('\n"$CONDA_EXEC" install --offline\n', result)
        c.audit_constructor_policy(result.encode(), 1)
        with self.assertRaisesRegex(ValueError, 'scope drift'):
            r.scope_constructor_commands(script, 2)
        with self.assertRaisesRegex(ValueError, 'scope drift'):
            r.scope_constructor_commands('CONDA_NO_PLUGINS=false ' + script, 1)

    def test_actual_shell_override_does_not_leak_to_following_install_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stub = root / 'bootstrap'
            stub.write_text('#!/bin/sh\nprintf "%s|%s|%s|%s|%s\\n" "$CONDA_NO_PLUGINS" "$CONDARC" '
                            '"$CONDA_RESTRICT_RC_SEARCH_PATH" "${PYTHONPATH:-}" "$1"\n')
            stub.chmod(0o700)
            original = '#!/bin/bash\nunset CONDARC\nif ! "$CONDA_EXEC" constructor --extract-conda-pkgs; then exit 3; fi\n"$CONDA_EXEC" install --offline\n'
            script = root / 'prepare.sh'; script.write_text(r.scope_native_script('prepare_installation.sh', original))
            env = {'PATH': '/usr/bin:/bin', 'CONDA_EXEC': str(stub), 'PYTHONPATH': 'caller-module-path',
                   'CONDARC': '/unselected/caller-config', 'CONDA_NO_PLUGINS': 'false'}
            result = subprocess.run(['/bin/bash', str(script)], env=env, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.splitlines(), ['false|/dev/null|1||constructor',
                                                          'true|/dev/null|1|caller-module-path|install'])

    def test_native_vendor_rc_reset_cannot_erase_empty_configuration(self):
        common = '#!/bin/bash\n# Installers should ignore pre-existing configuration files.\nunset CONDARC\nunset MAMBARC\n'
        bodies = {
            'prepare_installation.sh': 'if ! "$CONDA_EXEC" constructor --prefix "$PREFIX" --extract-conda-pkgs; then exit 1; fi\n',
            'run_installation.sh': '"$CONDA_EXEC" install --offline\nchown -R "${USER}" "$PREFIX"\n' + r.AMBIENT_CONDA_OWNERSHIP,
        }
        for name, body in bodies.items():
            with self.subTest(name=name):
                result = r.scope_native_script(name, common + body)
                self.assertNotIn('unset CONDARC', result)
                self.assertIn('# Installers should ignore pre-existing configuration files.\nexport CONDARC=/dev/null\n', result)
                c.audit_constructor_policy(result.encode(), 1 if name == 'prepare_installation.sh' else 0)
                for invalid in ((common + body).replace('unset CONDARC\n', ''), common + body + 'unset CONDARC\n'):
                    with self.assertRaisesRegex(ValueError, 'native RC reset drift'):
                        r.scope_native_script(name, invalid)

    def test_override_or_caller_configuration_broadening_refuses(self):
        correct = (r.CONSTRUCTOR_COMMAND + '\nexport CONDARC=/dev/null\nexport CONDA_RESTRICT_RC_SEARCH_PATH=1\n').encode()
        for bad in (correct + b'export CONDA_NO_PLUGINS=false\n',
                    correct.replace(b'PYTHONPATH= ', b''),
                    correct.replace(b'CONDARC=/dev/null', b'CONDARC="$HOME/.condarc"'),
                    correct + b'unset CONDARC\n'):
            with self.assertRaises(ValueError): c.audit_constructor_policy(bad, 1)

    def test_frozen_constructor_probe_requires_actual_help_and_closed_metadata(self):
        proof = {'protocol': 'symphony.distribution.frozen-constructor-probe.v1', 'conda_version': '26.9.4',
                 'frozen_paths_only': True, 'frozen_distributions_only': True,
                 'sys_path_entries': 4, 'embedded_distributions': 14}
        for case in ('passed', 'missing-help', 'bad-metadata', 'wrong-exit', 'caller-plugin-imported'):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); executable = root / 'bootstrap'; executable.write_bytes(b'fixture')
                selected = dict(proof)
                if case == 'bad-metadata': selected['frozen_distributions_only'] = False
                output = json.dumps(selected) + ('\nusage: conda constructor [-h] ...\n' if case != 'missing-help' else '\n')
                def invoke(*args, **kwargs):
                    self.assertEqual(kwargs['env']['CONDA_NO_PLUGINS'], 'false')
                    self.assertEqual(kwargs['env']['CONDARC'], '/dev/null')
                    self.assertEqual(kwargs['env']['CONDA_RESTRICT_RC_SEARCH_PATH'], '1')
                    self.assertIn('python', args[0]); self.assertIn('rogue_plugin.py', [p.name for p in Path(kwargs['cwd']).iterdir()])
                    if case == 'caller-plugin-imported':
                        (root / 'constructor-isolation-probe/HOST_PLUGIN_IMPORTED').write_text('bad')
                    return SimpleNamespace(returncode=1 if case == 'wrong-exit' else 0, stdout=output, stderr='')
                with patch.object(r.subprocess, 'run', side_effect=invoke):
                    if case == 'passed':
                        result = r.probe_frozen_constructor(executable, root)
                        self.assertTrue(result['caller_plugin_fixture_ignored'])
                    else:
                        with self.assertRaises(ValueError): r.probe_frozen_constructor(executable, root)

    def test_output_refuses_linked_parent_and_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); real = root / 'real'; real.mkdir()
            (root / 'alias').symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'linked installer'):
                c.admit_output(root / 'alias/output', [])
            with self.assertRaisesRegex(ValueError, 'overlaps selected input'):
                c.admit_output(real / 'output', [real])

    def check_shell(self, data, rows=None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'review.sh'; path.write_bytes(data)
            return c.audit_sh(path, rows or cohort()['archives'], c.sha(b'bootstrap'), [b'PRIVATE_CANARY'])

    def test_shell_exact_archives_and_bootstrap_without_execution(self):
        record = self.check_shell(shell_bytes(b'inert-conda-bytes'))
        self.assertEqual(record['archive_count'], 1)
        self.assertIs(record['installer_executed'], False)

    def test_shell_tampered_nested_bytes_refuse(self):
        with self.assertRaisesRegex(ValueError, 'archive bytes differ'):
            self.check_shell(shell_bytes(b'changed-conda-bytes'))

    def test_shell_builder_owner_metadata_refuses(self):
        with self.assertRaisesRegex(ValueError, 'publisher owner/time'):
            self.check_shell(shell_bytes(b'inert-conda-bytes', neutral=False))

    def test_shell_publisher_content_and_activation_hook_refuse(self):
        with self.assertRaisesRegex(ValueError, 'private publisher marker'):
            self.check_shell(shell_bytes(b'inert-conda-bytes', extra=[('conda-meta/history', b'PRIVATE_CANARY')]))
        with self.assertRaisesRegex(ValueError, 'activation hook'):
            self.check_shell(shell_bytes(b'inert-conda-bytes', extra=[('pkgs/user_post_install.sh', b'echo unsafe')]))

    def test_shell_archive_traversal_and_trailing_bytes_refuse(self):
        with self.assertRaisesRegex(ValueError, 'unsafe wrapper member'):
            self.check_shell(shell_bytes(b'inert-conda-bytes', extra=[('../escape', b'data')]))
        with self.assertRaisesRegex(ValueError, 'payload size differs'):
            self.check_shell(shell_bytes(b'inert-conda-bytes') + b'private-tail')

    def test_shell_bootstrap_mutation_refuses(self):
        with self.assertRaisesRegex(ValueError, 'bootstrap bytes changed'):
            self.check_shell(shell_bytes(b'inert-conda-bytes', bootstrap=b'changed-tool'))

    def test_tar_nonzero_padding_and_hidden_tail_refuse(self):
        raw = bytearray(tar_bytes([('metadata.txt', b'a')]))
        raw[513] = 65
        with self.assertRaisesRegex(ValueError, 'member padding'):
            c.audit_nested_tar(bytes(raw), {}, [])
        raw = bytearray(tar_bytes([('metadata.txt', b'a')]))
        raw[-1] = 65
        with self.assertRaisesRegex(ValueError, 'hidden trailing data'):
            c.audit_nested_tar(bytes(raw), {}, [])

    def test_private_policy_content_is_not_returned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'policy.json'
            path.write_text(json.dumps({'schema': 'symphony.source-privacy-policy.v1', 'markers': ['PRIVATE_CANARY']}))
            with self.assertRaisesRegex(ValueError, '^private publisher marker in wrapper content$'):
                c.privacy_scan(b'PRIVATE_CANARY', c.markers_from_policy(path))


if __name__ == '__main__':
    unittest.main()
