import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

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
              'if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then\nexit 1\nfi\n@@END_HEADER@@\n').encode()
    return header + bootstrap + raw


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
        self.assertEqual(changed, '#!/bin/bash\nexport CONDA_REPORT_ERRORS=false\nexport CONDA_NO_PLUGINS=true\nset -eu\necho "inert"\n')
        with self.assertRaisesRegex(ValueError, 'shebang drift'):
            r.inactive_script('#!/bin/zsh\necho unsafe\n')

    def test_native_adapter_preserves_only_selected_prefix_ownership(self):
        selected = 'chown -R "${USER}" "$PREFIX"\n'
        script = '#!/bin/bash\n' + selected + r.AMBIENT_CONDA_OWNERSHIP + '\nexit 0\n'
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
