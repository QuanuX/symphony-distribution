import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('external', Path(__file__).with_name('external.py'))
external = importlib.util.module_from_spec(spec)
spec.loader.exec_module(external)


class ExternalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, entries):
        path = self.root / 'source.tar'
        with tarfile.open(path, 'w') as tar:
            for name, content, target in entries:
                member = tarfile.TarInfo(name)
                if target is not None:
                    member.type, member.linkname = tarfile.SYMTYPE, target
                    tar.addfile(member)
                else:
                    member.size = len(content)
                    tar.addfile(member, io.BytesIO(content))
        return path

    def test_archive_escape_fails_before_writes(self):
        archive = self.archive([('source/file', b'good', None), ('source/../../escaped', b'bad', None)])
        destination = self.root / 'work'
        destination.mkdir()
        with self.assertRaisesRegex(ValueError, 'unsafe archive'):
            external.extract_archive(archive, destination, 'source')
        self.assertEqual(list(destination.iterdir()), [])

    def test_link_child_and_escape_refused(self):
        for entries in ([('source/link', b'', '../../outside')],
                        [('source/target', b'file', None), ('source/link', b'', 'target'), ('source/link/child', b'bad', None)]):
            archive = self.archive(entries)
            with self.assertRaises(ValueError):
                external.extract_archive(archive, self.root, 'source')
        self.assertFalse((self.root / 'source').exists())

    def test_internal_upstream_test_link_remains_contained(self):
        archive = self.archive([('source/bin/zstd', b'program', None), ('source/bin/unzstd', b'', 'zstd')])
        external.extract_archive(archive, self.root, 'source')
        self.assertEqual((self.root / 'source/bin/unzstd').read_bytes(), b'program')

    def test_work_never_adopts_existing_directory_or_symlink(self):
        old = self.root / 'old'
        old.mkdir()
        (old / 'retained').write_text('unchanged')
        for path in (old, self.root / 'link'):
            if path.name == 'link':
                path.symlink_to(old)
            with self.assertRaises(ValueError):
                external.fresh_work(path)
        self.assertEqual((old / 'retained').read_text(), 'unchanged')

    def test_ambient_environment_and_optional_dependencies_are_not_admitted(self):
        with patch.dict(os.environ, {'CMAKE_PREFIX_PATH': '/opt/homebrew', 'LDFLAGS': '-L/private/developer',
                                     'SSL_CERT_FILE': '/private/developer/trust.pem', 'CC': '/unselected/compiler'}):
            env = external.clean_env(self.root)
        self.assertFalse({'CMAKE_PREFIX_PATH', 'LDFLAGS', 'SSL_CERT_FILE', 'CC'} & env.keys())
        _, tls = external.system_tls('Darwin', None)
        options = external.configuration(self.root, '/usr/bin/clang', '/usr/bin/clang++', 'Darwin', tls)
        external.audit_curl_cache(options['curl'], 'Darwin')
        for extra in ({'CURL_USE_LIBSSH2': 'ON'}, {'ZLIB_LIBRARY': '/opt/homebrew/lib/libz.dylib'},
                      {'CURL_USE_SECTRANSP': 'OFF'}, {'CURL_USE_OPENSSL': 'ON'}):
            with self.assertRaises(ValueError):
                external.audit_curl_cache({**options['curl'], **extra}, 'Darwin')

    def test_linux_tls_cannot_silently_select_publisher_openssl(self):
        with self.assertRaisesRegex(ValueError, 'explicit system OpenSSL'):
            external.system_tls('Linux', None)
        with self.assertRaisesRegex(ValueError, 'SecureTransport'):
            external.system_tls('Darwin', {'ssl_library': '/opt/homebrew/lib/libssl.dylib'})

    def test_developer_directory_is_explicit_and_validated(self):
        with patch.dict(os.environ, {'DEVELOPER_DIR': '/ambient/toolchain'}):
            self.assertNotIn('DEVELOPER_DIR', external.clean_env(self.root))
        with patch.object(external.platform, 'system', return_value='Darwin'):
            self.assertEqual(external.clean_env(self.root, self.root)['DEVELOPER_DIR'], str(self.root))
            with self.assertRaises(ValueError):
                external.clean_env(self.root, self.root / 'absent')
        with patch.object(external.platform, 'system', return_value='Linux'):
            with self.assertRaises(ValueError):
                external.clean_env(self.root, self.root)

    def test_exact_pin_and_archive_bytes_rejected_before_build(self):
        notices = self.root / 'source/cmake/notices'
        notices.mkdir(parents=True)
        rows = [{'id': name, **pin} for name, pin in external.PINS.items()]
        (notices / 'sources.json').write_text(json.dumps({'components': rows}))
        archives = {}
        for name, pin in external.PINS.items():
            archives[name] = self.root / pin['archive']
            archives[name].write_bytes(b'untrusted bytes')
        with self.assertRaisesRegex(ValueError, 'archive digest differs'):
            external.verify_inputs(self.root / 'source', archives)
        rows[0]['version'] = 'newer-unreviewed'
        (notices / 'sources.json').write_text(json.dumps({'components': rows}))
        with self.assertRaisesRegex(ValueError, 'pin differs'):
            external.verify_inputs(self.root / 'source', archives)

    def test_sdk_metadata_follows_relocated_prefix(self):
        prefix = self.root / 'build/prefix'
        (prefix / 'lib/pkgconfig').mkdir(parents=True)
        (prefix / 'bin').mkdir()
        (prefix / 'lib/pkgconfig/libcurl.pc').write_text(f'prefix={prefix}\nlibdir={prefix}/lib\nincludedir=${{prefix}}/include\n')
        config = prefix / 'bin/curl-config'
        config.write_text(f'#!/bin/sh\nprefix="{prefix}"\necho "${{prefix}}/lib"\n')
        config.chmod(0o755)
        external.relocate_exports(prefix)
        relocated = self.root / 'installed elsewhere'
        shutil.copytree(prefix, relocated)
        shutil.rmtree(prefix.parent)
        output = subprocess.check_output([relocated / 'bin/curl-config'], text=True).strip()
        self.assertEqual(output, str(relocated / 'lib'))
        self.assertIn('prefix=${pcfiledir}/../..', (relocated / 'lib/pkgconfig/libcurl.pc').read_text())
        external.inventory(relocated, (str(prefix).encode(),))

    def test_payload_leak_or_absolute_loader_link_is_rejected(self):
        prefix = self.root / 'prefix'
        prefix.mkdir()
        (prefix / 'bad').write_bytes(b'compiler path: /Users/publisher/private')
        with self.assertRaisesRegex(ValueError, 'private/development'):
            external.inventory(prefix, ())
        (prefix / 'bad').unlink()
        (prefix / 'bad').symlink_to('/usr/lib')
        with self.assertRaisesRegex(ValueError, 'escapes prefix'):
            external.inventory(prefix, ())


if __name__ == '__main__':
    unittest.main()
