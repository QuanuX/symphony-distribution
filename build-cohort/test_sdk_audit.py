import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sdk = load('sdk_audit')
loader = load('loader_audit')


class SdkAuditTests(unittest.TestCase):
    def test_detached_copy_refuses_symlinks_and_build_outputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / 'source'
            source.mkdir()
            (source / 'main.cpp').write_text('int main(){}')
            (source / 'escape').symlink_to('/usr/include')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                sdk.safe_copy(source, root / 'copy', {})
            (source / 'escape').unlink()
            (source / 'build').mkdir()
            (source / 'build' / 'CMakeCache.txt').write_text('private path')
            with self.assertRaisesRegex(ValueError, 'artifacts'):
                sdk.safe_copy(source, root / 'second-copy', {})

    def test_exact_import_search_and_metadata(self):
        component = {'component_id': 'unit', 'exported_packages': [
            {'package': 'TestSdk', 'version': '1.2.0', 'receipt_release': '1.2.0-dev',
             'cmake_version_file': True, 'targets': ['Symphony::Unit']},
            {'package': 'TestAbi', 'version': '1.2.0', 'receipt_release': '1.2.0-dev',
             'cmake_version_file': False, 'targets': ['Symphony::Abi']}]}
        project = sdk.import_project([component], Path('/payload with spaces'))
        self.assertIn('1.2.0 EXACT REQUIRED CONFIG PATHS "/payload with spaces" NO_DEFAULT_PATH', project)
        self.assertIn('TestAbi REQUIRED CONFIG PATHS "/payload with spaces/lib/cmake/TestAbi/1.2.0-dev" NO_DEFAULT_PATH', project)
        self.assertNotIn('add_subdirectory', project)
        meta = sdk.consumer_metadata([component], ['consumer'])
        self.assertEqual([x['target'] for x in meta['first_party_sdk_dependencies']], ['Symphony::Unit', 'Symphony::Abi'])

    def test_no_cmake_injection(self):
        for value in ('/tmp/a;b', '/tmp/"x', '/tmp/${HOME}', '/tmp/a\nb'):
            with self.assertRaises(ValueError):
                sdk.cmake_quote(value)

    def test_macho_parse_identity_and_rpaths(self):
        deps, paths, identities = loader.macho_records('x:\n\t@rpath/libx.dylib (compatibility version 1.0.0, current version 1.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)',
            ' cmd LC_ID_DYLIB\n name @rpath/libx.dylib (offset 24)\n cmd LC_RPATH\n path @loader_path/../lib (offset 12)')
        self.assertEqual(deps, ['/usr/lib/libSystem.B.dylib'])
        self.assertEqual(paths, ['@loader_path/../lib'])
        self.assertEqual(identities, ['@rpath/libx.dylib'])

    def test_loader_requires_final_prefix_resolution(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            (root / 'bin').mkdir()
            (root / 'lib').mkdir()
            (root / 'lib/libcurl.4.dylib').write_bytes(b'fixture')
            binary = root / 'bin/client'
            result = loader.validate_records(binary, root, 'Darwin', ['@rpath/libcurl.4.dylib'], ['@loader_path/../lib'])
            self.assertEqual(result[0]['resolution'], ['lib/libcurl.4.dylib'])
            for dep, paths in [('/usr/local/lib/libcurl.4.dylib', []), ('@rpath/libmissing.dylib', ['@loader_path/../lib']), ('@rpath/libcurl.4.dylib', [str(root / 'lib')])]:
                with self.assertRaises(ValueError):
                    loader.validate_records(binary, root, 'Darwin', [dep], paths)

    def test_elf_closed_platform_baseline_and_private_origin(self):
        self.assertEqual(loader.elf_records(' (NEEDED) Shared library: [libcurl.so.4]\n (RUNPATH) Library runpath: [$ORIGIN/../lib]'), (['libcurl.so.4'], ['$ORIGIN/../lib']))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            result = loader.validate_records(root / 'app', root, 'Linux', ['libc.so.6', 'libstdc++.so.6'], [])
            self.assertEqual(len(result), 2)
            with self.assertRaises(ValueError):
                loader.validate_records(root / 'app', root, 'Linux', ['libcurl.so.4'], [])
            with self.assertRaises(ValueError):
                loader.validate_records(root / 'app', root, 'Linux', [], ['$ORIGIN/../../outside'])
            with self.assertRaises(ValueError):
                loader.validate_records(root / 'app', root, 'Linux', ['libssl.so.3'], [])
            bound = loader.validate_records(root / 'app', root, 'Linux', ['libssl.so.3'], [], allowed_system={'libssl.so.3': 'fixture-exact-hash'})
            self.assertEqual(bound[0]['resolution'], 'exact-system-build-input')

    def test_changed_system_tls_input_refuses_before_loader_use(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            evidence = root / 'third-party/share/symphony/dependency-evidence/curl-zstd.json'
            evidence.parent.mkdir(parents=True)
            evidence.write_text(json.dumps({'tls': {'backend': 'OpenSSL', 'inputs': {
                'ssl_library': {'system_path': '/usr/bin/true', 'sha256': '0' * 64},
                'crypto_library': {'system_path': '/usr/bin/false', 'sha256': '0' * 64}}}}))
            with self.assertRaisesRegex(ValueError, 'differs'):
                loader.system_runtime_allowance(root)


if __name__ == '__main__':
    unittest.main()
