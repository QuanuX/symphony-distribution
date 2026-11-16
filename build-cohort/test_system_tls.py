import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('tls_loader', Path(__file__).with_name('loader_audit.py'))
loader = importlib.util.module_from_spec(spec); spec.loader.exec_module(loader)


class SystemTLSClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.lib = self.root / 'system-libraries'; self.lib.mkdir()
        self.dynamic = {}
        for name, needed in {
            'libssl.so.3': ['libcrypto.so.3', 'libc.so.6'],
            'libcrypto.so.3': ['libz.so.1', 'libzstd.so.1', 'libc.so.6'],
            'libz.so.1': ['libc.so.6'], 'libzstd.so.1': ['libc.so.6'],
        }.items(): self.library(name, needed)
        self.inputs = {kind: {'system_path': str(self.lib / name), 'sha256': self.sha(self.lib / name)}
                       for kind, name in [('ssl_library', 'libssl.so.3'), ('crypto_library', 'libcrypto.so.3')]}
        # Fixtures model system files without writing into the host's system roots.
        self.path_patch = patch.object(loader, 'system_library_path', side_effect=lambda p: Path(p).resolve(strict=True))
        self.readelf_patch = patch.object(loader.subprocess, 'check_output', side_effect=self.readelf)
        self.path_patch.start(); self.readelf_patch.start()

    def tearDown(self):
        self.readelf_patch.stop(); self.path_patch.stop(); self.temp.cleanup()

    @staticmethod
    def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

    def library(self, name, needed, directory=None, machine=62):
        directory = directory or self.lib; directory.mkdir(exist_ok=True)
        path = directory / name
        header = bytearray(20); header[:4] = b'\x7fELF'; header[4] = 2; header[5] = 1
        header[18:20] = machine.to_bytes(2, 'little'); path.write_bytes(bytes(header) + name.encode())
        self.dynamic[str(path)] = f' (SONAME) Library soname: [{name}]\n' + ''.join(
            f' (NEEDED) Shared library: [{value}]\n' for value in needed)
        return path

    def readelf(self, argv, **kwargs):
        self.assertEqual(argv[:2], ['readelf', '-d'])
        self.assertNotIn('LD_LIBRARY_PATH', kwargs['env'])
        return self.dynamic[argv[-1]]

    def evidence(self, record):
        prefix = self.root / 'payload'
        path = prefix / 'third-party/share/symphony/dependency-evidence/curl-zstd.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        tls = {'backend': 'OpenSSL', 'inputs': self.inputs}
        if record is not None: tls['runtime_closure'] = record
        path.write_text(json.dumps({'tls': tls}))
        return prefix

    def test_exact_reachable_closure_is_recorded_without_global_product_fallback(self):
        observed = loader.observe_system_tls_closure(self.inputs)
        self.assertEqual({r['soname'] for r in observed['libraries']}, {'libssl.so.3', 'libcrypto.so.3', 'libz.so.1', 'libzstd.so.1'})
        self.assertTrue(all(r['sha256'] == self.sha(Path(r['system_path'])) for r in observed['libraries']))
        allowed = loader.system_runtime_allowance(self.evidence(observed))
        self.assertEqual(set(allowed), {'libssl.so.3', 'libcrypto.so.3'})
        self.assertFalse(loader.LINUX_SYSTEM.fullmatch('libzstd.so.1'))
        with self.assertRaisesRegex(ValueError, 'payload-owned resolution'):
            loader.validate_records(self.root / 'app', self.root, 'Linux', ['libzstd.so.1'], [], allowed_system=allowed)

    def test_changed_transitive_bytes_or_graph_refuse_recorded_closure(self):
        observed = loader.observe_system_tls_closure(self.inputs); prefix = self.evidence(observed)
        path = self.lib / 'libzstd.so.1'; original = path.read_bytes(); path.write_bytes(original + b'changed')
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            loader.system_runtime_allowance(prefix)
        path.write_bytes(original)
        self.dynamic[str(path)] += ' (NEEDED) Shared library: [libm.so.6]\n'
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            loader.system_runtime_allowance(prefix)

    def test_missing_or_extra_closure_cannot_be_inferred_from_current_host(self):
        with self.assertRaisesRegex(ValueError, 'require exact recorded closure'):
            loader.system_runtime_allowance(self.evidence(None))
        observed = loader.observe_system_tls_closure(self.inputs)
        changed = copy.deepcopy(observed); changed['libraries'].pop()
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            loader.system_runtime_allowance(self.evidence(changed))
        changed = copy.deepcopy(observed); changed['libraries'].append(dict(observed['libraries'][0]))
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            loader.system_runtime_allowance(self.evidence(changed))

    def test_preexisting_two_root_evidence_remains_bounded(self):
        self.dynamic[str(self.lib / 'libcrypto.so.3')] = ' (SONAME) Library soname: [libcrypto.so.3]\n (NEEDED) Shared library: [libc.so.6]\n'
        self.assertEqual(set(loader.system_runtime_allowance(self.evidence(None))), {'libssl.so.3', 'libcrypto.so.3'})

    def test_unknown_transitive_library_refuses_even_when_present(self):
        self.library('libunreviewed.so.1', ['libc.so.6'])
        self.dynamic[str(self.lib / 'libcrypto.so.3')] += ' (NEEDED) Shared library: [libunreviewed.so.1]\n'
        with self.assertRaisesRegex(ValueError, 'Unreviewed transitive.*libunreviewed'):
            loader.observe_system_tls_closure(self.inputs)

    def test_rpath_architecture_and_ambiguous_runtime_refuse(self):
        path = self.lib / 'libzstd.so.1'; original_dynamic = self.dynamic[str(path)]
        self.dynamic[str(path)] += ' (RUNPATH) Library runpath: [/private/unselected]\n'
        with self.assertRaisesRegex(ValueError, 'loader search path'):
            loader.observe_system_tls_closure(self.inputs)
        self.dynamic[str(path)] = original_dynamic
        raw = bytearray(path.read_bytes()); raw[18:20] = (183).to_bytes(2, 'little'); path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'architecture differs'):
            loader.observe_system_tls_closure(self.inputs)
        self.library('libzstd.so.1', ['libc.so.6'])
        other = self.root / 'other-system-libraries'
        ssl = self.library('libssl.so.3', ['libcrypto.so.3', 'libc.so.6'], other)
        self.library('libzstd.so.1', ['libc.so.6'], other)
        self.inputs['ssl_library'] = {'system_path': str(ssl), 'sha256': self.sha(ssl)}
        with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
            loader.observe_system_tls_closure(self.inputs)

    def test_system_path_validation_rejects_private_library(self):
        self.path_patch.stop()
        try:
            with self.assertRaisesRegex(ValueError, 'not a reviewed system library'):
                loader.system_library_path(self.lib / 'libcrypto.so.3')
        finally: self.path_patch.start()


if __name__ == '__main__': unittest.main()
