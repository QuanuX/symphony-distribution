import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('finalizer', Path(__file__).with_name('finalize_native.py'))
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)


class FinalizeTests(unittest.TestCase):
    def test_refuse_unowned_or_uncontrolled_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with self.assertRaisesRegex(ValueError, 'Noncanonical'):
                finalizer.owned_paths(root, ['../outside|regular'])
            with self.assertRaisesRegex(ValueError, 'escapes'):
                finalizer.resolve_dependency('/usr/local/lib/unreviewed.dylib', root / 'app', root, [], None, None)

    def test_external_copy_must_match_exact_input(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            original, root = base / 'external', base / 'stage'
            copied = root / 'third-party'
            original.mkdir()
            copied.mkdir(parents=True)
            (original / 'dependency').write_bytes(b'approved')
            (copied / 'dependency').write_bytes(b'changed')
            for dependency in (original / 'dependency', copied / 'dependency'):
                with self.assertRaisesRegex(ValueError, 'differs'):
                    finalizer.resolve_dependency(str(dependency), root / 'app', root, [], original, copied)

    def test_empty_rpath_resolves_only_unique_staged_native_library(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            selected = root / 'lib/symphony/owner/1.0/libowner.dylib'
            selected.parent.mkdir(parents=True)
            selected.write_bytes(b'first')
            self.assertEqual(finalizer.resolve_dependency('@rpath/libowner.dylib', root / 'app', root, [], None, None), selected)
            another = root / 'lib/symphony/owner/2.0/libowner.dylib'
            another.parent.mkdir()
            another.write_bytes(b'second')
            with self.assertRaisesRegex(ValueError, 'Ambiguous'):
                finalizer.resolve_dependency('@rpath/libowner.dylib', root / 'app', root, [], None, None)

    @unittest.skipUnless(platform.system() == 'Darwin' and Path('/usr/bin/clang').exists(), 'Mach-O finalization proof requires Apple tools')
    def test_actual_macho_relocation_before_receipt_and_sdk(self):
        with tempfile.TemporaryDirectory(prefix='d06-finalizer-') as raw:
            base = Path(raw).resolve()
            original, root = base / 'exact-external', base / 'stage'
            copied = root / 'third-party'
            (original / 'lib').mkdir(parents=True)
            (root / 'bin').mkdir(parents=True)
            library = original / 'lib/libfixture.dylib'
            (base / 'library.c').write_text('int fixture(void) { return 42; }\n')
            (base / 'main.c').write_text('extern int fixture(void); int main(void) { return fixture() != 42; }\n')
            subprocess.run(['/usr/bin/clang', '-dynamiclib', str(base / 'library.c'), '-o', str(library), '-Wl,-install_name,' + str(library)], check=True, capture_output=True)
            shutil.copytree(original, copied)
            binary = root / 'bin/client'
            subprocess.run(['/usr/bin/clang', str(base / 'main.c'), str(library), '-o', str(binary)], check=True, capture_output=True)
            finalizer.finalize(root, [binary], original, copied)
            sealed = finalizer.sha(binary)
            verified = {str((copied / 'lib/libfixture.dylib').resolve()): finalizer.sha(copied / 'lib/libfixture.dylib')}
            finalizer.finalize(root, [copied / 'lib/libfixture.dylib'], original, copied, verified)
            self.assertEqual(sealed, finalizer.sha(binary), 'Final external step must not alter receipt-sealed native bytes')
            shutil.rmtree(original)
            relocated = base / 'relocated payload with spaces'
            root.rename(relocated)
            subprocess.run([str(relocated / 'bin/client')], check=True, capture_output=True, env={'PATH': '/usr/bin:/bin'})
            evidence = finalizer.loader.audit(relocated)
            self.assertEqual(len(evidence['native_binaries']), 2)
            self.assertEqual(evidence['status'], 'passed')


if __name__ == '__main__':
    unittest.main()
