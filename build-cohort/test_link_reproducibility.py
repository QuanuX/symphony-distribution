import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(platform.system() == 'Darwin' and shutil.which('cmake'), 'native Apple linker qualification')
class StableLinkPolicy(unittest.TestCase):
    def test_two_private_dependency_roots_produce_equal_relocated_binaries(self):
        # Exercise CMake's actual imported-library link line. An absolute build
        # RPATH changes LC_UUID even after install_name_tool removes that path.
        sys.path.insert(0, str(ROOT / 'build-cohort'))
        import build
        import finalize_native
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source'; source.mkdir()
            (source / 'dep.c').write_text('int dependency(void) { return 7; }\n')
            (source / 'main.c').write_text('int dependency(void); int main(void) { return dependency() == 7 ? 0 : 1; }\n')
            (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.24)
project(RelocatedLinkIdentity C)
add_library(Dependency SHARED IMPORTED)
set_target_properties(Dependency PROPERTIES IMPORTED_LOCATION "${DEPENDENCY_PREFIX}/lib/libdependency.dylib")
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE Dependency)
install(TARGETS consumer RUNTIME DESTINATION bin)
''')
            external = root / 'input'; (external / 'lib').mkdir(parents=True)
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'TMPDIR': str(root), 'LANG': 'C', 'LC_ALL': 'C', 'ZERO_AR_DATE': '1',
                   'SYMPHONY_CODESIGN_IDENTITY': '-'}
            def run(argv):
                result = subprocess.run([str(x) for x in argv], env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
                return result
            run(['/usr/bin/clang', '-dynamiclib', '-O2', source/'dep.c', '-install_name', '@rpath/libdependency.dylib',
                 '-o', external/'lib/libdependency.dylib'])
            payloads = []
            for label in ('first-private-prefix', 'second-independent-prefix'):
                work = root / label; stage = work / 'stage'
                shutil.copytree(external, stage/'third-party')
                run([shutil.which('cmake'), '-S', source, '-B', work/'build', '-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_C_COMPILER=/usr/bin/clang', '-DCMAKE_EXE_LINKER_FLAGS=-Wl,-headerpad_max_install_names',
                     '-DCMAKE_INSTALL_PREFIX='+str(stage), '-DDEPENDENCY_PREFIX='+str(stage/'third-party'),
                     *build.native_link_policy()])
                run([shutil.which('cmake'), '--build', work/'build'])
                run([shutil.which('cmake'), '--install', work/'build'])
                binary = stage/'bin/consumer'
                finalize_native.finalize(stage, [binary], external, stage/'third-party')
                relocated = work/'relocated'; stage.rename(relocated)
                run([relocated/'bin/consumer'])
                payloads.append((relocated/'bin/consumer').read_bytes())
            self.assertEqual(payloads[0], payloads[1])

if __name__ == '__main__': unittest.main()
