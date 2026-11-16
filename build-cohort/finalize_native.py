#!/usr/bin/env python3
"""Finalize only the current owner's declared native files before receipt seal.

External dependencies may be rebound only to an identical copied clean input
under third-party/. This is a loader transformation, not an ownership admission.
The external cohort must be finalized after all native installs, then inventoried
separately; it does not acquire a Symphony native receipt by being copied.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path, PurePosixPath
import shutil
import subprocess

spec = importlib.util.spec_from_file_location('finalize_loader', Path(__file__).with_name('loader_audit.py'))
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)

archive_spec = importlib.util.spec_from_file_location('finalize_archive', Path(__file__).with_name('archive_padding.py'))
archive_padding = importlib.util.module_from_spec(archive_spec)
archive_spec.loader.exec_module(archive_padding)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv):
    return subprocess.check_output([str(x) for x in argv], stderr=subprocess.STDOUT, text=True, timeout=60)


def owned_paths(root, specs):
    result = []
    for value in specs:
        fields = value.split('|')
        require(len(fields) == 2 and fields[1] in ('regular', 'executable'), 'Invalid owner spec')
        rel = PurePosixPath(fields[0])
        require(not rel.is_absolute() and '..' not in rel.parts and str(rel) == fields[0], 'Noncanonical owned path')
        path = root / rel
        require(path.is_file() and not path.is_symlink() and loader.contained(path, root), 'Owned file absent or escapes root')
        result.append(path)
    require(len(result) == len(set(result)), 'Duplicate owned path')
    return result


def external_mapping(root):
    original = os.environ.get('SYMPHONY_D06_EXTERNAL_PREFIX')
    copied = os.environ.get('SYMPHONY_D06_STAGE_EXTERNAL')
    require(bool(original) == bool(copied), 'Both exact external prefixes are required together')
    if original:
        original, copied = Path(original).resolve(), Path(copied).resolve()
        require(original.is_dir() and copied.is_dir() and loader.contained(copied, root), 'Invalid staged external prefix')
    return original, copied


def resolve_dependency(value, binary, root, rpaths, original, copied, verified_external=None):
    if value.startswith(('/usr/lib/', '/System/Library/')):
        return None
    if value.startswith('@rpath/'):
        suffix = value[len('@rpath/'):]
        candidates = []
        for rpath in rpaths:
            if rpath.startswith(('@loader_path', '@executable_path')):
                candidates.append(loader.origin_path(rpath, binary, root, 'Darwin') / suffix)
            elif Path(rpath).is_absolute():
                candidates.append(Path(rpath) / suffix)
        if copied:
            candidates.append(copied / 'lib' / suffix)
        # CMake may emit @rpath identities while the final installation RPATH
        # is intentionally empty. Only a unique exact versioned staged native
        # library is admissible; never search the user's loader environment.
        if '/' not in suffix and (root / 'lib/symphony').is_dir():
            candidates.extend((root / 'lib/symphony').rglob(suffix))
        existing = [p for p in candidates if p.is_file()]
        require(existing, 'Unresolved @rpath dependency: ' + value)
        mapped = {resolve_dependency(str(p.resolve()), binary, root, [], original, copied, verified_external) for p in existing}
        require(len(mapped) == 1 and None not in mapped, 'Ambiguous @rpath dependency: ' + value)
        return mapped.pop()
    elif value.startswith(('@loader_path/', '@executable_path/')):
        path = loader.origin_path(value, binary, root, 'Darwin').resolve()
    else:
        path = Path(value)
        require(path.is_absolute(), 'Ambient relative native dependency refused: ' + value)
        path = path.resolve()
    if original and loader.contained(path, original):
        destination = copied / path.relative_to(original)
        require(destination.is_file() and loader.contained(destination, copied), 'External runtime copy absent')
        expected = sha(path)
        actual = (verified_external or {}).get(str(destination.resolve()), sha(destination))
        require(actual == expected, 'Staged external runtime differs from exact source input')
        return destination.resolve()
    require(path.is_file() and loader.contained(path, root), 'Native dependency escapes final stage: ' + str(path))
    if original and loader.contained(path, copied):
        input_path = original / path.relative_to(copied)
        require(input_path.is_file(), 'Staged external file has no exact input')
        require((verified_external or {}).get(str(path), sha(path)) == sha(input_path), 'Staged external runtime differs from exact source input')
    return path


def finalize(root, paths, original=None, copied=None, verified_external=None):
    results = []
    allowed_system = loader.system_runtime_allowance(root)
    for binary in paths:
        with binary.open('rb') as stream:
            header = stream.read(8)
        if header == b'!<arch>\n' and platform.system() == 'Darwin':
            # Only unsealed declared files (or exact copied external inputs)
            # enter this hook. Object bytes and archive offsets stay unchanged.
            normalized, proof = archive_padding.normalize_bytes(binary.read_bytes())
            if proof['changed_byte_count']:
                binary.write_bytes(normalized)
            results.append({'path': str(binary.relative_to(root)), 'sha256': sha(binary),
                            'kind': 'static_archive', 'padding_normalization': proof})
            continue
        magic = header[:4]
        if magic not in loader.MACHO and magic != b'\x7fELF':
            continue
        if magic in loader.MACHO:
            deps, rpaths, identities = loader.macho_records(run(['/usr/bin/otool', '-L', binary]), run(['/usr/bin/otool', '-l', binary]))
            for dependency in deps:
                target = resolve_dependency(dependency, binary, root, rpaths, original, copied, verified_external)
                if target is not None:
                    relative = '@loader_path/' + os.path.relpath(target, binary.parent)
                    if relative != dependency:
                        run(['/usr/bin/install_name_tool', '-change', dependency, relative, binary])
            if identities:
                run(['/usr/bin/install_name_tool', '-id', '@rpath/' + binary.name, binary])
            # Direct loader-relative dependencies need no inherited search path.
            for rpath in rpaths:
                run(['/usr/bin/install_name_tool', '-delete_rpath', rpath, binary])
            run(['/usr/bin/strip', '-S', binary])
            identity = os.environ.get('SYMPHONY_CODESIGN_IDENTITY', '-')
            require(identity == '-', 'D06 cohort finalizer only performs local ad hoc signatures')
            run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', binary])
            run(['/usr/bin/codesign', '--verify', '--strict', binary])
        else:
            patchelf = shutil.which('patchelf')
            require(patchelf is not None, 'Linux finalization requires patchelf')
            deps, old = loader.elf_records(run(['readelf', '-d', binary]))
            roots = set()
            for dependency in deps:
                if loader.LINUX_SYSTEM.fullmatch(dependency) or dependency in allowed_system:
                    continue
                candidates = []
                for rpath in old:
                    if rpath.startswith(('$ORIGIN', '${ORIGIN}')):
                        candidates.append(loader.origin_path(rpath, binary, root, 'Linux') / dependency)
                    elif Path(rpath).is_absolute():
                        candidates.append(Path(rpath) / dependency)
                if copied:
                    candidates.append(copied / 'lib' / Path(dependency).name)
                if '/' not in dependency and (root / 'lib/symphony').is_dir():
                    candidates.extend((root / 'lib/symphony').rglob(dependency))
                if Path(dependency).is_absolute():
                    candidates.append(Path(dependency))
                matches = [p.resolve() for p in candidates if p.is_file()]
                require(matches, 'ELF dependency has no exact staged runtime: ' + dependency)
                # Reuse the same exact-source mapping and containment proof.
                targets = {resolve_dependency(str(p), binary, root, [], original, copied, verified_external) for p in matches}
                require(len(targets) == 1, 'Ambiguous ELF dependency: ' + dependency)
                target = targets.pop()
                require(target is not None, 'Nonbaseline ELF dependency resolved as platform library')
                roots.add('$ORIGIN/' + os.path.relpath(target.parent, binary.parent))
                if '/' in dependency:
                    run([patchelf, '--replace-needed', dependency, target.name, binary])
            run([patchelf, '--set-rpath', ':'.join(sorted(roots)), binary])
            run(['strip', '--strip-unneeded', binary])
        results.append({'path': str(binary.relative_to(root)), 'sha256': sha(binary)})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--owned', action='append', default=[])
    parser.add_argument('--external', action='store_true', help='Finalize copied external files only after every native receipt is sealed')
    parser.add_argument('--evidence')
    args = parser.parse_args()
    root = Path(args.root).resolve()
    require(root.is_dir(), 'Package stage is absent')
    original, copied = external_mapping(root)
    verified = None
    if args.external:
        require(copied and not args.owned and args.evidence, 'External finalization needs an exact copied prefix and new evidence path')
        require(not Path(args.evidence).exists(), 'Preserve external finalization evidence')
        paths = [p for p in copied.rglob('*') if p.is_file() and not p.is_symlink()]
        verified = {str(p.resolve()): sha(p) for p in paths}
    else:
        paths = owned_paths(root, args.owned)
    result = finalize(root, paths, original, copied, verified)
    if args.evidence:
        Path(args.evidence).write_text(json.dumps({'protocol': 'symphony.distribution.pre-receipt-native-finalization.v1',
            'finalized': result, 'external_input_sha256': verified,
            'publisher_signing': False, 'external_runtime_ownership_admitted': False}, indent=2) + '\n')


if __name__ == '__main__':
    main()
