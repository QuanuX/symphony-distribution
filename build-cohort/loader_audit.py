#!/usr/bin/env python3
"""Read final native loader records without executing product binaries.

This proves declared dependencies and origin-relative search paths, not that a
different host actually loads the same bytes. Detached SDK execution and later
fresh-host qualification provide separate evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


MACHO = {bytes.fromhex(x) for x in ('feedface', 'feedfacf', 'cefaedfe', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}
LINUX_SYSTEM = re.compile(r'^(?:lib(?:c|m|dl|rt|pthread|resolv|util|gcc_s|stdc\+\+|c\+\+|c\+\+abi|unwind)\.so(?:\.[0-9]+)*|ld-linux[^/]*\.so(?:\.[0-9]+)*)$')


def require(value, message):
    if not value:
        raise ValueError(message)


def contained(path, prefix):
    resolved = path.resolve()
    return resolved == prefix or prefix in resolved.parents


def macho_records(dependencies, commands):
    linked = []
    # otool prints fat slice headings without a tab; every dependency is indented.
    for line in dependencies.splitlines():
        match = re.match(r'^\s+(.+?) \(compatibility version ', line)
        if match:
            linked.append(match.group(1))
    rpaths, identities = [], []
    command = None
    for line in commands.splitlines():
        match = re.match(r'\s*cmd (LC_\S+)', line)
        if match:
            command = match.group(1)
        elif command == 'LC_RPATH':
            match = re.match(r'\s*path (.+) \(offset [0-9]+\)', line)
            if match:
                rpaths.append(match.group(1))
        elif command == 'LC_ID_DYLIB':
            match = re.match(r'\s*name (.+) \(offset [0-9]+\)', line)
            if match:
                identities.append(match.group(1))
    return sorted(set(linked) - set(identities)), sorted(set(rpaths)), sorted(set(identities))


def elf_records(dynamic):
    needed, rpaths = [], []
    for line in dynamic.splitlines():
        match = re.search(r'\((NEEDED|RPATH|RUNPATH)\).*\[(.+?)\]', line)
        if match:
            if match.group(1) == 'NEEDED':
                needed.append(match.group(2))
            else:
                rpaths.extend(match.group(2).split(':'))
    return needed, rpaths


def system_runtime_allowance(prefix, readelf='readelf'):
    """Bind only the exact Linux TLS inputs recorded by the clean dependency build."""
    evidence = prefix / 'third-party/share/symphony/dependency-evidence/curl-zstd.json'
    if not evidence.is_file():
        return {}
    tls = json.loads(evidence.read_text()).get('tls', {})
    if tls.get('backend') != 'OpenSSL':
        return {}
    inputs = tls.get('inputs', {})
    require(set(inputs) == {'ssl_library', 'crypto_library'}, 'Exact system TLS input set differs')
    admitted, dependencies = {}, {}
    for kind, entry in inputs.items():
        path = Path(entry['system_path']).resolve(strict=True)
        require(Path('/usr') in path.parents and Path('/usr/local') not in path.parents and path.is_file(), 'TLS dependency is not a system library')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == entry['sha256'], 'Current TLS runtime differs from clean-build selection')
        dynamic = subprocess.check_output([readelf, '-d', str(path)], text=True, stderr=subprocess.STDOUT, timeout=30)
        names = re.findall(r'\(SONAME\).*\[(.+?)\]', dynamic)
        stem = 'libssl' if kind == 'ssl_library' else 'libcrypto'
        require(len(names) == 1 and re.fullmatch(re.escape(stem) + r'\.so\.[0-9.]+', names[0]), 'Unexpected bound TLS SONAME')
        require(names[0] not in admitted, 'Duplicate TLS runtime identity')
        admitted[names[0]] = digest
        dependencies[names[0]] = elf_records(dynamic)[0]
    for names in dependencies.values():
        require(all(name in admitted or LINUX_SYSTEM.fullmatch(name) for name in names), 'Bound TLS runtime has an unrecorded nonplatform dependency')
    return admitted


def origin_path(value, binary, prefix, system):
    tokens = ('@loader_path', '@executable_path') if system == 'Darwin' else ('$ORIGIN', '${ORIGIN}')
    for token in tokens:
        if value == token or value.startswith(token + '/'):
            # @executable_path is only meaningful for executables. Do not assume
            # the later process location for a dylib opened by an external client.
            require(token != '@executable_path' or binary.suffix != '.dylib', 'Shared library search uses executable-relative origin')
            path = binary.parent / value[len(token):].lstrip('/')
            require(contained(path, prefix), 'Loader-relative path escapes payload')
            return path
    raise ValueError('Loader search path is not origin-relative: ' + value)


def validate_records(binary, prefix, system, dependencies, rpaths, identities=(), allowed_system=None):
    roots = [origin_path(value, binary, prefix, system) for value in rpaths]
    for identity in identities:
        require(identity.startswith('@rpath/') or identity.startswith('@loader_path/'), 'Mach-O library identity contains an absolute or ambient path')
    result = []
    for dependency in dependencies:
        if system == 'Linux' and dependency in (allowed_system or {}):
            result.append({'dependency': dependency, 'resolution': 'exact-system-build-input', 'sha256': allowed_system[dependency]})
            continue
        if system == 'Darwin' and (dependency.startswith('/usr/lib/') or dependency.startswith('/System/Library/')):
            result.append({'dependency': dependency, 'resolution': 'platform-system'})
            continue
        if system == 'Linux' and LINUX_SYSTEM.fullmatch(dependency):
            result.append({'dependency': dependency, 'resolution': 'platform-system'})
            continue
        if system == 'Darwin' and dependency.startswith('@rpath/'):
            suffix = dependency[len('@rpath/'):]
            candidates = [root / suffix for root in roots]
        elif system == 'Darwin' and dependency.startswith(('@loader_path/', '@executable_path/')):
            candidates = [origin_path(dependency, binary, prefix, system)]
        elif system == 'Linux' and '/' not in dependency:
            candidates = [root / dependency for root in roots]
        else:
            raise ValueError('Uncontrolled loader dependency: ' + dependency)
        existing = [p for p in candidates if p.is_file() and contained(p, prefix)]
        require(existing, 'Loader dependency has no payload-owned resolution: ' + dependency)
        result.append({'dependency': dependency, 'resolution': sorted({str(p.resolve().relative_to(prefix)) for p in existing})})
    return result


def audit(prefix, otool='/usr/bin/otool', readelf='readelf'):
    prefix = Path(prefix).resolve()
    require(prefix.is_dir(), 'Final payload prefix is absent')
    records, seen = [], set()
    allowed_system = system_runtime_allowance(prefix, readelf)
    for path in sorted(prefix.rglob('*')):
        if not path.is_file():
            continue
        require(contained(path, prefix), 'Final payload symlink escapes selected prefix')
        if path.resolve() in seen:
            continue
        seen.add(path.resolve())
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic not in MACHO and magic != b'\x7fELF':
            continue
        def run(argv):
            return subprocess.check_output([str(x) for x in argv], text=True, stderr=subprocess.STDOUT, timeout=30)
        if magic in MACHO:
            deps, rpaths, identities = macho_records(run([otool, '-L', path]), run([otool, '-l', path]))
            system = 'Darwin'
        else:
            deps, rpaths = elf_records(run([readelf, '-d', path]))
            identities, system = [], 'Linux'
        resolved = validate_records(path, prefix, system, deps, rpaths, identities, allowed_system)
        records.append({'path': str(path.relative_to(prefix)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'format': system, 'rpaths': rpaths, 'dependencies': resolved})
    return {'protocol': 'symphony.distribution.native-loader-audit.v1', 'status': 'passed',
            'scope': 'static final-payload loader declarations; not fresh-host dynamic loading',
            'native_binaries': records, 'fresh_host_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--otool', default='/usr/bin/otool')
    parser.add_argument('--readelf', default='readelf')
    args = parser.parse_args()
    output = Path(args.output)
    require(not output.exists(), 'Preserve prior loader evidence')
    output.write_text(json.dumps(audit(args.prefix, args.otool, args.readelf), indent=2) + '\n')


if __name__ == '__main__':
    main()
