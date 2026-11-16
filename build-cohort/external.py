#!/usr/bin/env python3
"""Build the reviewed curl/zstd inputs into an inert, relocatable private prefix.

No downloads, ambient package discovery, publisher credentials or activation.
The caller supplies exact archives and compiler tools. Linux additionally binds
the system OpenSSL headers/libraries; their hashes are evidence, not a new pin.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('external_bounded', ROOT / 'qualification/native_campaign.py')
_bounded = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bounded)
PINS = {
    'curl': {'version': '8.7.1', 'source_sha256': '6fea2aac6a4610fbd0400afb0bcddbe7258a64c63f1f68e5855ebc0c659710cd',
             'notice_sha256': 'adb1fc06547fd136244179809f7b7c2d2ae6c4534f160aa513af9b6a12866a32',
             'archive': 'curl-8.7.1.tar.xz', 'notice': 'COPYING', 'notice_file': 'curl-8.7.1.COPYING'},
    'zstd': {'version': '1.5.7', 'source_sha256': 'eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3',
             'notice_sha256': '7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8',
             'archive': 'zstd-1.5.7.tar.gz', 'notice': 'LICENSE', 'notice_file': 'zstd-1.5.7.LICENSE'},
}
OFF_OPTIONS = ('CURL_BROTLI', 'CURL_ZSTD', 'USE_NGHTTP2', 'USE_NGTCP2', 'USE_QUICHE', 'USE_MSH3',
               'USE_OPENSSL_QUIC', 'USE_LIBIDN2', 'CURL_USE_LIBPSL', 'CURL_USE_LIBSSH2', 'CURL_USE_LIBSSH',
               'CURL_USE_GSSAPI', 'ENABLE_ARES', 'CURL_USE_MBEDTLS', 'CURL_USE_BEARSSL', 'CURL_USE_WOLFSSL',
               'CURL_USE_GNUTLS')
PRIVATE = (b'/Users/', b'/home/', b'/opt/homebrew/', b'/usr/local/Cellar/', b'-----BEGIN PRIVATE KEY-----')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def plain_path(path, *, exists=True):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and
            not any(c in str(path) for c in ('\n', '\r', ';', '"', '$', '\\', '`')), 'unsafe absolute path')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink path is not admitted: ' + str(part))
    require(not exists or path.exists(), 'path is absent: ' + str(path))
    return path


def tool(path):
    path = Path(path)
    require(path.is_absolute(), 'tool must be explicitly selected by absolute path')
    path = path.resolve(strict=True)
    require(path.is_file() and os.access(path, os.X_OK), 'tool is not executable')
    plain_path(path)
    return path


def fresh_work(path):
    path = plain_path(path, exists=False)
    require(path.parent.is_dir() and not os.path.lexists(path), 'work must be new with an existing parent')
    path.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'logs', 'prefix'):
        (path / name).mkdir(mode=0o700)
    return path


def clean_env(work, developer_dir=None):
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'),
            'TMPDIR': str(work / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'ZERO_AR_DATE': '1', 'SOURCE_DATE_EPOCH': '1711468800'}
    if developer_dir is not None:
        selected = plain_path(developer_dir)
        require(platform.system() == 'Darwin' and selected.is_dir(), 'developer directory requires a native Darwin directory')
        env['DEVELOPER_DIR'] = str(selected)
    return env


def verify_inputs(source, archives):
    source = plain_path(source)
    record = json.loads((source / 'cmake/notices/sources.json').read_text())
    rows = record['components']
    require(len(rows) == 2 and {x['id'] for x in rows} == set(PINS), 'source dependency notice set differs')
    require(set(archives) == set(PINS), 'both exact external archives are required')
    for row in rows:
        pin = PINS[row['id']]
        require(all(row.get(k) == pin[k] for k in ('version', 'source_sha256', 'notice_sha256', 'notice_file')),
                'reviewed external dependency pin differs')
        archive = plain_path(archives[row['id']])
        require(archive.is_file() and digest(archive) == pin['source_sha256'], 'source archive digest differs: ' + row['id'])
        notice = plain_path(source / 'cmake/notices' / pin['notice_file'])
        require(notice.is_file() and digest(notice) == pin['notice_sha256'], 'source-owned notice digest differs')
    return record


def extract_archive(archive, work, root_name):
    """Validate the whole member graph before creating any archive member."""
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        require(len(members) < 100000 and sum(m.size for m in members) < 1024 ** 3, 'archive exceeds bounded extraction')
        names, links = set(), {}
        for member in members:
            p = PurePosixPath(member.name)
            require(not p.is_absolute() and '..' not in p.parts and p.parts and p.parts[0] == root_name and
                    '\\' not in member.name and not any(ord(c) < 32 for c in member.name), 'unsafe archive member')
            name = str(p)
            require(name not in names and (member.isdir() or member.isfile() or member.issym()), 'duplicate or unsupported archive member')
            require(not member.mode & 0o6000, 'privileged archive member')
            names.add(name)
            if member.issym():
                target = PurePosixPath(member.linkname)
                require(not target.is_absolute() and '\\' not in member.linkname and
                        not any(ord(c) < 32 for c in member.linkname), 'unsafe archive link')
                combined = os.path.normpath(str(p.parent / target))
                require(combined.startswith(root_name + '/') and combined in names | {str(PurePosixPath(x.name)) for x in members},
                        'archive link escapes or has no target')
                links[name] = combined
        require(all(not any(str(parent) in links for parent in PurePosixPath(name).parents) for name in names),
                'archive member traverses a link')
        require(all(target not in links for target in links.values()), 'archive link chains are forbidden')
        for member in members:
            destination = work / member.name
            if member.isdir():
                destination.mkdir(mode=0o755, parents=True, exist_ok=True)
            elif member.isfile():
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with tar.extractfile(member) as incoming, destination.open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                destination.chmod(0o755 if member.mode & 0o111 else 0o644)
        for member in members:
            if member.issym():
                (work / member.name).symlink_to(member.linkname)


def system_tls(platform_name, openssl):
    require(platform_name in ('Darwin', 'Linux'), 'only native Darwin/Linux external builds are supported')
    if platform_name == 'Darwin':
        require(openssl is None, 'Darwin recipe uses only native SecureTransport')
        return {'backend': 'SecureTransport', 'trust': 'target-user macOS system trust', 'system_runtime': True}, {
            'CURL_USE_OPENSSL': 'OFF', 'CURL_USE_SECTRANSP': 'ON', 'CURL_CA_BUNDLE': 'none', 'CURL_CA_PATH': 'none'}
    require(isinstance(openssl, dict) and set(openssl) == {'ssl_library', 'crypto_library', 'include_dir', 'version'},
            'Linux requires explicit system OpenSSL library/header/version inputs')
    paths = {}
    for key in ('ssl_library', 'crypto_library', 'include_dir'):
        raw = Path(openssl[key])
        require(raw.is_absolute(), 'OpenSSL paths must be absolute')
        path = raw.resolve(strict=True)
        require(path == Path('/usr') or Path('/usr') in path.parents, 'only reviewed system OpenSSL roots are admitted')
        require(not (Path('/usr/local') == path or Path('/usr/local') in path.parents), 'local OpenSSL prefix is not a system dependency')
        paths[key] = path
    require(paths['include_dir'].is_dir() and all(paths[k].is_file() for k in ('ssl_library', 'crypto_library')), 'OpenSSL inputs have wrong file type')
    header = paths['include_dir'] / 'openssl/opensslv.h'
    text = header.read_text()
    version = re.search(r'^\s*#\s*define\s+OPENSSL_VERSION_STR\s+"([^"]+)"', text, re.M)
    require(version is not None and version.group(1) == openssl['version'], 'OpenSSL header version differs')
    record = {'backend': 'OpenSSL', 'version': openssl['version'], 'system_runtime': True,
              'trust': 'target-user system OpenSSL default trust; no publisher trust material',
              'inputs': {key: {'system_path': str(path), 'sha256': digest(path)} for key, path in paths.items() if key != 'include_dir'},
              'header': {'system_path': str(header), 'sha256': digest(header)}}
    loader_spec = importlib.util.spec_from_file_location('external_system_tls', Path(__file__).with_name('loader_audit.py'))
    loader = importlib.util.module_from_spec(loader_spec)
    loader_spec.loader.exec_module(loader)
    record['runtime_closure'] = loader.observe_system_tls_closure(record['inputs'])
    return record, {'CURL_USE_OPENSSL': 'ON', 'CURL_USE_SECTRANSP': 'OFF', 'OPENSSL_SSL_LIBRARY': str(paths['ssl_library']),
                    'OPENSSL_CRYPTO_LIBRARY': str(paths['crypto_library']), 'OPENSSL_INCLUDE_DIR': str(paths['include_dir']),
                    'CURL_CA_BUNDLE': 'none', 'CURL_CA_PATH': 'none', 'CURL_CA_FALLBACK': 'ON'}


def configuration(work, cc, cxx, platform_name, tls_options):
    prefix = work / 'prefix'
    mapped_flags = ' '.join(shlex.quote(f'-f{kind}-prefix-map={work}=.') for kind in ('file', 'debug'))
    shared = {'CMAKE_POLICY_VERSION_MINIMUM': '3.5', 'CMAKE_BUILD_TYPE': 'Release', 'CMAKE_INSTALL_PREFIX': str(prefix),
              'CMAKE_INSTALL_LIBDIR': 'lib', 'CMAKE_POSITION_INDEPENDENT_CODE': 'ON', 'CMAKE_C_COMPILER': str(cc),
              'CMAKE_CXX_COMPILER': str(cxx), 'CMAKE_MAKE_PROGRAM': '/usr/bin/make',
              'CMAKE_C_FLAGS': mapped_flags, 'CMAKE_CXX_FLAGS': mapped_flags,
              'CMAKE_FIND_USE_PACKAGE_REGISTRY': 'OFF', 'CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY': 'OFF',
              'CMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH': 'OFF', 'CMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH': 'OFF',
              'CMAKE_FIND_FRAMEWORK': 'LAST', 'CMAKE_IGNORE_PREFIX_PATH': '/opt/homebrew;/usr/local;/opt/local',
              'CMAKE_INSTALL_RPATH_USE_LINK_PATH': 'OFF', 'CMAKE_BUILD_RPATH_USE_ORIGIN': 'ON',
              'CMAKE_INSTALL_RPATH': '@loader_path' if platform_name == 'Darwin' else '$ORIGIN'}
    if platform_name == 'Darwin':
        shared.update(CMAKE_INSTALL_NAME_DIR='@rpath', CMAKE_BUILD_WITH_INSTALL_NAME_DIR='ON', CMAKE_MACOSX_RPATH='ON')
    curl = {**shared, 'BUILD_CURL_EXE': 'OFF', 'BUILD_TESTING': 'OFF', 'BUILD_SHARED_LIBS': 'ON', 'BUILD_STATIC_LIBS': 'OFF',
            'CURL_ENABLE_EXPORT_TARGET': 'ON', 'BUILD_LIBCURL_DOCS': 'OFF', 'ENABLE_CURL_MANUAL': 'OFF',
            'CURL_DISABLE_LDAP': 'ON', 'CURL_DISABLE_LDAPS': 'ON', 'CMAKE_DISABLE_FIND_PACKAGE_ZLIB': 'ON',
            **{x: 'OFF' for x in OFF_OPTIONS}, **tls_options}
    zstd = {**shared, 'ZSTD_BUILD_PROGRAMS': 'OFF', 'ZSTD_BUILD_TESTS': 'OFF', 'ZSTD_BUILD_SHARED': 'OFF', 'ZSTD_BUILD_STATIC': 'ON',
            'ZSTD_ZLIB_SUPPORT': 'OFF', 'ZSTD_LZMA_SUPPORT': 'OFF', 'ZSTD_LZ4_SUPPORT': 'OFF'}
    return {'curl': curl, 'zstd': zstd}


def cache_values(path):
    values = {}
    for line in path.read_text().splitlines():
        match = re.match(r'^([^/#][^:]*):[^=]*=(.*)$', line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def audit_curl_cache(values, platform_name):
    for name in OFF_OPTIONS:
        require(values.get(name) in ('OFF', 'FALSE', '0', ''), 'unselected curl dependency enabled or not recorded: ' + name)
    require(values.get('CMAKE_DISABLE_FIND_PACKAGE_ZLIB') == 'ON', 'zlib autodiscovery is not disabled')
    for key, value in values.items():
        if key.endswith(('_LIBRARY', '_LIBRARIES', '_INCLUDE_DIR', '_INCLUDE_DIRS')) and value and not value.endswith('-NOTFOUND'):
            require(not any(x in value for x in ('/opt/homebrew', '/usr/local', '/opt/local', '/Users/', '/home/')), 'ambient dependency in curl cache: ' + key)
    selected = 'CURL_USE_SECTRANSP' if platform_name == 'Darwin' else 'CURL_USE_OPENSSL'
    require(values.get(selected) == 'ON', 'selected TLS backend was not configured')
    other = 'CURL_USE_OPENSSL' if platform_name == 'Darwin' else 'CURL_USE_SECTRANSP'
    require(values.get(other) == 'OFF', 'additional TLS backend was selected')


def relocate_exports(prefix):
    changed = []
    for path in sorted((prefix / 'lib/pkgconfig').glob('*.pc')):
        require(not path.is_symlink(), 'SDK metadata symlink is forbidden')
        text = path.read_text()
        text, count = re.subn(r'^prefix=.*$', 'prefix=${pcfiledir}/../..', text, flags=re.M)
        require(count == 1, 'pkg-config prefix is absent or ambiguous')
        text = text.replace(str(prefix) + '/lib', '${prefix}/lib').replace(str(prefix) + '/include', '${prefix}/include')
        require(str(prefix) not in text, 'pkg-config export still contains build prefix')
        path.write_text(text)
        changed.append(str(path.relative_to(prefix)))
    config = prefix / 'bin/curl-config'
    if config.exists():
        require(not config.is_symlink(), 'curl-config symlink is forbidden')
        text = config.read_text()
        text, count = re.subn(r'^prefix=.*$', 'prefix=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)', text, flags=re.M)
        require(count == 1, 'curl-config prefix is absent or ambiguous')
        # Upstream CMake also expands libdir in flags; retain that relation.
        text = text.replace(str(prefix), '${prefix}')
        config.write_text(text)
        changed.append('bin/curl-config')
    return changed


def inventory(prefix, forbidden):
    result = []
    for path in sorted(prefix.rglob('*')):
        rel = str(path.relative_to(prefix))
        if path.is_symlink():
            target = os.readlink(path)
            require(not Path(target).is_absolute() and prefix in path.resolve(strict=True).parents,
                    'installed dependency symlink escapes prefix')
            result.append({'path': rel, 'type': 'symlink', 'target': target})
        elif path.is_file():
            raw = path.read_bytes()
            require(not any(marker in raw for marker in (*PRIVATE, *forbidden)), 'private/development path in dependency payload: ' + rel)
            require(not path.stat().st_mode & 0o6000, 'privileged dependency output')
            result.append({'path': rel, 'type': 'file', 'sha256': digest(path), 'size': len(raw)})
        else:
            require(path.is_dir(), 'unsupported dependency output type')
    return result


def prepare(source, work, archives, *, cmake, cc, cxx, platform_name=None, openssl=None, developer_dir=None, jobs=2, timeout=1800):
    platform_name = platform_name or platform.system()
    require(platform_name == platform.system(), 'cross-build is not native qualification')
    require(type(jobs) is int and 1 <= jobs <= 32 and 1 <= timeout <= 7200, 'invalid bounded build settings')
    source = plain_path(source)
    notices = verify_inputs(source, archives)
    tls, tls_options = system_tls(platform_name, openssl)
    cmake, cc, cxx = map(tool, (cmake, cc, cxx))
    # Validate explicitly selected developer tools before creating any output.
    env = clean_env(Path(work), developer_dir)
    work = fresh_work(work)
    report = {'protocol': 'symphony.distribution.external-build.v1', 'status': 'incomplete',
              'host': {'system': platform_name, 'machine': platform.machine(), 'release': platform.release()},
              'publication_authorized': False, 'fresh_host_accepted': False, 'runtime_tls_qualified': False,
              'commands': [], 'tools': {name: {'path': str(path), 'sha256': digest(path)} for name, path in [('cmake', cmake), ('cc', cc), ('cxx', cxx)]}}
    evidence = work / 'external-build.json'
    def save():
        evidence.write_text(json.dumps(report, indent=2) + '\n')
    save()
    if developer_dir is not None:
        report['developer_dir'] = str(developer_dir)
    def run(label, argv):
        log = work / 'logs' / (label + '.log')
        with log.open('wb') as stream:
            code = _bounded.bounded_run([str(x) for x in argv], cwd=work / 'tmp', env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=timeout)
        report['commands'].append({'name': label, 'exit_code': code, 'log_sha256': digest(log)})
        save()
        require(code == 0, 'external build failed: ' + label + '; retained log ' + str(log))
    options = configuration(work, cc, cxx, platform_name, tls_options)
    try:
        for name, pin in PINS.items():
            archive = work / pin['archive']
            with archive.open('xb') as outgoing, Path(archives[name]).open('rb') as incoming:
                shutil.copyfileobj(incoming, outgoing)
            require(digest(archive) == pin['source_sha256'], 'archive changed during private copy')
            extract_archive(archive, work, name + '-' + pin['version'])
            root = work / (name + '-' + pin['version'])
            require(digest(root / pin['notice']) == pin['notice_sha256'], 'upstream notice differs from reviewed notice')
            build = work / (name + '-build')
            directory = root if name == 'curl' else root / 'build/cmake'
            run(name + '-configure', [cmake, '-S', directory, '-B', build, '-G', 'Unix Makefiles',
                                     *[f'-D{k}={v}' for k, v in sorted(options[name].items())]])
            if name == 'curl':
                audit_curl_cache(cache_values(build / 'CMakeCache.txt'), platform_name)
            run(name + '-build', [cmake, '--build', build, '--parallel', str(jobs)])
            run(name + '-install', [cmake, '--install', build])
        prefix = work / 'prefix'
        report['relocated_exports'] = relocate_exports(prefix)
        for name, pin in PINS.items():
            destination = prefix / 'share/licenses' / name / pin['version'] / 'LICENSE'
            destination.parent.mkdir(parents=True)
            shutil.copyfile(source / 'cmake/notices' / pin['notice_file'], destination)
        selection = {**notices, 'protocol': 'symphony.distribution.external-selection.v1',
                     'publication_authorized': False, 'runtime_tls_qualified': False,
                     'observation_scope': 'verified source and build-time selection; no TLS handshake, publisher approval or fresh-host acceptance',
                     'tls': tls, 'optional_curl_dependencies': {x: False for x in OFF_OPTIONS}, 'curl_zlib': False,
                     'linkage': {'curl': 'shared', 'zstd': 'static'},
                     'relocated_exports': report['relocated_exports']}
        selected = prefix / 'share/symphony/dependency-evidence/curl-zstd.json'
        selected.parent.mkdir(parents=True)
        selected.write_text(json.dumps(selection, indent=2) + '\n')
        report['inventory'] = inventory(prefix, (str(work).encode(), str(source).encode()))
        report.update(status='built_and_scanned', prefix=str(prefix), evidence=str(evidence), selection_sha256=digest(selected))
        save()
        return report
    except Exception as error:
        report.update(status='failed', failure=str(error))
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'curl-archive', 'zstd-archive', 'cmake', 'cc', 'cxx'):
        parser.add_argument('--' + name, required=True)
    for name in ('ssl-library', 'crypto-library', 'include-dir', 'version'):
        parser.add_argument('--openssl-' + name)
    parser.add_argument('--jobs', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--developer-dir')
    args = parser.parse_args()
    ssl = {name: getattr(args, 'openssl_' + name) for name in ('ssl_library', 'crypto_library', 'include_dir', 'version')}
    result = prepare(args.source, args.work, {'curl': args.curl_archive, 'zstd': args.zstd_archive}, cmake=args.cmake,
                     cc=args.cc, cxx=args.cxx, openssl=ssl if any(ssl.values()) else None, developer_dir=args.developer_dir,
                     jobs=args.jobs, timeout=args.timeout)
    print(json.dumps({key: result[key] for key in ('status', 'prefix', 'evidence')}))


if __name__ == '__main__':
    main()
