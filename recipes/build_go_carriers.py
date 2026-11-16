#!/usr/bin/env python3
"""Build and audit inert, source-bound Conda v2 Go carriers; never upload or activate."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('s06_go_recipe', HERE / 'go_generate.py')
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)
d = g.d
require, sha, canonical, strict_json = d.require, d.sha, d.canonical, d.strict_json
AUDITOR_SHA256 = sha(Path(__file__).read_bytes())
MAX_ARCHIVE = 512 * 1024 * 1024
INFO_NAMES = frozenset({'info/index.json', 'info/about.json', 'info/files', 'info/paths.json',
                        'info/hash_input.json', 'info/git', 'info/licenses/LICENSE-AGPL-3.0'})
PRIVATE = (b'/Users/', b'/home/', b'\\Users\\', b'SYMPHONY_PUBLISHER_WORKSPACE',
           b'SYMPHONY_PRIVATE_CANARY', b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----')


def privacy(data, *, forbidden=()):
    lower = data.lower()
    require(not any(x.lower() in lower for x in (*PRIVATE, *forbidden) if x), 'private/home/build path or secret marker in archive')


def safe_name(name):
    require(isinstance(name, str) and name and len(name) < 1024 and not any(ord(c) < 32 for c in name), 'invalid archive name')
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and '..' not in p.parts and '\\' not in name,
            'archive name escapes its root')
    return p


def validate_recipe(recipe, expected_manifest_digest, *, fixture=False):
    recipe = d.absolute(recipe)
    fd = d.directory(recipe)
    try:
        require(set(os.listdir(fd)) == {'LOCK', 'meta.yaml', 'stage_payload.py', 'recipe-evidence.json', 'payload'}, 'unexpected recipe files')
    finally:
        os.close(fd)
    raw, _ = d.regular(recipe / 'payload/carrier-manifest.json')
    manifest = strict_json(raw)
    d.owners.validate_seal(manifest, 'manifest_digest', expected_manifest_digest)
    catalog = strict_json((HERE.parent / 'go-owner-catalog.json').read_bytes())
    manifest, _ = d.verify_carrier(catalog, manifest['catalog_digest'], recipe / 'payload', expected_manifest_digest,
                                   fixture=fixture, binding=d.owners.reviewed_binding())
    require(type(manifest['fixture']) is bool and (not manifest['fixture'] or fixture), 'fixture archive requires explicit fixture selection')
    require(manifest['profile'] != d.owners.FIXTURE_PROFILE or manifest['fixture'], 'unqualified profile must remain a fixture')
    require(all(manifest[k] is False for k in ('publisher_trust_accepted', 'publication_authorized', 'release_acceptance_complete')),
            'carrier cannot assert publication or acceptance')
    meta, stage, manifest_bytes, record = g.recipe_documents(manifest)
    require(raw == manifest_bytes, 'noncanonical carrier manifest')
    for name, expected in [('meta.yaml', meta), ('stage_payload.py', stage), ('recipe-evidence.json', canonical(record) + b'\n')]:
        data, _ = d.regular(recipe / name)
        require(data == expected, 'generated recipe or staging code differs: ' + name)
    files = d.artifact_files(recipe / 'payload', d.owners.OWNERS[manifest['component_id']])
    expected_rows = [d.file_record(name, *files[name]) for name in sorted(files)]
    require(manifest['files'] == expected_rows, 'manifest payload inventory differs')
    identity = strict_json(files['artifact-identity.json'][0])
    unit = d.owners.OWNERS[manifest['component_id']]
    require(set(identity) == d.IDENTITY_FIELDS and identity['component_id'] == manifest['component_id'] and
            identity['version'] == manifest['native_version'] and identity['source_commit'] == manifest['source_commit'] and
            identity['source_tree'] == manifest['source_tree'] and identity['binary_name'] == unit['binary_name'] and
            identity['executable_sha256'] == sha(files[unit['binary_name']][0]) and identity['publication_authorized'] is False,
            'artifact source/native identity differs')
    require(files['LICENSE-AGPL-3.0'][0] == (HERE.parent / 'LICENSE').read_bytes(), 'license differs from repository AGPL text')
    files['carrier-manifest.json'] = (manifest_bytes, 0o644)
    expected = {record['carrier_destination'] + '/' + name: value for name, value in files.items()}
    return manifest, record, expected


def audit_entries(entries, manifest, record, expected, *, allow_conda_mode_expansion=False, forbidden=()):
    """Pure audit core: name -> (bytes, mode); used by real archive and unit tests."""
    require(set(entries) == set(expected) | INFO_NAMES, 'archive has missing/extra files, hooks, recipes, or runtime state')
    for name, (data, mode) in entries.items():
        safe_name(name)
        privacy(name.encode() + b'\n' + data, forbidden=forbidden)
        want_mode = expected[name][1] if name in expected else 0o644
        allowed_modes = {want_mode, want_mode | 0o020} if allow_conda_mode_expansion and name in expected else {want_mode}
        require(mode in allowed_modes, 'archive file mode differs: ' + name)
        if name in expected:
            require(data == expected[name][0], 'archive payload differs from selected carrier: ' + name)
    index = strict_json(entries['info/index.json'][0])
    allowed_index = {'arch', 'build', 'build_number', 'depends', 'license', 'name', 'platform', 'subdir', 'timestamp', 'version'}
    require(set(index) == allowed_index, 'unexpected Conda index fields')
    platform, architecture = {'osx-64': ('osx', 'x86_64'), 'osx-arm64': ('osx', 'arm64'),
                              'linux-64': ('linux', 'x86_64'), 'linux-aarch64': ('linux', 'aarch64')}[manifest['conda_subdir']]
    require(index['name'] == manifest['conda_name'] and index['version'] == manifest['conda_version'] and
            index['build'] == record['build_string'] and index['build_number'] == manifest['build_number'] and
            type(index['build_number']) is int and index['depends'] == [] and index['license'] == 'AGPL-3.0-only' and
            (index['platform'], index['arch'], index['subdir']) == (platform, architecture, manifest['conda_subdir']) and
            type(index['timestamp']) is int and index['timestamp'] > 0, 'Conda package identity, platform or dependencies differ')
    files = entries['info/files'][0].decode().splitlines()
    require(len(files) == len(set(files)) and set(files) == set(expected), 'Conda file inventory differs')
    paths = strict_json(entries['info/paths.json'][0])
    require(set(paths) == {'paths', 'paths_version'} and paths['paths_version'] == 1 and
            isinstance(paths['paths'], list) and len(paths['paths']) == len(expected), 'Conda path inventory differs')
    seen = set()
    for row in paths['paths']:
        require(set(row) == {'_path', 'path_type', 'sha256', 'size_in_bytes'}, 'prefix replacement/link metadata is forbidden')
        name = row['_path']
        require(name in expected and name not in seen and row['path_type'] == 'hardlink' and
                row['sha256'] == sha(expected[name][0]) and row['size_in_bytes'] == len(expected[name][0]), 'Conda path content differs')
        seen.add(name)
    require(entries['info/licenses/LICENSE-AGPL-3.0'][0] == expected[record['carrier_destination'] + '/LICENSE-AGPL-3.0'][0], 'archive license differs')
    require(entries['info/git'][0] == b'', 'publisher Git/worktree details entered archive')
    require(strict_json(entries['info/hash_input.json'][0]) == {}, 'unexpected build variant metadata')
    about = strict_json(entries['info/about.json'][0])
    require(set(about) == {'channels', 'conda_build_version', 'conda_version', 'env_vars', 'extra', 'identifiers', 'keywords',
                           'license', 'license_file', 'root_pkgs', 'summary', 'tags'}, 'unexpected publisher metadata')
    require(about['channels'] == [] and about['env_vars'] == {'CIO_TEST': '<not set>'} and
            about['conda_version'] == '26.10.0' and about['conda_build_version'] == '26.9.1' and
            all(about[x] == [] for x in ('identifiers', 'keywords', 'tags')) and about['license'] == 'AGPL-3.0-only' and
            about['license_file'] == 'LICENSE-AGPL-3.0' and
            about['summary'] == 'Inert Symphony ' + manifest['component_id'] + ' payload; explicit owner materialization required',
            'publisher metadata, tools, or license differs')
    require(isinstance(about['root_pkgs'], list) and all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_.-]+ [A-Za-z0-9_.+!-]+ [A-Za-z0-9_.-]+', x)
                                                       for x in about['root_pkgs']), 'publisher package inventory contains uncontrolled values')
    require(about['extra'] == {'copy_test_source_files': True, 'final': True, 'fixture': manifest['fixture'],
                               'native_version': manifest['native_version'], 'owner_contract': manifest['owner_contract'],
                               'publication_authorized': False, 'runtime_activation': False, 'runtime_python_dependency': False,
                               'target_subdir': manifest['conda_subdir']}, 'archive extra metadata differs')
    return {'protocol': 'symphony.distribution.conda-go-archive-audit.v1', 'component_id': manifest['component_id'],
            'source_commit': manifest['source_commit'], 'source_tree': manifest['source_tree'],
            'manifest_digest': manifest['manifest_digest'], 'catalog_digest': manifest['catalog_digest'],
            'native_version': manifest['native_version'], 'conda_name': manifest['conda_name'], 'conda_version': manifest['conda_version'],
            'build_number': manifest['build_number'], 'build_string': record['build_string'], 'subdir': manifest['conda_subdir'],
            'fixture': manifest['fixture'], 'payload_file_count': len(expected), 'metadata_file_count': len(INFO_NAMES),
            'exact_payload_verified': True, 'personal_paths_absent': True, 'host_state_absent': True,
            'recipe_included': False, 'runtime_dependencies': [], 'lifecycle_hooks': [], 'native_install_owner_invoked': False,
            'publication_authorized': False, 'publisher_trust_accepted': False, 'fresh_host_accepted': False}


def validate_zip_layout(raw, zipped):
    """Reject hidden ZIP prefix/tail/comment/extra data before decompression."""
    offset = 0
    for info in sorted(zipped.infolist(), key=lambda item: item.header_offset):
        require(info.header_offset == offset and info.extra == b'' and info.comment == b'' and info.flag_bits == 0,
                'uncontrolled ZIP header, gap or extra metadata')
        require(raw[offset:offset + 4] == b'PK\x03\x04', 'invalid local ZIP header')
        name_size, extra_size = struct.unpack_from('<HH', raw, offset + 26)
        name = raw[offset + 30:offset + 30 + name_size]
        require(name == info.filename.encode('ascii'), 'ZIP member identity differs')
        extra = raw[offset + 30 + name_size:offset + 30 + name_size + extra_size]
        require(extra in (b'', struct.pack('<HHQQ', 1, 16, info.file_size, info.compress_size)),
                'uncontrolled local ZIP metadata')
        offset += 30 + name_size + extra_size + info.compress_size
    require(offset == zipped.start_dir and len(raw) >= 22 and raw[-22:-18] == b'PK\x05\x06',
            'ZIP contains unaccounted prefix/tail data')
    disk, central_disk, on_disk, total, size, start, comment = struct.unpack_from('<HHHHIIH', raw, len(raw) - 18)
    require((disk, central_disk, on_disk, total, start, comment) == (0, 0, 3, 3, zipped.start_dir, 0) and
            start + size == len(raw) - 22, 'ZIP central directory boundary differs')


def archive_entries(archive):
    """Stream both tar components without extracting any archive-controlled path."""
    from conda_package_streaming.package_streaming import stream_conda_component
    archive = d.absolute(archive)
    raw, _ = d.regular(archive, limit=MAX_ARCHIVE)
    require(archive.name.endswith('.conda'), 'only Conda v2 archives are qualified')
    dist = archive.name[:-6]
    require(re.fullmatch(r'[a-zA-Z0-9_.-]+', dist), 'invalid Conda archive filename')
    wanted = {'metadata.json', 'info-' + dist + '.tar.zst', 'pkg-' + dist + '.tar.zst'}
    entries = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
        require(len(zipped.infolist()) == 3 and set(zipped.namelist()) == wanted and zipped.comment == b'', 'invalid Conda ZIP inventory')
        for info in zipped.infolist():
            require(info.compress_type == zipfile.ZIP_STORED and not info.flag_bits & 1 and not info.comment and info.file_size <= MAX_ARCHIVE,
                    'unexpected ZIP encoding or metadata')
        require(strict_json(zipped.read('metadata.json')) == {'conda_pkg_format_version': 2}, 'Conda format differs')
        validate_zip_layout(raw, zipped)
        total = 0
        for component in ('info', 'pkg'):
            for tar, member in stream_conda_component(archive, component=component, zf=zipped):
                name = member.name
                require(not tar.pax_headers, 'global archive metadata is forbidden')
                safe_name(name)
                require(name not in entries and member.isfile() and not member.linkname and
                        member.uid == member.gid == 0 and member.uname == member.gname == '', 'archive link, duplicate, user, or special file')
                require(set(member.pax_headers) <= {'path', 'mtime'} and
                        ('path' not in member.pax_headers or member.pax_headers['path'] == name) and
                        ('mtime' not in member.pax_headers or re.fullmatch(r'[0-9]{1,16}(?:\.[0-9]{1,9})?', member.pax_headers['mtime'])),
                        'uncontrolled tar metadata')
                require((component == 'info') == name.startswith('info/'), 'Conda component boundary differs')
                require(0 <= member.size <= d.MAX_BINARY and total + member.size <= MAX_ARCHIVE and len(entries) < 32, 'archive exceeds bound')
                data = tar.extractfile(member).read(member.size + 1)
                require(len(data) == member.size, 'truncated tar member')
                entries[name] = (data, member.mode)
                total += member.size
    return entries, sha(raw), len(raw)


def audit_archive(archive, recipe, *, expected_manifest_digest, fixture=False, forbidden=()):
    manifest, record, expected = validate_recipe(recipe, expected_manifest_digest, fixture=fixture)
    entries, digest, size = archive_entries(archive)
    require(Path(archive).name == manifest['conda_name'] + '-' + manifest['conda_version'] + '-' + record['build_string'] + '.conda', 'archive filename differs')
    result = audit_entries(entries, manifest, record, expected, forbidden=forbidden)
    return {**result, 'archive_filename': Path(archive).name, 'archive_sha256': digest, 'archive_size': size, 'auditor_sha256': AUDITOR_SHA256}


def run_owned(command, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600):
    """Bound and reap only the publisher process group created by this call."""
    process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
    try:
        output, error = process.communicate(timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, output, error)
    except subprocess.TimeoutExpired:
        # A leader exiting on TERM does not prove that descendants stopped.
        # Signal the entire owned group before reaping its leader, including
        # descendants that ignore TERM while their output is redirected.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
        raise ValueError('publisher operation timed out; owned process group killed, private work retained')


def snapshot_recipe(manifest, record, expected, path):
    """Freeze reviewed instructions and payload before running publisher tools."""
    meta, stage, manifest_bytes, again = g.recipe_documents(manifest)
    require(again == record, 'renderer changed before recipe snapshot')
    prefix = record['carrier_destination'] + '/'
    snapshot = d.Output(path)
    try:
        snapshot.write('meta.yaml', meta, 0o644)
        snapshot.write('stage_payload.py', stage, 0o644)
        snapshot.document('recipe-evidence.json', record)
        for name, (data, mode) in expected.items():
            require(name.startswith(prefix), 'snapshot payload escaped selected carrier')
            relative = name[len(prefix):]
            require('/' not in relative and relative, 'unexpected nested Go carrier payload')
            snapshot.write('payload/' + relative, data, mode)
        require(expected[prefix + 'carrier-manifest.json'][0] == manifest_bytes, 'snapshot manifest differs')
    finally:
        snapshot.close()
    return path


def build_recipe(recipe, output, *, expected_manifest_digest, fixture=False, python=None):
    recipe, output = d.absolute(recipe), d.absolute(output)
    interpreter = Path(python or sys.executable).resolve()
    if interpreter != Path(sys.executable).resolve():
        cmd = [str(interpreter), str(Path(__file__).resolve()), 'build', '--recipe', str(recipe), '--output', str(output),
               '--manifest-digest', expected_manifest_digest]
        if fixture:
            cmd.append('--fixture')
        run = run_owned(cmd, timeout=900)
        require(run.returncode == 0, run.stderr.decode(errors="replace"))
        return strict_json(run.stdout)
    manifest, record, expected = validate_recipe(recipe, expected_manifest_digest, fixture=fixture)
    import conda
    import conda_build
    import conda_package_handling.api as package_api
    require((conda.__version__, conda_build.__version__) == ('26.10.0', '26.9.1'), 'unqualified publisher tool versions')
    out = d.Output(output, [recipe])
    # The workspace is deliberately neutral and outside both recipe and public
    # output. Retain it on failure; no unqualified archive enters the output.
    work = Path(tempfile.mkdtemp(prefix='symphony-conda-build-', dir=Path('/tmp').resolve())).resolve()
    try:
        out.document('build-intent.json', {'protocol': 'symphony.distribution.conda-build-intent.v1',
                     'manifest_digest': expected_manifest_digest, 'source_commit': manifest['source_commit'],
                     'private_work_directory': str(work), 'state': 'prepared', 'publication_authorized': False})
        frozen_recipe = snapshot_recipe(manifest, record, expected, work / 'recipe')
        home, temp = work / 'home', work / 'tmp'
        home.mkdir(); temp.mkdir()
        config = home / 'condarc'
        config.write_text('channels: []\nreport_errors: false\nanaconda_upload: false\n')
        env = {'HOME': str(home), 'PATH': str(interpreter.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
               'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'TMPDIR': str(temp), 'TEMP': str(temp), 'TMP': str(temp),
               'USER': 'builder', 'LOGNAME': 'builder', 'CONDARC': str(config), 'CONDA_OFFLINE': 'true',
               'CONDA_SUBDIR': manifest['conda_subdir'], 'CONDA_PKGS_DIRS': str(work / 'pkgs'),
               'CONDA_ENVS_PATH': str(work / 'envs'), 'CONDA_REPORT_ERRORS': 'false',
               'CONDA_NO_PLUGINS': 'true', 'CONDA_SOLVER': 'classic',
               'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
        command = [str(interpreter), '-c',
                   'from conda_build.cli.main_build import execute; raise SystemExit(execute())', '--no-anaconda-upload', '--no-include-recipe',
                   '--no-test', '--package-format', '2', '--croot', str(work / 'build'),
                   '--output-folder', str(work / 'packages'), str(frozen_recipe)]
        with (work / 'build.log').open('wb') as log:
            run = run_owned(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        require(run.returncode == 0, 'Conda build failed; private workspace retained at ' + str(work))
        archives = list((work / 'packages').rglob('*.conda'))
        require(len(archives) == 1, 'build did not produce exactly one archive; private work retained at ' + str(work))
        raw_entries, raw_digest, _ = archive_entries(archives[0])
        forbidden = (str(work).encode(), str(recipe).encode(), str(interpreter.parent.parent).encode())
        audit_entries(raw_entries, manifest, record, expected, allow_conda_mode_expansion=True, forbidden=forbidden)
        # conda-build expands group write permissions. Restore only the closed
        # manifest modes, preserve every content byte, and package with Conda's
        # official v2 writer; this creates no hooks or publisher metadata.
        normalized = d.Output(work / 'normalized')
        try:
            for name, (data, _) in raw_entries.items():
                normalized.write(name, data, expected[name][1] if name in expected else 0o644)
        finally:
            normalized.close()
        (work / 'final').mkdir(mode=0o700)
        package_api.create(str(work / 'normalized'), sorted(raw_entries), archives[0].name, out_folder=str(work / 'final'))
        final = work / 'final' / archives[0].name
        result = audit_archive(final, frozen_recipe, expected_manifest_digest=expected_manifest_digest, fixture=fixture, forbidden=forbidden)
        result.update({'raw_conda_archive_sha256': raw_digest, 'manifest_modes_restored': True,
                       'publisher_conda_version': conda.__version__, 'publisher_conda_build_version': conda_build.__version__,
                       'packaging_build_only': True, 'native_binaries_rebuilt': False})
        data, _ = d.regular(final, limit=MAX_ARCHIVE)
        require(sha(data) == result['archive_sha256'] and len(data) == result['archive_size'], 'audited archive changed before output')
        out.write(final.name, data, 0o644)
        out.document('archive-audit.json', result)
        out.write('build.log', (work / 'build.log').read_bytes())
        return result
    finally:
        out.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['build', 'audit'])
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--manifest-digest', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--python', type=Path)
    parser.add_argument('--fixture', action='store_true')
    args = parser.parse_args()
    try:
        if args.operation == 'build':
            require(args.output is not None and args.archive is None, 'build requires only --output')
            result = build_recipe(args.recipe, args.output, expected_manifest_digest=args.manifest_digest, fixture=args.fixture, python=args.python)
        else:
            require(args.archive is not None and args.output is None, 'audit requires only --archive')
            result = audit_archive(args.archive, args.recipe, expected_manifest_digest=args.manifest_digest, fixture=args.fixture)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, ImportError, subprocess.CalledProcessError) as error:
        parser.exit(2, 'REFUSED: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
