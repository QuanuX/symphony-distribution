#!/usr/bin/env python3
"""Explicit publisher-side Go carrier preparation and native owner materialization.

No product runtime Python dependency, service activation, user selection, sudo,
profile mutation, live raw cleanup, or automatic retry is provided here.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess

_spec = importlib.util.spec_from_file_location('s05_native_owners', Path(__file__).resolve().parents[1] / 'owner-catalog/native_owners.py')
owners = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(owners)
require, canonical, sha, strict_json = owners.require, owners.canonical, owners.sha, owners.strict_json
MANIFEST = 'symphony.distribution.go-carrier.v2'
CUSTODY = 'symphony.distribution.executable-custody.v1'
MAX_BINARY = 256 * 1024 * 1024
IDENTITY_FIELDS = set('protocol component_id version binary_name source_commit source_tree source_date_epoch dependency_map_sha256 release_identity_catalog_sha256 go_mod_sha256 go_sum_sha256 build_recipe go_version goos goarch executable_sha256 isolated_builds reproducibility publication_authorized'.split())
PRIVATE = (b'/Users/', b'/home/', b'SYMPHONY_PUBLISHER_WORKSPACE', b'SYMPHONY_PRIVATE_CANARY', b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----')


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)) and str(path) != '/', 'canonical absolute non-root path required')
    return path


def relative(name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and name and not p.is_absolute() and str(p) == name and '..' not in p.parts and '\\' not in name,
            'unsafe relative path')
    require(not any(x in p.parts for x in ('.git', '__pycache__', '.symphony-package-retirement', '.symphony-lifecycle.lock')),
            'host-local or build state cannot enter a carrier')
    return p


def directory(path):
    p = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular(path, *, linked=False, executable=False, limit=2 * 1024 * 1024):
    p = absolute(path)
    parent = directory(p.parent)
    try:
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and (linked or before.st_nlink == 1) and before.st_uid in (0, os.geteuid())
                and not stat.S_IMODE(before.st_mode) & 0o022 and not before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX),
                'file ownership, mode, kind or links are unsafe')
        require(0 < before.st_size <= limit and (not executable or before.st_mode & 0o111), 'file size or executable mode invalid')
        chunks = []
        size = 0
        while True:
            b = os.read(fd, min(1024 * 1024, limit + 1 - size))
            if not b:
                break
            chunks.append(b)
            size += len(b)
            require(size <= limit, 'file grew beyond bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink), 'file changed during read')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(fd)


def file_record(name, data, mode):
    return {'path': name, 'sha256': sha(data), 'size': len(data), 'mode': mode}


class Output:
    """Private new attempt pinned to its directory inode; never reuses old work."""
    def __init__(self, path, protected=()):
        self.path = absolute(path)
        for root in protected:
            root = absolute(root)
            require(self.path != root and root not in self.path.parents and self.path not in root.parents, 'output overlaps selected input or runtime root')
        parent = directory(self.path.parent)
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=parent)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.lock = os.open('LOCK', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(self.lock)
        os.fsync(self.fd)

    def check(self):
        current = directory(self.path)
        try:
            a, b = os.fstat(current), os.fstat(self.fd)
            require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'output root was replaced')
        finally:
            os.close(current)

    def write(self, name, data, mode=0o600):
        rel = relative(name)
        self.check()
        fd = os.dup(self.fd)
        try:
            for part in rel.parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                st = os.fstat(child)
                require(st.st_uid == os.geteuid() and not stat.S_IMODE(st.st_mode) & 0o077, 'private output directory changed')
                os.close(fd)
                fd = child
            target = os.open(rel.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(target, view)
                    require(n > 0, 'short write')
                    view = view[n:]
                os.fchmod(target, mode)
                os.fsync(target)
            finally:
                os.close(target)
            os.fsync(fd)
            self.check()
        finally:
            os.close(fd)

    def document(self, name, value):
        self.write(name, canonical(value) + b'\n')

    def mkdir(self, name):
        require(len(relative(name).parts) == 1, 'one output directory component required')
        self.check()
        os.mkdir(name, 0o700, dir_fd=self.fd)
        os.fsync(self.fd)
        self.check()
        return self.path / name

    def close(self):
        os.close(self.lock)
        os.close(self.fd)


def identity_check(identity, unit, binary, profile, binding):
    require(set(identity) == IDENTITY_FIELDS, 'closed build identity fields differ')
    require(identity['protocol'] == 'symphony.artifact-build-identity.v1' and
            identity['component_id'] == unit['component_id'] and identity['binary_name'] == unit['binary_name'] and
            identity['version'] == unit['native_version'], 'build component or native version differs')
    require(identity['source_commit'] == binding['source_commit'] and identity['source_tree'] == binding['source_tree'], 'build source differs from reviewed owner source')
    require(identity['go_version'] == 'go1.26.5' and (identity['goos'], identity['goarch']) == owners.PROFILES[profile][:2], 'toolchain or platform differs')
    require(identity['executable_sha256'] == sha(binary) and identity['publication_authorized'] is False, 'build bytes or publication state differs')
    recipe, count, reproduction = ('symphony.qxctl.reproducible-build.v1', 2, 'verified_on_recorded_profile') if unit['component_id'] == 'qxctl' else ('symphony.go.candidate-build.v1', 1, 'not_assessed')
    require(type(identity['isolated_builds']) is int and
            (identity['build_recipe'], identity['isolated_builds'], identity['reproducibility']) == (recipe, count, reproduction), 'unreviewed build recipe evidence')
    require(isinstance(identity['source_date_epoch'], str) and re.fullmatch(r'0|[1-9][0-9]*', identity['source_date_epoch']), 'invalid source epoch')
    source = {p['path']: p['sha256'] for p in binding['source_evidence']}
    fields = {'dependency_map_sha256': 'cmake/mvp-dependencies.json', 'release_identity_catalog_sha256': 'cmake/mvp-release-identities.json',
              'go_mod_sha256': unit['source_root'] + '/go.mod', 'go_sum_sha256': unit['source_root'] + '/go.sum'}
    for field, path in fields.items():
        require(identity[field] == source.get(path), 'build dependency/source evidence differs: ' + field)


def artifact_files(root, unit, linked=False):
    root = absolute(root)
    fd = directory(root)
    try:
        expected = {unit['binary_name'], 'artifact-identity.json', 'LICENSE-AGPL-3.0'}
        names = set(os.listdir(fd))
        require(names in (expected, expected | {'carrier-manifest.json'}), 'carrier contains missing/extra files or host-local state')
    finally:
        os.close(fd)
    result = {}
    for name in sorted(expected):
        binary = name == unit['binary_name']
        data, mode = regular(root / name, linked=linked, executable=binary, limit=MAX_BINARY if binary else 2 * 1024 * 1024)
        require(mode == (0o755 if binary else 0o644), 'carrier mode differs')
        require(not any(marker.lower() in data.lower() for marker in PRIVATE), 'publisher/private marker in carrier')
        result[name] = (data, mode)
    return result


def make_manifest(value, catalog_digest, component, root, profile, build_number, *, fixture=False, binding=None, linked=False):
    binding = owners.reviewed_binding() if binding is None else binding
    owners.validate_catalog(value, catalog_digest, binding)
    require(profile in owners.PROFILES and (profile != owners.FIXTURE_PROFILE or fixture), 'unqualified platform requires explicit fixture selection')
    require(type(build_number) is int and build_number >= 0, 'packaging build number invalid')
    unit = owners.unit(value, component)
    files = artifact_files(root, unit, linked)
    source = {row['path']: row['sha256'] for row in binding['source_evidence']}
    require(sha(files['LICENSE-AGPL-3.0'][0]) == source.get('LICENSE'), 'license differs from selected source')
    identity_check(strict_json(files['artifact-identity.json'][0]), unit, files[unit['binary_name']][0], profile, binding)
    manifest = {'schema': MANIFEST, 'format_version': 2, 'component_id': component, 'unit_id': unit['unit_id'],
                'kind': 'go_command', 'native_version': unit['native_version'], 'owner_contract': unit['owner_contract'],
                'definition_digest': unit['definition_digest'], 'catalog_digest': catalog_digest,
                'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
                'profile': profile, 'build_number': build_number, 'conda_name': unit['conda_name'],
                'conda_version': unit['conda_version'], 'conda_subdir': owners.PROFILES[profile][2],
                'files': [file_record(name, *files[name]) for name in sorted(files)],
                'fixture': fixture, 'publisher_trust_accepted': False, 'publication_authorized': False,
                'release_acceptance_complete': False}
    return owners.sealed(manifest, 'manifest_digest')


def verify_carrier(value, catalog_digest, root, expected, *, fixture=False, binding=None):
    data, _ = regular(absolute(root) / 'carrier-manifest.json', linked=True)
    manifest = strict_json(data)
    owners.validate_seal(manifest, 'manifest_digest', expected)
    actual = make_manifest(value, catalog_digest, manifest['component_id'], root, manifest['profile'], manifest['build_number'],
                           fixture=fixture, binding=binding, linked=True)
    require(actual == manifest, 'carrier inventory, owner, source or identity changed')
    return manifest, artifact_files(root, owners.unit(value, manifest['component_id']), linked=True)


def verify_receipt(prefix, manifest, unit):
    profile = owners.PROFILES[manifest['profile']]
    binary = next(f for f in manifest['files'] if f['path'] == unit['binary_name'])
    expected = owners.receipt_expected(unit['component_id'], binary['size'], binary['sha256'], profile[0], profile[1])
    receipt_relative = f"share/symphony/receipts/{unit['component_id']}/{unit['native_version']}/install-receipt.json"
    data, mode = regular(absolute(prefix) / receipt_relative)
    require(mode == 0o644 and strict_json(data) == expected, 'native owner receipt identity/content differs')
    installed, installed_mode = regular(absolute(prefix) / expected['files'][0]['path'], executable=True, limit=MAX_BINARY)
    require(installed_mode == 0o755 and sha(installed) == binary['sha256'] and len(installed) == binary['size'], 'native owner installed bytes differ')
    return {'receipt_relative': receipt_relative, 'receipt_digest': expected['receipt_digest'],
            'receipt_file_sha256': sha(data), 'binary_relative': expected['files'][0]['path'],
            'binary_sha256': binary['sha256']}


def materialize(value, catalog_digest, carrier, expected, output, *, install_native=False, fixture=False, binding=None):
    manifest, files = verify_carrier(value, catalog_digest, carrier, expected, fixture=fixture, binding=binding)
    component = manifest['component_id']
    unit = owners.unit(value, component)
    if install_native:
        require(component in owners.SERVICE_IDS and os.geteuid() != 0, 'native materialization supports the three user-owned installers only')
        host = ('darwin' if platform.system() == 'Darwin' else platform.system().lower(), {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine()))
        require(host == owners.PROFILES[manifest['profile']][:2], 'cannot execute a carrier for a different host')
    out = Output(output, [carrier])
    try:
        out.document('intent.json', {'protocol': 'symphony.distribution.go-materialization-intent.v1',
                     'manifest_digest': expected, 'catalog_digest': catalog_digest,
                     'operation': 'native_install' if install_native else 'retain_delivery',
                     'automatic_retry': False, 'runtime_selection_changed': False, 'publication_authorized': False})
        for name, (data, mode) in files.items():
            out.write('retained-carrier/' + name, data, mode)
        out.document('retained-carrier/carrier-manifest.json', manifest)
        retained = out.path / 'retained-carrier'
        verify_carrier(value, catalog_digest, retained, expected, fixture=fixture, binding=binding)
        executable = retained / unit['binary_name']
        out.check()
        result = {'protocol': CUSTODY, 'component_id': component, 'native_version': unit['native_version'],
                  'owner_contract': unit['owner_contract'], 'manifest_digest': expected, 'catalog_digest': catalog_digest,
                  'build_number': manifest['build_number'], 'source_commit': manifest['source_commit'],
                  'source_tree': manifest['source_tree'], 'retained_executable': str(executable),
                  'executable_sha256': sha(files[unit['binary_name']][0]), 'executable_size': len(files[unit['binary_name']][0]),
                  'retained_claim_ids': [], 'selection_owner': unit['selection_owner'],
                  'custody_only': True, 'native_receipt_created': False, 'runtime_installation': None,
                  'runtime_selection_changed': False, 'runtime_activation_changed': False,
                  'administrator_provisioned': False, 'live_raw_cleanup_supported': False,
                  'external_claim_coverage': 'not_asserted', 'private_operator_evidence': True,
                  'publication_authorized': False, 'release_acceptance_complete': False}
        if install_native:
            prefix = out.mkdir('installation')
            home = out.mkdir('private-install-home')
            argv = owners.install_argv(component, executable, prefix)
            out.document('owner-call.json', {'argv': argv, 'scope': 'fresh_stopped_install_only', 'automatic_retry': False})
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home), 'TMPDIR': str(home),
                   'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_STATE_HOME': str(home / 'state'), 'XDG_RUNTIME_DIR': str(home / 'runtime')}
            # This isolated environment is NEVER used for maintenance/removal.
            log = os.open('owner.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out.fd)
            try:
                with os.fdopen(log, 'wb') as stream:
                    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                               cwd=out.path, env=env, timeout=120, check=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(completed.returncode == 0, 'native owner failed; retain intent/logs and inspect, do not replay')
                out.check()
                evidence = verify_receipt(prefix, manifest, unit)
                verify_carrier(value, catalog_digest, retained, expected, fixture=fixture, binding=binding)
            except (OSError, ValueError, subprocess.SubprocessError):
                out.document('outcome-unknown.json', {'state': 'inspect_retained_owner_evidence', 'automatic_retry': False,
                              'runtime_selection_changed': False, 'recovery_source': str(executable)})
                raise
            result.update(custody_only=False, native_receipt_created=True,
                          runtime_installation={'prefix': str(prefix), **evidence})
        out.document('custody.json', owners.sealed(result, 'custody_digest'))
        return owners.sealed(result, 'custody_digest')
    finally:
        out.close()


def inspect_custody(value, catalog_digest, output, expected, *, fixture=False, binding=None):
    """Verify retained bytes without needing or trusting the original Conda carrier."""
    root = absolute(output)
    record = strict_json(regular(root / 'custody.json')[0])
    owners.validate_seal(record, 'custody_digest', expected)
    require(record['protocol'] == CUSTODY and record['catalog_digest'] == catalog_digest, 'custody protocol/catalog differs')
    unit = owners.unit(value, record['component_id'])
    retained = root / 'retained-carrier'
    manifest, files = verify_carrier(value, catalog_digest, retained, record['manifest_digest'], fixture=fixture, binding=binding)
    data = files[unit['binary_name']][0]
    executable = retained / unit['binary_name']
    # Retained custody must remain an independent inode even though Conda input
    # carriers are allowed to use their package cache's hardlinks.
    for name in files:
        regular(retained / name, executable=name == unit['binary_name'], limit=MAX_BINARY)
    require(record['retained_executable'] == str(executable) and record['executable_sha256'] == sha(data) and
            record['executable_size'] == len(data) and record['native_version'] == unit['native_version'] and
            record['owner_contract'] == unit['owner_contract'] and record['source_commit'] == manifest['source_commit'] and
            record['source_tree'] == manifest['source_tree'] and record['build_number'] == manifest['build_number'], 'custody path/bytes/owner/source differs')
    require(record['retained_claim_ids'] == [] and record['external_claim_coverage'] == 'not_asserted' and
            all(record[k] is False for k in ('runtime_selection_changed', 'runtime_activation_changed',
                'administrator_provisioned', 'live_raw_cleanup_supported', 'publication_authorized', 'release_acceptance_complete')),
            'custody claims unqualified runtime authority')
    require(type(record['native_receipt_created']) is bool, 'native receipt disposition is not boolean')
    if record['native_receipt_created']:
        require(unit['component_id'] in owners.SERVICE_IDS and record['custody_only'] is False, 'raw command cannot claim native receipt')
        prefix = root / 'installation'
        evidence = verify_receipt(prefix, manifest, unit)
        require(record['runtime_installation'] == {'prefix': str(prefix), **evidence}, 'native installation evidence differs')
    else:
        require(record['custody_only'] is True and record['runtime_installation'] is None, 'unexpected native runtime evidence')
    return record


def export_native(value, catalog_digest, custody_root, custody_digest, output, *, fixture=False, binding=None):
    """Export only exact receipt-owned bytes/receipt; never installation guards."""
    record = inspect_custody(value, catalog_digest, custody_root, custody_digest, fixture=fixture, binding=binding)
    require(record['native_receipt_created'] is True, 'raw executable custody has no receipt export')
    runtime = record['runtime_installation']
    prefix = Path(runtime['prefix'])
    unit = owners.unit(value, record['component_id'])
    manifest, _ = verify_carrier(value, catalog_digest, Path(custody_root) / 'retained-carrier', record['manifest_digest'],
                                 fixture=fixture, binding=binding)
    selected = []
    for field, limit in [('binary_relative', MAX_BINARY), ('receipt_relative', 2 * 1024 * 1024)]:
        name = runtime[field]
        data, mode = regular(prefix / name, limit=limit)
        selected.append((name, data, mode))
    out = Output(output, [custody_root])
    try:
        for name, data, mode in selected:
            out.write('payload/' + name, data, mode)
        verify_receipt(out.path / 'payload', manifest, unit)
        evidence = {'protocol': 'symphony.distribution.native-payload-export.v1', 'component_id': record['component_id'],
                    'custody_digest': custody_digest, 'manifest_digest': record['manifest_digest'],
                    'files': [file_record(name, data, mode) for name, data, mode in selected],
                    'retained_native_owner': record['retained_executable'],
                    'host_local_guard_exported': False, 'runtime_selection_changed': False,
                    'publication_authorized': False, 'private_operator_evidence': True}
        out.document('export.json', evidence)
        return evidence
    finally:
        out.close()


def refuse_cleanup(*_):
    raise ValueError('RAW_USE_OWNER_REQUIRED: custody is not proof of released clients, jobs, host fallbacks or arbitrary processes; preserve retained bytes')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=['manifest', 'retain', 'install-native', 'inspect', 'export-native', 'cleanup'])
    for name in ('catalog', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--carrier', type=Path)
    p.add_argument('--catalog-digest', required=True)
    p.add_argument('--manifest-digest')
    p.add_argument('--custody-digest')
    p.add_argument('--custody-root', type=Path)
    p.add_argument('--component')
    p.add_argument('--profile')
    p.add_argument('--build-number', type=int, default=0)
    p.add_argument('--fixture', action='store_true')
    args = p.parse_args()
    try:
        value = strict_json(regular(absolute(args.catalog))[0])
        if args.operation == 'cleanup':
            refuse_cleanup()
        elif args.operation == 'inspect':
            value = inspect_custody(value, args.catalog_digest, args.output, args.custody_digest, fixture=args.fixture)
        elif args.operation == 'export-native':
            require(args.custody_root is not None, 'explicit custody root required')
            value = export_native(value, args.catalog_digest, args.custody_root, args.custody_digest, args.output, fixture=args.fixture)
        elif args.operation == 'manifest':
            require(args.carrier is not None, 'explicit carrier path required')
            value = make_manifest(value, args.catalog_digest, args.component, args.carrier, args.profile, args.build_number, fixture=args.fixture)
            out = Output(args.output, [args.carrier, args.catalog])
            try:
                out.document('carrier-manifest.json', value)
            finally:
                out.close()
        else:
            require(args.carrier is not None, 'explicit carrier path required')
            require(args.manifest_digest, 'independently reviewed carrier digest required')
            value = materialize(value, args.catalog_digest, args.carrier, args.manifest_digest, args.output,
                                install_native=args.operation == 'install-native', fixture=args.fixture)
        print(json.dumps(value, sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        p.exit(2, 'REFUSED: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
