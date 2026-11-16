#!/usr/bin/env python3
"""Bounded Conda 26.10.0 carrier transactions in newly owned private prefixes.

This is publisher/qualification tooling, not a Symphony runtime dependency or a
wrapper for arbitrary user environments. A live Attempt is the only authority to
its newly created prefix. It cannot be reopened, adopted, or replayed after an
uncertain outcome. Conda has no general prefix transaction lock; exclusive private
custody is a precondition, not a promise about unrelated Conda clients.
"""
from __future__ import annotations

import argparse
import errno
from contextlib import contextmanager, redirect_stdout
import fcntl
from functools import wraps
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
import uuid
import zipfile

PINNED_CONDA = '26.10.0'
IDENTITY_FIELDS = ('name', 'version', 'build', 'build_number', 'subdir', 'filename', 'sha256', 'md5', 'depends', 'constrains')
TOKEN = re.compile(r'^[A-Za-z0-9_.+-]+$')
NAME = re.compile(r'^[a-z0-9][a-z0-9_.-]*$')
_CONTEXT_LOCK = threading.Lock()


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def _json(data):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'Duplicate JSON field')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs)


def _relative(name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and str(p) == name and not p.is_absolute() and
            '..' not in p.parts and '\\' not in name and name not in ('', '.'), 'Unsafe relative path')
    return p


def _absolute(path):
    p = Path(os.path.abspath(path))
    for parent in reversed((p, *p.parents)):
        require(not parent.is_symlink(), 'Symlink in owned path')
    return p


def _file(path):
    """Open a trusted regular file without following a final symlink."""
    path = _absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_mode & 0o022:
        os.close(fd)
        raise Refused('File must be regular, independent and not writable by others')
    return os.fdopen(fd, 'rb')


def _hash_file(path):
    with _file(path) as source:
        h = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
        s = os.fstat(source.fileno())
        return {'sha256': h.hexdigest(), 'size': s.st_size, 'mode': stat.S_IMODE(s.st_mode)}


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_dir(Path(path).parent)


def _read_small(path, limit=16 * 1024 * 1024):
    with _file(path) as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, 'Oversized metadata')
    return data


def artifact_identity(archive):
    """Inspect a .conda carrier without extracting it or executing package code.

    Returns portable complete package identity plus exact payload hashes. The
    caller must review this identity; it is not a publisher signature/trust grant.
    """
    from conda_package_streaming.package_streaming import stream_conda_component
    archive = _absolute(archive)
    require(archive.name.endswith('.conda'), 'Only reviewed .conda carriers are supported')
    files, metadata, carrier_metadata = {}, {}, {}
    with _file(archive) as source:
        before = os.fstat(source.fileno())
        digest, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
            md5.update(chunk)
        source.seek(0)
        with zipfile.ZipFile(source) as zf:
            stem = archive.name[:-6]
            require(sorted(zf.namelist()) == sorted(['metadata.json', f'info-{stem}.tar.zst', f'pkg-{stem}.tar.zst']),
                    'Unexpected archive components')
            require(_json(zf.read('metadata.json')).get('conda_pkg_format_version') == 2, 'Unsupported Conda archive format')
            for component in ('info', 'pkg'):
                seen = set()
                for tar, member in stream_conda_component(str(archive), component=component, zf=zf):
                    name = member.name.rstrip('/') if member.isdir() else member.name
                    _relative(name)
                    require(name not in seen, 'Duplicate archive path')
                    seen.add(name)
                    require(member.isfile() or member.isdir(), 'Archive links/devices are forbidden')
                    require(not member.mode & 0o7022, 'Unsafe archive permissions')
                    if component == 'info':
                        require(name == 'info' or name.startswith('info/'), 'Unexpected metadata path')
                        if member.isfile() and name in ('info/index.json', 'info/paths.json', 'info/files', 'info/has_prefix', 'info/link.json'):
                            require(member.size <= 16 * 1024 * 1024, 'Oversized archive metadata')
                            metadata[name] = tar.extractfile(member).read()
                        require(not name.startswith(('info/prelink_messages', 'info/menu')), 'Interactive package metadata is forbidden')
                    else:
                        require(name == 'share' or name == 'share/symphony' or name == 'share/symphony/carriers' or
                                name.startswith('share/symphony/carriers/'), 'Package may write only inert carrier payloads')
                        if member.isfile():
                            parts = PurePosixPath(name).parts
                            require(len(parts) == 7 and all(TOKEN.fullmatch(x) for x in parts[3:]), 'Unexpected carrier layout')
                            tail = '/'.join(parts[6:])
                            h = hashlib.sha256()
                            stream = tar.extractfile(member)
                            saved = []
                            if tail == 'carrier-manifest.json':
                                require(member.size <= 1024 * 1024, 'Oversized carrier manifest')
                            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                                h.update(chunk)
                                if tail == 'carrier-manifest.json':
                                    saved.append(chunk)
                            if tail == 'carrier-manifest.json':
                                carrier_metadata[name] = _json(b''.join(saved))
                            files[name] = {'sha256': h.hexdigest(), 'size': member.size, 'mode': member.mode & 0o777}
        after = os.fstat(source.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Archive changed while inspected')
    index = _json(metadata['info/index.json'])
    for field in ('name', 'version', 'build', 'subdir'):
        require(isinstance(index[field], str) and TOKEN.fullmatch(index[field]), 'Invalid identity token')
    require(NAME.fullmatch(index['name']), 'Invalid package name')
    require(isinstance(index['build_number'], int) and index['build_number'] >= 0, 'Invalid build number')
    require(archive.name == f"{index['name']}-{index['version']}-{index['build']}.conda", 'Filename and package identity differ')
    require(not index.get('noarch') and not index.get('features') and not index.get('track_features'), 'Noarch/features are outside carrier policy')
    require(not metadata.get('info/has_prefix', b'').strip(), 'Prefix replacement is forbidden')
    require(not metadata.get('info/link.json'), 'Link scripts/entrypoints are forbidden')
    require(bool(files), 'Empty carrier payload')
    roots = {'/'.join(PurePosixPath(name).parts[:6]) for name in files}
    require(len(roots) == 1, 'A carrier must own exactly one immutable package directory')
    carrier_root = next(iter(roots))
    manifest = carrier_metadata.get(carrier_root + '/carrier-manifest.json')
    require(manifest and manifest.get('schema') == 'symphony.distribution.go-carrier.v2' and manifest.get('format_version') == 2,
            'Source-bound Go carrier manifest required')
    require((manifest['conda_name'], manifest['conda_version'], manifest['conda_subdir'], manifest['build_number']) ==
            (index['name'], index['version'], index['subdir'], index['build_number']), 'Carrier and Conda identity differ')
    require(manifest['component_id'] == carrier_root.split('/')[3] and manifest['native_version'] == carrier_root.split('/')[4],
            'Carrier directory and owner identity differ')
    manifest_rows = manifest['files']
    require(len(manifest_rows) == 3 and len(files) == 4, 'Carrier must contain exactly the reviewed four files')
    payload_names = {r['path'] for r in manifest_rows}
    require(len(payload_names) == 3 and {'artifact-identity.json', 'LICENSE-AGPL-3.0'} <= payload_names,
            'Carrier source/license/binary inventory differs')
    for row in manifest_rows:
        require(TOKEN.fullmatch(row['path']) and row['path'] != 'carrier-manifest.json' and
                files.get(carrier_root + '/' + row['path']) == {k: row[k] for k in ('sha256', 'size', 'mode')},
                'Carrier manifest payload hash/size/mode differs')
    unsigned = dict(manifest)
    claimed = unsigned.pop('manifest_digest', None)
    require(claimed == 'sha256:' + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
            'Carrier manifest digest differs')
    paths = _json(metadata['info/paths.json'])
    require(paths.get('paths_version') == 1, 'Unsupported archive paths format')
    expected = {}
    for row in paths['paths']:
        name = row['_path']
        require(name not in expected and row['path_type'] == 'hardlink' and not row.get('prefix_placeholder'), 'Unsafe/duplicate package path')
        expected[name] = {'sha256': row['sha256'], 'size': row['size_in_bytes']}
    require(set(expected) == set(files) == set(metadata['info/files'].decode().splitlines()), 'Package file inventories disagree')
    require(all(expected[k] == {x: files[k][x] for x in ('sha256', 'size')} for k in files), 'Archive payload hash differs from paths metadata')
    return {**{k: index[k] for k in ('name', 'version', 'build', 'build_number', 'subdir')},
            'filename': archive.name, 'sha256': digest.hexdigest(), 'md5': md5.hexdigest(),
            'depends': sorted(index.get('depends', [])), 'constrains': sorted(index.get('constrains', [])), 'files': files}


def _key(identity):
    return (identity['name'], identity['version'], identity['build'], identity['subdir'], identity['sha256'])


def _core(identity):
    return {k: identity[k] for k in IDENTITY_FIELDS}


def _record(record):
    if not isinstance(record, dict):
        record = record.dump()
    return {k: (record.get('fn') if k == 'filename' else sorted(record.get(k, [])) if k in ('depends', 'constrains') else record.get(k))
            for k in IDENTITY_FIELDS}


def _snapshot(root):
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            p = Path(folder) / name
            require(not p.is_symlink(), 'Symlink directory in private prefix')
        for name in files:
            p = Path(folder) / name
            result[p.relative_to(root).as_posix()] = _hash_file(p)
    return result


def _single_owner(method):
    """Reject a competing caller before it can change attempt state/evidence."""
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self._exclusive():
            try:
                return method(self, *args, **kwargs)
            except BaseException:
                # Includes failures while creating the durable intent, before
                # the method's execution/outcome handler has been entered.
                self.poisoned = True
                raise
    return guarded


class Attempt:
    """Fresh private carrier prefix; all files/evidence persist on close or failure."""
    def __init__(self):
        raise Refused('Use Attempt.create; existing prefixes cannot be adopted')

    @classmethod
    def create(cls, new_attempt_root, local_channel_root, subdir):
        import conda
        require(conda.__version__ == PINNED_CONDA, 'Pinned Conda version required')
        require(subdir in ('osx-64', 'osx-arm64', 'linux-64', 'linux-aarch64'), 'Unsupported platform')
        root, channel = _absolute(new_attempt_root), _absolute(local_channel_root)
        require(not root.exists(), 'Existing attempt/prefix adoption is forbidden')
        require(channel.is_dir() and root not in channel.parents and channel not in root.parents, 'Channel and attempt must be separate')
        root.mkdir(mode=0o700)
        obj = object.__new__(cls)
        obj.root, obj.prefix, obj.channel, obj.subdir = root, root / 'prefix', root / 'channel', subdir
        obj.poisoned, obj.closed, obj.sequence = False, False, 0
        obj._creator_pid, obj._operation_lock = os.getpid(), threading.Lock()
        obj.catalog, obj.installed, obj.previous_snapshot = {}, {}, {}
        obj._lock, obj._lock_identity, obj._directory_identities = None, None, {}
        obj._root_identity = root.stat().st_dev, root.stat().st_ino
        try:
            obj._lock = os.open(root / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            obj._lock_identity = os.fstat(obj._lock).st_dev, os.fstat(obj._lock).st_ino
            fcntl.flock(obj._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for p in ('prefix', 'channel', 'cache', 'home', 'envs', 'evidence'):
                (root / p).mkdir(mode=0o700)
            (obj.prefix / 'conda-meta').mkdir(mode=0o700)
            _write_new(obj.prefix / 'conda-meta/history', b'')
            obj._prefix_identity = obj.prefix.stat().st_dev, obj.prefix.stat().st_ino
            obj._cache_identity = (root / 'cache').stat().st_dev, (root / 'cache').stat().st_ino
            obj._directory_identities = {name: ((root / name).stat().st_dev, (root / name).stat().st_ino)
                                         for name in ('channel', 'cache', 'home', 'envs', 'evidence', 'prefix/conda-meta')}
            _write_new(root / 'ATTEMPT.json', canonical({'protocol': 'symphony.conda.private-attempt.v1', 'id': str(uuid.uuid4()),
                'conda_version': PINNED_CONDA, 'subdir': subdir, 'reopen_supported': False,
                'boundary': 'new private carrier prefix; no arbitrary environment or concurrent external writer guarantee'}))
            for target in (subdir, 'noarch'):
                out = obj.channel / target
                out.mkdir(mode=0o700)
                records = {}
                incoming = channel / target
                require(incoming.is_dir() and not incoming.is_symlink(), 'Local channel subdir missing')
                repodata = _json(_read_small(incoming / 'repodata.json'))
                require(not repodata.get('packages'), 'Legacy tar packages are outside this gate')
                for filename, record in repodata.get('packages.conda', {}).items():
                    require(Path(filename).name == filename and filename.endswith('.conda'), 'Unsafe channel filename')
                    path = incoming / filename
                    identity = artifact_identity(path)
                    require(identity['subdir'] == target and target == subdir, 'Noarch/foreign-platform packages are forbidden')
                    require(record.get('sha256') == identity['sha256'], 'Repodata archive hash differs')
                    normalized = _record({**record, 'fn': filename, 'subdir': target})
                    require(normalized == _core(identity), 'Repodata package identity differs from archive')
                    destination = out / filename
                    with _file(path) as source:
                        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, 'wb') as dest:
                            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                                dest.write(chunk)
                            dest.flush()
                            os.fsync(dest.fileno())
                    require(_hash_file(destination)['sha256'] == identity['sha256'], 'Channel changed during private copy')
                    require(identity['filename'] not in obj.catalog, 'Duplicate package filename')
                    obj.catalog[filename] = identity
                    records[filename] = {k: identity[k] for k in ('name', 'version', 'build', 'build_number', 'subdir', 'sha256', 'md5', 'depends', 'constrains')}
                    records[filename]['size'] = destination.stat().st_size
                _write_new(out / 'repodata.json', canonical({'info': {'subdir': target}, 'packages': {}, 'packages.conda': records, 'repodata_version': 1}))
            obj._channel_snapshot = _snapshot(obj.channel)
            obj.previous_snapshot = _snapshot(obj.prefix)
            return obj
        except BaseException as exc:
            obj.poisoned = True
            try:
                _absolute(root)
                held_root = root.lstat()
                require((held_root.st_dev, held_root.st_ino) == obj._root_identity and
                        held_root.st_uid == os.geteuid() and not held_root.st_mode & 0o077,
                        'Cannot write failure evidence outside retained custody')
                folder = root
                if 'evidence' in obj._directory_identities:
                    evidence = _absolute(root / 'evidence')
                    held_evidence = evidence.lstat()
                    if ((held_evidence.st_dev, held_evidence.st_ino) == obj._directory_identities['evidence'] and
                            held_evidence.st_uid == os.geteuid() and not held_evidence.st_mode & 0o077):
                        folder = evidence
                _write_new(folder / 'create-failed.json', canonical({'status': 'refused-retained',
                    'error_type': type(exc).__name__, 'error': str(exc), 'automatic_retry': False}))
            except (OSError, ValueError):
                pass
            try:
                obj.close()
            except (OSError, ValueError):
                pass  # retain the original setup failure; never close a foreign descriptor
            raise

    def __enter__(self):
        with self._exclusive():
            self._check()
        return self

    def __exit__(self, *ignored):
        self.close()

    @contextmanager
    def _exclusive(self):
        # flock belongs to an open file description and is inherited by fork.
        # It is not proof that a child process may reuse this live authority.
        require(os.getpid() == self._creator_pid, 'Attempt belongs to its creating process; fork reuse is forbidden')
        require(self._operation_lock.acquire(blocking=False), 'Attempt already has an active operation')
        try:
            yield
        finally:
            self._operation_lock.release()

    @_single_owner
    def close(self):
        if self.closed:
            return
        self.closed = True
        if self._lock is None:
            return  # creation failed before a lock descriptor was acquired
        try:
            held = os.fstat(self._lock)
        except OSError as exc:
            self.poisoned = True
            if exc.errno == errno.EBADF:
                return  # an already-closed descriptor has nothing to release
            raise
        require((held.st_dev, held.st_ino) == self._lock_identity,
                'Custody lock descriptor changed; foreign handle retained')
        os.close(self._lock)

    def _check(self):
        require(os.getpid() == self._creator_pid, 'Attempt belongs to its creating process; fork reuse is forbidden')
        require(not self.closed and not self.poisoned, 'Closed/failed attempts cannot be replayed or reopened')
        for path, expected in ((self.root, self._root_identity), (self.prefix, self._prefix_identity), (self.root / 'cache', self._cache_identity), (self.root / 'owner.lock', self._lock_identity)):
            _absolute(path)
            s = path.lstat()
            require((s.st_dev, s.st_ino) == expected and s.st_uid == os.geteuid() and not s.st_mode & 0o077,
                    'Private custody identity/permissions changed')
        for name, expected in self._directory_identities.items():
            path = _absolute(self.root / name)
            s = path.lstat()
            require(stat.S_ISDIR(s.st_mode) and (s.st_dev, s.st_ino) == expected and
                    s.st_uid == os.geteuid() and not s.st_mode & 0o077,
                    'Private directory custody identity/permissions changed')
        held = os.fstat(self._lock)
        require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and
                (held.st_dev, held.st_ino) == self._lock_identity, 'Live custody lock descriptor changed')
        require(_snapshot(self.channel) == self._channel_snapshot, 'Private channel changed')

    @contextmanager
    def _context(self, *, always_yes=False):
        require(_CONTEXT_LOCK.acquire(blocking=False), 'Conda adapter is single-thread/process-context only')
        previous = os.environ.copy()
        try:
            for key in tuple(os.environ):
                if key.startswith('CONDA_') or key in ('CONDARC', 'MAMBA_ROOT_PREFIX'):
                    del os.environ[key]
            os.environ.update({'HOME': str(self.root / 'home'), 'XDG_CONFIG_HOME': str(self.root / 'home/.config'),
                               'XDG_CACHE_HOME': str(self.root / 'home/.cache'), 'CONDARC': os.devnull,
                               'CONDA_NO_PLUGINS': 'true', 'CONDA_PKGS_DIRS': str(self.root / 'cache'),
                               'CONDA_ENVS_PATH': str(self.root / 'envs'), 'CONDA_SUBDIR': self.subdir})
            from conda.base.context import reset_context
            reset_context(search_path=()).plugin_manager.disable_external_plugins()
            context = reset_context(search_path=(), argparse_args=argparse.Namespace(
                offline=True, always_copy=True, allow_softlinks=False, safety_checks='enabled', always_yes=always_yes,
                extra_safety_checks=True, path_conflict='prevent', rollback_enabled=True,
                create_default_packages=[], aggressive_update_packages=[], pinned_packages=[],
                channel=[self.channel.as_uri()], override_channels=True, no_plugins=True,
                register_envs=False, notify_outdated_conda=False, auto_update_conda=False,
                verify_threads=1, execute_threads=1, quiet=True, json=True, solver='classic',
                prefix_data_interoperability=False, repodata_use_zst=False,
                repodata_fns=['repodata.json'], use_only_tar_bz2=False))
            context.plugin_manager.disable_external_plugins()
            require(context.always_copy and context.offline and context.extra_safety_checks and
                    str(context.path_conflict) == 'prevent' and str(context.safety_checks) == 'enabled' and
                    context.pkgs_dirs == (str(self.root / 'cache'),), 'Unsafe effective Conda configuration: ' + repr((context.always_copy, context.offline, context.extra_safety_checks, str(context.path_conflict), str(context.safety_checks), context.pkgs_dirs)))
            from conda.core.prefix_data import PrefixData
            for key in tuple(PrefixData._cache_):
                if key[0] == self.prefix:
                    del PrefixData._cache_[key]
            yield
        finally:
            os.environ.clear()
            os.environ.update(previous)
            # Restore context configuration for callers; no owner/client subprocess
            # runs with the temporary publisher HOME or configuration.
            try:
                from conda.base.context import reset_context
                reset_context()
            finally:
                _CONTEXT_LOCK.release()

    @_single_owner
    def inventory(self):
        return self._inventory()

    def _inventory(self):
        self._check()
        rows = {}
        for path in (self.prefix / 'conda-meta').glob('*.json'):
            data = _json(_read_small(path))
            record = _record(data)
            require(record['name'] not in rows, 'Duplicate installed package records')
            identity = self.catalog.get(record['filename'])
            require(identity and record == _core(identity), 'Installed record is outside reviewed channel identity')
            require(sorted(data.get('files', [])) == sorted(identity['files']), 'Installed file inventory differs')
            for name, expected in identity['files'].items():
                require(_hash_file(self.prefix / name) == expected, 'Installed payload differs from archive')
            rows[record['name']] = identity
        return rows

    def _expected(self, rows):
        value = {}
        for row in rows:
            known = self.catalog.get(row.get('filename'))
            require(known is not None and row == known, 'Expected identity is not the full reviewed artifact identity')
            require(row['name'] not in value, 'Duplicate expected package name')
            value[row['name']] = row
        return value

    def _validate_plan(self, transaction, links, unlinks):
        require(set(transaction.prefix_setups) == {str(self.prefix)}, 'Transaction targets an unexpected prefix')
        setup = transaction.prefix_setups[str(self.prefix)]
        for direction, actual, expected in (('LINK', setup.link_precs, links), ('UNLINK', setup.unlink_precs, unlinks)):
            got = [_record(row) for row in actual]
            require(len(got) == len(expected) and {row['name']: row for row in got} == {name: _core(row) for name, row in expected.items()},
                    'Complete solver LINK/UNLINK ' + direction + ' delta differs from reviewed identities: ' + repr([(v['name'], v['version'], v['build']) for v in got]))
            for row in actual:
                require(str(row.channel.base_url).rstrip('/') == self.channel.as_uri().rstrip('/'), 'Unexpected package channel')

    def _validate_actions(self, transaction, links, unlinks):
        from conda.models.enums import LinkType
        require(set(transaction.prefix_action_groups) == {str(self.prefix)}, 'Prepared actions target another prefix')
        groups = transaction.prefix_action_groups[str(self.prefix)]
        seen_link, seen_unlink, seen_records = {}, {}, set()
        for group_list in groups:
            for group in group_list:
                require(group.target_prefix == str(self.prefix), 'Prepared action prefix differs')
                actions = tuple(group.actions)
                if group.type in ('remove_menus', 'make_menus', 'entry_point', 'compile', 'initial', 'final'):
                    require(not actions, 'Menus, entrypoints, compilation and plugin actions are forbidden')
                    continue
                require(group.type in ('link', 'unlink', 'record', 'register', 'unregister'), 'Unknown prepared action group')
                if group.type in ('link', 'unlink'):
                    is_link = group.type == 'link'
                    rec = group.pkg_data.repodata_record if is_link else group.pkg_data
                    identity = (links if is_link else unlinks).get(rec.name)
                    require(identity is not None and _record(rec) == _core(identity), 'Prepared package identity differs')
                    (seen_link if is_link else seen_unlink)[rec.name] = identity
                    require(not identity['depends'] and not identity['constrains'], 'Runtime dependencies/constraints are outside inert carrier policy')
                    expected_files = set(identity['files'])
                    observed_files = set()
                    if is_link:
                        extracted = Path(group.pkg_data.extracted_package_dir)
                        # Validate every extracted payload, not merely the record
                        # cached before prepare, including hidden lifecycle scripts.
                        actual_files = _snapshot(extracted)
                        require({k: v for k, v in actual_files.items() if not k.startswith('info/')} == identity['files'],
                                'Prepared extracted package has unexpected or changed payload')
                    for action in actions:
                        cls = type(action).__name__
                        rel = getattr(action, 'target_short_path', None)
                        _relative(rel)
                        require(action.target_prefix == str(self.prefix), 'Action target prefix changed')
                        if is_link:
                            require(cls == 'LinkPathAction', 'Only exact file-copy link actions are permitted')
                            if action.link_type == LinkType.directory:
                                require(any(name.startswith(rel + '/') for name in expected_files), 'Unexpected directory creation')
                            else:
                                require(action.link_type == LinkType.copy and rel in expected_files and action.source_short_path == rel,
                                        'Unexpected payload action or shared inode link')
                                require(Path(action.source_prefix) == extracted, 'Action source differs from prepared package')
                                require(rel not in observed_files, 'Duplicate payload link')
                                observed_files.add(rel)
                        elif cls == 'RemoveLinkedPackageRecordAction':
                            require(rel == f"conda-meta/{identity['name']}-{identity['version']}-{identity['build']}.json", 'Unexpected metadata removal')
                        else:
                            require(cls == 'UnlinkPathAction', 'Unknown unlink action')
                            if action.link_type == LinkType.directory:
                                require(any(name.startswith(rel + '/') for name in expected_files), 'Unexpected directory removal')
                            else:
                                require(rel in expected_files and rel not in observed_files, 'Unexpected payload removal')
                                observed_files.add(rel)
                    require(observed_files == expected_files, 'Prepared payload effects are incomplete')
                elif group.type == 'record':
                    for action in actions:
                        require(type(action).__name__ == 'CreatePrefixRecordAction', 'Unexpected metadata action')
                        record = _record(action.package_info.repodata_record)
                        identity = links.get(record['name'])
                        require(identity and record == _core(identity), 'Prepared prefix record differs')
                        require(sorted(a.target_short_path for a in action.all_link_path_actions if getattr(a, 'link_type', None) != LinkType.directory) == sorted(identity['files']), 'Prepared metadata files differ')
                        require(action.target_prefix == str(self.prefix) and action.target_short_path ==
                                f"conda-meta/{identity['name']}-{identity['version']}-{identity['build']}.json", 'Unexpected metadata destination')
                        seen_records.add(record['name'])
                else:
                    allowed = {'register': {'RegisterEnvironmentLocationAction', 'UpdateHistoryAction'},
                               'unregister': {'UnregisterEnvironmentLocationAction'}}[group.type]
                    for action in actions:
                        require(type(action).__name__ in allowed and action.target_prefix == str(self.prefix), 'Unexpected bookkeeping action')
                        if type(action).__name__ == 'UpdateHistoryAction':
                            require(action.target_short_path == 'conda-meta/history', 'Unexpected history destination')
        require(seen_link == links and seen_unlink == unlinks and seen_records == set(links), 'Prepared package effects differ from full solver delta')

    @_single_owner
    def clean_cache(self):
        """Run normal Conda clean --all only on this empty attempt's own cache.

        The explicit tempfile root is essential: Conda 26.10.0 otherwise scans
        sys.prefix under --all. No force-pkgs-dirs, general environment adoption,
        external cache, or runtime cleanup is supported.
        """
        try:
            self._check()
        except BaseException:
            self.poisoned = True
            raise
        self.sequence += 1
        evidence = self.root / 'evidence' / f'{self.sequence:04d}'
        evidence.mkdir(mode=0o700)
        _sync_dir(evidence.parent)
        cache = self.root / 'cache'
        _write_new(evidence / 'intent.json', canonical({'operation': 'clean-cache', 'conda_version': PINNED_CONDA,
            'all': True, 'force_pkgs_dirs': False, 'cache_scope': 'this-attempt-only',
            'tempfile_scope': 'this-attempt-cache-only', 'automatic_retry': False}))
        executing = False
        try:
            require(not self.installed and not self._inventory(), 'Cache cleanup requires an empty owned delivery prefix')
            before = _snapshot(self.prefix)
            require(all(before.get(k) == v for k, v in self.previous_snapshot.items()), 'Prefix changed before cache cleanup')
            cache_before = _snapshot(cache)
            with self._context(always_yes=True):
                from conda.cli import main_clean
                from conda.base.context import context
                require(main_clean.find_pkgs_dirs() == [str(cache)] and context.pkgs_dirs == (str(cache),),
                        'Conda cleanup includes an external package cache')
                args = argparse.Namespace(all=True, force_pkgs_dirs=False, tarballs=False, index_cache=False,
                    packages=False, tempfiles=[str(cache)], logfiles=False, dry_run=False)
                preflight = {'tarballs': main_clean.find_tarballs(), 'packages': main_clean.find_pkgs(),
                    'index_cache': {'files': main_clean.find_index_cache()},
                    'tempfiles': main_clean.find_tempfiles(args.tempfiles), 'logfiles': main_clean.find_logfiles()}

                def targets(report):
                    result = set()
                    for category in ('tarballs', 'packages'):
                        group = report.get(category, {})
                        require(not group.get('warnings'), 'Cache cleanup discovery produced warnings')
                        for parent, names in group.get('pkgs_dirs', {}).items():
                            require(parent == str(cache), 'Cleanup targets an external cache')
                            for name in names:
                                require(Path(name).name == name and name not in ('', '.', '..'), 'Unsafe cache entry name')
                                result.add(cache / name)
                    result.update(Path(p) for p in report.get('index_cache', {}).get('files', []))
                    result.update(Path(p) for p in report.get('tempfiles', []))
                    result.update(Path(p) for p in report.get('logfiles', []))
                    for path in result:
                        require(path.is_absolute() and path != cache and cache in path.parents and _absolute(path) == path,
                                'Cleanup path is outside exact owned cache')
                    return result

                planned = targets(preflight)
                require(preflight['tarballs']['pkgs_dirs'] or preflight['packages']['pkgs_dirs'],
                        'No actual cached package is available to qualify cleanup')
                require(_snapshot(cache) == cache_before and _snapshot(self.prefix) == before,
                        'Owned files changed during cleanup discovery')
                self._check()
                _write_new(evidence / 'validated.json', canonical({'status': 'validated-private-cache',
                    'targets': sorted(str(p.relative_to(cache)) for p in planned), 'force_pkgs_dirs': False}))
                _write_new(evidence / 'execution-started.json', canonical({'status': 'outcome-unknown-until-observed'}))
                executing = True
                output = io.StringIO()
                with redirect_stdout(output):
                    status = main_clean.execute(args, None)
                result = _json(output.getvalue())
                require(status == 0 and result.get('success') is True and targets(result) <= planned,
                        'Conda cleanup result differs from reviewed private-cache scope')
            self._check()
            require(_snapshot(self.prefix) == before and not self._inventory(), 'Cache cleanup changed delivery prefix')
            require(all(not os.path.lexists(path) for path in planned), 'Conda did not remove every selected cache target')
            cache_after = _snapshot(cache)
            removed = {name for name in cache_before if any(cache / name == path or path in (cache / name).parents for path in planned)}
            require({k: v for k, v in cache_before.items() if k not in removed} == cache_after,
                    'Cache cleanup changed files outside selected cache entries')
            self.previous_snapshot = before
            report = {'protocol': 'symphony.conda.cache-clean-result.v1', 'status': 'observed-complete',
                'sequence': self.sequence, 'conda_version': PINNED_CONDA, 'normal_conda_clean_all': True,
                'force_pkgs_dirs': False, 'only_attempt_cache_mutated': True,
                'removed_targets': sorted(str(p.relative_to(cache)) for p in planned),
                'removed_file_count': len(removed), 'prefix_and_channel_preserved': True,
                'native_activation_performed': False, 'native_retirement_performed': False}
            _write_new(evidence / 'result.json', canonical(report))
            return report
        except BaseException as exc:
            self.poisoned = True
            try:
                _write_new(evidence / 'failure.json', canonical({'status': 'uncertain-retained' if executing else 'refused-retained',
                    'operation': 'clean-cache', 'error_type': type(exc).__name__, 'error': str(exc),
                    'execution_started': executing, 'automatic_retry': False}))
            except (OSError, ValueError):
                pass
            raise

    @_single_owner
    def transact(self, operation, *, add_specs=(), remove_names=(), expected_link=(), expected_unlink=()):
        """Solve, validate and execute the SAME transaction object exactly once.

        Rollback is a new reviewed exact transaction to a retained old artifact,
        never history replay, forced dependency removal, or native-owner unretire.
        """
        try:
            self._check()
        except BaseException:
            self.poisoned = True
            raise
        self.sequence += 1
        evidence = self.root / 'evidence' / f'{self.sequence:04d}'
        evidence.mkdir(mode=0o700)
        _sync_dir(evidence.parent)
        executing = False
        before = None
        _write_new(evidence / 'intent.json', canonical({'operation': operation, 'add_specs': list(add_specs),
            'remove_names': list(remove_names), 'expected_link': list(expected_link), 'expected_unlink': list(expected_unlink)}))
        try:
            require(operation in ('install', 'update', 'upgrade', 'swap', 'remove', 'rollback'), 'Unknown operation')
            links, unlinks = self._expected(expected_link), self._expected(expected_unlink)
            exact_specs = {f"{v['name']}={v['version']}={v['build']}" for v in links.values()}
            require(len(add_specs) == len(set(add_specs)) and set(add_specs) == exact_specs, 'Every added package must use its exact reviewed spec')
            require(len(remove_names) == len(set(remove_names)) and all(NAME.fullmatch(x) for x in remove_names), 'Invalid exact removal names')
            require(set(remove_names) == set(unlinks) - set(links), 'Explicit removal names must equal the reviewed removed-only names')
            require(bool(links or unlinks), 'Empty transaction is not a journey')
            if operation == 'install':
                require(links and not unlinks, 'Install may only add reviewed packages')
            elif operation in ('update', 'upgrade'):
                require(links and set(links) == set(unlinks) and all(links[k] != unlinks[k] for k in links),
                        'Upgrade requires exact old and replacement identities')
            elif operation == 'rollback':
                require(links and unlinks and (set(links) == set(unlinks) or not set(links).intersection(unlinks)) and
                        all(links[k] != unlinks[k] for k in set(links).intersection(unlinks)),
                        'Rollback requires exact reverse replacement or swap identities')
            elif operation == 'remove':
                require(unlinks and not links, 'Removal may only unlink reviewed packages')
            else:
                require(links and unlinks and not set(links).intersection(unlinks), 'Swap requires distinct reviewed package owners')
            before = _snapshot(self.prefix)
            # Conda runs post-link and unlink hooks from the destination prefix,
            # including an unowned script placed there by a separate actor. Keep
            # such foreign files intact, but refuse to execute this transaction.
            for name in set(links) | set(unlinks):
                for phase in ('pre-link', 'post-link', 'pre-unlink', 'post-unlink'):
                    require(f'bin/.{name}-{phase}.sh' not in before, 'Existing lifecycle hook prevents inert transaction')
            require(all(before.get(k) == v for k, v in self.previous_snapshot.items()), 'Private prefix changed since prior observation')
            actual_before = self._inventory()
            require(actual_before == self.installed, 'Installed metadata changed since prior observation')
            require(all(actual_before.get(k) == v for k, v in unlinks.items()), 'Unlink identity is not installed')
            require(not (set(links) & set(actual_before) - set(unlinks)), 'Replacement lacks exact reviewed unlink identity')
            # Refuse collisions with foreign files before Conda can run clobber logic.
            removable = {p for v in unlinks.values() for p in v['files']}
            require(not ({p for v in links.values() for p in v['files']} & (set(before) - removable)), 'Incoming payload collides with retained/foreign files')
            with self._context():
                from conda.core.solve import Solver
                from conda.base.constants import DepsModifier, UpdateModifier
                from conda.models.channel import Channel
                # UPDATE_SPECS is Conda's ordinary dependency-aware solve. Its
                # FREEZE_INSTALLED mode can re-add explicitly removed packages
                # in a mixed swap. Complete delta validation below is the scope
                # boundary; no dependency bypass or forced solve is used.
                solver = Solver(str(self.prefix), channels=(Channel(self.channel.as_uri()),), subdirs=(self.subdir, 'noarch'),
                                specs_to_add=tuple(add_specs), specs_to_remove=tuple(remove_names), repodata_fn='repodata.json', command=operation)
                transaction = solver.solve_for_transaction(update_modifier=UpdateModifier.UPDATE_SPECS,
                    deps_modifier=DepsModifier.NOT_SET, prune=False, ignore_pinned=False, force_remove=False,
                    force_reinstall=False, should_retry_solve=False)
                self._validate_plan(transaction, links, unlinks)
                require(_snapshot(self.prefix) == before, 'Prefix changed while solver planned')
                transaction.prepare()
                self._validate_plan(transaction, links, unlinks)
                self._validate_actions(transaction, links, unlinks)
                require(_snapshot(self.prefix) == before, 'Prefix changed during preparation')
                transaction.verify()
                self._validate_plan(transaction, links, unlinks)
                self._validate_actions(transaction, links, unlinks)
                require(_snapshot(self.prefix) == before, 'Prefix changed during verification')
                self._check()
                _write_new(evidence / 'validated.json', canonical({'status': 'validated-same-object',
                    'link': list(links.values()), 'unlink': list(unlinks.values()), 'forced_dependencies': False,
                    'package_hooks': False, 'independent_copies': True}))
                _write_new(evidence / 'execution-started.json', canonical({'status': 'outcome-unknown-until-observed'}))
                executing = True
                transaction.execute()
            after = self._inventory()
            expected_final = {k: v for k, v in actual_before.items() if k not in unlinks}
            expected_final.update(links)
            require(after == expected_final, 'Final complete installed inventory differs from reviewed delta')
            after_files = _snapshot(self.prefix)
            changed = set(removable) | {p for v in links.values() for p in v['files']} | {'conda-meta/history'}
            changed.update(f"conda-meta/{v['name']}-{v['version']}-{v['build']}.json" for v in (*unlinks.values(), *links.values()))
            require({k: v for k, v in before.items() if k not in changed} ==
                    {k: v for k, v in after_files.items() if k not in changed}, 'Foreign files or unrelated package metadata changed')
            removed_only = removable - {p for v in links.values() for p in v['files']}
            require(not removed_only.intersection(after_files), 'Removed payload is unexpectedly retained')
            self.installed, self.previous_snapshot = after, after_files
            result = {'protocol': 'symphony.conda.transaction-result.v1', 'status': 'observed-complete',
                      'operation': operation, 'sequence': self.sequence, 'link': list(links.values()),
                      'unlink': list(unlinks.values()), 'inventory': after, 'unrelated_files_preserved': True,
                      'native_activation_performed': False, 'native_retirement_performed': False}
            _write_new(evidence / 'result.json', canonical(result))
            return result
        except BaseException as exc:
            self.poisoned = True
            outcome = {'status': 'uncertain-retained' if executing else 'refused-retained',
                       'error_type': type(exc).__name__, 'error': str(exc), 'automatic_retry': False,
                       'execution_started': executing, 'prefix_preserved_for_independent_inspection': True}
            try:
                _write_new(evidence / 'failure.json', canonical(outcome))
                _write_new(evidence / 'observed-files.json', canonical(_snapshot(self.prefix)))
            except (OSError, ValueError):
                pass
            raise
