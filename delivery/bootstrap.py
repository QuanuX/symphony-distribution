#!/usr/bin/env python3
"""Retain verified installed beta candidates in a new private directory.

Python 3.11+; standard library only. This never installs a native runtime,
selects modules, starts services, edits client configuration or deletes files.
The index SHA256 must come from the independently verified release manifest.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
import tarfile
import zipfile

INDEX = 'symphony.distribution.retention-index.v1'
CUSTODY = 'symphony.distribution.retained-candidates.v1'
LIMIT = 512 * 1024 * 1024
INDEX_PATH = 'share/symphony/installer/BOOTSTRAP-INDEX.json'
SCRIPT_PATH = 'share/symphony/installer/symphony-retain.py'
OWNERS = {'go:secure-identity-access-governance', 'go:stav-append-authority', 'go:accordare-stav-producer'}
DEFAULT = {'go:qxctl', 'client:client'}


def require(value, reason):
    if not value: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON key'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def relative(name):
    require(isinstance(name, str) and name and not name.startswith('/') and '\\' not in name and
            all(ord(ch) >= 32 and ord(ch) != 127 for ch in name) and
            all(part not in ('', '.', '..') for part in name.split('/')), 'Unsafe relative path')
    return name


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Exact SHA256 required')
    return value


def stable_stat(value):
    return tuple(getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def directory(path):
    path = Path(os.path.abspath(path)); require(str(path) != '/', 'Directory root cannot be filesystem root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = following
        return fd
    except BaseException:
        os.close(fd); raise


def read_at(root, name, limit=LIMIT):
    parts = relative(name).split('/'); fd = os.dup(root)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = following
        selected = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(selected)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'Input is not a bounded regular file')
            with os.fdopen(os.dup(selected), 'rb') as stream: raw = stream.read(limit + 1)
            after = os.fstat(selected)
            require(len(raw) == before.st_size and stable_stat(before) == stable_stat(after), 'Input changed during snapshot')
            return raw
        finally: os.close(selected)
    finally: os.close(fd)


def prepare_index(cohort_root, cohort):
    """Assembly-only API; product CLI never imports publisher tooling."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'installer_assembly'))
    import carriers as c
    root = c.safe_root(cohort_root)
    require(c.audit_cohort(root) == cohort and len(cohort['entries']) == 59, 'Exact audited full beta cohort required')
    entries = []
    for entry in cohort['entries']:
        unit, _ = c.validate_recipe(root, entry)
        payload = root / entry['recipe_path'] / 'payload'
        entries.append({key: entry[key] for key in ('unit_id', 'kind', 'component_id', 'native_version', 'carrier_destination')} |
            {'carrier_files': {name: sha((payload / name).read_bytes()) for name in
                ('carrier-manifest.json', 'unit.json', 'payload.tar')}})
    return {'protocol': INDEX, 'cohort_digest': cohort['cohort_digest'], 'profile': cohort['profile'],
        'script_sha256': sha(Path(__file__).read_bytes()), 'entries': entries,
        'python_minimum': '3.11', 'native_installation_performed': False, 'runtime_activation_changed': False}


def validate_index(index):
    require(index['protocol'] == INDEX and index['python_minimum'] == '3.11' and
        re.fullmatch('sha256:[0-9a-f]{64}', index['cohort_digest']) and
        index['native_installation_performed'] is False and index['runtime_activation_changed'] is False,
        'Retention index identity or authority differs')
    digest(index['script_sha256'])
    entries = {row['unit_id']: row for row in index['entries']}
    require(len(entries) == len(index['entries']) == 59 and DEFAULT | OWNERS <= entries.keys(), 'Incomplete beta retention index')
    require(sum(row['kind'] == 'native_receipt_unit' for row in entries.values()) == 51 and
        sum(row['kind'] == 'go_command' for row in entries.values()) == 6 and
        sum(row['kind'] == 'external_inert_runtime_and_sdk' for row in entries.values()) == 1 and
        sum(row['kind'] == 'client_bridge_bundle' for row in entries.values()) == 1, 'Unexpected beta owner census')
    destinations = set()
    for row in entries.values():
        dest = relative(row['carrier_destination'])
        require(dest.startswith('share/symphony/carriers/') and dest not in destinations, 'Carrier destinations overlap')
        destinations.add(dest)
        require(set(row['carrier_files']) == {'carrier-manifest.json', 'unit.json', 'payload.tar'}, 'Carrier file closure differs')
        for value in row['carrier_files'].values(): digest(value)
    return entries


def tar_members(raw, rows):
    expected = {relative(row['path']): row for row in rows}
    require(len(expected) == len(rows) <= 10000, 'Duplicate or excessive payload members')
    data = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        require(not archive.pax_headers, 'Global TAR metadata refused')
        for member in archive:
            name = relative(member.name)
            require(name in expected and name not in data and not member.pax_headers and
                member.uid == member.gid == member.mtime == 0 and member.uname == member.gname == '', 'Unselected TAR member or metadata')
            row = expected[name]
            if 'link' in row:
                require(member.issym() and member.mode == 0o777 and member.size == 0 and member.linkname == row['link'], 'Payload link differs')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), row['link']))
                require(name.startswith('third-party/lib/libcurl') and not row['link'].startswith('/') and
                    target in expected and target.startswith('third-party/lib/'), 'External alias escapes selected closure')
                data[name] = (None, 0o777, row['link'])
            else:
                require(member.isfile() and member.mode == row['mode'] and row['mode'] in (0o644, 0o755) and
                    member.size == row['size'] <= LIMIT, 'Payload file type, size or mode differs')
                content = archive.extractfile(member).read(member.size + 1); total += len(content)
                require(total <= LIMIT and len(content) == row['size'] and sha(content) == digest(row['sha256']), 'Payload digest differs')
                data[name] = (content, row['mode'], None)
    require(data.keys() == expected.keys(), 'Payload members missing')
    # Every padding/header byte is canonical; hidden archive data is refused.
    rendered = io.BytesIO()
    with tarfile.open(fileobj=rendered, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(data):
            content, mode, link = data[name]; member = tarfile.TarInfo(name); member.mode = mode
            if link is not None: member.type = tarfile.SYMTYPE; member.linkname = link; archive.addfile(member)
            else: member.size = len(content); archive.addfile(member, io.BytesIO(content))
    require(rendered.getvalue() == raw, 'Noncanonical TAR headers, padding, order or tail')
    for name, (_, _, link) in data.items():
        seen = {name}
        while link is not None:
            name = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
            require(name not in seen and name in data, 'Cyclic or absent external alias')
            seen.add(name); link = data[name][2]
    return data


def client_members(raw, inventory):
    files = {}; total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(not archive.comment and len(archive.infolist()) <= 5000, 'Unexpected client ZIP envelope')
        for row in archive.infolist():
            name = relative(row.filename); mode = row.external_attr >> 16
            require(name not in files and name in inventory and not row.is_dir() and not row.extra and not row.comment and
                not row.flag_bits & 1 and stat.S_ISREG(mode) and stat.S_IMODE(mode) ==
                (0o755 if name == 'bin/symphony-mcp' else 0o644) and row.file_size <= LIMIT, 'Unselected client ZIP member')
            content = archive.read(row); total += len(content)
            require(total <= LIMIT and 'sha256:' + sha(content) == inventory[name], 'Client package digest differs')
            files[name] = (content, stat.S_IMODE(mode), None)
    require(files.keys() == inventory.keys() and {'bin/symphony-mcp', 'catalog/tools.json',
        'scripts/configure_connection.py', 'scripts/configure_clients.py'} <= files.keys(), 'Client package incomplete')
    return files


def selected_payload(root, entry):
    dest = entry['carrier_destination']; fd = os.dup(root)
    try:
        for part in relative(dest).split('/'):
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = following
        require(set(os.listdir(fd)) == set(entry['carrier_files']), 'Unexpected installed carrier member')
        blobs = {name: read_at(fd, name) for name in entry['carrier_files']}
    finally: os.close(fd)
    require({name: sha(raw) for name, raw in blobs.items()} == entry['carrier_files'], 'Installed carrier differs from trusted index')
    manifest, unit = document(blobs['carrier-manifest.json']), document(blobs['unit.json'])
    require(manifest['protocol'] == 'symphony.distribution.d08-inert-carrier.v1' and manifest['destination'] == dest and
        manifest['unit_id'] == entry['unit_id'] and manifest['runtime_install_supported'] is False and
        all(unit[key] == entry[key] for key in ('unit_id', 'kind', 'component_id', 'native_version')) and
        unit['native_runtime_install_supported'] is False, 'Carrier owner or authority differs')
    require({row['path'] for row in manifest['files']} == {'payload.tar', 'unit.json'} and
        len(manifest['files']) == 2 and all(row['sha256'] == sha(blobs[row['path']]) and row['size'] == len(blobs[row['path']])
        for row in manifest['files']), 'Carrier manifest file hashes differ')
    data = tar_members(blobs['payload.tar'], unit['files'])
    if entry['kind'] == 'client_bridge_bundle':
        require(set(data) == {'client.zip', 'qualification.json', 'derivation.json', 'package-inventory.json'}, 'Client evidence closure differs')
        return {'client/' + name: row for name, row in client_members(data['client.zip'][0], document(data['package-inventory.json'][0])).items()}, blobs
    if entry['kind'] == 'native_receipt_unit':
        name = 'share/symphony/receipts/' + entry['component_id'] + '/' + entry['native_version'] + '/install-receipt.json'
        require(name in data, 'Native receipt absent')
        receipt = document(data[name][0]); body = dict(receipt); seal = body.pop('receipt_digest')
        require(receipt['protocol'] == 'symphony.knowledge.install-receipt.v2' and
            receipt['component_id'] == entry['component_id'] and receipt['version'] == entry['native_version'] and
            seal == 'sha256:' + sha(canonical(body)), 'Native receipt seal or identity differs')
        require({row['path'] for row in receipt['files']} == data.keys() - {name} and
            all(data[row['path']][0] is not None and row['digest'] == 'sha256:' + sha(data[row['path']][0]) and
                row['size'] == len(data[row['path']][0]) for row in receipt['files']), 'Native receipt file closure differs')
    # Go/external carriers each embed their own complete legal closure. Those
    # repeated delivery-only names are not runtime ownership and stay separate
    # per unit, while every native path remains byte-for-byte and path-identical.
    result = {}
    for name, row in data.items():
        if name.startswith('delivery-notices/'):
            require(entry['kind'] in ('go_command', 'external_inert_runtime_and_sdk') and row[2] is None and row[1] == 0o644,
                'Unexpected delivery-only notice')
            target = 'notices/' + relative(entry['component_id']) + '/' + relative(entry['native_version']) + '/' + name.removeprefix('delivery-notices/')
        else: target = 'candidate/' + name
        require(target not in result, 'Retained unit paths overlap'); result[target] = row
    return result, blobs


def write_at(root, name, raw, mode):
    parts = relative(name).split('/'); fd = os.dup(root)
    try:
        for part in parts[:-1]:
            try: os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError: pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = following
        out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
        with os.fdopen(out, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), mode)
    finally: os.close(fd)


def retain(prefix, expected_index, output, *, owners=False, all_units=False, external_index=None):
    require(sys.version_info >= (3, 11), 'Python3.11 or newer required')
    require(os.geteuid() != 0, 'Retain candidates as the intended unprivileged user')
    prefix, output = Path(os.path.abspath(prefix)), Path(os.path.abspath(output))
    require(prefix != output and prefix not in output.parents and output not in prefix.parents, 'Custody must be independent of carrier prefix')
    root = directory(prefix); outfd = parent = index_fd = None
    try:
        if external_index is not None:
            external_index = Path(os.path.abspath(external_index))
            require(output != external_index and output not in external_index.parents, 'Custody must exclude external setup inputs')
            index_fd = directory(external_index.parent)
        index_root, index_name = (index_fd, external_index.name) if external_index is not None else (root, INDEX_PATH)
        index_raw = read_at(index_root, index_name, 5 * 1024 * 1024)
        require(sha(index_raw) == digest(expected_index), 'Retention index differs from independently selected digest')
        index = document(index_raw); entries = validate_index(index)
        own_path = Path(os.path.abspath(__file__)); own_fd = directory(own_path.parent)
        try: own_raw = read_at(own_fd, own_path.name, 1024 * 1024)
        finally: os.close(own_fd)
        require(index['script_sha256'] == sha(own_raw), 'Retention helper differs from signed index')
        if external_index is None:
            require(sha(read_at(root, SCRIPT_PATH, 1024 * 1024)) == index['script_sha256'], 'Installed retention helper differs')
        selected = set(entries) if all_units else DEFAULT | (OWNERS if owners else set())
        retained, snapshots = {}, {}
        for uid in sorted(selected):
            files, blobs = selected_payload(root, entries[uid])
            require(not retained.keys() & files.keys(), 'Selected native/client ownership overlaps')
            retained.update(files); snapshots[uid] = blobs
        require(sum(len(row[0]) for row in retained.values() if row[0] is not None) <= LIMIT, 'Retained cohort exceeds bound')
        parent = directory(output.parent); os.mkdir(output.name, 0o700, dir_fd=parent)
        outfd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        require(os.fstat(outfd).st_uid == os.geteuid(), 'Custody is not owned by current user')
        for name, (raw, mode, link) in sorted(retained.items()):
            if link is None: write_at(outfd, name, raw, mode)
        for name, (raw, mode, link) in sorted(retained.items()):
            if link is not None:
                fd = directory(output / PurePosixPath(name).parent)
                try: os.symlink(link, PurePosixPath(name).name, dir_fd=fd)
                finally: os.close(fd)
        for uid in sorted(selected):
            require(all(read_at(root, entries[uid]['carrier_destination'] + '/' + name) == raw
                for name, raw in snapshots[uid].items()), 'Installed carrier changed during retention')
        require(read_at(index_root, index_name, 5 * 1024 * 1024) == index_raw, 'Installed bootstrap changed during retention')
        if external_index is None:
            require(sha(read_at(root, SCRIPT_PATH, 1024 * 1024)) == index['script_sha256'], 'Installed bootstrap changed during retention')
        own_fd = directory(own_path.parent)
        try: require(read_at(own_fd, own_path.name, 1024 * 1024) == own_raw, 'Executing helper changed during retention')
        finally: os.close(own_fd)
        rows = [{'path': name, 'mode': mode, **({'link': link} if link is not None else {'sha256': sha(raw), 'size': len(raw)})}
            for name, (raw, mode, link) in sorted(retained.items())]
        require(all(read_at(outfd, row['path']) == retained[row['path']][0] for row in rows if 'link' not in row), 'Retained bytes differ')
        require(os.stat(output.name, dir_fd=parent, follow_symlinks=False).st_ino == os.fstat(outfd).st_ino,
            'Custody directory identity changed')
        require(all(os.readlink(output / row['path']) == row['link'] for row in rows if 'link' in row), 'Retained alias differs')
        result = {'protocol': CUSTODY, 'state': 'retained_verified_candidates', 'cohort_digest': index['cohort_digest'],
            'profile': index['profile'], 'index_sha256': expected_index, 'script_sha256': index['script_sha256'],
            'selected_units': sorted(selected), 'files': rows,
            'entrypoints': {'qxctl': 'candidate/go/qxctl/bin/qxctl', 'client': 'client/bin/symphony-mcp'},
            'native_installation_performed': False, 'runtime_activation_changed': False, 'client_configuration_changed': False,
            'native_retirement_authority': False, 'automatic_cleanup_supported': False,
            'custody_scope': 'verified immutable candidate copies; native installation and selection remain existing owner actions'}
        write_at(outfd, 'CUSTODY.json', canonical(result) + b'\n', 0o600)
        return result
    finally:
        for fd in (outfd, parent, index_fd, root):
            if fd is not None: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--index-sha256', required=True)
    parser.add_argument('--index', type=Path, help='Separately downloaded signed setup index for CLI-only carrier installs')
    parser.add_argument('--output', required=True, type=Path)
    scope = parser.add_mutually_exclusive_group(); scope.add_argument('--owners', action='store_true'); scope.add_argument('--all', action='store_true')
    args = parser.parse_args()
    try:
        result = retain(args.prefix, args.index_sha256, args.output, owners=args.owners, all_units=args.all, external_index=args.index)
        print(json.dumps({'state': result['state'], 'selected_unit_count': len(result['selected_units']),
            'custody_sha256': sha(canonical(result) + b'\n'), 'native_installation_performed': False}))
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, 'Retention refused: ' + str(error) + '. Preserve any partial custody; do not overwrite or replay.\n')


if __name__ == '__main__': main()
