#!/usr/bin/env python3
"""Canonicalize only unused Darwin BSD32 archive symbol-string alignment bytes.

Every symbol reference and object-member header offset is checked before any
change. Member order, names, headers, sizes, offsets, referenced strings and
object bytes are preserved. Unknown formats fail closed. This is a pre-seal
packaging transformation, never an update to an already receipted installation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct

MAGIC = b'!<arch>\n'
TABLES = ('__.SYMDEF', '__.SYMDEF SORTED')
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBERS = 100000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def number(field, *, base=10, empty=False):
    value = field.strip(b' ')
    require((empty and value == b'') or bool(re.fullmatch(b'[0-7]+' if base == 8 else b'[0-9]+', value)),
            'invalid archive numeric field')
    return int(value, base) if value else 0


def archive_members(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_ARCHIVE and raw.startswith(MAGIC),
            'bounded regular Darwin archive required; thin/unknown formats refused')
    offset, members = len(MAGIC), []
    while offset < len(raw):
        require(len(members) < MAX_MEMBERS, 'archive member bound exceeded')
        header = raw[offset:offset + 60]
        require(len(header) == 60 and header[58:60] == b'`\n', 'invalid archive member header')
        for field in (header[16:28], header[28:34], header[34:40]):
            require(number(field, empty=True) == 0, 'archive retains builder identity or timestamp')
        require(number(header[40:48], base=8, empty=True) & 0o6000 == 0, 'privileged archive member')
        size = number(header[48:58])
        payload_start, end = offset + 60, offset + 60 + size
        require(end <= len(raw), 'truncated archive member')
        name = header[:16].rstrip(b' ')
        if name.startswith(b'#1/'):
            length = number(name[3:])
            require(0 < length <= size, 'invalid BSD extended member name length')
            extended = raw[payload_start:payload_start + length]
            name = extended.rstrip(b'\0')
            require(name and b'\0' not in name, 'invalid BSD member name padding')
            payload_start += length
        else:
            # A trailing slash terminates ordinary ar names. GNU index/name
            # tables and indexed long names are outside this Darwin format.
            require(not name.startswith(b'/'), 'unknown GNU archive metadata refused')
            name = name.removesuffix(b'/')
        try:
            text = name.decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('invalid archive member name encoding') from error
        p = PurePosixPath(text)
        require(text and not p.is_absolute() and '..' not in p.parts and '\\' not in text and
                all(ord(c) >= 32 and ord(c) != 127 for c in text), 'unsafe archive member name')
        require(not text.startswith('__.SYMDEF') or text in TABLES, 'unknown Darwin symbol table layout')
        members.append({'name': text, 'header_offset': offset, 'payload_start': payload_start,
                        'payload_end': end, 'member_size': size})
        if size % 2:
            require(raw[end:end + 1] == b'\n', 'invalid archive alignment byte')
        offset = end + size % 2
    require(offset == len(raw) and members, 'empty or trailing archive data')
    indexes = [m for m in members if m['name'] in TABLES]
    require(len(indexes) == 1 and indexes[0] is members[0] and len(members) > 1,
            'one leading recognized Darwin symbol table and object members are required')
    return members


def normalize_bytes(raw):
    """Return new bytes and a portable proof; never mutate the caller's input."""
    members = archive_members(raw)
    table = members[0]
    start, end = table['payload_start'], table['payload_end']
    require(end - start >= 8, 'truncated BSD32 symbol table')
    entry_bytes = struct.unpack_from('<I', raw, start)[0]
    require(entry_bytes % 8 == 0 and entry_bytes <= end - start - 8, 'unknown or malformed BSD32 ranlib table')
    length_offset = start + 4 + entry_bytes
    string_size = struct.unpack_from('<I', raw, length_offset)[0]
    strings = length_offset + 4
    require(strings + string_size == end, 'symbol table has unrecognized trailing or missing fields')
    object_offsets = {m['header_offset'] for m in members[1:]}
    referenced, used_end = [], strings
    semantic = hashlib.sha256()
    for entry in range(start + 4, length_offset, 8):
        string_offset, object_offset = struct.unpack_from('<II', raw, entry)
        require(object_offset in object_offsets, 'symbol references no object-member header')
        require(string_offset < string_size, 'symbol string offset is outside its table')
        begin = strings + string_offset
        terminator = raw.find(b'\0', begin, end)
        require(terminator > begin, 'empty or unterminated symbol string')
        name = raw[begin:terminator]
        referenced.append(name)
        used_end = max(used_end, terminator + 1)
        semantic.update(raw[entry:entry + 8])
        semantic.update(name + b'\0')
    if table['name'] == '__.SYMDEF SORTED':
        require(referenced == sorted(referenced), 'sorted Darwin symbol table is not sorted')
    used_size = used_end - strings
    require(string_size == ((used_size + 7) // 8) * 8 and 0 <= end - used_end < 8,
            'unreferenced symbol tail is not the exact Darwin eight-byte alignment padding')
    padding = raw[used_end:end]
    normalized = raw[:used_end] + bytes(len(padding)) + raw[end:]
    require(len(normalized) == len(raw) and normalized[:used_end] == raw[:used_end] and normalized[end:] == raw[end:],
            'normalization changed nonpadding bytes')
    objects = [{'name': m['name'], 'header_offset': m['header_offset'],
                'size': m['payload_end'] - m['payload_start'],
                'sha256': sha(raw[m['payload_start']:m['payload_end']])} for m in members[1:]]
    proof = {'protocol': 'symphony.distribution.darwin-archive-padding.v1', 'layout': 'Darwin BSD32 little-endian',
             'scope': 'only fully unreferenced symbol-string tail alignment bytes; no object or header rewrite',
             'source_sha256': sha(raw), 'normalized_sha256': sha(normalized), 'archive_size': len(raw),
             'symbol_table': table['name'], 'symbol_reference_count': entry_bytes // 8,
             'referenced_symbol_semantics_sha256': semantic.hexdigest(),
             'padding_offset': used_end, 'padding_size': len(padding), 'changed_byte_count': sum(b != 0 for b in padding),
             'original_padding_sha256': sha(padding), 'normalized_padding_sha256': sha(bytes(len(padding))),
             'object_members': objects, 'member_offsets_preserved': True, 'all_nonpadding_bytes_preserved': True,
             'publication_authorized': False, 'release_acceptance_complete': False}
    return normalized, proof


def no_links(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink path refused')
    return path


def normalize_copy(source, output, expected_sha256):
    """Create a new copy only; existing source/candidate and outputs are immutable."""
    source, output = no_links(source), no_links(output)
    require(re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None, 'exact expected source SHA256 required')
    require(source != output and not os.path.lexists(output), 'output must be new; in-place normalization is forbidden')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_ARCHIVE,
                'regular unaliased bounded source archive required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_ARCHIVE + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and sha(raw) == expected_sha256,
                'source archive changed or differs from expected bytes')
    finally:
        os.close(fd)
    normalized, proof = normalize_bytes(raw)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(before.st_mode))
    with os.fdopen(fd, 'wb') as stream:
        stream.write(normalized)
    require(source.read_bytes() == raw, 'source archive changed during copy; preserve output for inspection')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output', 'expected-sha256', 'evidence'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    evidence = no_links(args.evidence)
    require(not os.path.lexists(evidence), 'preserve existing normalization evidence')
    proof = normalize_copy(args.source, args.output, args.expected_sha256)
    fd = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(proof, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps({'normalized_sha256': proof['normalized_sha256'], 'changed_byte_count': proof['changed_byte_count'],
                      'all_nonpadding_bytes_preserved': True, 'release_acceptance_complete': False}))


if __name__ == '__main__':
    main()
