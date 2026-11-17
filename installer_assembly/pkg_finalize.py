#!/usr/bin/env python3
"""Remove publisher metadata from generated, unsigned Apple wrapper containers.

Every real Payload/Scripts file byte and mode must survive unchanged. Native
receipts and Conda archives are opaque content here. Only generated wrapper
CPIO metadata, AppleDouble metadata, matching BOM records and outer XAR
properties are finalized. Original packages are never modified or installed.
"""
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import os
import stat
import struct
import subprocess
import xml.etree.ElementTree as ET
import zlib

MAX = 2 * 1024 ** 3
FORBIDDEN_XAR = {'uid', 'gid', 'user', 'group', 'atime', 'mtime', 'ctime', 'inode', 'deviceno', 'ea', 'FinderCreateTime'}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def name_safe(name):
    if name == '.':
        return name
    require(name.startswith('./'), 'nonrelative generated CPIO name')
    value = name[2:]
    require(value and not PurePosixPath(value).is_absolute() and '\\' not in value and
            all(p not in ('', '.', '..') for p in value.split('/')) and
            all(ord(c) >= 32 and ord(c) != 127 for c in value), 'unsafe generated CPIO path')
    return name


def apple_double(name):
    return any(p.startswith('._') for p in name.split('/'))


def recognized_apple_double(row, names):
    """Only copyfile's metadata-only AppleDouble form may be omitted."""
    name, content = row['name'], row['content']
    parts = name.split('/')
    require(parts[-1].startswith('._') and not any(p.startswith('._') for p in parts[:-1]) and
            len(parts[-1]) > 2 and stat.S_ISREG(row['mode']), 'unqualified AppleDouble path or type')
    companion = '/'.join([*parts[:-1], parts[-1][2:]])
    require(companion in names, 'orphan AppleDouble metadata refused')
    require(len(content) >= 82 and content[:8] == bytes.fromhex('0005160700020000') and
            struct.unpack('>H', content[24:26])[0] == 2, 'unrecognized AppleDouble binary format')
    finder, resource = (struct.unpack('>III', content[pos:pos + 12]) for pos in (26, 38))
    require(finder == (9, 50, len(content) - 50) and resource == (2, len(content), 0),
            'AppleDouble includes nonmetadata or unqualified resource content')
    return True


def cpio_records(data):
    require(len(data) <= MAX, 'generated CPIO exceeds limit')
    rows, names, offset = [], set(), 0
    while True:
        header = data[offset:offset + 76]
        require(len(header) == 76 and header[:6] == b'070707' and
                all(c in b'01234567' for c in header[6:]), 'unqualified or malformed generated CPIO header')
        number = lambda start, end: int(header[start:end], 8)
        length, size = number(59, 65), number(65, 76)
        require(0 < length <= 4096 and size <= MAX and offset + 76 + length + size <= len(data), 'CPIO member exceeds bounds')
        raw_name = data[offset + 76:offset + 76 + length]
        require(raw_name.endswith(b'\0') and b'\0' not in raw_name[:-1], 'invalid generated CPIO name')
        name = raw_name[:-1].decode('utf-8', errors='strict')
        content = data[offset + 76 + length:offset + 76 + length + size]
        offset += 76 + length + size
        if name == 'TRAILER!!!':
            require(size == 0 and not any(data[offset:]) and len(data[offset:]) < 512,
                    'CPIO trailer or hidden trailing bytes differ')
            break
        name_safe(name)
        require(name not in names and len(names) < 100000, 'duplicate or excessive CPIO members')
        names.add(name)
        mode = number(18, 24)
        require(stat.S_IFMT(mode) in (stat.S_IFDIR, stat.S_IFREG) and not mode & 0o7000,
                'generated CPIO link/special/privileged member refused')
        require(not stat.S_ISDIR(mode) or size == 0, 'directory carries CPIO content')
        require(number(36, 42) >= 1, 'invalid generated CPIO link count')
        rows.append({'name': name, 'header': header, 'content': content, 'mode': mode,
                     'uid': number(24, 30), 'gid': number(30, 36), 'mtime': number(48, 59),
                     'device': number(6, 12), 'rdevice': number(42, 48), 'inode': number(12, 18),
                     'link_count': number(36, 42)})
    require(rows and rows[0]['name'] == '.' and stat.S_ISDIR(rows[0]['mode']), 'generated CPIO directory root is absent')
    parents = {row['name']: row for row in rows}
    for row in rows[1:]:
        parent = row['name'].rsplit('/', 1)[0]
        require(parent in parents and stat.S_ISDIR(parents[parent]['mode']), 'CPIO parent directory is absent or non-directory')
    # pkgbuild carries the source file's link count: constructor links each
    # .conda from its private cache. That external alias is not an archive
    # member. Refuse real aliases within the CPIO, while permitting independent
    # full-content members whose original cache link count was greater than 1.
    real_regular = [row for row in rows if stat.S_ISREG(row['mode']) and not apple_double(row['name'])]
    require(len({(row['device'], row['inode']) for row in real_regular}) == len(real_regular),
            'generated CPIO hard-link alias refused')
    return rows


def content_inventory(rows):
    return {row['name']: {'mode': row['mode'], 'size': len(row['content']), 'sha256': sha(row['content'])}
            for row in rows if not apple_double(row['name'])}


def cpio_header(name, mode, size, index):
    raw_name = name.encode() + b'\0'
    header = ('070707' + f'{0:06o}{index:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{0:011o}' +
              f'{len(raw_name):06o}{size:011o}').encode()
    require(len(header) == 76, 'normalized CPIO header exceeds field width')
    return header + raw_name


def normalize_cpio(raw):
    original = cpio_records(raw)
    names = {row['name'] for row in original}
    for row in original:
        if apple_double(row['name']):
            recognized_apple_double(row, names)
    kept = [row for row in original if not apple_double(row['name'])]
    data = bytearray()
    for index, row in enumerate(kept):
        data += cpio_header(row['name'], row['mode'], len(row['content']), index) + row['content']
    data += cpio_header('TRAILER!!!', 0, 0, len(kept))
    data += b'\0' * (-len(data) % 512)
    normalized = cpio_records(bytes(data))
    require(content_inventory(original) == content_inventory(normalized), 'CPIO real file content or mode changed')
    require(all(row['uid'] == row['gid'] == row['mtime'] == row['device'] == row['rdevice'] == 0 for row in normalized),
            'normalized CPIO metadata differs')
    return bytes(data), {'real_members': len(kept), 'apple_double_members_removed': len(original) - len(kept),
                        'content_inventory_sha256': sha(json.dumps(content_inventory(normalized), sort_keys=True, separators=(',', ':')).encode())}


def gzip_bytes(raw):
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    data = decompressor.decompress(raw, MAX + 1)
    require(len(data) <= MAX and decompressor.eof and not decompressor.unused_data and not decompressor.unconsumed_tail,
            'generated gzip has trailing bytes, additional streams or exceeds limit')
    return data


def filtered_bom(text, rows):
    by_name = {row['name']: row for row in rows}
    seen, keep = set(), []
    for line in text.splitlines():
        fields = line.split('\t')
        require(len(fields) in (3, 5), 'unsupported generated BOM record')
        name = name_safe(fields[0])
        require(name in by_name and name not in seen, 'BOM/CPIO membership differs')
        seen.add(name)
        if apple_double(name):
            recognized_apple_double(by_name[name], set(by_name))
            continue
        row = by_name[name]
        require(int(fields[1], 8) == row['mode'] and fields[2] == '0/0', 'BOM mode or ownership differs')
        if stat.S_ISREG(row['mode']):
            require(len(fields) == 5 and int(fields[3]) == len(row['content']), 'BOM file size differs')
        else:
            require(len(fields) == 3, 'BOM directory has file data')
        keep.append(line)
    require(seen == set(by_name), 'BOM omits CPIO members')
    return '\n'.join(keep) + '\n'


def execute(argv, *, cwd, env, timeout=180):
    completed = subprocess.run([str(x) for x in argv], cwd=cwd, env=env, capture_output=True, timeout=timeout)
    require(completed.returncode == 0, 'Apple wrapper inspection/finalization command failed')
    return completed.stdout


def toc(path, destination, env):
    execute(['/usr/bin/xar', '-f', path, '--dump-toc=' + str(destination)], cwd=destination.parent, env=env)
    raw = destination.read_bytes()
    require(len(raw) <= 8 * 1024 ** 2 and b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,
            'unsafe or oversized XAR TOC')
    root = ET.fromstring(raw)
    require(not any(node.tag in ('signature', 'x-signature') for node in root.iter()), 'signed wrapper cannot be rewritten')
    names = set()
    def walk(element, parents=()):
        for node in element.findall('file'):
            name = node.findtext('name')
            require(isinstance(name, str) and name not in ('', '.', '..') and '/' not in name and '\\' not in name and
                    all(ord(c) >= 32 and ord(c) != 127 for c in name), 'unsafe XAR member name')
            full = '/'.join((*parents, name))
            require(full not in names, 'duplicate XAR member')
            names.add(full)
            require(node.findtext('type') in ('file', 'directory'), 'XAR link/special member refused')
            walk(node, (*parents, name))
    walk(root.find('toc'))
    return raw, root, names


def tree_inventory(root):
    values = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink() and (path.is_file() or path.is_dir()), 'unqualified extracted wrapper entry')
        if path.is_file():
            values[path.relative_to(root).as_posix()] = sha(path.read_bytes())
    return values


def finalize(source, output, work, env):
    source, output, work = (Path(os.path.abspath(p)) for p in (source, output, work))
    require(all(not p.is_symlink() for selected in (source, output, work) for p in (selected, *selected.parents)),
            'linked wrapper input/output path refused')
    require(source.is_file() and not output.exists() and not work.exists() and output.parent.is_dir() and work.parent.is_dir(),
            'wrapper finalization requires fresh outputs with existing parents')
    require(source != output and source != work and output != work and
            all(a not in b.parents and b not in a.parents for a, b in ((source, output), (source, work), (output, work))),
            'wrapper finalization paths overlap')
    original_sha = sha(source.read_bytes())
    work.mkdir(mode=0o700)
    _, _, names = toc(source, work / 'before.xml', env)
    extracted = work / 'components'; extracted.mkdir(mode=0o700)
    execute(['/usr/bin/xar', '-xf', source, '-C', extracted], cwd=work, env=env)
    before = tree_inventory(extracted)
    require(set(before) <= names and 'Distribution' in before, 'XAR extraction inventory differs')
    transformations = []
    allowed_changes = set()
    for payload in sorted(extracted.glob('*.pkg/Payload')):
        component = payload.parent
        raw = gzip_bytes(payload.read_bytes()); original_rows = cpio_records(raw)
        normalized, record = normalize_cpio(raw)
        payload.write_bytes(gzip.compress(normalized, mtime=0))
        allowed_changes.add(payload.relative_to(extracted).as_posix())
        bom = component / 'Bom'
        require(bom.is_file(), 'generated component BOM is absent')
        original_bom = execute(['/usr/bin/lsbom', bom], cwd=work, env=env).decode()
        listing = filtered_bom(original_bom, original_rows)
        filelist = work / (component.name + '.bom-list.txt'); filelist.write_text(listing)
        replacement_bom = work / (component.name + '.Bom')
        execute(['/usr/bin/mkbom', '-i', filelist, replacement_bom], cwd=work, env=env)
        require(execute(['/usr/bin/lsbom', replacement_bom], cwd=work, env=env).decode() == listing,
                'regenerated BOM entries/checksums differ')
        bom.write_bytes(replacement_bom.read_bytes()); allowed_changes.add(bom.relative_to(extracted).as_posix())
        info = component / 'PackageInfo'
        parsed = ET.fromstring(info.read_bytes())
        descriptor = parsed.find('payload'); require(descriptor is not None, 'component payload descriptor absent')
        descriptor.set('numberOfFiles', str(record['real_members']))
        size_kib = (sum(len(r['content']) for r in original_rows if not apple_double(r['name'])) + 1023) // 1024
        descriptor.set('installKBytes', str(max(int(descriptor.attrib['installKBytes']), size_kib)))
        info.write_bytes(ET.tostring(parsed, encoding='utf-8', xml_declaration=True))
        allowed_changes.add(info.relative_to(extracted).as_posix())
        scripts = component / 'Scripts'
        if scripts.exists():
            fixed, scripts_record = normalize_cpio(gzip_bytes(scripts.read_bytes()))
            scripts.write_bytes(gzip.compress(fixed, mtime=0))
            record['scripts'] = scripts_record
            allowed_changes.add(scripts.relative_to(extracted).as_posix())
        transformations.append({'component': component.name, **record})
    require(transformations and {r['component'] for r in transformations} == {'prepare_installation.pkg', 'run_installation.pkg'},
            'unapproved generated PKG component set')
    after = tree_inventory(extracted)
    require(before.keys() == after.keys() and all(before[n] == after[n] for n in before.keys() - allowed_changes),
            'unselected wrapper component bytes changed')
    args = ['/usr/bin/xar', '-cf', output, '--distribution', '--toc-cksum=sha256', '--file-cksum=sha256', '--compression=none']
    args += ['--prop-exclude=' + name for name in sorted(FORBIDDEN_XAR)]
    args += sorted(path.name for path in extracted.iterdir())
    execute(args, cwd=extracted, env=env)
    final_xml, final_root, final_names = toc(output, work / 'after.xml', env)
    require(final_names == names and not any(node.tag in FORBIDDEN_XAR for node in final_root.iter()),
            'final XAR contains publisher ownership/device/extended metadata')
    verify = work / 'verified-components'; verify.mkdir(mode=0o700)
    execute(['/usr/bin/xar', '-xf', output, '-C', verify], cwd=work, env=env)
    require(tree_inventory(verify) == after, 'final XAR altered component bytes')
    require(sha(source.read_bytes()) == original_sha, 'original wrapper changed during finalization')
    return {'protocol': 'symphony.distribution.unsigned-pkg-finalization.v1',
            'original_sha256': original_sha, 'final_sha256': sha(output.read_bytes()),
            'final_toc_sha256': sha(final_xml), 'components': transformations,
            'original_wrapper_unchanged': True, 'all_real_payload_and_script_bytes_unchanged': True,
            'native_or_conda_bytes_modified': False, 'installer_executed': False,
            'signed_input_refused': True, 'publication_authorized': False,
            'helper_sha256': sha(Path(__file__).read_bytes())}
