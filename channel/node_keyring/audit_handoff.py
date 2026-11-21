"""Hash-bind and privacy-scan the twelve public node-keyring downloads and their expanded payloads."""
import argparse
import gzip
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from prepare_release import CONDA_SHA, INDEX, PACKAGES, PREFIX, RELEASE, SOURCE, load_publisher, require, sha, tar

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def entries(data, mode, scanner, context, *, directories=False, limit=1024):
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as stream:
        for member in stream:
            if member.isdir() and directories:
                continue
            name = member.name.removeprefix('./') if directories else member.name
            scanner.safe_path(name)
            require(member.isfile() and not member.linkname and name not in result and len(result) < limit and
                    member.size <= MAX_FILE and total + member.size <= MAX_TOTAL, 'Unexpected archive member or size')
            raw = stream.extractfile(member).read(member.size + 1)
            require(len(raw) == member.size, 'Truncated nested download')
            scanner.scan(context + '/' + name, raw)
            require(not re.search(rb'(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9_.-]+(?:/|\\|[\x00\x20])', raw), 'Publisher home path in ' + context + '/' + name)
            result[name] = raw
            total += member.size
    return result


def audit(files, pub, scanner, temp):
    expected = {INDEX, PREFIX + '/README.md', SOURCE, 'source/optional-node-keyring/LICENSE-AGPL-3.0.txt'}
    for arch in PACKAGES:
        expected.update(f'{PREFIX}/ubuntu26.04-{arch}/{name}' for name in
                        ('explicit.txt', 'conda-archive.tar', 'installed-qualification.txt', 'symphony-node-keyring.deb'))
    require(set(files) == expected, 'Unexpected supplemental download list')
    manifest = pub.b.strict_json(files[INDEX])
    require(manifest['release'] == RELEASE and manifest['source'] == SOURCE, 'Unselected supplemental release')
    rows = sorted((dict(path=k, size=len(v), sha256=sha(v)) for k, v in files.items() if k != INDEX), key=lambda x: x['path'])
    require(rows == manifest['downloads'], 'Manifest does not describe exact downloads')
    for name, data in files.items():
        scanner.scan(name, data)
        if name.endswith(('.md', '.txt', '.json')):
            require(not re.search(rb'(?<![A-Za-z0-9_])/(?:Users|home)/[A-Za-z0-9_.-]+', data), 'Local path in public document')
    src = entries(files[SOURCE], 'r:gz', scanner, 'source')
    require(src['Symphony/LICENSE'] == files['source/optional-node-keyring/LICENSE-AGPL-3.0.txt'], 'Source and license differ')
    for arch, (subdir, deb_sha) in PACKAGES.items():
        row, = [r for r in manifest['packages'] if r['profile'] == 'ubuntu26.04-' + arch]
        require(row['subdir'] == subdir and row['sha256'] == CONDA_SHA[arch], 'Conda identity differs')
        mirror = entries(files[row['archive_mirror']], 'r:', scanner, 'mirror', limit=1)
        require(set(mirror) == {row['filename']} and sha(mirror[row['filename']]) == CONDA_SHA[arch], 'Conda mirror differs')
        package = temp / row['filename']
        package.write_bytes(mirror[row['filename']])
        pub.audit_archive(package, {**row, 'selection': 'optional-node-keyring'})
        archive, _, _ = pub.c.archive_entries(package)
        for name, (raw, _) in archive.items():
            scanner.scan('conda/' + name, raw)
        nested = entries(archive[row['carrier_destination'] + '/payload.tar'][0], 'r:', scanner, 'payload', limit=1)
        deb = files[row['debian_download']]
        require(len(nested) == 1 and nested[row['debian']['filename']] == deb and sha(deb) == deb_sha, 'Debian identity differs')
        debfile = temp / (arch + '.deb')
        debfile.write_bytes(deb)
        members = subprocess.check_output(['ar', 't', str(debfile)], text=True).splitlines()
        require(members == ['debian-binary', 'control.tar.xz', 'data.tar.xz'], 'Unexpected Debian container')
        for name in members[1:]:
            raw = subprocess.check_output(['ar', 'p', str(debfile), name])
            entries(raw, 'r:xz', scanner, 'deb-' + arch + '/' + name, directories=True)
    return {'files': len(files), 'source_members': len(src), 'supplement_sha256': sha(files[INDEX]), 'policy_sha256': scanner.POLICY_DIGEST}


def deterministic_gzip(data):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0) as stream:
        stream.write(data)
    return buffer.getvalue()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('pack', 'unpack'))
    for name in ('distribution', 'privacy-policy', 'directory', 'archive'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--sha256')
    a = p.parse_args()
    pub = load_publisher(a.distribution)
    scanner = pub.c.load_module('node_privacy', a.distribution / 'source-export/export_source.py')
    scanner.configure_policy(a.privacy_policy)
    root = pub.fs.plain(a.directory)
    if a.command == 'pack':
        members = list(root.rglob('*'))
        require(len(members) < 32 and not any(x.is_symlink() for x in members), 'Noncanonical or excessive entries')
        files = {f.relative_to(root).as_posix(): pub.c.bounded(pub.fs.regular(f), MAX_FILE)[0] for f in members if f.is_file()}
    else:
        data = pub.c.bounded(pub.fs.regular(a.archive), MAX_FILE)[0]
        require(sha(data) == a.sha256 and a.sha256 is not None, 'Handoff archive differs from independent pin')
        files = entries(data, 'r:gz', scanner, 'handoff', limit=12)
    with tempfile.TemporaryDirectory() as tmp:
        result = audit(files, pub, scanner, Path(tmp).resolve())
    if a.command == 'pack':
        data = deterministic_gzip(tar({k: (v, 0o644) for k, v in files.items()}))
        pub.fs.write(a.archive, data, 0o644)
    else:
        root = pub.fs.new_directory(root)
        for name, raw in files.items():
            dest = root / pub.b.relative(name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            pub.fs.write(dest, raw, 0o644)
    print(json.dumps({**result, 'archive_sha256': sha(data)}, sort_keys=True))


if __name__ == '__main__':
    main()
