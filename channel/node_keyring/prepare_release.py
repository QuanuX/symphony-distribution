"""Stage the optional Ubuntu node keyring and attach it to a fresh unsigned release copy."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from build import PACKAGES, RELEASE_SOURCE, SOURCE_TREE, git

HERE = Path(__file__).resolve().parent
PREFIX = 'supplements/linux-node-keyring'
INDEX = PREFIX + '/index.json'
SOURCE = 'source/optional-node-keyring/corresponding-source.tar.gz'
RELEASE = '0.2.0-beta.2.1'
TOOLKIT = '6e4bb749b9274d3a91c5eb6a2e99fc02061a5613'
CONDA_SHA = {'amd64': 'dcca67af24933a5596670d08693c16b3b69c5ee8e4c074f636d056481789dd41',
             'arm64': '59c6c58fe5f371c4cb8a527c02dfd56f411f24c9fe6084413d18676d347a7c0c'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def tar(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, (raw, mode) in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.mode, member.size = mode, len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return out.getvalue()


def git_sources(repo, commit, prefix, paths):
    raw = subprocess.check_output(['git', '-C', str(repo), 'archive', commit, '--', *paths])
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        files = {}
        for member in archive:
            if member.isdir():
                continue
            require(member.isfile() and '..' not in Path(member.name).parts, 'Unexpected source member')
            files[f'{prefix}/{member.name}'] = (archive.extractfile(member).read(), member.mode & 0o755)
    return files


def load_publisher(repo):
    sys.path[:0] = [str(repo.resolve() / 'channel'), str(repo.resolve() / 'installer_assembly')]
    import beta_publish
    return beta_publish


def stage(a):
    pub = load_publisher(a.distribution)
    a.carriers = pub.fs.plain(a.carriers)
    require(git(a.core, 'rev-parse', RELEASE_SOURCE + '^{tree}') == SOURCE_TREE, 'Source tree differs')
    original = pub.document(a.carriers / 'supplement.json')
    require((original['source_commit'], original['distribution_toolkit']) == (RELEASE_SOURCE, TOOLKIT), 'Provenance differs')
    out = pub.fs.new_directory(a.output)
    def put(path, data):
        pub.b.relative(path)
        dest = out / path
        dest.parent.mkdir(exist_ok=True, parents=True)
        pub.fs.write(dest, data, 0o644)
        return {'path': path, 'sha256': sha(data), 'size': len(data)}
    base = 'modules/secure-identity-access-governance'
    files = git_sources(a.core, RELEASE_SOURCE, 'Symphony', ['LICENSE', 'cmake', base + '/platform',
                        base + '/go.mod', base + '/go.sum', base + '/CREDENTIAL-QUALIFICATION.md'])
    files.update(git_sources(a.distribution, TOOLKIT, 'symphony-distribution', ['LICENSE', 'installer_assembly/carriers.py',
                             'installer_assembly/supplements.py', 'installer_assembly/tool-lock.json', 'recipes/build_go_carriers.py',
                             'recipes/go_generate.py', 'recipes/stage_payload.py', 'lifecycle/go_delivery.py', 'owner-catalog/native_owners.py']))
    for name in ('build.py', 'verify.sh', 'operator.md'):
        files['supplement/' + name] = ((HERE / name).read_bytes(), 0o644)
    files['README.md'] = (('This archive contains the selected native sources, build scripts, qualification fixture, '
        'and the corresponding distribution tools.\n\nCore commit ' + RELEASE_SOURCE + '\n\nDistribution commit ' + TOOLKIT +
        '\n\nOn each Ubuntu 26.04 architecture run `bash Symphony/' + base + '/platform/linux-node-keyring/packaging/build-deb.sh "$PWD/debs"`. '
        'See the component README for build prerequisites. `supplement/build.py --help` describes building the Conda delivery with the '
        'published Git checkouts and retained Debian packages. The generated recipes for both exact packages are included.\n').encode(), 0o644)
    downloads = [put(PREFIX + '/README.md', (HERE / 'operator.md').read_bytes()),
                 put('source/optional-node-keyring/LICENSE-AGPL-3.0.txt', files['Symphony/LICENSE'][0])]
    packages = []
    for arch, (subdir, deb_sha) in PACKAGES.items():
        profile = 'ubuntu26.04-' + arch
        row, = [row for row in original['archives'] if row['profile'] == profile]
        require((row['subdir'], row['sha256'], row['debian']['sha256']) == (subdir, CONDA_SHA[arch], deb_sha), 'Unexpected target identity')
        package = a.carriers / 'channel' / subdir / row['filename']
        pub.audit_archive(package, {**row, 'selection': 'optional-node-keyring'})
        raw = package.read_bytes()
        contents, _, _ = pub.c.archive_entries(package)
        payload = contents[row['carrier_destination'] + '/payload.tar'][0]
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as archive:
            name = row['debian']['filename']
            require(archive.getnames() == [name] and archive.getmember(name).isfile(), 'Unexpected Debian payload')
            deb = archive.extractfile(name).read()
        require(sha(deb) == deb_sha, 'Embedded Debian hash differs')
        for item in sorted((a.carriers / 'recipes' / profile).rglob('*')):
            if item.is_file() and item.name != 'payload.tar':
                files['supplement/' + str(item.relative_to(a.carriers))] = (item.read_bytes(), 0o644)
        nested = put(f'{PREFIX}/{profile}/conda-archive.tar', tar({row['filename']: (raw, 0o644)}))
        explicit = put(f'{PREFIX}/{profile}/explicit.txt', ('@EXPLICIT\n' + pub.url(row) + '#sha256:' + row['sha256'] + '\n').encode())
        binary = put(f'{PREFIX}/{profile}/symphony-node-keyring.deb', deb)
        log = getattr(a, arch + '_log').read_bytes()
        require(len(log) <= 16384 and f'PASS Ubuntu 26.04 {arch} Conda delivery, native installation, offline authentication and removal\n'.encode() in log,
                'Full installed qualification missing for ' + arch)
        proof = put(f'{PREFIX}/{profile}/installed-qualification.txt', log)
        downloads.extend([nested, explicit, binary, proof])
        packages.append({**row, 'archive_mirror': nested['path'], 'explicit_file': explicit['path'], 'debian_download': binary['path'],
                         'qualification': proof['path'], 'url': pub.url(row)})
    downloads.append(put(SOURCE, gzip.compress(tar(files), mtime=0)))
    put(INDEX, canonical({'release': RELEASE, 'core_commit': RELEASE_SOURCE, 'core_tree': SOURCE_TREE,
        'distribution_toolkit': TOOLKIT, 'default_installer_inclusion': False, 'source': SOURCE,
        'qualification': 'Ubuntu 26.04 architecture-specific disposable containers with synthetic credentials and emulated service directories',
        'hardware_qualification': False, 'packages': packages, 'downloads': sorted(downloads, key=lambda r: r['path'])}))
    print(json.dumps({'supplement_index': INDEX, 'sha256': pub.fs.digest(out / INDEX), 'downloads': len(downloads) + 1}))


def attach(a):
    pub = load_publisher(a.distribution)
    root, extra = pub.fs.plain(a.primary), pub.fs.plain(a.supplement)
    out = pub.fs.plain(a.output)
    require(all(out != path and path not in out.parents and out not in path.parents for path in (root, extra)), 'Roots must be separate')
    original = pub.fs.regular(root / 'release-index.json')
    require(pub.fs.digest(original) == a.primary_sha256, 'Primary release index changed')
    index = pub.document(original)
    require(index['release'] == RELEASE and index['state'] == 'qualified_public_beta_bundle_prepared' and
            set(index['profiles']) == set(pub.PROFILES) and len(index['conda_packages']) == 240 and
            all(p['source_binding']['source_commit'] == RELEASE_SOURCE and p['source_binding']['source_tree'] == SOURCE_TREE for p in index['profiles'].values()) and
            index['publication_performed'] is False and index['signature_performed'] is False and 'optional_linux_node_keyring' not in index,
            'Complete fresh unsigned primary bundle required')
    require(not any((root / name).exists() for name in ['beta-manifest.json', 'beta-manifest.sig']), 'Previously signed artifact root')
    paths = {r['path'] for r in index['artifacts'] if r['path'].endswith('.conda')}
    require(len(paths) == 240 and paths == {r['path'] for r in index['conda_packages']}, 'Primary Conda closure differs')
    for profile in pub.PROFILES:
        selected = [r for r in index['conda_packages'] if r['profile'] == profile]
        require(sum(r['selection'] == 'default' for r in selected) == 59 and
                sum(r['selection'] == 'optional-source' for r in selected) == 1, 'Primary profile coverage differs')
    manifest = pub.document(extra / INDEX)
    require(pub.fs.digest(extra / INDEX) == a.supplement_sha256 and manifest['release'] == RELEASE and manifest['core_commit'] == RELEASE_SOURCE,
            'Supplement differs from selection')
    wanted = [r['path'] for r in manifest['downloads']]
    require(pub.b.artifact_rows(extra, [extra / pub.b.relative(n) for n in wanted]) == manifest['downloads'], 'Supplement inventory differs')
    require(all(n.startswith((PREFIX + '/', 'source/optional-node-keyring/')) and not n.endswith('.conda') for n in wanted), 'Unselected supplemental path')
    extras = pub.b.artifact_rows(extra, [extra / n for n in [*wanted, INDEX]])
    require(pub.b.artifact_rows(root, [root / pub.b.relative(r['path']) for r in index['artifacts']]) == index['artifacts'], 'Primary inventory differs')
    rows = sorted(index['artifacts'] + extras, key=lambda r: r['path'])
    require(len({r['path'].casefold() for r in rows}) == len(rows) < 1024 and len(index['public_downloads']) + len(extras) <= 768, 'Release limits exceeded')
    out = pub.fs.new_directory(out)
    for source, selected in ((root, index['artifacts']), (extra, extras)):
        for row in selected:
            dest = out / row['path']
            dest.parent.mkdir(exist_ok=True, parents=True)
            shutil.copyfile(source / row['path'], dest)
    require(pub.b.artifact_rows(out, [out / r['path'] for r in rows]) == rows, 'Copied release bytes changed')
    index.update(artifacts=rows, optional_linux_node_keyring={'index': INDEX, 'sha256': a.supplement_sha256,
                 'source': SOURCE, 'default_installer_inclusion': False}, primary_bundle_index_sha256=a.primary_sha256)
    index['public_downloads'] = sorted(index['public_downloads'] + [r['path'] for r in extras],
                                       key=lambda n: (0 if n.startswith('source/') else 1 if n.startswith('installers/') else 2, n))
    pub.fs.write(out / 'release-index.json', pub.fs.canonical(index), 0o644)
    print(json.dumps({'release_index_sha256': pub.fs.digest(out / 'release-index.json'), 'primary_packages': 240, 'optional_packages': 2}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    make = sub.add_parser('stage'); join = sub.add_parser('attach')
    for parser in (make, join):
        for name in ('distribution', 'output'):
            parser.add_argument('--' + name, type=Path, required=True)
    for name in ('core', 'carriers', 'amd64-log', 'arm64-log'):
        make.add_argument('--' + name, type=Path, required=True)
    for name in ('primary', 'supplement'):
        join.add_argument('--' + name, type=Path, required=True)
        join.add_argument('--' + name + '-sha256', required=True)
    args = p.parse_args()
    (stage if args.command == 'stage' else attach)(args)


if __name__ == '__main__':
    main()
