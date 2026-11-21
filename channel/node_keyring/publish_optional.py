"""Prepare or execute the signed two-package Anaconda supplement after public source readback."""
import argparse
import io
import json
from pathlib import Path
import tarfile
import tempfile

from prepare_release import CONDA_SHA, INDEX, PACKAGES, RELEASE, RELEASE_SOURCE, SOURCE, load_publisher, require, sha


def mirrored_bytes(root, row, pub):
    path = pub.fs.regular(root / pub.b.relative(row['archive_mirror']))
    data = pub.c.bounded(path)[0]
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        require(archive.getnames() == [row['filename']], 'Mirror member differs')
        member = archive.getmember(row['filename'])
        require(member.isfile() and member.size == row['size'], 'Mirror package size differs')
        raw = archive.extractfile(member).read()
    require(sha(raw) == row['sha256'], 'Immutable Conda bytes differ')
    return raw


def prepare(a, pub):
    import beta_downloads as downloads
    import verify_beta as verifier
    root = pub.fs.plain(a.artifacts_root)
    verified = downloads.prepare(root, a.signature_root, verifier.CERTIFICATE_SHA256, verifier.PUBLIC_KEY_SHA256, a.openssl)
    require(verified['release'] == RELEASE, 'Unselected beta release')
    objects = {r['path']: r for r in verified['objects']}
    digest = objects[INDEX]['sha256']
    index = pub.document(root / 'release-index.json')
    selection = index['optional_linux_node_keyring']
    require(selection == {'index': INDEX, 'sha256': digest, 'source': SOURCE, 'default_installer_inclusion': False}, 'Signed selection differs')
    manifest = pub.document(root / INDEX)
    require(manifest['release'] == RELEASE and manifest['core_commit'] == RELEASE_SOURCE and manifest['default_installer_inclusion'] is False
            and manifest['source'] == SOURCE and len(manifest['packages']) == 2, 'Incorrect supplemental release')
    for record in manifest['downloads']:
        require(all(objects[record['path']][k] == v for k, v in record.items()), 'Supplemental download differs from signed inventory')
    rows = []
    for arch, (subdir, _) in PACKAGES.items():
        row, = [r for r in manifest['packages'] if r['profile'] == 'ubuntu26.04-' + arch]
        require(row['subdir'] == subdir and row['sha256'] == CONDA_SHA[arch] and row['name'] == 'symphony-node-keyring-deb-payload' and
                row['filename'] == f"{row['name']}-{row['version']}-{row['build']}.conda" and
                row['url'] == pub.url(row) and row['archive_mirror'] in objects, 'Unselected supplemental archive')
        raw = mirrored_bytes(root, row, pub)
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp).resolve() / row['filename']
            file.write_bytes(raw)
            pub.audit_archive(file, {**row, 'selection': 'optional-node-keyring'})
        rows.append(row)
    return pub.s.seal({'release': RELEASE, 'release_index_sha256': verified['release_index_sha256'], 'supplement_sha256': digest,
            'source': objects[SOURCE], 'license': objects['source/optional-node-keyring/LICENSE-AGPL-3.0.txt'], 'packages': rows,
            'labels': ['beta', 'beta-' + RELEASE + '-' + verified['release_index_sha256'][:12]]})


def publish(a, pub, plan):
    import beta_downloads as downloads
    require(a.allow_public_beta_publication and a.plan and pub.document(a.plan) == plan, 'Exact prepared plan and publisher opt-in required')
    output = pub.fs.plain(a.output)
    for protected in (a.artifacts_root, a.signature_root, a.plan):
        protected = pub.fs.plain(protected)
        require(output != protected and output not in protected.parents and protected not in output.parents, 'Select a separate journal directory')
    for name in ('source', 'license'):
        downloads.public_readback(plan[name])
    api = pub.s.publisher_api()
    for row in plan['packages']:
        pub.metadata(api, row)
    attempt = pub.Attempt(output, plan)
    attempt.event({'state': 'public_source_and_license_verified', 'source_sha256': plan['source']['sha256']})
    results = []
    try:
        pub.ensure_catalog(api, plan, plan['packages'][0], attempt, require_existing=False)
        for row in plan['packages']:
            data = mirrored_bytes(a.artifacts_root, row, pub)
            existing = pub.metadata(api, row)
            if existing is None:
                with tempfile.TemporaryFile(dir=output) as stream:
                    stream.write(data)
                    stream.seek(0)
                    attempt.mutate('upload', row, lambda: api.upload('QuanuX', *pub.remote_key(row), stream, 'conda',
                        description='Optional Ubuntu 26.04 Debian delivery for a node keyring. Corresponding source: ' + plan['source']['url'],
                        sha256=row['sha256'], size=row['size'], dependencies={'depends': []}, attrs=pub.s.upload_attrs(row), channels=plan['labels']))
                existing = pub.metadata(api, row)
                require(existing is not None, 'Upload not confirmed; reconcile before retry')
            for label in plan['labels']:
                if label not in existing['labels']:
                    attempt.mutate('add_exact_build_label_' + label, row, lambda: api.add_channel(label, 'QuanuX', *pub.remote_key(row)))
                    existing = pub.metadata(api, row)
                    require(existing and label in existing['labels'], 'Label not confirmed; reconcile before retry')
                location = output / (label + '-' + row['filename'])
                results.append(pub.s.download({**row, 'url': pub.url(row, label)}, location))
            attempt.event({'state': 'public_bytes_verified', 'filename': row['filename'], 'sha256': row['sha256']})
    except Exception as exc:
        attempt.event({'state': 'stopped_reconcile_before_retry', 'error_class': type(exc).__name__})
        raise
    pub.fs.write(output / 'publication.json', pub.fs.canonical({'release': RELEASE, 'plan_sha256': plan['plan_sha256'], 'public_readbacks': results}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('prepare', 'publish'))
    for name in ('distribution', 'artifacts-root', 'signature-root', 'openssl', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--plan', type=Path)
    p.add_argument('--allow-public-beta-publication', action='store_true')
    a = p.parse_args()
    pub = load_publisher(a.distribution)
    plan = prepare(a, pub)
    if a.command == 'prepare':
        pub.fs.write(a.output, pub.fs.canonical(plan))
    else:
        publish(a, pub, plan)
    print(json.dumps({'command': a.command, 'source': plan['source']['url'], 'packages': len(plan['packages']), 'plan_sha256': plan['plan_sha256']}))


if __name__ == '__main__':
    main()
