#!/usr/bin/env python3
"""Publish selected signed beta downloads without replacing remote objects.

Uses a bucket-scoped S3 credential supplied by the publisher. Every new object
has a durable intent, conditional creation and exact byte readback. An unknown
write outcome is retained and must be reconciled before another invocation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import sys
import ssl
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
import beta_signing as signing

BUCKET = 'symphony-downloads'
ACCOUNT = '82afd25f0c2dee226529c3177be8b950'
PREFIX = 'symphony/0.2.0-beta.1/'
ORIGIN = 'https://downloads.quanux.org/'
PROTOCOL = 'symphony.distribution.beta-download-publication.v1'
USER_AGENT = 'Symphony-Beta-Publisher/1 (+https://github.com/QuanuX/symphony-distribution)'
require = signing.require
sha = signing.sha


def release_prefix(release):
    signing.release_policy(release)
    return 'symphony/' + release + '/'


def prepare(root, signature, certificate, public_key, openssl):
    root, signature = signing.base.plain(root), signing.base.plain(signature)
    manifest_path = signing.base.regular(signature / 'beta-manifest.json')
    raw = manifest_path.read_bytes()
    signature_raw = signing.base.regular(signature / 'beta-manifest.sig').read_bytes()
    verification = signing.verify(signature, root, certificate, public_key, openssl)
    require(manifest_path.read_bytes() == raw and (signature / 'beta-manifest.sig').read_bytes() == signature_raw,
            'Manifest or signature changed after signature verification')
    manifest = signing.strict_json(raw)
    index_raw = (root / signing.relative(manifest['release_index']['path'])).read_bytes()
    require(sha(index_raw) == verification['release_index_sha256'], 'Release index changed after verification')
    index = signing.strict_json(index_raw)
    release = index['release']; prefix = release_prefix(release)
    selected = index.get('public_downloads')
    require(type(selected) is list and 0 < len(selected) <= 768, 'Exact public download selection required')
    signed = {r['path']: r for r in manifest['artifacts']}
    rows = []
    for name in selected:
        signing.relative(name)
        require(name in signed and not name.endswith('.conda'), 'Downloads must be signed non-Conda artifacts')
        rows.append({**signed[name], 'source': 'artifacts', 'key': prefix + name, 'url': ORIGIN + prefix + name})
    require(len(set(selected)) == len(selected), 'Duplicate download selection')
    for name in ('beta-manifest.json', 'beta-manifest.sig', 'beta-cert.pem'):
        path = signing.base.regular(signature / name)
        expected = {'beta-manifest.json': sha(raw), 'beta-manifest.sig': sha(signature_raw), 'beta-cert.pem': certificate}
        require(signing.base.digest(path) == expected[name], 'Verified signature-side bytes changed')
        rows.append({'path': name, 'size': path.stat().st_size, 'sha256': signing.base.digest(path),
                     'source': 'signature', 'key': prefix + name, 'url': ORIGIN + prefix + name})
    require(len({r['key'].casefold() for r in rows}) == len(rows), 'Colliding download keys')
    return {'protocol': PROTOCOL, 'release': release, 'bucket': BUCKET,
            'manifest_sha256': signing.base.digest(signature / 'beta-manifest.json'),
            'release_index_sha256': verification['release_index_sha256'], 'objects': rows,
            'overwrite_supported': False, 'automatic_mutation_retry': False}


def journal(path, value):
    signing.base.write(path, signing.base.canonical(value))
    for target in (path, path.parent):
        descriptor = os.open(target, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def client(credentials):
    import boto3
    from botocore.config import Config
    from botocore.httpsession import get_cert_path
    path = signing.base.regular(credentials, private=True)
    value = signing.strict_json(path.read_bytes())
    require(set(value) == {'id', 'value', 'expires_on'}, 'Unexpected publisher credential format')
    return boto3.client('s3', endpoint_url=f'https://{ACCOUNT}.r2.cloudflarestorage.com', region_name='auto',
        aws_access_key_id=value['id'], aws_secret_access_key=sha(value['value'].encode()),
        verify=get_cert_path(True),
        config=Config(signature_version='s3v4', s3={'addressing_style': 'path'},
            connect_timeout=20, read_timeout=180, proxies={}, retries={'total_max_attempts': 1},
            request_checksum_calculation='when_required', response_checksum_validation='when_required'))


def streamed_digest(stream, expected_size):
    digest = hashlib.sha256(); size = 0
    try:
        while True:
            part = stream.read(1024 * 1024)
            if not part: break
            size += len(part); require(size <= expected_size, 'Remote object exceeds selected length'); digest.update(part)
    finally:
        stream.close()
    require(size == expected_size, 'Remote object length differs')
    return digest.hexdigest()


def remote(api, row):
    try:
        response = api.get_object(Bucket=BUCKET, Key=row['key'])
    except Exception as error:
        code = getattr(error, 'response', {}).get('Error', {}).get('Code')
        if code in ('NoSuchKey', '404', 'NotFound'): return False
        raise
    require(response['ContentLength'] == row['size'], 'Existing object size differs; no overwrite permitted')
    require(streamed_digest(response['Body'], row['size']) == row['sha256'],
            'Existing object bytes differ; no overwrite permitted')
    return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Public download redirected away from the selected object')


def public_readback(row):
    require(row['url'] == ORIGIN + row['key'], 'Public download destination differs')
    from botocore.httpsession import get_cert_path
    context = ssl.create_default_context(cafile=get_cert_path(True))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context), NoRedirect())
    with opener.open(urllib.request.Request(row['url'], headers={
            'Cache-Control': 'no-cache', 'User-Agent': USER_AGENT}), timeout=180) as response:
        require(response.status == 200 and response.geturl() == row['url'], 'Public download response differs')
        require(streamed_digest(response, row['size']) == row['sha256'], 'Public download hash differs')


def publish(plan, root, signature, certificate, public_key, openssl, output, api, readback=public_readback):
    require(prepare(root, signature, certificate, public_key, openssl) == plan, 'Exact current signed download plan required')
    root, signature = Path(root), Path(signature)
    prefix = release_prefix(plan['release'])
    require(plan['protocol'] == PROTOCOL and plan['bucket'] == BUCKET and
            plan['overwrite_supported'] is False and plan['automatic_mutation_retry'] is False, 'Publication scope differs')
    output = signing.base.new_directory(output)
    parent = os.open(output.parent, os.O_RDONLY)
    try: os.fsync(parent)
    finally: os.close(parent)
    journal(output / 'plan.json', plan)
    results = []
    for number, row in enumerate(plan['objects']):
        source = root if row['source'] == 'artifacts' else signature
        path = signing.base.regular(source / signing.relative(row['path']))
        require((path.stat().st_size, signing.base.digest(path)) == (row['size'], row['sha256']), 'Selected local bytes changed')
        require(row['key'] == prefix + row['path'] and row['url'] == ORIGIN + row['key'], 'Unselected destination')
        exists = remote(api, row)
        item = {'key': row['key'], 'sha256': row['sha256'], 'size': row['size'], 'url': row['url'], 'existing_identical': exists}
        if not exists:
            journal(output / f'{number:03d}-intent.json', item)
            try:
                with tempfile.TemporaryFile(dir=output) as stream:
                    digest = hashlib.sha256(); size = 0
                    with path.open('rb') as original:
                        for part in iter(lambda: original.read(1024 * 1024), b''):
                            size += len(part); require(size <= row['size'], 'Upload snapshot exceeds bound')
                            digest.update(part); stream.write(part)
                    require((size, digest.hexdigest()) == (row['size'], row['sha256']), 'Upload snapshot differs')
                    stream.seek(0)
                    api.put_object(Bucket=BUCKET, Key=row['key'], Body=stream, ContentLength=row['size'],
                        ContentType=mimetypes.guess_type(path.name)[0] or 'application/octet-stream',
                        CacheControl='public, max-age=31536000, immutable', Metadata={'sha256': row['sha256']}, IfNoneMatch='*')
            except BaseException as error:
                journal(output / f'{number:03d}-unknown.json',
                    {**item, 'state': 'unknown_write_outcome', 'exception_type': type(error).__name__, 'automatic_retry': False})
                raise ValueError('Publication stopped with unknown write outcome; reconcile retained intent and remote object before another attempt') from None
            require(remote(api, row), 'Uploaded object absent at immediate readback')
        readback(row)
        journal(output / f'{number:03d}-verified.json', {**item, 'state': 'public_bytes_verified'})
        results.append(item)
    result = {'protocol': PROTOCOL, 'release': plan['release'], 'state': 'all_selected_public_downloads_verified',
              'manifest_sha256': plan['manifest_sha256'], 'objects': results, 'overwrite_performed': False}
    journal(output / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'publish'])
    for name in ('artifacts-root', 'signature-root', 'openssl', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('certificate-sha256', 'public-key-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--plan', type=Path); parser.add_argument('--credentials', type=Path)
    parser.add_argument('--allow-public-beta-publication', action='store_true')
    args = parser.parse_args()
    plan = prepare(args.artifacts_root, args.signature_root, args.certificate_sha256, args.public_key_sha256, args.openssl)
    if args.command == 'prepare':
        signing.base.write(args.output, signing.base.canonical(plan)); print(json.dumps({'objects': len(plan['objects'])}))
    else:
        require(args.allow_public_beta_publication and args.plan and args.credentials, 'Explicit publication and exact prepared plan required')
        require(signing.strict_json(args.plan.read_bytes()) == plan, 'Prepared download plan differs from verified release')
        result = publish(plan, args.artifacts_root, args.signature_root, args.certificate_sha256, args.public_key_sha256, args.openssl, args.output, client(args.credentials))
        print(json.dumps({'state': result['state'], 'objects': len(result['objects'])}))

if __name__ == '__main__': main()
