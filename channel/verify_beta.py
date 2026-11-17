#!/usr/bin/env python3
"""Verify a Symphony beta download against the pinned publisher signature.

Python3.11+ and OpenSSL are required. No packages, accounts or system trust
changes are needed. Download beta-manifest.json, beta-manifest.sig and
beta-cert.pem beside this script. Select only files you actually downloaded.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

CERTIFICATE_SHA256 = '03e9535b87e040410cf7130f2491d4e053298f3171071faee26b076d43e3da91'
PUBLIC_KEY_SHA256 = '34621e652aef5649ba2eea9310a93a108cfc65466abc2c164d8fab0079715010'
DECISION_SHA256 = 'd87a413093f3e70b67f86973db3b04dfd0d4e394b1b2d0dce384b70a4730e943'
RELEASE = '0.2.0-beta.1'


def require(value, reason):
    if not value: raise ValueError(reason)


def regular(path, limit):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked paths are refused')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit, 'Expected a bounded regular file')
    return path


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    require(isinstance(name, str) and len(name) <= 512 and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,220}', p)
        for p in name.split('/')) and str(PurePosixPath(name)) == name, 'Unsafe signed path')
    return name


def run(openssl, args, data=None):
    result = subprocess.run([str(openssl), *map(str, args)], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30)
    require(result.returncode == 0, 'Signature or OpenSSL operation failed')
    return result.stdout


def verify(signature_root, artifact_root, paths, openssl):
    signatures, root = Path(signature_root), Path(artifact_root)
    cert = regular(signatures / 'beta-cert.pem', 65536)
    require(digest(cert) == CERTIFICATE_SHA256, 'Publisher certificate differs from the independently pinned identity')
    public = run(openssl, ['x509', '-in', cert, '-pubkey', '-noout'])
    der = run(openssl, ['pkey', '-pubin', '-outform', 'DER'], public)
    require(hashlib.sha256(der).hexdigest() == PUBLIC_KEY_SHA256, 'Publisher public key differs')
    manifest = regular(signatures / 'beta-manifest.json', 4 * 1024 * 1024)
    signature = regular(signatures / 'beta-manifest.sig', 384)
    require(signature.stat().st_size == 384, 'Unexpected beta signature length')
    raw = manifest.read_bytes()
    with tempfile.TemporaryDirectory() as temp:
        key = Path(temp) / 'public.pem'; key.write_bytes(public)
        run(openssl, ['dgst', '-sha256', '-verify', key, '-signature', signature, manifest])
    require(manifest.read_bytes() == raw, 'Manifest changed during verification')
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'Duplicate manifest field'); result[name] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, 'Nonfinite manifest'))
    require(raw == (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode(), 'Noncanonical manifest')
    require(value['protocol'] == 'symphony.distribution.public-beta-signature.v1' and value['release'] == RELEASE and
        value['certificate_sha256'] == CERTIFICATE_SHA256 and value['public_key_sha256'] == PUBLIC_KEY_SHA256 and
        value['publisher_decision']['sha256'] == DECISION_SHA256 and
        all(value[k] is False for k in ('apple_developer_id', 'notarized', 'gatekeeper_acceptance', 'system_trust_changed')),
        'Signed release or trust scope differs')
    require(type(value['artifacts']) is list and 0 < len(value['artifacts']) <= 1024, 'Invalid artifact selection')
    selected = {}; portable = set()
    for row in value['artifacts']:
        require(type(row) is dict and set(row) == {'path', 'size', 'sha256'}, 'Invalid signed artifact record')
        name = relative(row['path'])
        require(name.casefold() not in portable and type(row['size']) is int and 0 <= row['size'] <= 4*1024**3 and
                re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Invalid signed artifact identity')
        selected[name] = row; portable.add(name.casefold())
    require(paths and len(paths) == len(set(paths)), 'Select unique downloaded artifacts')
    for name in paths:
        relative(name); require(name in selected, 'Artifact is absent from signed release')
        row = selected[name]; path = regular(root / name, row['size'])
        require(path.stat().st_size == row['size'] and digest(path) == row['sha256'], 'Downloaded artifact differs: ' + name)
    return {'release': RELEASE, 'verified_downloads': paths, 'publisher_signature': 'verified',
            'apple_developer_id': False, 'notarized': False, 'system_trust_changed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signature-root', type=Path, default=Path('.'))
    parser.add_argument('--artifact-root', type=Path, default=Path('.'))
    parser.add_argument('--artifact', action='append', required=True, help='Signed relative path preserved under artifact-root')
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    print(json.dumps(verify(args.signature_root, args.artifact_root, args.artifact, args.openssl), sort_keys=True))

if __name__ == '__main__': main()
