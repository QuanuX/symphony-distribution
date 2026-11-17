#!/usr/bin/env python3
"""Self-sign review artifact manifests without changing payloads or system trust.

An explicitly pinned self-signed certificate authenticates possession of a review
key only. It is not Apple Developer ID, notarization or publication approval.
Private credentials stay in a separate, private custody directory. No default
keychain or trust-store operation is performed by this tool.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

SCHEMA = 'symphony.distribution.review-signature.v1'
SCOPE = 'review-only artifact integrity; explicit certificate pin required'
SUBJECT = '/O=QuanuX/OU=Symphony Review Only/CN=QuanuX Symphony Review Installer'
LIMIT = 8 * 1024 * 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def plain(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked path refused')
    return path


def regular(path, *, private=False):
    path = plain(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= LIMIT,
            'Expected a bounded unaliased regular file')
    if private:
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                'Signing credential must be private to its owner')
    return path


def digest(path):
    path = regular(path)
    before = path.stat(); h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Artifact changed while hashed')
    return h.hexdigest()


def new_directory(path):
    path = plain(path)
    require(path.parent.is_dir() and not os.path.lexists(path), 'Output requires a new directory')
    path.mkdir(mode=0o700)
    return path


def write(path, data, mode=0o600):
    fd = os.open(plain(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def run(openssl, args, *, data=None):
    result = subprocess.run([str(regular(openssl)), *map(str, args)], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'OpenSSL review operation failed; no credential output retained')
    return result.stdout


def pinned_certificate(openssl, certificate, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected or ''), 'Independently selected certificate SHA256 required')
    certificate = regular(certificate)
    require(digest(certificate) == expected, 'Certificate differs from selected review key')
    run(openssl, ['x509', '-in', certificate, '-checkend', '0', '-noout'])
    run(openssl, ['verify', '-check_ss_sig', '-CAfile', certificate, certificate])
    return certificate


def initialize(custody, openssl):
    root = plain(custody)
    repo = Path(__file__).resolve().parents[1]
    require(repo not in root.parents and root != repo, 'Private key custody must be outside the source repository')
    root = new_directory(root)
    password = root / 'password'; key = root / 'review-key.pem'; cert = root / 'review-cert.pem'
    write(password, secrets.token_urlsafe(48).encode() + b'\n')
    # umask also protects keys created by the child process, including on error.
    old = os.umask(0o077)
    try:
        run(openssl, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
                      '-aes-256-cbc', '-pass', 'file:' + str(password), '-out', key])
        run(openssl, ['req', '-new', '-x509', '-sha256', '-days', '365', '-key', key,
                      '-passin', 'file:' + str(password), '-out', cert, '-subj', SUBJECT,
                      '-addext', 'basicConstraints=critical,CA:TRUE',
                      '-addext', 'keyUsage=critical,digitalSignature,keyCertSign',
                      '-addext', 'extendedKeyUsage=codeSigning'])
    finally:
        os.umask(old)
    regular(key, private=True); regular(password, private=True)
    fingerprint = digest(cert); pinned_certificate(openssl, cert, fingerprint)
    report = {'protocol': SCHEMA, 'state': 'self_signed_review_key_created',
        'certificate_sha256': fingerprint, 'subject': SUBJECT, 'algorithm': 'RSA-3072 / SHA-256',
        'private_material_exported': False, 'system_trust_changed': False,
        'apple_developer_id': False, 'notarized': False, 'publication_authorized': False}
    write(root / 'public-identity.json', canonical(report))
    return report


def artifact_rows(paths):
    rows = []
    for path in paths:
        path = regular(path)
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,220}', path.name), 'Unsafe artifact filename')
        rows.append({'name': path.name, 'sha256': digest(path), 'size': path.stat().st_size})
    require(rows and len(rows) <= 256 and len({r['name'] for r in rows}) == len(rows),
            'Empty, duplicate or excessive artifact set')
    return sorted(rows, key=lambda row: row['name'])


def sign(paths, custody, expected, output, openssl):
    root = plain(custody)
    require(stat.S_IMODE(root.stat().st_mode) & 0o077 == 0 and root.stat().st_uid == os.getuid(),
            'Review custody must be private to its owner')
    key = regular(root / 'review-key.pem', private=True)
    password = regular(root / 'password', private=True)
    cert = pinned_certificate(openssl, root / 'review-cert.pem', expected)
    files = artifact_rows(paths)
    require(all(plain(p) != root and root not in plain(p).parents for p in paths),
            'Credential custody is never an artifact')
    out = new_directory(output)
    value = {'protocol': SCHEMA, 'scope': SCOPE,
             'certificate_sha256': expected, 'artifacts': files, 'apple_developer_id': False,
             'notarized': False, 'independent_publisher_authentication': False,
             'release_acceptance_complete': False, 'publication_authorized': False}
    write(out / 'review-manifest.json', canonical(value), 0o644)
    write(out / 'review-cert.pem', cert.read_bytes(), 0o644)
    run(openssl, ['dgst', '-sha256', '-sign', key, '-passin', 'file:' + str(password),
                  '-out', out / 'review-manifest.sig', out / 'review-manifest.json'])
    verify_manifest_signature(openssl, cert, out / 'review-manifest.sig', out / 'review-manifest.json')
    require(artifact_rows(paths) == files, 'Artifact changed during signing')
    return value


def verify_manifest_signature(openssl, cert, signature, manifest):
    with tempfile.TemporaryDirectory(prefix='symphony-review-verify-') as temporary:
        pub = Path(temporary) / 'public.pem'
        pub.write_bytes(run(openssl, ['x509', '-in', cert, '-pubkey', '-noout']))
        run(openssl, ['dgst', '-sha256', '-verify', pub, '-signature', signature, manifest])


def verify(signature_root, artifacts, expected, openssl):
    root, artifacts = plain(signature_root), plain(artifacts)
    cert = pinned_certificate(openssl, root / 'review-cert.pem', expected)
    manifest, signature = regular(root / 'review-manifest.json'), regular(root / 'review-manifest.sig')
    require(manifest.stat().st_size <= 1024 * 1024, 'Manifest exceeds bound')
    raw = manifest.read_bytes()
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate manifest key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(raw == canonical(value) and set(value) == {'protocol', 'scope', 'certificate_sha256', 'artifacts',
            'apple_developer_id', 'notarized', 'independent_publisher_authentication',
            'release_acceptance_complete', 'publication_authorized'} and value['protocol'] == SCHEMA and
            value['certificate_sha256'] == expected and value['scope'] == SCOPE, 'Review manifest shape, scope or certificate differs')
    require(all(value[k] is False for k in ('apple_developer_id', 'notarized', 'independent_publisher_authentication',
                                          'release_acceptance_complete', 'publication_authorized')), 'Unselected trust/approval claim')
    require(type(value['artifacts']) is list and 0 < len(value['artifacts']) <= 256, 'Invalid artifact set')
    for row in value['artifacts']:
        require(type(row) is dict and set(row) == {'name', 'size', 'sha256'} and
                re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,220}', row['name']), 'Unsafe artifact entry')
    verify_manifest_signature(openssl, cert, signature, manifest)
    require(artifact_rows([artifacts / row['name'] for row in value['artifacts']]) == value['artifacts'],
            'Signed artifact bytes, sizes or selection differ')
    return {'protocol': SCHEMA, 'state': 'review_signature_and_artifacts_verified',
            'certificate_sha256': expected, 'artifact_count': len(value['artifacts']),
            'system_trust_changed': False, 'publication_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('initialize'); init.add_argument('--custody', type=Path, required=True)
    signing = sub.add_parser('sign'); signing.add_argument('--custody', type=Path, required=True)
    signing.add_argument('--output', type=Path, required=True)
    signing.add_argument('--artifact', type=Path, action='append', required=True)
    checking = sub.add_parser('verify'); checking.add_argument('--signature-root', type=Path, required=True)
    checking.add_argument('--artifacts', type=Path, required=True)
    for command in (signing, checking): command.add_argument('--trusted-certificate-sha256', required=True)
    args = parser.parse_args()
    if args.command == 'initialize': result = initialize(args.custody, args.openssl)
    elif args.command == 'sign': result = sign(args.artifact, args.custody, args.trusted_certificate_sha256, args.output, args.openssl)
    else: result = verify(args.signature_root, args.artifacts, args.trusted_certificate_sha256, args.openssl)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
