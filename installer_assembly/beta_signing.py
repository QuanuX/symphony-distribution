#!/usr/bin/env python3
"""Sign final public-beta artifact bytes without changing payloads or OS trust.

Publisher permission is an exact separate decision. A self-signed signature
proves integrity under explicitly selected certificate and public-key pins; it
does not imply Apple Developer ID, notarization or Gatekeeper acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('beta_review_primitives', HERE / 'review_signing.py')
base = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(base)
PROTOCOL = 'symphony.distribution.public-beta-signature.v1'
RELEASE = '0.2.0-beta.1'
DECISION = 'd87a413093f3e70b67f86973db3b04dfd0d4e394b1b2d0dce384b70a4730e943'
# Each immutable release retains its separately approved decision.
RELEASE_POLICIES = {
    RELEASE: {'decision_sha256': DECISION},
    '0.2.0-beta.2': {'decision_sha256': '420e682c63bb86cd5781443df1964d17bb5f70c95b33c79b8b23f2d4a604f85a',
        'core_commit': 'bae2e817120467561ae051c1b08cf61be3436bac',
        'client_commit': '572627e939250763756167a9dc05d8cb37ab4e30'},
}
SUBJECT = '/O=QuanuX/OU=Symphony Public Beta/CN=QuanuX Symphony Beta Distribution'
RFC_SUBJECT = 'subject=CN=QuanuX Symphony Beta Distribution,OU=Symphony Public Beta,O=QuanuX'
SCOPE = 'public beta artifact integrity; explicit certificate and public-key pins required'
FIELDS = {'protocol', 'release', 'scope', 'certificate_sha256', 'public_key_sha256', 'publisher_decision',
          'release_index', 'artifacts', 'apple_developer_id', 'notarized', 'gatekeeper_acceptance', 'system_trust_changed'}


def require(ok, message): base.require(ok, message)
def sha(raw): return hashlib.sha256(raw).hexdigest()


def release_policy(release):
    require(type(release) is str and release in RELEASE_POLICIES, 'Release index version differs from approved policy')
    return dict(RELEASE_POLICIES[release])


def public_key_pin(openssl, certificate):
    public = base.run(openssl, ['x509', '-in', certificate, '-pubkey', '-noout'])
    return sha(base.run(openssl, ['pkey', '-pubin', '-outform', 'DER'], data=public))


def certificate(openssl, path, expected, public_pin):
    require(re.fullmatch('[0-9a-f]{64}', public_pin or ''), 'Independently selected public-key SHA256 required')
    path = base.pinned_certificate(openssl, path, expected)
    require(path.stat().st_size <= 65536, 'Beta certificate exceeds bound')
    require(base.run(openssl, ['x509', '-in', path, '-subject', '-noout', '-nameopt', 'RFC2253']).decode().strip() == RFC_SUBJECT,
            'Certificate is not the selected public-beta purpose identity')
    require(public_key_pin(openssl, path) == public_pin, 'Certificate public key differs from selected pin')
    return path


def initialize(custody, openssl):
    root = base.plain(custody); repository = HERE.parent
    require(root != repository and repository not in root.parents, 'Beta credentials must remain outside the repository')
    root = base.new_directory(root)
    password, key, cert = root / 'password', root / 'beta-key.pem', root / 'beta-cert.pem'
    base.write(password, secrets.token_urlsafe(48).encode() + b'\n')
    old = os.umask(0o077)
    try:
        base.run(openssl, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
            '-aes-256-cbc', '-pass', 'file:' + str(password), '-out', key])
        base.run(openssl, ['req', '-new', '-x509', '-sha256', '-days', '365', '-key', key,
            '-passin', 'file:' + str(password), '-out', cert, '-subj', SUBJECT,
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,digitalSignature,keyCertSign',
            '-addext', 'extendedKeyUsage=codeSigning'])
    finally:
        os.umask(old)
    base.regular(key, private=True); base.regular(password, private=True)
    cert_pin, public_pin = base.digest(cert), public_key_pin(openssl, cert)
    certificate(openssl, cert, cert_pin, public_pin)
    result = {'protocol': PROTOCOL, 'state': 'public_beta_integrity_key_created', 'subject': SUBJECT,
        'algorithm': 'RSA-3072 / SHA-256', 'certificate_sha256': cert_pin, 'public_key_sha256': public_pin,
        'private_material_exported': False, 'system_trust_changed': False, 'apple_developer_id': False, 'notarized': False}
    base.write(root / 'public-identity.json', base.canonical(result), 0o644)
    return result


def relative(name):
    require(isinstance(name, str) and len(name) <= 512 and
        all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,220}', part) for part in name.split('/')) and
        str(PurePosixPath(name)) == name and not PurePosixPath(name).is_absolute(), 'Unsafe beta artifact path')
    return PurePosixPath(name)


def artifact_rows(root, paths):
    root = base.plain(root); require(root.is_dir(), 'Explicit artifact root required')
    rows, portable = [], set()
    for path in paths:
        path = base.regular(path)
        require(root in path.parents, 'Beta artifact outside selected root')
        name = path.relative_to(root).as_posix(); relative(name)
        require(name.casefold() not in portable, 'Duplicate or colliding beta artifact path'); portable.add(name.casefold())
        rows.append({'path': name, 'size': path.stat().st_size, 'sha256': base.digest(path)})
    require(0 < len(rows) <= 1024, 'Empty or excessive beta artifact selection')
    return sorted(rows, key=lambda row: row['path'])


def binding(root, path, rows):
    path = base.regular(path); require(root in path.parents, 'Binding must be included inside artifact root')
    name = path.relative_to(root).as_posix(); relative(name)
    found = [r for r in rows if r['path'] == name]
    require(len(found) == 1 and base.digest(path) == found[0]['sha256'], 'Binding must be among exact signed artifact bytes')
    return {'path': name, 'sha256': found[0]['sha256']}


def strict_json(raw):
    require(len(raw) <= 4 * 1024 * 1024, 'Beta JSON exceeds bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate beta manifest field'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'Nonfinite beta JSON'))


def verify_bindings(root, manifest):
    rows = manifest['artifacts']
    for key in ('publisher_decision', 'release_index'):
        item = manifest[key]
        require(type(item) is dict and set(item) == {'path', 'sha256'}, 'Beta binding shape differs')
        require(binding(root, root / relative(item['path']), rows) == item, 'Beta binding differs')
    policy = release_policy(manifest['release'])
    require(manifest['publisher_decision']['sha256'] == policy['decision_sha256'], 'Unselected publisher decision')
    index = strict_json((root / manifest['release_index']['path']).read_bytes())
    require(type(index) is dict and index.get('release') == manifest['release'], 'Release index version differs')


def sign(root, paths, release_index, decision, custody, expected, public_pin, output, openssl):
    root, custody = base.plain(root), base.plain(custody)
    require(stat.S_IMODE(custody.stat().st_mode) & 0o077 == 0 and custody.stat().st_uid == os.getuid(),
            'Beta credential custody must be private to its owner')
    require(root != custody and root not in custody.parents and custody not in root.parents,
            'Signing credentials and release artifacts must be separate')
    key = base.regular(custody / 'beta-key.pem', private=True)
    password = base.regular(custody / 'password', private=True)
    cert = certificate(openssl, custody / 'beta-cert.pem', expected, public_pin)
    rows = artifact_rows(root, paths)
    release = strict_json(base.regular(release_index).read_bytes()).get('release')
    release_policy(release)
    value = {'protocol': PROTOCOL, 'release': release, 'scope': SCOPE, 'certificate_sha256': expected,
        'public_key_sha256': public_pin, 'publisher_decision': binding(root, decision, rows),
        'release_index': binding(root, release_index, rows), 'artifacts': rows,
        'apple_developer_id': False, 'notarized': False, 'gatekeeper_acceptance': False, 'system_trust_changed': False}
    verify_bindings(root, value)
    out = base.plain(output)
    require(out != custody and custody not in out.parents, 'Signature output cannot enter credential custody')
    out = base.new_directory(out)
    base.write(out / 'beta-manifest.json', base.canonical(value), 0o644)
    base.write(out / 'beta-cert.pem', cert.read_bytes(), 0o644)
    base.run(openssl, ['dgst', '-sha256', '-sign', key, '-passin', 'file:' + str(password),
        '-out', out / 'beta-manifest.sig', out / 'beta-manifest.json'])
    (out / 'beta-manifest.sig').chmod(0o644)
    verify(out, root, expected, public_pin, openssl)
    require(artifact_rows(root, paths) == rows, 'Release artifact changed during beta signing')
    return value


def verify(signature_root, root, expected, public_pin, openssl):
    signatures, root = base.plain(signature_root), base.plain(root)
    cert = certificate(openssl, signatures / 'beta-cert.pem', expected, public_pin)
    path = base.regular(signatures / 'beta-manifest.json'); signature = base.regular(signatures / 'beta-manifest.sig')
    require(path.stat().st_size <= 4 * 1024 * 1024 and signature.stat().st_size == 384,
            'Unexpected beta manifest or RSA-3072 signature size')
    raw = path.read_bytes(); value = strict_json(raw)
    require(type(value) is dict and set(value) == FIELDS and raw == base.canonical(value) and
        value['protocol'] == PROTOCOL and value['release'] in RELEASE_POLICIES and value['scope'] == SCOPE and
        value['certificate_sha256'] == expected and value['public_key_sha256'] == public_pin,
        'Beta manifest identity or canonical form differs')
    require(all(value[k] is False for k in ('apple_developer_id', 'notarized', 'gatekeeper_acceptance', 'system_trust_changed')),
            'Self-signed beta manifest cannot grant Apple or system trust')
    require(type(value['artifacts']) is list and 0 < len(value['artifacts']) <= 1024, 'Invalid beta artifact set')
    for row in value['artifacts']:
        require(type(row) is dict and set(row) == {'path', 'size', 'sha256'}, 'Invalid beta artifact row')
        relative(row['path'])
        require(type(row['size']) is int and 0 <= row['size'] <= base.LIMIT and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                'Invalid beta artifact size or digest')
    base.verify_manifest_signature(openssl, cert, signature, path)
    require(artifact_rows(root, [root / r['path'] for r in value['artifacts']]) == value['artifacts'],
            'Signed beta artifact bytes or exact selection differ')
    verify_bindings(root, value)
    return {'protocol': PROTOCOL, 'state': 'public_beta_signature_and_artifacts_verified', 'release': value['release'],
        'artifact_count': len(value['artifacts']), 'certificate_sha256': expected, 'public_key_sha256': public_pin,
        'publisher_decision_sha256': release_policy(value['release'])['decision_sha256'], 'release_index_sha256': value['release_index']['sha256'],
        'apple_developer_id': False, 'notarized': False, 'gatekeeper_acceptance': False, 'system_trust_changed': False}


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--openssl', type=Path, required=True)
    commands = p.add_subparsers(dest='command', required=True)
    init = commands.add_parser('initialize'); init.add_argument('--custody', type=Path, required=True)
    signing = commands.add_parser('sign')
    signing.add_argument('--custody', type=Path, required=True); signing.add_argument('--output', type=Path, required=True)
    signing.add_argument('--artifact', type=Path, action='append', required=True)
    signing.add_argument('--release-index', type=Path, required=True); signing.add_argument('--publisher-decision', type=Path, required=True)
    checking = commands.add_parser('verify'); checking.add_argument('--signature-root', type=Path, required=True)
    for cmd in (signing, checking):
        cmd.add_argument('--artifacts-root', type=Path, required=True)
        cmd.add_argument('--trusted-certificate-sha256', required=True); cmd.add_argument('--trusted-public-key-sha256', required=True)
    a = p.parse_args()
    if a.command == 'initialize': value = initialize(a.custody, a.openssl)
    elif a.command == 'sign': value = sign(a.artifacts_root, a.artifact, a.release_index, a.publisher_decision, a.custody,
        a.trusted_certificate_sha256, a.trusted_public_key_sha256, a.output, a.openssl)
    else: value = verify(a.signature_root, a.artifacts_root, a.trusted_certificate_sha256, a.trusted_public_key_sha256, a.openssl)
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__': main()
