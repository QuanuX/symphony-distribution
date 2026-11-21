#!/usr/bin/env python3
"""Prepare a beta release bundle on the runner holding the source privacy policy."""
import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys

import release_bundle as bundle
from qualification import beta_artifacts, d09_platform

ROOT = bundle.ROOT
RELEASE = '0.2.0-beta.2.1'
RELEASE_ID = 453879498
NODE_ASSET = {'id': 776444855, 'name': 'symphony-beta21-node-keyring-supplement.tar.gz',
              'state': 'uploaded', 'size': 798850,
              'digest': 'sha256:eed4337e49ec8c7f770a9bd03d0a877a90b17dfb797a7f4d2faad33c2b936784'}
NODE_INDEX = 'deb6dd8ac42ef446ec4962d3cc93c06ec796401181a7128f48e12c7e61158bef'
TOOLS = ROOT / 'channel/node_keyring'


def check_asset(release, asset):
    bundle.c.require(release.get('id') == RELEASE_ID and release.get('tag_name') == 'v' + RELEASE and
                     any(row.get('id') == NODE_ASSET['id'] for row in release.get('assets', [])) and
                     all(asset.get(k) == value for k, value in NODE_ASSET.items()), 'Pinned optional release asset differs')


def fetch_supplement(work):
    transport = beta_artifacts.transport
    gh, env = transport.transport_environment(work, Path(shutil.which('gh')).resolve(strict=True))
    base = 'repos/' + beta_artifacts.REPOSITORY + '/releases/'
    endpoint = base + 'assets/' + str(NODE_ASSET['id'])
    check_asset(transport.gh_json(gh, base + str(RELEASE_ID), env), transport.gh_json(gh, endpoint, env))
    target = work / NODE_ASSET['name']
    size = NODE_ASSET['size']
    with target.open('xb') as stream:
        result = subprocess.run([str(gh), 'api', '--hostname', 'github.com', '-H', 'Accept: application/octet-stream', endpoint],
                                env=env, stdout=stream, stderr=subprocess.PIPE, timeout=120,
                                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (size, size)))
    bundle.c.require(result.returncode == 0 and target.stat().st_size == size and
                     bundle.fs.digest(target) == NODE_ASSET['digest'].removeprefix('sha256:'), 'Pinned asset download failed')


def audit_supplement(work, policy):
    source = work / NODE_ASSET['name']
    admitted = work / 'verified-supplement'
    result = subprocess.run([sys.executable, '-B', str(TOOLS / 'audit_handoff.py'), 'unpack', '--distribution', str(ROOT),
                             '--privacy-policy', str(policy), '--archive', str(source), '--directory', str(admitted),
                             '--sha256', NODE_ASSET['digest'].removeprefix('sha256:')], check=True, stdout=subprocess.PIPE)
    proof = json.loads(result.stdout)
    bundle.c.require(proof['supplement_sha256'] == NODE_INDEX and proof['files'] == 12 and
                     proof['archive_sha256'] == NODE_ASSET['digest'].removeprefix('sha256:') and
                     proof['source_members'] == 130, 'Supplement admission differs')
    bundle.fs.write(work / 'node-admission.json', bundle.fs.canonical({**proof, 'release': RELEASE,
                    'asset_id': NODE_ASSET['id'], 'source_and_embedded_packages_scanned': True, 'publication_performed': False}))
    return admitted


def early_admission(work):
    policy = d09_platform.write_private_policy(work / 'privacy-policy.json', os.environ.pop('PRIVATE_SOURCE_POLICY', ''))
    try:
        admitted = audit_supplement(work, policy)
    finally:
        policy.unlink(missing_ok=True)
    subprocess.run([sys.executable, '-B', str(TOOLS / 'test_publication.py'), '--distribution', str(ROOT),
                    '--supplement', str(admitted)], check=True)


def selected_transport(work, profile, role):
    suffix = {'beta': 'final', 'maintenance': 'maintenance', 'native_pkg': 'native-pkg'}[role]
    selection = ROOT / 'evidence/beta-selections' / f'{profile}-beta21-{suffix}.json'
    digest = bundle.fs.digest(selection)
    selected = beta_artifacts.validate_selection(selection, digest)
    bundle.c.require(selected['profile'] == profile and set(selected['artifacts']) == {role},
                     'Committed final selection must match the requested profile and role')
    return {'root': str(work / f'{profile}-{role}'), 'selection': str(selection), 'selection_sha256': digest}


def request_for(work):
    profiles = {profile: {role: selected_transport(work, profile, role) for role in ('beta', 'maintenance')}
                for profile in bundle.publisher.PROFILES}
    decision = ROOT / 'evidence/beta21-publisher-decision.json'
    cert = ROOT / 'channel/keys/symphony-beta-2026.pem'
    documents = [('docs/BETA21-INSTALL.md', 'docs/BETA-INSTALL.md'), ('delivery/README.md', 'docs/RETENTION.md')]
    return {'protocol': bundle.REQUEST, 'release': RELEASE, 'profiles': profiles,
            'native_pkg': selected_transport(work, 'macos15-arm64', 'native_pkg'),
            'publisher_decision': {'path': str(decision), 'sha256': bundle.signing.release_policy(RELEASE)['decision_sha256']},
            'public_certificate': {'path': str(cert), 'sha256': bundle.verifier.CERTIFICATE_SHA256},
            'privacy_policy': str(work / 'privacy-policy.json'),
            'additional_documents': [{'source': str(ROOT / source), 'path': target, 'sha256': bundle.fs.digest(ROOT / source)}
                                     for source, target in documents]}


def fetch(work):
    fetch_supplement(work)
    request = request_for(work)
    inputs = [item for profile in request['profiles'].values() for item in profile.values()] + [request['native_pkg']]
    gh = Path(shutil.which('gh')).resolve(strict=True)
    for item in inputs:
        beta_artifacts.fetch(Path(item['selection']), item['selection_sha256'], Path(item['root']), gh)
    bundle.fs.write(work / 'request.json', bundle.fs.canonical(request))


def assemble(work):
    request = work / 'request.json'
    expected = bundle.fs.canonical(request_for(work))
    bundle.c.require(bundle.raw(request) == expected, 'Fetched release request differs from committed inputs')
    policy = d09_platform.write_private_policy(work / 'privacy-policy.json', os.environ.pop('PRIVATE_SOURCE_POLICY', ''))
    try:
        openssl = Path(shutil.which('openssl')).resolve(strict=True)
        admitted = audit_supplement(work, policy)
        primary = work / 'primary-public'
        index = bundle.assemble(request, bundle.c.sha(expected), primary, openssl)
        subprocess.run([sys.executable, '-B', str(TOOLS / 'prepare_release.py'), 'attach', '--distribution', str(ROOT),
                        '--primary', str(primary), '--primary-sha256', bundle.fs.digest(primary / 'release-index.json'),
                        '--supplement', str(admitted), '--supplement-sha256', NODE_INDEX, '--output', str(work / 'public')], check=True)
        print(f"Verified {index['release']} for {len(index['profiles'])} profiles, {len(index['conda_packages'])} primary packages and two optional Ubuntu node packages")
    finally:
        policy.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('fetch', 'assemble', 'fetch-supplement', 'audit-supplement'))
    parser.add_argument('work', type=Path)
    args = parser.parse_args()
    if args.phase in ('fetch', 'fetch-supplement'):
        work = bundle.fs.new_directory(args.work)
        (fetch if args.phase == 'fetch' else fetch_supplement)(work)
    else:
        (assemble if args.phase == 'assemble' else early_admission)(bundle.fs.plain(args.work))
