#!/usr/bin/env python3
"""Publish an exact signed public beta to QuanuX, with source-first readback.

Every attempt is new and journaled. An uncertain write stops the attempt; this
module has no overwrite, delete, automatic retry or historical review mutation.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import staging as s
import beta_signing as b
c, fs = s.c, b.base
PROTOCOL = 'symphony.distribution.public-beta-publish.v1'
PROFILES = {'macos15-arm64': 'osx-arm64', 'ubuntu24.04-amd64': 'linux-64',
            'ubuntu24.04-arm64': 'linux-aarch64', 'ubuntu26.04-amd64': 'linux-64'}
ROW = {'profile', 'path', 'name', 'version', 'build', 'build_number', 'subdir', 'filename', 'sha256', 'size', 'selection'}
SUMMARY = 'Symphony modular package payload; installation, removal and application selection remain explicit.'
SERVER_FIELDS = {'access', 'builds', 'conda_platforms', 'created_at', 'files', 'full_name', 'html_url', 'id',
    'latest_version', 'modified_at', 'name', 'ndownloads', 'owner', 'platforms', 'public', 'releases', 'revision',
    'upvoted', 'url', 'versions', 'watchers'}


def remote_key(row): return row['name'], row['version'], row['subdir'] + '/' + row['filename']
def url(row, label='beta'): return f"https://conda.anaconda.org/QuanuX/label/{label}/{row['subdir']}/{row['filename']}"
def document(path): return b.strict_json(c.bounded(fs.regular(path))[0])


def audit_archive(path, row):
    entries, digest, size = c.archive_entries(path)
    c.require((digest, size) == (row['sha256'], row['size']), 'Signed archive changed during admission')
    payload = {n: value for n, value in entries.items() if not n.startswith('info/')}
    parents = {str(Path(n).parent) for n in payload}
    c.require(len(parents) == 1 and len(payload) == 3, 'Only complete inert carrier payloads are admitted')
    prefix = next(iter(parents))
    c.require(prefix.startswith('share/symphony/carriers/') and
        {Path(n).name for n in payload} == {'payload.tar', 'unit.json', 'carrier-manifest.json'}, 'Carrier paths differ')
    entry = {target: row[source] for source, target in [('name', 'conda_name'), ('version', 'conda_version'),
        ('build', 'build_string'), ('build_number', 'build_number'), ('subdir', 'conda_subdir')]}
    c.require(entries == payload | c.metadata_for(entry, payload), 'Carrier metadata, hooks or prefix rewrites differ')
    unit = b.strict_json(payload[prefix + '/unit.json'][0])
    manifest = b.strict_json(payload[prefix + '/carrier-manifest.json'][0])
    c.require((unit['kind'] == 'optional_corresponding_source') == (row['selection'] == 'optional-source'),
        'Corresponding source selection differs from carrier content')
    c.require(manifest['destination'] == prefix and manifest['unit_id'] == unit['unit_id'] and
        manifest['files'] == [c.file_row(n, payload[prefix + '/' + n][0]) for n in ('payload.tar', 'unit.json')] and
        all(manifest[k] == row[v] for k, v in [('conda_name', 'name'), ('conda_version', 'version'),
            ('build', 'build'), ('build_number', 'build_number'), ('subdir', 'subdir')]), 'Carrier manifest identity differs')
    c.require(all(mode == 0o644 for _, mode in payload.values()), 'Carrier payload mode differs')


def prepare(release_root, signature_root, cert_pin, public_key_pin, openssl, profiles=None):
    root, signatures = fs.plain(release_root), fs.plain(signature_root)
    manifest_raw = c.bounded(fs.regular(signatures / 'beta-manifest.json'))[0]
    proof = b.verify(signatures, root, cert_pin, public_key_pin, openssl)
    manifest = b.strict_json(manifest_raw)
    c.require(c.bounded(signatures / 'beta-manifest.json')[0] == manifest_raw, 'Signed manifest changed')
    index_raw = c.bounded(root / b.relative(manifest['release_index']['path']))[0]
    c.require(c.sha(index_raw) == proof['release_index_sha256'], 'Signed release index changed')
    index = b.strict_json(index_raw)
    rows = index.get('conda_packages')
    c.require(index['release'] == b.RELEASE and type(rows) is list and 1 <= len(rows) <= 512, 'Invalid beta package selection')
    signed = {row['path']: row for row in manifest['artifacts']}
    identities, paths, present_profiles = {}, set(), set()
    for row in rows:
        c.require(type(row) is dict and set(row) == ROW, 'Beta package row fields differ')
        b.relative(row['path'])
        c.require(row['profile'] in PROFILES and row['subdir'] == PROFILES[row['profile']], 'Package platform differs')
        c.require(all(type(row[k]) is str and s.TOKEN.fullmatch(row[k]) for k in ('name', 'version', 'build')),
                  'Unsafe package identity')
        c.require(row['filename'] == f"{row['name']}-{row['version']}-{row['build']}.conda" and
            Path(row['path']).name == row['filename'], 'Package filename differs')
        c.require(type(row['build_number']) is int and row['build_number'] >= 0 and
            type(row['size']) is int and 0 < row['size'] <= c.LIMIT, 'Invalid package size or build number')
        c.digest(row['sha256'])
        c.require(row['selection'] in ('default', 'optional-source') and row['path'] not in paths, 'Duplicate or invalid package selection')
        c.require(signed.get(row['path']) == {k: row[k] for k in ('path', 'sha256', 'size')}, 'Package is not in signed release')
        key = remote_key(row); identity = {k: row[k] for k in ('sha256', 'size', 'build_number', 'selection')}
        c.require(key not in identities or identities[key] == identity, 'Profiles collide at different immutable build bytes')
        identities[key] = identity; paths.add(row['path']); present_profiles.add(row['profile'])
        audit_archive(root / row['path'], row)
    c.require(paths == {name for name in signed if name.endswith('.conda')}, 'Signed Conda package closure differs')
    for profile in present_profiles:
        selected = [row for row in rows if row['profile'] == profile]
        c.require(sum(row['selection'] == 'optional-source' for row in selected) == 1 and
            any(row['selection'] == 'default' for row in selected) and
            len({remote_key(row) for row in selected}) == len(selected), 'Each profile requires one source and unique default packages')
    selected_profiles = sorted(present_profiles if profiles is None else profiles)
    c.require(selected_profiles and len(set(selected_profiles)) == len(selected_profiles) and
        set(selected_profiles) <= present_profiles, 'Requested profiles differ from signed release')
    selected = sorted((dict(row, url=url(row)) for row in rows if row['profile'] in selected_profiles),
                      key=lambda row: (row['selection'] != 'optional-source', row['profile'], row['filename']))
    label = 'beta-' + b.RELEASE + '-' + proof['release_index_sha256'][:12]
    sources = {row['profile']: url(row, label) for row in selected if row['selection'] == 'optional-source'}
    return s.seal({'protocol': PROTOCOL, 'release': b.RELEASE, 'organization': 'QuanuX', 'labels': ['beta', label],
        'profiles': selected_profiles, 'packages': selected, 'corresponding_source_urls': sources,
        'certificate_sha256': cert_pin, 'public_key_sha256': public_key_pin,
        'publisher_decision_sha256': b.DECISION, 'release_index_sha256': proof['release_index_sha256'],
        'signed_manifest_sha256': c.sha(manifest_raw), 'publisher_helper_sha256': fs.digest(Path(__file__)),
        'shared_remote_builds': len({remote_key(row) for row in selected}) != len(selected),
        'publication_authorized': True, 'overwrite_supported': False, 'automatic_retry': False,
        'native_install_or_activation': False, 'apple_developer_id': False, 'notarized': False})


def metadata(api, row):
    from binstar_client.errors import NotFound
    try: value = api.distribution('QuanuX', *remote_key(row))
    except NotFound: return None
    c.require(value.get('sha256') == row['sha256'] and value.get('size') == row['size'],
              'Existing immutable build differs; overwrite refused')
    c.require(type(value.get('labels')) is list and all(type(x) is str for x in value['labels']), 'Distribution labels unavailable')
    return value


def public_attrs(package):
    if 'public_attrs' in package:
        c.require(type(package['public_attrs']) is dict, 'Package attributes unavailable')
        return copy.deepcopy(package['public_attrs'])
    return copy.deepcopy({k: v for k, v in package.items() if k not in SERVER_FIELDS})


class Attempt:
    def __init__(self, output, plan):
        self.root = fs.new_directory(output)
        for path in (self.root.parent, self.root): self.sync(path)
        self.event({'state': 'started', 'plan_sha256': plan['plan_sha256'], 'automatic_retry': False})
    @staticmethod
    def sync(path):
        fd = os.open(path, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    def event(self, value):
        with (self.root / 'attempt.jsonl').open('ab') as stream:
            stream.write(fs.canonical(value)); stream.flush(); os.fsync(stream.fileno())
        self.sync(self.root)
    def mutate(self, operation, row, callback):
        public = {'operation': operation, 'name': row['name'], 'version': row['version'], 'filename': row['filename']}
        self.event({'state': 'mutation_pending', **public})
        try: result = callback()
        except Exception as exc:
            self.event({'state': 'uncertain_do_not_retry', **public, 'error_class': type(exc).__name__})
            raise ValueError('Publication stopped; reconcile journal and remote state before another mutation') from None
        self.event({'state': 'mutation_returned', **public}); return result


def ensure_catalog(api, plan, row, attempt, *, require_existing):
    from binstar_client.errors import NotFound
    from binstar_client.utils.config import PackageType
    try: package = api.package('QuanuX', row['name'])
    except NotFound:
        c.require(not require_existing, 'Serial catalog preparation required before parallel profile publication')
        attempt.mutate('create_package', row, lambda: api.add_package('QuanuX', row['name'], summary=SUMMARY,
            license='LicenseRef-Complete-Embedded-Notices', public=True, package_type=PackageType.CONDA))
        package = api.package('QuanuX', row['name'])
    c.require(package.get('public') is True, 'Existing package is not public')
    attrs = public_attrs(package)
    if attrs.get('summary') != SUMMARY:
        c.require(not require_existing, 'Serial package metadata preparation required')
        updated = {**attrs, 'summary': SUMMARY}
        attempt.mutate('update_summary_preserving_attributes', row, lambda: api.update_package('QuanuX', row['name'], updated))
        after = api.package('QuanuX', row['name'])
        c.require(after.get('public') is True and public_attrs(after) == updated, 'Package attributes were not preserved')
    try: api.release('QuanuX', row['name'], row['version'])
    except NotFound:
        c.require(not require_existing, 'Serial release preparation required before parallel publication')
        sources = '; '.join(f"{profile}: {location}" for profile, location in sorted(plan['corresponding_source_urls'].items()))
        attempt.mutate('create_release', row, lambda: api.add_release('QuanuX', row['name'], row['version'], {}, '',
            {'description': 'Symphony public beta modular payload. Corresponding source: ' + sources +
                '. Install the optional source carrier separately and unpack its payload.tar under share/symphony/carriers. '
                'Read the source index and scope records inside. Application activation remains explicit.'}))
        api.release('QuanuX', row['name'], row['version'])


def execute(plan, release_root, signature_root, cert_pin, public_key_pin, openssl, output, api,
            *, catalog_only=False, require_catalog=False):
    """Re-admit signature and all local bytes before a new non-replayable attempt."""
    fresh = prepare(release_root, signature_root, cert_pin, public_key_pin, openssl, plan['profiles'])
    c.require(plan == fresh, 'Exact current signed publication plan required')
    root, signatures, output = fs.plain(release_root), fs.plain(signature_root), fs.plain(output)
    c.require(all(output != item and item not in output.parents and output not in item.parents for item in (root, signatures)),
              'Attempt output must be separate from signed artifacts and signatures')
    # Detect all existing collisions before even creating remote catalog entries.
    for row in plan['packages']: metadata(api, row)
    attempt = Attempt(output, plan); completed, source_ready, catalog = [], set(), set()
    try:
        for row in plan['packages']:
            key = (row['name'], row['version'])
            if catalog_only:
                if key not in catalog: ensure_catalog(api, plan, row, attempt, require_existing=False); catalog.add(key)
                continue
            if row['selection'] == 'default': c.require(row['profile'] in source_ready, 'Public source must be retrieved before binaries')
            raw, _ = c.bounded(fs.regular(root / row['path']))
            c.require((c.sha(raw), len(raw)) == (row['sha256'], row['size']), 'Candidate changed before upload snapshot')
            with tempfile.TemporaryFile(dir=output) as snapshot:
                snapshot.write(raw); snapshot.seek(0); del raw
                if key not in catalog:
                    ensure_catalog(api, plan, row, attempt, require_existing=require_catalog); catalog.add(key)
                value = metadata(api, row)
                if value is None:
                    source = plan['corresponding_source_urls'][row['profile']]
                    attempt.mutate('upload', row, lambda: api.upload('QuanuX', *remote_key(row), snapshot, 'conda',
                        description='Symphony public beta. Corresponding source: ' + source +
                            '. Install the optional source carrier separately; unpack payload.tar under share/symphony/carriers. '
                            'No automatic application activation.', sha256=row['sha256'], size=row['size'],
                        dependencies={'depends': []}, attrs=s.upload_attrs(row), channels=plan['labels']))
                    value = metadata(api, row)
                    c.require(value is not None, 'Uploaded distribution absent; reconcile before retry')
                for label in plan['labels']:
                    if label not in value['labels']:
                        attempt.mutate('add_exact_build_label_' + label, row, lambda label=label:
                            api.add_channel(label, 'QuanuX', row['name'], row['version'], row['subdir'] + '/' + row['filename']))
                        value = metadata(api, row)
                        c.require(value is not None and label in value['labels'], 'Label effect absent; reconcile before retry')
                c.require(set(plan['labels']) <= set(value['labels']), 'Selected labels absent')
            # Both beta and immutable source URLs are actually read without account credentials.
            directory = output / row['profile']; directory.mkdir(exist_ok=True)
            target = directory / row['filename']
            proof = s.download(row, target)
            if row['selection'] == 'optional-source':
                immutable = dict(row, url=plan['corresponding_source_urls'][row['profile']])
                source_proof = s.download(immutable, directory / ('source-' + row['filename']))
                proof = {**proof, 'immutable_source_retrieval': source_proof}; source_ready.add(row['profile'])
            completed.append({'profile': row['profile'], 'selection': row['selection'], **proof})
            attempt.event({'state': 'public_bytes_verified', 'profile': row['profile'], 'filename': row['filename'], 'sha256': row['sha256']})
    except Exception as exc:
        attempt.event({'state': 'stopped_reconcile_before_retry', 'error_class': type(exc).__name__, 'completed': len(completed)})
        raise ValueError('Publication stopped; reconcile journal and remote state before another mutation') from None
    result = {'protocol': PROTOCOL, 'state': 'catalog_prepared' if catalog_only else 'public_beta_packages_freshly_verified',
        'release': b.RELEASE, 'plan_sha256': plan['plan_sha256'], 'release_index_sha256': plan['release_index_sha256'],
        'signed_manifest_sha256': plan['signed_manifest_sha256'], 'publisher_decision_sha256': b.DECISION,
        'labels': plan['labels'], 'profiles': plan['profiles'], 'packages': completed,
        'publication_authorized': True, 'account_credentials_used_for_download': False,
        'automatic_retry': False, 'overwrite_performed': False, 'native_install_or_activation': False}
    fs.write(output / 'publication.json', fs.canonical(result)); return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('prepare', 'catalog', 'publish'))
    p.add_argument('--artifacts-root', type=Path, required=True); p.add_argument('--signature-root', type=Path, required=True)
    p.add_argument('--certificate-sha256', required=True); p.add_argument('--public-key-sha256', required=True)
    p.add_argument('--openssl', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--profile', action='append', choices=sorted(PROFILES)); p.add_argument('--plan', type=Path)
    p.add_argument('--require-catalog', action='store_true'); p.add_argument('--allow-public-beta-publication', action='store_true')
    a = p.parse_args(); args = (a.artifacts_root, a.signature_root, a.certificate_sha256, a.public_key_sha256, a.openssl)
    plan = prepare(*args, a.profile)
    if a.command == 'prepare':
        fs.write(a.output, fs.canonical(plan)); result = {'state': 'prepared', 'plan_sha256': plan['plan_sha256'], 'packages': len(plan['packages'])}
    else:
        c.require(a.allow_public_beta_publication and a.plan and document(a.plan) == plan, 'Explicit exact public beta publication selection required')
        result = execute(plan, *args, a.output, s.publisher_api(), catalog_only=a.command == 'catalog', require_catalog=a.require_catalog)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
