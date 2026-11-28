#!/usr/bin/env python3
"""Immutable Anaconda review staging and credential-free retrieval qualification.

Staging is publicly reachable. It is not a beta release, native install, or an
independent trust decision. No package replacement, default label, deletion or
automatic retry of an uncertain write is implemented.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
if __package__:
    from . import package_metadata
else:
    import package_metadata
import carriers as c
import review_signing as signing

PROTOCOL = 'symphony.distribution.d09-public-review-stage.v1'
LABEL = re.compile(r'd09-review-[0-9a-f]{12}')
TOKEN = re.compile(r'[a-z0-9][a-z0-9_.-]{0,199}')
DOWNLOAD_HOSTS = {'conda.anaconda.org', 'api.anaconda.org', 'anaconda.org',
                  'binstar-cio-packages-prod.s3.amazonaws.com',
                  'binstar-cio-packages-prod.s3.us-east-1.amazonaws.com'}


def seal(value):
    return {**value, 'plan_sha256': c.sha(c.canonical(value))}


def check_plan(plan):
    c.require(plan.get('plan_sha256') == seal({k: v for k, v in plan.items() if k != 'plan_sha256'})['plan_sha256'],
              'Staging plan seal differs')
    c.require(plan['protocol'] == PROTOCOL and plan['organization'] == 'QuanuX' and
              LABEL.fullmatch(plan['label']) and plan['visibility'] == 'public-review-only' and
              plan['beta_release_authorized'] is False and plan['overwrite_supported'] is False,
              'Review staging scope differs')
    c.require(0 < len(plan['packages']) <= 128, 'Empty or excessive package set')
    sources = [r for r in plan['packages'] if r['selection'] == 'optional-source']
    c.require(len(sources) == 1 and plan['packages'][0] == sources[0] and
              plan['corresponding_source_url'] == sources[0]['url'], 'Exact source carrier must precede binaries')
    identities = set()
    for row in plan['packages']:
        for key in ('name', 'version', 'build'):
            c.require(TOKEN.fullmatch(row[key]), 'Unsafe package identity')
        c.require(row['subdir'] in {'osx-64', 'osx-arm64', 'linux-64', 'linux-aarch64'}, 'Unselected platform')
        c.require(row['filename'] == f"{row['name']}-{row['version']}-{row['build']}.conda", 'Filename identity differs')
        c.require(row['filename'] not in identities, 'Duplicate package identity'); identities.add(row['filename'])
        c.digest(row['sha256']); c.require(type(row['size']) is int and 0 < row['size'] <= c.LIMIT, 'Invalid archive size')
        c.require(row['url'] == package_url(plan, row), 'Retrieval URL differs from exact identity')
    return plan


def package_url(plan, row):
    return f"https://conda.anaconda.org/QuanuX/label/{plan['label']}/{row['subdir']}/{row['filename']}"


def prepare(delivery, pin, openssl):
    delivery = signing.plain(delivery); artifacts = delivery / 'artifacts'
    signing.verify(delivery / 'signature', artifacts, pin, openssl)
    manifest = c.document(delivery / 'signature/review-manifest.json')
    signed = {r['name']: r for r in manifest['artifacts']}
    cohort = c.document(artifacts / 'CARRIER-COHORT.json')
    optional = c.document(artifacts / 'OPTIONAL-SOURCE-COHORT.json')
    c.check_seal(cohort); c.check_seal(optional)
    c.require(optional['base_carrier_cohort_digest'] == cohort['cohort_digest'] and
              len(cohort['archives']) == 59 and len(optional['archives']) == 1,
              'Selected complete core/client/source cohort differs')
    rows = []; label = 'd09-review-' + cohort['cohort_digest'][7:19]
    for archive in cohort['archives'] + optional['archives']:
        name = archive['filename']; bound = signed[name]
        c.require((archive['sha256'], archive['size']) == (bound['sha256'], bound['size']), 'Unsigned carrier selection')
        entries, digest, size = c.archive_entries(artifacts / name)
        c.require((digest, size) == (bound['sha256'], bound['size']), 'Carrier changed after signature verification')
        index = json.loads(entries['info/index.json'][0])
        c.require(index['depends'] == [] and index['license'] == 'LicenseRef-Complete-Embedded-Notices',
                  'Only inert exact carriers are admitted')
        row = {k: index[k] for k in ('name', 'version', 'build', 'build_number', 'subdir')}
        row.update(filename=name, sha256=digest, size=size,
                   selection='optional-source' if archive in optional['archives'] else 'default-carrier')
        row['url'] = package_url({'label': label}, row); rows.append(row)
    c.require({r['filename'] for r in rows} == {n for n in signed if n.endswith('.conda')}, 'Signed package closure differs')
    source = c.document(artifacts / 'SOURCE-INDEX.json')
    return check_plan(seal({'protocol': PROTOCOL, 'organization': 'QuanuX', 'label': label,
        'visibility': 'public-review-only', 'label_is_access_control': False,
        'profile': cohort['profile'], 'carrier_cohort_digest': cohort['cohort_digest'],
        'optional_source_cohort_digest': optional['cohort_digest'], 'source_bindings': source['source_bindings'],
        'review_certificate_sha256': pin,
        'signed_manifest_sha256': signing.digest(delivery / 'signature/review-manifest.json'),
        'staging_helper_sha256': signing.digest(Path(__file__)),
        'packages': sorted(rows, key=lambda r: (r['selection'] != 'optional-source', r['filename'])),
        'corresponding_source_url': next(r['url'] for r in rows if r['selection'] == 'optional-source'), 'overwrite_supported': False,
        'beta_release_authorized': False, 'standalone_installer_upload': False,
        'native_install_or_activation': False, 'independent_acceptance_complete': False}))


def destination(url, *, initial=False):
    p = urllib.parse.urlsplit(url)
    c.require(p.scheme == 'https' and p.hostname in DOWNLOAD_HOSTS and not p.username and not p.password and
              p.port in (None, 443) and not p.fragment and (not initial or not p.query),
              'Unselected or credential-bearing download destination')
    return p


def public_url(url):
    p = destination(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, '', ''))


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__(); self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination(newurl)
        c.require(len(self.hops) < 5, 'Too many retrieval redirects')
        self.hops.append({'status': code, 'from': public_url(req.full_url), 'to': public_url(newurl),
                          'query_values_retained': False})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(row, target):
    destination(row['url'], initial=True)
    redirect = Redirects()
    # No proxy environment, cookie jar, authentication handler or account token.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirect)
    request = urllib.request.Request(row['url'], headers={'Accept-Encoding': 'identity', 'User-Agent': 'Symphony-D09-review-verifier/1'})
    h = hashlib.sha256(); total = 0
    with opener.open(request, timeout=30) as response, target.open('xb') as output:
        c.require(response.status == 200 and response.headers.get('Content-Encoding', 'identity') == 'identity',
                  'Unexpected download status/encoding')
        length = response.headers.get('Content-Length')
        if length is not None: c.require(int(length) == row['size'], 'HTTP archive size differs')
        while True:
            block = response.read(min(1024 * 1024, row['size'] - total + 1))
            if not block: break
            total += len(block); c.require(total <= row['size'], 'Download exceeds selected bound')
            h.update(block); output.write(block)
        final = public_url(response.url)
    c.require(total == row['size'] and h.hexdigest() == row['sha256'], 'Fresh downloaded bytes differ')
    return {'filename': row['filename'], 'url': row['url'], 'sha256': h.hexdigest(), 'size': total,
            'final_url': final, 'redirects': redirect.hops, 'account_credentials_used': False}


def retrieve(plan, output):
    check_plan(plan); output = signing.new_directory(output); rows = []
    try:
        for row in plan['packages']:
            rows.append(download(row, output / row['filename']))
    except Exception as exc:
        result = {'protocol': PROTOCOL, 'state': 'retrieval_incomplete', 'plan_sha256': plan['plan_sha256'],
                  'completed': rows, 'error_class': type(exc).__name__, 'beta_release_authorized': False}
        signing.write(output / 'retrieval.json', signing.canonical(result)); raise
    result = {'protocol': PROTOCOL, 'state': 'all_selected_archives_freshly_retrieved',
              'plan_sha256': plan['plan_sha256'], 'packages': rows, 'account_credentials_used': False,
              'beta_release_authorized': False, 'native_install_or_activation': False}
    signing.write(output / 'retrieval.json', signing.canonical(result)); return result


def public_metadata(api, plan, row):
    from binstar_client.errors import NotFound
    try: value = api.distribution(plan['organization'], row['name'], row['version'], row['subdir'] + '/' + row['filename'])
    except NotFound: return None
    c.require(value.get('sha256') == row['sha256'] and value.get('size') == row['size'],
              'Existing immutable build differs; overwrite refused')
    c.require(plan['label'] in value.get('labels', []), 'Existing build lacks selected label; no implicit relabel')
    return {'filename': row['filename'], 'sha256': row['sha256'], 'size': row['size'],
            'selected_label_present': True}


def bound_publisher_transport(api):
    import binstar_client
    import requests
    from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
    c.require(bool(api.session.verify), 'Publisher TLS verification must remain enabled')
    api.session.trust_env = False
    request = api.session.request
    def bounded_request(method, url, **kwargs):
        destination(url)
        kwargs['timeout'] = (15, 60)
        kwargs['allow_redirects'] = False
        return request(method, url, **kwargs)
    api.session.request = bounded_request
    def bounded_multipart(url, data, files=None, progress_bar=None, **kwargs):
        p = destination(url)
        c.require(p.hostname.endswith('.amazonaws.com'), 'Unselected object-upload destination')
        c.require(bool(kwargs.get('verify', True)), 'Object upload TLS verification required')
        body = dict(data)
        if files: body.update(files)
        encoder = MultipartEncoder(body)
        if progress_bar:
            encoder = MultipartEncoderMonitor(encoder, lambda m: progress_bar.update(m.bytes_read-progress_bar.n))
        with requests.Session() as session:
            session.trust_env = False
            return session.post(url, data=encoder, headers={'Content-Type': encoder.content_type},
                timeout=(15, 120), allow_redirects=False, verify=kwargs.get('verify', True))
    # Version-bound SDK uses this module-level upload function, outside api.session.
    binstar_client.multipart_files_upload = bounded_multipart


def publisher_api():
    from importlib.metadata import version
    from binstar_client.utils import get_server_api
    c.require(version('anaconda-client') == '1.16.0', 'Selected publisher version differs')
    api = get_server_api(None, None)
    c.require(api.domain == 'https://api.anaconda.org', 'Unselected publisher endpoint')
    bound_publisher_transport(api)
    api.user()
    c.require(any(str(r.get('login', '')).lower() == 'quanux' for r in api.user_orgs()), 'Selected organization membership absent')
    return api


def upload_attrs(row):
    platform, machine = {'osx-64': ('osx', 'x86_64'), 'osx-arm64': ('osx', 'arm64'),
        'linux-64': ('linux', 'x86_64'), 'linux-aarch64': ('linux', 'aarch64')}[row['subdir']]
    operating = 'darwin' if platform == 'osx' else platform
    return {k: row[k] for k in ('build', 'build_number', 'subdir')} | {
        'platform': platform, 'arch': machine, 'machine': machine, 'operatingsystem': operating,
        'target-triplet': machine + '-any-' + operating, 'depends': [], 'has_prefix': False,
        'license': 'LicenseRef-Complete-Embedded-Notices', 'timestamp': 0}


def stage(plan, delivery, output, api):
    """One new, non-replayable attempt; exceptions leave durable uncertain evidence."""
    check_plan(plan); artifacts = signing.plain(delivery) / 'artifacts'
    # Admission of every archive precedes any remote mutation.
    for row in plan['packages']:
        c.require(signing.digest(artifacts / row['filename']) == row['sha256'] and
                  (artifacts / row['filename']).stat().st_size == row['size'], 'Local candidate changed')
    existing = {r['filename']: public_metadata(api, plan, r) for r in plan['packages']}
    output = signing.new_directory(output)
    journal = output / 'attempt.jsonl'
    for directory in (output.parent, output):
        fd = os.open(directory, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    def event(value):
        with journal.open('ab') as stream:
            stream.write(signing.canonical(value)); stream.flush(); os.fsync(stream.fileno())
        fd = os.open(output, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    def mutate_catalog(operation, row, callback):
        event({'state': 'mutation_pending', 'operation': operation, 'filename': row['filename']})
        return callback()

    event({'state': 'started', 'plan_sha256': plan['plan_sha256'], 'public_staging_authorized': True,
           'beta_release_authorized': False, 'automatic_retry': False})
    completed = []
    source_directions = ('Exact reviewed corresponding source: ' + plan['corresponding_source_url'] +
        '. Link this optional inert carrier into a separate Conda prefix, then extract its payload.tar under share/symphony/carriers; ' +
        'read source-index.json and SOURCE-SCOPE.json inside the nested corresponding-source archive for original and derived source bindings. No native activation is performed.')
    for row in plan['packages']:
        if existing[row['filename']]:
            if row['selection'] == 'optional-source':
                proof = download(row, output / row['filename'])
                signing.write(output / 'source-retrieval.json', signing.canonical(proof))
            event({'state': 'already_present_exact', 'filename': row['filename']}); completed.append(row['filename']); continue
        event({'state': 'mutation_pending', 'filename': row['filename']})
        snapshot = None
        try:
            raw, _ = c.bounded(artifacts / row['filename'])
            c.require(c.sha(raw) == row['sha256'] and len(raw) == row['size'], 'Candidate changed before upload snapshot')
            snapshot = tempfile.TemporaryFile(dir=output)
            snapshot.write(raw); snapshot.seek(0); del raw
            fields = package_metadata.overview(row['name'], review_source=plan['corresponding_source_url'])
            package_metadata.ensure_catalog(api, plan['organization'], row, fields, mutate_catalog)
            with snapshot as stream:
                api.upload(plan['organization'], row['name'], row['version'], row['subdir'] + '/' + row['filename'],
                    stream, 'conda', description='D09 public review staging; no release acceptance. ' + source_directions,
                    sha256=row['sha256'], size=row['size'], dependencies={'depends': []},
                    attrs=upload_attrs(row), channels=[plan['label']])
            c.require(public_metadata(api, plan, row) is not None, 'Committed distribution is absent; reconcile before retry')
            if row['selection'] == 'optional-source':
                proof = download(row, output / row['filename'])
                signing.write(output / 'source-retrieval.json', signing.canonical(proof))
        except Exception as exc:
            event({'state': 'uncertain_do_not_retry', 'filename': row['filename'], 'error_class': type(exc).__name__})
            raise ValueError('Staging stopped; reconcile the durable attempt and remote state before another mutation') from None
        finally:
            if snapshot is not None: snapshot.close()
        completed.append(row['filename']); event({'state': 'staged_verified', 'filename': row['filename']})
    result = {'protocol': PROTOCOL, 'state': 'public_review_staged_metadata_verified',
              'plan_sha256': plan['plan_sha256'], 'packages': completed,
              'fresh_download_qualified': False, 'beta_release_authorized': False}
    signing.write(output / 'staging.json', signing.canonical(result)); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'retrieve', 'stage'])
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--delivery', type=Path)
    parser.add_argument('--certificate-sha256')
    parser.add_argument('--openssl', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-public-review-upload', action='store_true')
    args = parser.parse_args()
    if args.command in ('prepare', 'stage'):
        c.require(args.delivery and args.certificate_sha256 and args.openssl, 'Exact signed delivery and certificate pin required')
        plan = prepare(args.delivery, args.certificate_sha256, args.openssl)
    if args.command == 'prepare':
        signing.write(args.output, signing.canonical(plan)); result = {'state': 'prepared', 'plan_sha256': plan['plan_sha256'], 'packages': len(plan['packages'])}
    elif args.command == 'retrieve': result = retrieve(c.document(args.plan), args.output)
    else:
        c.require(args.allow_public_review_upload and args.plan and c.document(args.plan) == plan,
                  'Explicit exact public review staging selection required')
        result = stage(plan, args.delivery, args.output, publisher_api())
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
