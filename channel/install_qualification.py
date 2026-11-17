#!/usr/bin/env python3
"""Install/remove exact public review carriers through Conda in fresh private state.

This links opaque carriers only. No native installer, owner, service, provider,
application selection or publication command is invoked.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
import carriers as c
import link_qualification as linking
import review_signing as signing

PROTOCOL = 'symphony.distribution.d09-public-conda-install-qualification.v1'
HELPERS = ('channel/install_qualification.py', 'installer_assembly/link_qualification.py',
           'installer_assembly/carriers.py', 'installer_assembly/review_signing.py',
           'recipes/build_go_carriers.py', 'recipes/go_generate.py', 'lifecycle/go_delivery.py',
           'owner-catalog/native_owners.py', 'qualification/host_platform.py')


def validate_plan(plan, selected_digest, stage):
    c.digest(selected_digest)
    body = {k: v for k, v in plan.items() if k != 'plan_sha256'}
    c.require(plan.get('plan_sha256') == selected_digest == c.sha(c.canonical(body)), 'Selected staging plan differs')
    c.require(plan['protocol'] == 'symphony.distribution.d09-public-review-stage.v1' and
              plan['organization'] == 'QuanuX' and re.fullmatch(r'd09-review-[0-9a-f]{12}', plan['label']) and
              plan['visibility'] == 'public-review-only' and plan['overwrite_supported'] is False and
              plan['beta_release_authorized'] is False and plan['native_install_or_activation'] is False,
              'Unselected review staging scope')
    rows = plan['packages']
    c.require(len(rows) == 60 and sum(r['selection'] == 'default-carrier' for r in rows) == 59 and
              sum(r['selection'] == 'optional-source' for r in rows) == 1, 'Exact default59 plus optional source required')
    names, filenames, subdirs = set(), set(), set()
    for row in rows:
        for key in ('name', 'version', 'build'):
            c.require(re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,199}', row[key]), 'Unsafe package identity')
        c.require(row['filename'] == f'{row["name"]}-{row["version"]}-{row["build"]}.conda' and
                  row['filename'] not in filenames and row['name'] not in names, 'Repeated or mismatched package identity')
        names.add(row['name']); filenames.add(row['filename']); subdirs.add(row['subdir'])
        c.digest(row['sha256']); c.require(type(row['size']) is int and 0 < row['size'] <= c.LIMIT, 'Invalid package size')
        wanted = f'https://conda.anaconda.org/QuanuX/label/{plan["label"]}/{row["subdir"]}/{row["filename"]}'
        c.require(row['url'] == wanted, 'Unselected or credential-bearing package URL')
    c.require(len(subdirs) == 1 and subdirs <= {'osx-64', 'osx-arm64', 'linux-64', 'linux-aarch64'}, 'Mixed or unknown native cohort')
    c.require(stage['protocol'] == plan['protocol'] and stage['plan_sha256'] == selected_digest and
              stage['state'] == 'public_review_staged_metadata_verified' and stage['beta_release_authorized'] is False and
              len(stage['packages']) == len(filenames) and set(stage['packages']) == filenames,
              'Selected stage has not completed')
    return rows


def expected_carrier(entries, entry, row):
    destination = str(c.relative(entry['carrier_destination']))
    wanted_names = {destination + '/' + name for name in ('payload.tar', 'unit.json', 'carrier-manifest.json')}
    payload = {name: value for name, value in entries.items() if not name.startswith('info/')}
    c.require(set(payload) == wanted_names and all(mode == 0o644 for _, mode in payload.values()),
              'Only three opaque carrier files with fixed modes are admitted; hooks/activation refused')
    for name, digest_key in (('payload.tar', 'payload_sha256'), ('unit.json', 'unit_manifest_sha256'),
                             ('carrier-manifest.json', 'carrier_manifest_sha256')):
        c.require(c.sha(payload[destination + '/' + name][0]) == entry[digest_key], 'Nested selected carrier bytes differ')
    c.require(len(payload[destination + '/payload.tar'][0]) == entry['payload_size'], 'Nested carrier size differs')
    c.require(entries == payload | c.metadata_for(entry, payload), 'Carrier metadata, hooks or prefix rewrite differs')
    index = json.loads(entries['info/index.json'][0])
    c.require(all(index[k] == row[k] for k in ('name', 'version', 'build', 'build_number', 'subdir')) and
              index['depends'] == [], 'Selected package metadata differs')
    return payload


def admit_delivery(plan, delivery, certificate, openssl):
    delivery = c.safe_root(delivery); artifacts = c.safe_root(delivery / 'artifacts')
    c.require(certificate == plan['review_certificate_sha256'], 'Review certificate selection differs')
    signing.verify(delivery / 'signature', artifacts, certificate, openssl)
    c.require(signing.digest(delivery / 'signature/review-manifest.json') == plan['signed_manifest_sha256'],
              'Selected signed manifest differs')
    manifest = c.document(delivery / 'signature/review-manifest.json')
    signed = {r['name']: r for r in manifest['artifacts']}
    cohort, optional = (c.document(artifacts / name) for name in ('CARRIER-COHORT.json', 'OPTIONAL-SOURCE-COHORT.json'))
    c.check_seal(cohort); c.check_seal(optional)
    c.require(cohort['cohort_digest'] == plan['carrier_cohort_digest'] and
              optional['cohort_digest'] == plan['optional_source_cohort_digest'] and
              optional['base_carrier_cohort_digest'] == cohort['cohort_digest'], 'Selected cohort digests differ')
    entries = {e['unit_id']: e for e in cohort['entries'] + optional['entries']}
    archive_rows = {r['filename']: r for r in cohort['archives'] + optional['archives']}
    c.require(len(entries) == len(archive_rows) == 60 and set(archive_rows) == {r['filename'] for r in plan['packages']},
              'Signed complete package selection differs')
    source = c.document(artifacts / 'SOURCE-INDEX.json')
    c.require(source['source_bindings'] == plan['source_bindings'], 'Selected source trio differs')
    expected = {}
    for row in plan['packages']:
        bound = signed[row['filename']]; selected = archive_rows[row['filename']]
        c.require(all(row[k] == bound[k] == selected[k] for k in ('sha256', 'size')), 'Package signature/cohort binding differs')
        archive, digest, size = c.archive_entries(artifacts / row['filename'])
        c.require(digest == row['sha256'] and size == row['size'], 'Local archive changed after signature verification')
        payload = expected_carrier(archive, entries[selected['unit_id']], row)
        c.require(not expected.keys() & payload.keys(), 'Selected carriers overlap'); expected.update(payload)
    c.require(len(expected) == 180, 'Expected complete linked carrier count differs')
    return expected


def isolated_env(output, interpreter, subdir):
    for name in ('home', 'tmp', 'pkgs', 'envs'):
        (output / name).mkdir(mode=0o700)
    config = output / 'home/condarc'
    config.write_text('channels: []\ndefault_channels: []\ncreate_default_packages: []\nreport_errors: false\n'
                      'anaconda_upload: false\nregister_envs: false\nadd_anaconda_token: false\nssl_verify: true\nproxy_servers: {}\n')
    return {'HOME': str(output / 'home'), 'PATH': str(interpreter.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
        'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'USER': 'builder', 'LOGNAME': 'builder',
        'TMPDIR': str(output / 'tmp'), 'TEMP': str(output / 'tmp'), 'TMP': str(output / 'tmp'),
        'CONDARC': str(config), 'CONDA_SUBDIR': subdir, 'CONDA_OFFLINE': 'false',
        'CONDA_PKGS_DIRS': str(output / 'pkgs'), 'CONDA_ENVS_PATH': str(output / 'envs'),
        'CONDA_REPORT_ERRORS': 'false', 'CONDA_NO_PLUGINS': 'true', 'CONDA_SOLVER': 'classic',
        'CONDA_REGISTER_ENVS': 'false', 'CONDA_ADD_ANACONDA_TOKEN': 'false', 'CONDA_SSL_VERIFY': 'true',
        'CONDA_REMOTE_CONNECT_TIMEOUT_SECS': '15', 'CONDA_REMOTE_READ_TIMEOUT_SECS': '60',
        'CONDA_REMOTE_MAX_RETRIES': '0', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def explicit_urls(plan):
    return '@EXPLICIT\n' + ''.join(row['url'] + '#' + row['sha256'] + '\n' for row in plan['packages'])


def downloaded_and_linked(prefix, cache, rows, expected):
    linked_count = linking.verify_linked(prefix, expected)
    packages = {}
    metadata = list((prefix / 'conda-meta').glob('*.json'))
    for path in metadata:
        row = c.document(path)
        c.require(row['name'] not in packages, 'Duplicate installed package record'); packages[row['name']] = row
    c.require(set(packages) == {r['name'] for r in rows}, 'Installed package selection differs')
    cached = {p.name: p for p in cache.glob('*.conda')}
    c.require(set(cached) == {r['filename'] for r in rows}, 'Fresh cache package selection differs')
    records = []
    for row in rows:
        record = packages[row['name']]
        c.require(all(record[k] == row[k] for k in ('name', 'version', 'build', 'build_number', 'subdir', 'sha256')),
                  'Installed package identity differs')
        parsed = urlsplit(record['url'])
        c.require(urlunsplit(parsed._replace(fragment='')) == row['url'], 'Installed package URL differs')
        raw, _ = c.bounded(cached[row['filename']])
        c.require(c.sha(raw) == row['sha256'] and len(raw) == row['size'], 'Fresh Conda download bytes differ')
        records.append({k: row[k] for k in ('filename', 'url', 'sha256', 'size')})
    return linked_count, records


def qualify(plan_path, stage_path, delivery, output, *, plan_sha256, certificate, openssl, python):
    helpers = {name: signing.digest(ROOT / name) for name in HELPERS}
    plan_raw = c.bounded(signing.plain(plan_path))[0]; plan = json.loads(plan_raw)
    stage_raw = c.bounded(signing.plain(stage_path))[0]; stage = json.loads(stage_raw)
    rows = validate_plan(plan, plan_sha256, stage)
    host = c.load_module('d09_install_host', ROOT / 'qualification/host_platform.py')
    observed_host = host.observe_host()
    c.require(host.profile_matches(plan['profile'], observed_host), 'CLI qualification requires matching selected native host')
    expected = admit_delivery(plan, delivery, certificate, openssl)
    interpreter = Path(python).resolve(strict=True)
    c.require(interpreter.is_file(), 'Selected publisher interpreter absent')
    output = c.safe_root(output, exists=False)
    inputs = [signing.plain(p) for p in (delivery, plan_path, stage_path, ROOT, interpreter)]
    c.require(not output.exists() and output.parent.is_dir() and
              all(output != p and p not in output.parents and output not in p.parents for p in inputs),
              'Qualification output must be fresh and disjoint')
    output.mkdir(mode=0o700)
    env = isolated_env(output, interpreter, rows[0]['subdir'])
    config_sha = signing.digest(output / 'home/condarc')
    tool = subprocess.run([str(interpreter), '-c', "import conda, importlib.metadata as m, conda_pycosat_solver.plugin as p, hashlib, json; print(json.dumps({'conda':conda.__version__,'solver':m.version('conda-pycosat-solver'),'solver_module_sha256':hashlib.sha256(open(p.__file__,'rb').read()).hexdigest()}))"],
                          env=env, capture_output=True, timeout=30)
    c.require(tool.returncode == 0, 'Selected isolated Conda inspection failed')
    tool_identity = json.loads(tool.stdout)
    c.require(tool_identity['conda'] == tool_identity['solver'] == '26.10.0', 'Unqualified Conda/solver version')
    c.digest(tool_identity['solver_module_sha256'])
    c.require(not list((output / 'pkgs').iterdir()) and not (output / 'prefix').exists(), 'Qualification did not start with empty cache/prefix')
    prefix = output / 'prefix'; outside = output / 'outside-sentinel'; outside.write_bytes(b'outside-owned-state\n')
    explicit = output / 'explicit.txt'; explicit.write_text(explicit_urls(plan))
    command = [str(interpreter), '-m', 'conda', '--no-plugins', '--enable-plugins', 'conda-pycosat-solver']
    try:
        create_log = linking.invoke(command + ['create', '--prefix', str(prefix), '--file', str(explicit), '--yes',
            '--copy', '--solver', 'classic', '--no-default-packages'], env, output / 'create.log')
        linked_count, downloads = downloaded_and_linked(prefix, output / 'pkgs', rows, expected)
        c.require(outside.read_bytes() == b'outside-owned-state\n', 'Create changed outside state')
        (prefix / 'user-state.txt').write_bytes(b'user-owned-state\n')
        remove_log = linking.invoke(command + ['remove', '--prefix', str(prefix), '--offline', '--yes',
            '--solver', 'classic', *sorted(r['name'] for r in rows)], env | {'CONDA_OFFLINE': 'true'}, output / 'remove.log')
        c.require((prefix / 'user-state.txt').read_bytes() == b'user-owned-state\n' and outside.read_bytes() == b'outside-owned-state\n',
                  'Removal changed user or outside state')
        c.require(not list((prefix / 'conda-meta').glob('*.json')), 'Carrier package records remain after removal')
        linking.verify_linked(prefix, {})
        c.require(c.bounded(plan_path)[0] == plan_raw and c.bounded(stage_path)[0] == stage_raw, 'Selected delivery records changed')
        c.require(helpers == {name: signing.digest(ROOT / name) for name in HELPERS} and
                  config_sha == signing.digest(output / 'home/condarc'), 'Qualification helpers or private configuration changed')
        result = {'protocol': PROTOCOL, 'state': 'public_explicit_url_install_and_removal_passed',
            'plan_sha256': plan_sha256, 'plan_file_sha256': c.sha(plan_raw), 'stage_record_sha256': c.sha(stage_raw),
            'signed_manifest_sha256': plan['signed_manifest_sha256'], 'review_certificate_sha256': certificate,
            'source_bindings': plan['source_bindings'], 'profile': plan['profile'], 'label': plan['label'],
            'observed_host': observed_host,
            'package_count': len(rows), 'default_carrier_count': 59, 'optional_source_carrier_count': 1,
            'linked_file_count': linked_count, 'packages': downloads, 'conda_tool_identity': tool_identity,
            'interpreter_sha256': c.sha(interpreter.read_bytes()), 'imported_helpers': helpers,
            'initial_cache_empty': True, 'explicit_https_sha256_urls': True, 'copy_mode': True,
            'exact_downloaded_and_linked_bytes': True, 'all_selected_carriers_removed': True,
            'user_state_preserved': True, 'outside_state_preserved': True, 'account_credentials_supplied': False,
            'create_log_sha256': create_log, 'remove_log_sha256': remove_log,
            'native_runtime_owner_invoked': False, 'runtime_installation_accepted': False,
            'service_or_provider_activated': False, 'fresh_host_accepted': False,
            'independent_acceptance_complete': False, 'publisher_trust_accepted': False,
            'beta_release_authorized': False, 'publication_authorized': False}
        signing.write(output / 'result.json', signing.canonical(result)); return result
    except Exception as error:
        signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
            'error_class': type(error).__name__, 'plan_sha256': plan_sha256, 'private_logs_retained': True,
            'native_runtime_owner_invoked': False, 'beta_release_authorized': False}))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'stage-record', 'delivery', 'output', 'openssl', 'python'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--plan-sha256', required=True); parser.add_argument('--certificate-sha256', required=True)
    args = parser.parse_args()
    result = qualify(args.plan, args.stage_record, args.delivery, args.output, plan_sha256=args.plan_sha256,
        certificate=args.certificate_sha256, openssl=args.openssl, python=args.python)
    print(json.dumps({'state': result['state'], 'package_count': result['package_count'],
                      'linked_file_count': result['linked_file_count'], 'beta_release_authorized': False}))


if __name__ == '__main__': main()
