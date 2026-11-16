#!/usr/bin/env python3
"""Explicit isolated-prefix qualification using real, source-bound Conda archives.

This is a publisher/test gate, not an end-user runtime selector or supervisor.
It creates only new private directories, keeps all evidence and rollback bytes,
and never uploads a package or mutates an existing Conda environment.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lifecycle'))
sys.path.insert(0, str(ROOT / 'recipes'))
import go_delivery as d
import go_generate


def load(path):
    return d.strict_json(d.regular(path)[0])


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def prepare(go_root, qxctl_root, output, profile, fixture):
    catalog = load(ROOT / 'go-owner-catalog.json')
    digest = catalog['catalog_digest']
    license_data = (ROOT / 'LICENSE').read_bytes()
    binding = d.owners.reviewed_binding()
    d.require(d.sha(license_data) == next(x['sha256'] for x in binding['source_evidence'] if x['path'] == 'LICENSE'),
              'license differs from bound core source')
    out = d.Output(output, [go_root, qxctl_root])
    rows = []
    try:
        for component, policy in sorted(d.owners.OWNERS.items()):
            binary = qxctl_root / 'first/bin/qxctl' if component == 'qxctl' else go_root / component / 'bin' / policy['binary_name']
            identity = qxctl_root / 'artifact-identity.json' if component == 'qxctl' else go_root / 'identities' / (component + '.json')
            binary_bytes, _ = d.regular(binary, executable=True, limit=d.MAX_BINARY)
            identity_bytes, _ = d.regular(identity)
            d.identity_check(d.strict_json(identity_bytes), policy, binary_bytes, profile, binding)
            for build_number in (0, 1):
                relative = component + '/' + str(build_number)
                base = output / relative
                for name, data, mode in ((policy['binary_name'], binary_bytes, 0o755),
                                          ('artifact-identity.json', identity_bytes, 0o644),
                                          ('LICENSE-AGPL-3.0', license_data, 0o644)):
                    out.write(relative + '/carrier/' + name, data, mode)
                manifest = d.make_manifest(catalog, digest, component, base / 'carrier', profile, build_number, fixture=fixture)
                out.write(relative + '/carrier/carrier-manifest.json', d.canonical(manifest) + b'\n', 0o644)
                recipe = go_generate.render(catalog, digest, base / 'carrier', manifest['manifest_digest'], base / 'recipe', fixture=fixture)
                rows.append({'component_id': component, 'build_number': build_number,
                             'recipe': relative + '/recipe', 'manifest_digest': manifest['manifest_digest'],
                             'carrier_destination': recipe['carrier_destination'], 'build_string': recipe['build_string']})
        result = {'protocol': 'symphony.distribution.conda-journey-inputs.v1', 'source_commit': binding['source_commit'],
                  'catalog_digest': digest, 'profile': profile, 'fixture': fixture, 'recipes': rows,
                  'two_packaging_builds': True, 'two_native_versions': False, 'publication_authorized': False}
        out.document('inputs.json', result)
        return result
    finally:
        out.close()


def build(prepared, output):
    import build_go_carriers as builder
    inputs = load(prepared / 'inputs.json')
    out = d.Output(output, [prepared])
    archives = []
    try:
        for row in inputs['recipes']:
            label = row['component_id'] + '-' + str(row['build_number'])
            report = builder.build_recipe(prepared / row['recipe'], output / label,
                                          expected_manifest_digest=row['manifest_digest'], fixture=inputs['fixture'])
            candidates = sorted((output / label).rglob('*.conda'))
            d.require(len(candidates) == 1, 'builder did not retain exactly one archive')
            archives.append({**row, 'archive': str(candidates[0].relative_to(output)), 'audit': report})
        result = {**inputs, 'archives': archives}
        out.document('archives.json', result)
        return result
    finally:
        out.close()


def validate_inputs(inputs, catalog):
    """Validate exact source/owner coverage before creating a journey output."""
    d.require(set(inputs) == set('protocol source_commit catalog_digest profile fixture recipes two_packaging_builds two_native_versions publication_authorized archives'.split()),
              'archive report fields differ')
    d.require(inputs['protocol'] == 'symphony.distribution.conda-journey-inputs.v1' and
              inputs['catalog_digest'] == catalog['catalog_digest'] and inputs['source_commit'] == catalog['source_commit'] and
              inputs['two_packaging_builds'] is True and inputs['two_native_versions'] is False and inputs['publication_authorized'] is False,
              'archive source, catalog, or qualification boundary differs')
    profile, fixture = inputs['profile'], inputs['fixture']
    d.require(fixture is True, 'this local journey harness requires an explicit fixture profile')
    d.require(profile in d.owners.PROFILES, 'unknown journey platform profile')
    expected_units = {(component, number) for component in d.owners.OWNERS for number in (0, 1)}
    d.require(isinstance(inputs['archives'], list) and isinstance(inputs['recipes'], list) and
              len(inputs['archives']) == len(inputs['recipes']) == len(expected_units),
              'exact seven by two archive coverage required')
    seen = set()
    for row in inputs['archives']:
        d.require(set(row) == set('component_id build_number recipe manifest_digest carrier_destination build_string archive audit'.split()),
                  'archive row fields differ')
        key = (row['component_id'], row['build_number'])
        d.require(type(row['build_number']) is int and key in expected_units and key not in seen,
                  'unknown or duplicate archive identity')
        d.require({k: v for k, v in row.items() if k not in ('archive', 'audit')} in inputs['recipes'],
                  'archive and prepared recipe differ')
        d.relative(row['archive'])
        d.require(isinstance(row['audit'], dict), 'archive audit must be an object')
        seen.add(key)
    d.require(seen == expected_units, 'archive coverage differs')
    return profile, fixture, expected_units


def validate_archive_evidence(row, observed_audit, archive_name, archive_digest, archive_size, data):
    """Bind a recorded audit to the independently inspected and copied bytes."""
    d.require(d.sha(data) == archive_digest and archive_size == len(data), 'archive changed between copy and audit')
    d.require(all(row['audit'].get(k) == v for k, v in observed_audit.items()) and
              row['audit'].get('archive_sha256') == archive_digest and row['audit'].get('archive_size') == len(data) and
              row['audit'].get('archive_filename') == archive_name, 'archive audit does not match actual bytes')


def validate_retirement(prefix, component, record, old_receipt, before_root, state):
    """Require exact durable owner evidence and absence of both owned paths."""
    d.require(len(old_receipt['files']) == 1, 'native owner receipt must identify exactly one executable')
    owned_binary = old_receipt['files'][0]
    receipt_path = prefix / d.relative(record['runtime_installation']['receipt_relative'])
    binary_path = prefix / d.relative(owned_binary['path'])
    expected_identity = {'owner': component, 'version': record['native_version'],
                         'receipt_digest': old_receipt['receipt_digest'], 'binary_digest': owned_binary['digest'],
                         'binary_relative': owned_binary['path'], 'receipt_relative': record['runtime_installation']['receipt_relative'],
                         'binary_size': owned_binary['size']}
    after_root = prefix.lstat()
    d.require(state['protocol'] == 'symphony.package-retirement-state.v1' and state['phase'] == 'retired' and
              state['identity'] == expected_identity and
              (state['root_device'], state['root_inode']) == (before_root.st_dev, before_root.st_ino) == (after_root.st_dev, after_root.st_ino),
              'native retirement did not retain exact owner tombstone')
    # A dangling symlink is a remaining artifact, not proof of removal.
    d.require(not os.path.lexists(receipt_path), 'retired receipt remains')
    d.require(not os.path.lexists(binary_path), 'retired executable remains')


def run(archives_root, output):
    import conda_transaction as ct
    import build_go_carriers as builder
    from conda_index.api import update_index
    catalog = load(ROOT / 'go-owner-catalog.json')
    inputs = load(archives_root / 'archives.json')
    profile, fixture, expected_units = validate_inputs(inputs, catalog)
    out = d.Output(output, [archives_root])
    custody = {}
    try:
        channel = out.mkdir('channel')
        subdir = d.owners.PROFILES[profile][2]
        (channel / subdir).mkdir(mode=0o700)
        (channel / 'noarch').mkdir(mode=0o700)
        rows = {}
        for row in inputs['archives']:
            key = (row['component_id'], row['build_number'])
            archive = archives_root / d.relative(row['archive'])
            data, mode = d.regular(archive, limit=512 * 1024 * 1024)
            entries, archive_digest, archive_size = builder.archive_entries(archive)
            d.require(d.sha(data) == archive_digest and archive_size == len(data), 'archive changed between copy and audit')
            manifest_path = row['carrier_destination'] + '/carrier-manifest.json'
            d.require(manifest_path in entries, 'archive lacks selected carrier manifest')
            manifest = d.strict_json(entries[manifest_path][0])
            d.require(manifest['component_id'] == key[0] and manifest['build_number'] == key[1] and
                      manifest['profile'] == profile and manifest['fixture'] is fixture, 'archive manifest identity differs')
            _, _, _, recipe = go_generate.recipe_documents(manifest)
            d.require(recipe['carrier_destination'] == row['carrier_destination'] and recipe['build_string'] == row['build_string'], 'archive recipe identity differs')
            validation = output / ('validated-' + key[0] + '-' + str(key[1]))
            checked = d.Output(validation)
            try:
                unit = d.owners.unit(catalog, key[0])
                for name in (unit['binary_name'], 'artifact-identity.json', 'LICENSE-AGPL-3.0', 'carrier-manifest.json'):
                    payload, permission = entries[row['carrier_destination'] + '/' + name]
                    checked.write('payload/' + name, payload, permission)
            finally:
                checked.close()
            # The Output lock stays outside the exact four-file carrier.
            payload_dir = validation / 'payload'
            d.verify_carrier(catalog, catalog['catalog_digest'], payload_dir, row['manifest_digest'], fixture=fixture)
            expected = {row['carrier_destination'] + '/' + name: d.regular(payload_dir / name, executable=name == unit['binary_name'], limit=d.MAX_BINARY)
                        for name in (unit['binary_name'], 'artifact-identity.json', 'LICENSE-AGPL-3.0', 'carrier-manifest.json')}
            observed_audit = builder.audit_entries(entries, manifest, recipe, expected)
            validate_archive_evidence(row, observed_audit, archive.name, archive_digest, archive_size, data)
            destination = channel / subdir / archive.name
            with destination.open('xb') as stream:
                stream.write(data)
            identity = ct.artifact_identity(destination)
            rows[(row['component_id'], row['build_number'])] = {**row, 'identity': identity}
        d.require(set(rows) == expected_units, 'archive coverage differs')
        update_index(str(channel), subdir=[subdir, 'noarch'], threads=1)
        reports = []

        def spec(identity):
            return identity['name'] + '=' + identity['version'] + '=' + identity['build']

        def retain(attempt, component, number, label):
            row = rows[(component, number)]
            carrier = Path(attempt.prefix) / row['carrier_destination']
            target = output / label
            result = d.materialize(catalog, catalog['catalog_digest'], carrier, row['manifest_digest'], target,
                                   install_native=component in d.owners.SERVICE_IDS, fixture=fixture)
            custody[label] = result
            return result

        def check_retained():
            for label, record in custody.items():
                d.inspect_custody(catalog, catalog['catalog_digest'], output / label, record['custody_digest'], fixture=fixture)

        with ct.Attempt.create(output / 'delivery', channel, subdir) as attempt:
            identities = [rows[(component, 0)]['identity'] for component in sorted(d.owners.OWNERS)]
            reports.append(attempt.transact('install', add_specs=[spec(i) for i in identities],
                                            expected_link=identities, expected_unlink=[]))
            for component in sorted(d.owners.OWNERS):
                retain(attempt, component, 0, component + '-original')
            for component in sorted(d.owners.OWNERS):
                old, new = rows[(component, 0)]['identity'], rows[(component, 1)]['identity']
                reports.append(attempt.transact('upgrade', add_specs=[spec(new)], expected_link=[new], expected_unlink=[old]))
                retain(attempt, component, 1, component + '-replacement')
                check_retained()
                reports.append(attempt.transact('rollback', add_specs=[spec(old)], expected_link=[old], expected_unlink=[new]))
                check_retained()
            for component in sorted(d.owners.OWNERS):
                old = rows[(component, 0)]['identity']
                reports.append(attempt.transact('remove', remove_names=[old['name']], expected_link=[], expected_unlink=[old]))
                check_retained()
            d.require(not attempt.inventory(), 'carrier removal left installed packages')
            cache_report = attempt.clean_cache()
            check_retained()

        # A delivery swap changes only carriers. Existing runtime selection and
        # live sessions are deliberately not altered by a package manager.
        with ct.Attempt.create(output / 'swap-delivery', channel, subdir) as attempt:
            ssh = rows[('sov-ssh-adapter', 0)]['identity']
            stdio = rows[('sov-stdio-adapter', 0)]['identity']
            unrelated = rows[('secure-identity-access-governance', 0)]['identity']
            reports.append(attempt.transact('install', add_specs=[spec(ssh), spec(unrelated)],
                                            expected_link=[ssh, unrelated], expected_unlink=[]))
            check_retained()
            reports.append(attempt.transact('swap', add_specs=[spec(stdio)], remove_names=[ssh['name']],
                                            expected_link=[stdio], expected_unlink=[ssh]))
            check_retained()
            reports.append(attempt.transact('rollback', add_specs=[spec(ssh)], remove_names=[stdio['name']],
                                            expected_link=[ssh], expected_unlink=[stdio]))
            check_retained()
        retired = []
        rollback_installs = []
        for component in sorted(d.owners.SERVICE_IDS):
            label = component + '-replacement'
            record = custody[label]
            prefix = Path(record['runtime_installation']['prefix'])
            sentinel = prefix / 'unrelated-user-data'
            sentinel.write_text('preserve fixture data\n')
            d.inspect_custody(catalog, catalog['catalog_digest'], output / label, record['custody_digest'], fixture=fixture)
            before_root = prefix.stat()
            old_receipt = load(prefix / record['runtime_installation']['receipt_relative'])
            owned_binary = old_receipt['files'][0]
            argv = d.owners.install_argv(component, record['retained_executable'], prefix)
            argv[argv.index('install')] = 'uninstall'
            intent = {'component_id': component, 'prefix': str(prefix), 'controller_sha256': record['executable_sha256'],
                      'scope': 'fresh_stopped_fixture_only', 'automatic_retry': False}
            save(output / (label + '-retirement-intent.json'), intent)
            # Maintenance inherits the actual caller environment. A separate
            # fake HOME must never hide references from a native removal owner.
            with (output / (label + '-retirement.log')).open('xb') as stream:
                completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                           timeout=120, check=False)
            d.require(completed.returncode == 0, 'native fixture retirement uncertain/refused; retain evidence, do not replay')
            state = load(prefix / '.symphony-package-retirement' / component / record['native_version'] / 'state.json')
            validate_retirement(prefix, component, record, old_receipt, before_root, state)
            d.require(sentinel.read_text() == 'preserve fixture data\n', 'native removal changed unrelated data')
            d.verify_carrier(catalog, catalog['catalog_digest'], output / label / 'retained-carrier', record['manifest_digest'], fixture=fixture)
            del custody[label]  # its immutable receipt record now describes a retired installation
            retired.append(component)
            original = custody[component + '-original']
            recovered = d.materialize(catalog, catalog['catalog_digest'], output / (component + '-original') / 'retained-carrier',
                                      original['manifest_digest'], output / (component + '-rollback-install'), install_native=True, fixture=fixture)
            custody[component + '-rollback-install'] = recovered
            rollback_installs.append(component)
            check_retained()
        result = {'protocol': 'symphony.distribution.conda-journeys.v1', 'source_commit': inputs['source_commit'],
                  'catalog_digest': catalog['catalog_digest'], 'profile': profile,
                  'archive_count': len(rows), 'transaction_count': len(reports), 'retained_candidates': len(custody),
                  'native_installations': sum(r['native_receipt_created'] for r in custody.values()),
                  'fresh_stopped_native_retirements': retired, 'independent_native_rollback_installs': rollback_installs,
                  'independent_module_transactions': True, 'retained_bytes_verified_after_every_transaction': True,
                  'private_conda_cache_cleaned': cache_report['status'] == 'observed-complete',
                  'install_upgrade_delivery_swap_remove_rollback': True,
                  'two_packaging_builds': True, 'two_native_versions': False,
                  'existing_environment_mutated': False, 'runtime_selection_changed': False,
                  'runtime_activation_changed': False, 'live_runtime_removal_qualified': False,
                  'full_profile_apply_executed': False, 'physical_beta_host_qualified': False,
                  'publication_authorized': False, 'transactions': reports}
        out.document('result.json', result)
        return result
    finally:
        out.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--go-root', type=Path, required=True)
    prep.add_argument('--qxctl-root', type=Path, required=True)
    prep.add_argument('--output', type=Path, required=True)
    prep.add_argument('--profile', required=True)
    prep.add_argument('--fixture', action='store_true')
    builds = sub.add_parser('build')
    builds.add_argument('--prepared', type=Path, required=True)
    builds.add_argument('--output', type=Path, required=True)
    journeys = sub.add_parser('run')
    journeys.add_argument('--archives', type=Path, required=True)
    journeys.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.command == 'prepare':
        result = prepare(a.go_root, a.qxctl_root, a.output, a.profile, a.fixture)
    elif a.command == 'build':
        result = build(a.prepared, a.output)
    else:
        result = run(a.archives, a.output)
    print(json.dumps({k: v for k, v in result.items() if k not in ('recipes', 'archives', 'transactions')}, sort_keys=True))


if __name__ == '__main__':
    main()
