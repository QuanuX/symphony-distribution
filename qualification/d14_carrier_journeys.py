#!/usr/bin/env python3
"""Qualify genuine packaging revisions without inventing native releases.

Revision one ships an explicit maintenance contract in every opaque unit. Native
payload archives and receipts remain identical. Conda alone owns these carriers;
no service, native installer, selector or provider is invoked by this campaign.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_rewrap as native
from qualification import d09_platform as gate

c = native.c
PROTOCOL = 'symphony.distribution.carrier-revision-journeys.v1'
CONTRACT = 'symphony.distribution.inert-carrier-maintenance.v1'
HELPERS = tuple(sorted(set(native.HELPERS) | {
    'qualification/d14_carrier_journeys.py', 'lifecycle/conda_transaction.py',
    'installer_assembly/link_qualification.py', 'qualification/beta_artifacts.py',
    '.github/workflows/d14-carrier-journeys.yml'}))


def hashes():
    return {name: gate.sha(ROOT / name) for name in HELPERS}


def maintenance_contract(entry, cohort_digest):
    return {'protocol': CONTRACT, 'packaging_revision': 1,
        'previous_cohort_digest': cohort_digest,
        'previous_carrier_manifest_sha256': entry['carrier_manifest_sha256'],
        'retained_native_version': entry['native_version'],
        'unchanged_native_payload_sha256': entry['payload_sha256'],
        'conda_ownership': 'opaque_carrier_files_only',
        'replacement': 'explicit_selected_package_revision',
        'rollback': 'explicit_retained_archive_transaction',
        'native_runtime_effect': 'none', 'runtime_selection': 'existing_native_owner_only',
        'automatic_activation': False, 'live_native_removal_supported': False,
        'distinct_native_version_transition_supported': False}


def revise_entry(root, entry, cohort_digest):
    """Make one useful metadata revision, preserving exact native archive bytes."""
    entry = dict(entry)
    recipe = root / c.relative(entry['recipe_path']); payload = recipe / 'payload'
    unit, _ = c.validate_recipe(root, entry)
    c.require(entry['build_number'] == 0 and 'maintenance_contract' not in unit,
              'Only the exact unrevised initial carrier is admitted')
    unit['maintenance_contract'] = maintenance_contract(entry, cohort_digest)
    raw = c.canonical(unit) + b'\n'; (payload / 'unit.json').write_bytes(raw)
    previous = c.document(payload / 'carrier-manifest.json')
    files = [c.file_row(name, c.bounded(payload / name)[0]) for name in ('payload.tar', 'unit.json')]
    build = 'd14_' + c.sha(c.canonical({'files': files, 'helper_sha256': gate.sha(Path(__file__)),
        'previous_carrier_manifest_sha256': entry['carrier_manifest_sha256']}))[:20] + '_1'
    destination = f'share/symphony/carriers/{entry["component_id"]}/{entry["native_version"]}/{build}'
    manifest = dict(previous, files=files, build=build, build_number=1, destination=destination)
    manifest_raw = c.canonical(manifest) + b'\n'
    (payload / 'carrier-manifest.json').write_bytes(manifest_raw)
    # Keep the exact reviewed no-hooks/no-relocation recipe; change only its
    # documented packaging identity and manifest-bound staging arguments.
    text = (recipe / 'meta.yaml').read_text()
    for old, new in [('  number: 0\n', '  number: 1\n'),
                     ('  string: ' + entry['build_string'] + '\n', '  string: ' + build + '\n'),
                     (entry['carrier_manifest_sha256'], c.sha(manifest_raw)),
                     (entry['carrier_destination'], destination)]:
        c.require(text.count(old) == 1, 'Original recipe identity occurrence differs')
        text = text.replace(old, new)
    (recipe / 'meta.yaml').write_text(text)
    entry.update(build_string=build, build_number=1, carrier_destination=destination,
        carrier_manifest_sha256=c.sha(manifest_raw), unit_manifest_sha256=c.sha(raw),
        recipe_files={name: gate.sha(recipe / name) for name in entry['recipe_files']})
    c.validate_recipe(root, entry)
    return entry


def prepare_revision(original, output, expected_digest):
    original = c.safe_root(original); before = c.audit_cohort(original)
    c.require(before['cohort_digest'] == expected_digest, 'Original carrier selection differs')
    output = gate.fresh(output, (original, ROOT))
    shutil.copytree(original / 'recipes', output / 'recipes', copy_function=shutil.copyfile)
    entries = [revise_entry(output, entry, expected_digest) for entry in before['entries']]
    result = {k: v for k, v in before.items() if k not in ('cohort_digest', 'archive_assembly')}
    result.update(state='prepared', archives=[], entries=entries,
        packaging_revision={'number': 1, 'previous_cohort_digest': expected_digest,
            'generator_sha256': gate.sha(Path(__file__)), 'native_payload_changed': False,
            'purpose': 'explicit inert ownership, retained rollback and unsupported live-transition contract'})
    result = c.sealed(result); (output / 'cohort.json').write_bytes(c.canonical(result) + b'\n')
    c.validate_prepared(output, result['cohort_digest'])
    c.require(c.audit_cohort(original) == before, 'Original carrier archive changed')
    return result


def verify_revision(original, revised, expected_original, expected_revised):
    old, new = c.audit_cohort(original), c.audit_cohort(revised)
    c.require((old['cohort_digest'], new['cohort_digest']) == (expected_original, expected_revised), 'Selected revisions differ')
    c.require(old['profile'] == new['profile'] and old['selected_evidence'] == new['selected_evidence'] and
        old['payload_assignment'] == new['payload_assignment'] and old['sdk_selection'] == new['sdk_selection'] and
        old['initial_selection'] == new['initial_selection'], 'Revision changes native source, ownership or SDK selection')
    previous = {row['unit_id']: row for row in old['entries']}
    c.require(len(previous) == len(new['entries']), 'Revision omits selected carriers')
    for row in new['entries']:
        prior = previous[row['unit_id']]
        unchanged = ('component_id', 'kind', 'native_version', 'conda_name', 'conda_version', 'conda_subdir',
            'payload_sha256', 'payload_size', 'payload_entries', 'dependency_units', 'external_dependency_units', 'sdk_exports')
        c.require(all(row[key] == prior[key] for key in unchanged) and row['build_number'] == prior['build_number'] + 1 == 1 and
            row['carrier_destination'] != prior['carrier_destination'] and row['build_string'] != prior['build_string'],
            'Packaging revision changes native bytes or fails to change packaging identity')
        old_unit, _ = c.validate_recipe(original, prior); new_unit, _ = c.validate_recipe(revised, row)
        contract = new_unit.pop('maintenance_contract', None)
        c.require(contract == maintenance_contract(prior, expected_original) and new_unit == old_unit,
                  'Revision must contain only the explicit maintenance contract')
    return old, new


def identity_adapter(catalog):
    """Closed archive oracle for a private copy of the existing transaction engine.

    Its original Go-only parser is unchanged on disk. Only these already audited
    three-file inert carriers can enter this campaign, at their exact hashes.
    """
    def inspect(path):
        path = Path(path); c.require(path.name in catalog, 'Unselected transaction archive')
        row = catalog[path.name]
        entries, digest, size = c.archive_entries(path)
        c.require(digest == row['sha256'] and size == row['size'] and entries == row['entries'],
                  'Transaction archive differs from audited carrier')
        return dict(row['identity'])
    return inspect


def transaction_engine(catalog):
    engine = c.load_module('d14_private_conda_engine', ROOT / 'lifecycle/conda_transaction.py')
    engine.artifact_identity = identity_adapter(catalog)
    base = engine.Attempt
    class ClosedCarrierAttempt(base):
        @contextmanager
        def _context(self, **kwargs):
            with super()._context(**kwargs):
                # Conda26.10 split classic into a package. Register only the
                # explicitly inspected solver in this private process context.
                from conda.base.context import context
                import conda_pycosat_solver.plugin as solver
                if not context.plugin_manager.is_registered(solver):
                    context.plugin_manager.register(solver)
                yield
    return engine, ClosedCarrierAttempt


def channel_inputs(original, revised, old, new, output):
    channel = output / 'channel'; channel.mkdir(mode=0o700)
    subdir = old['conda_subdir']; catalog, pairs = {}, {}
    for target in (subdir, 'noarch'): (channel / target).mkdir(mode=0o700)
    for root, record, number in ((original, old, 0), (revised, new, 1)):
        entries = {row['unit_id']: row for row in record['entries']}
        for row in record['archives']:
            path = root / 'channel' / subdir / row['filename']
            c.require(row == c.audit_archive(path, root, entries[row['unit_id']]), 'Archive audit changed')
            contents, digest, size = c.archive_entries(path)
            _, files = c.validate_recipe(root, entries[row['unit_id']])
            identity = {key: row[key] for key in ('name', 'version', 'build', 'build_number', 'subdir', 'filename', 'sha256', 'md5', 'depends')}
            identity.update(constrains=[], files={name: {'sha256': c.sha(raw), 'size': len(raw), 'mode': mode}
                for name, (raw, mode) in files.items()})
            c.require(row['filename'] not in catalog, 'Duplicate selected archive identity')
            catalog[row['filename']] = {'identity': identity, 'sha256': digest, 'size': size, 'entries': contents}
            pairs[(row['unit_id'], number)] = identity
            shutil.copyfile(path, channel / subdir / row['filename']); (channel / subdir / row['filename']).chmod(0o600)
    for target in (subdir, 'noarch'):
        records = {name: {**{k: item['identity'][k] for k in ('name', 'version', 'build', 'build_number', 'subdir', 'sha256', 'md5', 'depends', 'constrains')},
                          'size': item['size']} for name, item in catalog.items()} if target == subdir else {}
        (channel / target / 'repodata.json').write_bytes(c.canonical({'info': {'subdir': target}, 'packages': {}, 'packages.conda': records, 'repodata_version': 1}))
    return channel, catalog, pairs


def transitions(attempt, pairs, units, sentinel):
    results = []
    spec = lambda row: row['name'] + '=' + row['version'] + '=' + row['build']
    def run(operation, add=(), remove=()):
        result = attempt.transact(operation, add_specs=[spec(row) for row in add],
            remove_names=sorted({row['name'] for row in remove} - {row['name'] for row in add}),
            expected_link=list(add), expected_unlink=list(remove))
        c.require(sentinel.read_bytes() == b'preserve user state\n', 'User state changed during carrier transition')
        results.append({'operation': operation, 'sequence': result['sequence'],
            'link': [{key: row[key] for key in ('name', 'version', 'build', 'sha256')} for row in add],
            'unlink': [{key: row[key] for key in ('name', 'version', 'build', 'sha256')} for row in remove],
            'result_sha256': c.sha(c.canonical(result) + b'\n'), 'unrelated_files_preserved': result['unrelated_files_preserved']})
    run('install', [pairs[(unit, 0)] for unit in units])
    for unit in units:
        run('upgrade', [pairs[(unit, 1)]], [pairs[(unit, 0)]])
        run('rollback', [pairs[(unit, 0)]], [pairs[(unit, 1)]])
    # This is a Conda carrier swap only. It never selects a transport in Maestro.
    names = {row['name']: unit for (unit, revision), row in pairs.items() if revision == 0}
    a, b = [pairs[(names['symphony-' + name + '-payload'], 0)] for name in ('sov-ssh-adapter', 'sov-stdio-adapter')]
    run('remove', remove=[b]); run('swap', add=[b], remove=[a]); run('rollback', add=[a], remove=[b]); run('install', add=[b])
    for unit in units: run('remove', remove=[pairs[(unit, 0)]])
    c.require(not attempt.inventory(), 'Carrier metadata remains after complete named removal')
    return results


def qualify(original, revised, output, expected_original, expected_revised, *, allow_ephemeral=False):
    c.require(allow_ephemeral is True, 'Explicit isolated carrier-maintenance opt-in required')
    original, revised = c.safe_root(original), c.safe_root(revised)
    old, new = verify_revision(original, revised, expected_original, expected_revised)
    imported = hashes(); output = gate.fresh(output, (original, revised, ROOT))
    import conda, importlib.metadata
    import conda_pycosat_solver.plugin as solver
    c.require(conda.__version__ == importlib.metadata.version('conda-pycosat-solver') == '26.10.0', 'Pinned Conda/solver required')
    tool_identity = {'conda': conda.__version__, 'classic_solver': '26.10.0', 'solver_sha256': gate.sha(Path(solver.__file__))}
    channel, catalog, pairs = channel_inputs(original, revised, old, new, output)
    engine, attempt_type = transaction_engine(catalog)
    outside = output / 'outside-sentinel'; outside.write_bytes(b'preserve outside state\n')
    with attempt_type.create(output / 'attempt', channel, old['conda_subdir']) as attempt:
        sentinel = attempt.prefix / 'user-state.txt'; sentinel.write_bytes(b'preserve user state\n')
        observations = transitions(attempt, pairs, sorted(old['initial_selection']), sentinel)
        c.require(set(engine._snapshot(attempt.prefix)) == {'conda-meta/history', 'user-state.txt'}, 'Removal left carrier files')
        cache = attempt.clean_cache()
        c.require(sentinel.read_bytes() == b'preserve user state\n', 'Cache cleanup changed retained user state')
    c.require(outside.read_bytes() == b'preserve outside state\n' and hashes() == imported and
        gate.sha(Path(solver.__file__)) == tool_identity['solver_sha256'] and
        verify_revision(original, revised, expected_original, expected_revised) == (old, new),
        'Original archives, helpers, solver or outside state changed')
    result = {'protocol': PROTOCOL, 'state': 'packaging_revision_upgrade_swap_rollback_and_removal_passed',
        'profile': old['profile'], 'original_cohort_digest': expected_original, 'revised_cohort_digest': expected_revised,
        'executing_os': platform.system(), 'executing_architecture': platform.machine(),
        'scope': 'opaque carrier transactions only; primary host custody requires the separate primary entrypoint',
        'carrier_count': len(old['entries']), 'transaction_count': len(observations), 'transactions': observations,
        'tools': tool_identity, 'executing_helpers': imported, 'cache_cleanup_result_sha256': c.sha(c.canonical(cache) + b'\n'),
        'packaging_revisions': [0, 1], 'native_payloads_and_receipts_identical': True,
        'all_modules_independently_upgraded_and_rolled_back': True, 'unrelated_user_state_preserved': True,
        'native_owner_invoked': False, 'runtime_selection_changed': False, 'services_or_providers_started': False,
        'live_native_removal_qualified': False, 'distinct_native_release_upgrade_qualified': False,
        'distinct_native_release_rollback_qualified': False, 'publication_authorized': False}
    (output / 'result.json').write_bytes(c.canonical(result) + b'\n')
    return result


def run_primary(args):
    from qualification import beta_artifacts as transport
    c.require(args.allow_ephemeral_maintenance is True, 'Explicit isolated carrier-maintenance opt-in required')
    proof = transport.admit(args.artifact, args.selection, args.selection_sha256)
    selected = proof['selection']; c.require('package' in selected['artifacts'], 'Completed primary package required')
    imported = hashes()
    from qualification.d11_native_maintenance import committed_helpers
    toolkit = committed_helpers(imported)
    host = native.reuse.custody(selected['profile'], args.output)
    tools = native.reuse.inspection_tools(args.inspection_tools, selected['profile'])
    package_root = args.artifact / 'artifacts/package'
    package_sha = selected['artifacts']['package']['result_sha256']
    package, base, _ = native.admit_package(package_root, package_sha)
    c.require(package['profile'] == selected['profile'], 'Primary package platform differs')
    out = gate.fresh(args.output, (args.artifact, args.selection, args.inspection_tools, args.privacy_policy, ROOT))
    original = package_root / 'carrier-capsule/carriers'
    prepared = prepare_revision(original, out / 'prepared', base['cohort_digest'])
    revision = c.build_cohort(out / 'prepared', out / 'revision-one', prepared['cohort_digest'])
    privacy = native.retention.scanner(args.privacy_policy)
    for entry in revision['entries']:
        unit = out / 'revision-one' / entry['recipe_path'] / 'payload/unit.json'
        privacy.scan(entry['unit_id'] + '/unit.json', unit.read_bytes())
    journey = qualify(original, out / 'revision-one', out / 'journey', base['cohort_digest'],
        revision['cohort_digest'], allow_ephemeral=True)
    c.require(transport.admit(args.artifact, args.selection, args.selection_sha256) == proof and
        native.admit_package(package_root, package_sha)[0] == package and hashes() == imported and
        committed_helpers(imported) == toolkit and native.reuse.inspection_tools(args.inspection_tools, selected['profile']) == tools,
        'Original delivery, selection, tools or executing source changed')
    result = {**journey, 'state': 'primary_carrier_packaging_transitions_passed',
        'host': host, 'selection_sha256': args.selection_sha256, 'original_package_result_sha256': package_sha,
        'original_native_lineage': package['lineage'], 'qualification_toolkit': toolkit, 'inspection_tools': tools,
        'journey_result_sha256': gate.sha(out / 'journey/result.json'),
        'revision_cohort_sha256': gate.sha(out / 'revision-one/cohort.json'), 'private_source_policy_scan': 'pass'}
    privacy.scan('result.json', c.canonical(result))
    (out / 'result.json').write_bytes(c.canonical(result) + b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='command', required=True)
    prep = modes.add_parser('prepare')
    for name in ('original', 'output'): prep.add_argument('--' + name, required=True, type=Path)
    prep.add_argument('--original-digest', required=True)
    test = modes.add_parser('qualify')
    for name in ('original', 'revised', 'output'): test.add_argument('--' + name, required=True, type=Path)
    for name in ('original-digest', 'revised-digest'): test.add_argument('--' + name, required=True)
    test.add_argument('--allow-ephemeral-maintenance', action='store_true')
    primary = modes.add_parser('primary')
    for name in ('selection', 'artifact', 'inspection-tools', 'privacy-policy', 'output'):
        primary.add_argument('--' + name, required=True, type=Path)
    primary.add_argument('--selection-sha256', required=True)
    primary.add_argument('--allow-ephemeral-maintenance', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'prepare': result = prepare_revision(args.original, args.output, args.original_digest)
        elif args.command == 'primary': result = run_primary(args)
        else: result = qualify(args.original, args.revised, args.output, args.original_digest, args.revised_digest,
                               allow_ephemeral=args.allow_ephemeral_maintenance)
    except BaseException as error:
        gate.failure_summary(args.output, error)
        raise
    print(json.dumps({'state': result['state'], 'publication_authorized': False}))


if __name__ == '__main__': main()
