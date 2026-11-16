#!/usr/bin/env python3
"""Qualify all seven genuine candidate artifacts through inert delivery routes.

Inputs must carry their actual existing build identities. This gate neither
builds binaries nor invents metadata. Native installs remain fresh/stopped/user
only; all output is retained local evidence, not publication approval.
"""
import argparse
import importlib.util
import json
from pathlib import Path

import go_delivery as d
import handoff


def exact_paths(values):
    result = {}
    for value in values:
        d.require(value.count('=') == 1, 'component=/absolute/file binding required')
        component, path = value.split('=', 1)
        d.require(component in d.owners.OWNERS and component not in result, 'unknown or duplicate component binding')
        result[component] = d.absolute(path)
    d.require(set(result) == set(d.owners.OWNERS), 'all seven exact artifact bindings required')
    return result


def qualify(catalog, catalog_digest, binaries, identities, license_path, output, profile, *, fixture=False):
    binding = d.owners.reviewed_binding()
    d.owners.validate_catalog(catalog, catalog_digest, binding)
    d.require(set(binaries) == set(identities) == set(d.owners.OWNERS), 'all seven exact artifacts required')
    license_data, _ = d.regular(d.absolute(license_path))
    source = {row['path']: row['sha256'] for row in binding['source_evidence']}
    d.require(d.sha(license_data) == source['LICENSE'], 'selected license differs from immutable source')
    payloads = {}
    for component, unit in d.owners.OWNERS.items():
        binary, _ = d.regular(binaries[component], executable=True, limit=d.MAX_BINARY)
        identity, _ = d.regular(identities[component])
        d.identity_check(d.strict_json(identity), unit, binary, profile, binding)
        payloads[component] = (binary, identity)
    recipes = Path(__file__).resolve().parents[1] / 'recipes'
    spec = importlib.util.spec_from_file_location('s05_candidate_recipe', recipes / 'go_generate.py')
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    spec = importlib.util.spec_from_file_location('s05_candidate_stage', recipes / 'stage_payload.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    out = d.Output(output, [*binaries.values(), *identities.values(), license_path])
    rows = []
    try:
        for component in sorted(payloads):
            binary, identity = payloads[component]
            unit = d.owners.unit(catalog, component)
            base = out.path / component
            for name, data, mode in [(unit['binary_name'], binary, 0o755), ('artifact-identity.json', identity, 0o644),
                                      ('LICENSE-AGPL-3.0', license_data, 0o644)]:
                out.write(component + '/carrier/' + name, data, mode)
            carrier = base / 'carrier'
            manifest = d.make_manifest(catalog, catalog_digest, component, carrier, profile, 0, fixture=fixture)
            out.write(component + '/carrier/carrier-manifest.json', d.canonical(manifest) + b'\n', 0o644)
            recipe = generator.render(catalog, catalog_digest, carrier, manifest['manifest_digest'], base / 'recipe', fixture=fixture)
            conda_prefix = base / 'conda-stage'
            conda_prefix.mkdir(mode=0o700)
            sentinel = conda_prefix / 'unrelated-user-data'
            sentinel.write_text('preserve\n')
            stage.stage(base / 'recipe/payload', conda_prefix, recipe['manifest_file_sha256'], recipe['carrier_destination'])
            linked = conda_prefix / recipe['carrier_destination']
            d.verify_carrier(catalog, catalog_digest, linked, manifest['manifest_digest'], fixture=fixture)
            custody = d.materialize(catalog, catalog_digest, linked, manifest['manifest_digest'], base / 'custody',
                                    install_native=component in d.owners.SERVICE_IDS, fixture=fixture)
            d.inspect_custody(catalog, catalog_digest, base / 'custody', custody['custody_digest'], fixture=fixture)
            exported = None
            native_handoff = None
            if component in d.owners.SERVICE_IDS:
                exported = d.export_native(catalog, catalog_digest, base / 'custody', custody['custody_digest'], base / 'export', fixture=fixture)
                runtime = custody['runtime_installation']
                receipt = d.strict_json(d.regular(Path(runtime['prefix']) / runtime['receipt_relative'])[0])
                request = {'unit_id': unit['unit_id'], 'component_id': component, 'state_scope': 'user'}
                owner = handoff.validate_owner(catalog, catalog_digest, request, receipt)
                argv, native_handoff = handoff.native_owner_arguments(
                    [component + '=' + custody['retained_executable']], owner, request, receipt,
                    {'configured_roots': [runtime['prefix']]},
                    {'commit': binding['source_commit'], 'tree': binding['source_tree']},
                    catalog=catalog, manifest_digest=manifest['manifest_digest'], fixture=fixture)
                d.require(argv == ['--native-owner', component + '=' + custody['retained_executable']], 'native handoff changed controller')
            d.require(sentinel.read_text() == 'preserve\n', 'carrier stage altered unrelated files')
            rows.append({'component_id': component, 'manifest_digest': manifest['manifest_digest'],
                         'custody_digest': custody['custody_digest'], 'build_string': recipe['build_string'],
                         'native_owner_invoked': component in d.owners.SERVICE_IDS,
                         'native_export_verified': exported is not None, 'exact_build_stage_verified': True,
                         'native_owner_handoff_verified': native_handoff is not None,
                         'conda_archive_built': False, 'administrator_provisioned': False,
                         'unrelated_data_preserved': True})
        result = {'protocol': 'symphony.distribution.go-candidate-delivery-fixture.v1',
                  'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
                  'catalog_digest': catalog_digest, 'profile': profile, 'fixture': fixture, 'units': rows,
                  'build_identity_matches_source': True, 'independent_publisher_attestation': False,
                  'host_services_changed': False, 'runtime_selection_changed': False,
                  'public_beta_host_accepted': False, 'publication_authorized': False}
        out.document('result.json', result)
        return result
    finally:
        out.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog', type=Path, required=True)
    p.add_argument('--catalog-digest', required=True)
    p.add_argument('--binary', action='append', default=[], required=True)
    p.add_argument('--identity', action='append', default=[], required=True)
    p.add_argument('--license', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--profile', required=True)
    p.add_argument('--fixture', action='store_true')
    a = p.parse_args()
    try:
        catalog = d.strict_json(d.regular(a.catalog)[0])
        print(json.dumps(qualify(catalog, a.catalog_digest, exact_paths(a.binary), exact_paths(a.identity), a.license,
                                 a.output, a.profile, fixture=a.fixture), sort_keys=True))
    except (OSError, ValueError, KeyError, d.subprocess.SubprocessError) as error:
        p.exit(2, 'REFUSED: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
