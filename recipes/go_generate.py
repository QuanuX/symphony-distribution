#!/usr/bin/env python3
"""Author source-bound inert Go carrier recipes; this is publisher tooling only."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('s05_delivery', HERE.parent / 'lifecycle/go_delivery.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def recipe_documents(manifest):
    """Derive only closed inert build instructions; never embed publisher paths."""
    d.owners.validate_seal(manifest, 'manifest_digest', manifest['manifest_digest'])
    d.require(manifest['schema'] == d.MANIFEST and manifest['format_version'] == 2, 'carrier schema differs')
    component = manifest['component_id']
    unit = d.owners.OWNERS.get(component)
    d.require(unit is not None and manifest['native_version'] == unit['native_version'] and
              manifest['owner_contract'] == unit['owner_contract'], 'owner version/contract differs')
    d.require(manifest['conda_name'] == 'symphony-' + component + '-payload' and
              manifest['conda_version'] == manifest['native_version'].replace('-dev', 'dev0'), 'Conda identity differs')
    d.require(type(manifest['build_number']) is int and manifest['build_number'] >= 0 and
              manifest['profile'] in d.owners.PROFILES and
              manifest['conda_subdir'] == d.owners.PROFILES[manifest['profile']][2], 'package build/platform differs')
    d.require(all(isinstance(manifest[key], str) and __import__('re').fullmatch(r'[0-9a-f]{40}', manifest[key])
                  for key in ('source_commit', 'source_tree')), 'invalid source identity')
    stage = (HERE / 'stage_payload.py').read_bytes()
    renderer = d.sha(Path(__file__).read_bytes() + b'\x00' + stage)
    manifest_digest = manifest['manifest_digest']
    build = f"s06_{manifest['source_commit'][:12]}_{manifest_digest[7:19]}_{renderer[:12]}_{manifest['build_number']}"
    destination = f"share/symphony/carriers/{component}/{manifest['native_version']}/{build}"
    manifest_bytes = d.canonical(manifest) + b'\n'
    manifest_file_sha = d.sha(manifest_bytes)
    # SYS_PYTHON is Conda's publisher interpreter. No target Python environment
    # is solved, linked, installed or added as a runtime dependency.
    script = '\"$SYS_PYTHON\" \"$RECIPE_DIR/stage_payload.py\" \"$SRC_DIR\" \"$PREFIX\" ' + manifest_file_sha + ' ' + destination
    meta = '\n'.join([
        'package:', '  name: ' + manifest['conda_name'], '  version: ' + json.dumps(manifest['conda_version']),
        'source:', '  path: payload', 'build:', '  number: ' + str(manifest['build_number']),
        '  string: ' + json.dumps(build), '  include_recipe: false',
        '  binary_relocation: false', '  detect_binary_files_with_prefix: false',
        '  ignore_prefix_files: true', '  script: ' + json.dumps(script),
        'about:', '  license: AGPL-3.0-only', '  license_file: LICENSE-AGPL-3.0',
        '  summary: ' + json.dumps('Inert Symphony ' + component + ' payload; explicit owner materialization required'),
        'extra:', '  target_subdir: ' + json.dumps(manifest['conda_subdir']),
        '  publication_authorized: false', '  fixture: ' + str(manifest['fixture']).lower(),
        '  native_version: ' + json.dumps(manifest['native_version']), '  owner_contract: ' + json.dumps(manifest['owner_contract']),
        '  runtime_activation: false', '  runtime_python_dependency: false', ''])
    record = {'protocol': 'symphony.distribution.go-recipe.v2', 'component_id': component,
              'manifest_digest': manifest_digest, 'catalog_digest': manifest['catalog_digest'],
              'build_string': build, 'carrier_destination': destination, 'target_subdir': manifest['conda_subdir'],
              'renderer_sha256': renderer, 'manifest_file_sha256': manifest_file_sha,
              'conda_build_argv_proposal': ['python', 'recipes/build_go_carriers.py', 'build', '--recipe', '<recipe-directory>',
                                          '--output', '<fresh-output-directory>', '--manifest-digest', manifest_digest],
              'native_install_owner_invoked': False, 'runtime_dependencies': [], 'lifecycle_hooks': [],
              'privilege_mutation': False, 'publication_authorized': False, 'fresh_host_accepted': False}
    return meta.encode(), stage, manifest_bytes, record


def render(value, catalog_digest, carrier, manifest_digest, output, *, fixture=False, binding=None):
    manifest, files = d.verify_carrier(value, catalog_digest, carrier, manifest_digest, fixture=fixture, binding=binding)
    meta, stage, manifest_bytes, record = recipe_documents(manifest)
    out = d.Output(output, [carrier])
    try:
        for name, (data, mode) in files.items():
            out.write('payload/' + name, data, mode)
        out.write('payload/carrier-manifest.json', manifest_bytes, 0o644)
        out.write('stage_payload.py', stage, 0o644)
        out.write('meta.yaml', meta, 0o644)
        out.document('recipe-evidence.json', record)
        return record
    finally:
        out.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ('catalog', 'carrier', 'output'):
        p.add_argument('--' + field, type=Path, required=True)
    p.add_argument('--catalog-digest', required=True)
    p.add_argument('--manifest-digest', required=True)
    p.add_argument('--fixture', action='store_true')
    a = p.parse_args()
    try:
        value = d.strict_json(d.regular(d.absolute(a.catalog))[0])
        print(json.dumps(render(value, a.catalog_digest, a.carrier, a.manifest_digest, a.output, fixture=a.fixture), sort_keys=True))
    except (OSError, ValueError, KeyError) as e:
        p.exit(2, 'REFUSED: ' + str(e) + '\n')


if __name__ == '__main__':
    main()
