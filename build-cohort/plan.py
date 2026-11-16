#!/usr/bin/env python3
"""Derive the frozen D06 cohort from exact core source; never build or publish.

The plan records requirements, not observations. All runtime acceptance remains
false until separate final-byte and host campaigns supply their own evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    'dependencies': 'cmake/mvp-dependencies.json',
    'identities': 'cmake/mvp-release-identities.json',
    'platforms': 'cmake/mvp-platform-profiles.json',
    'packages': 'tests/public-beta/package-plan.json',
    'construction': 'tests/public-beta/execution/w12-review/construction.json',
    'sdk': 'tests/native-sdk-distribution/manifest.json',
}
PROFILES = ('macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64')
CORE_SELECTIONS = {'include_in_core_native_set', 'include_complete_receipt_as_core_dependency_only'}
REQUIRED_GATES = (
    'verified_derived_source_export', 'native_target_host_and_toolchain',
    'exact_external_dependency_inputs', 'native_dag_and_installed_sdk_import_proof',
    'final_loader_closure_without_development_paths', 'final_receipt_inventory_and_hashes',
    'final_payload_privacy_scan', 'final_payload_sbom_notices_and_corresponding_source',
    'copied_sdk_consumers_against_final_stage', 'native_owner_regressions_against_final_stage',
    'go_public_module_closure_without_workspace_replacements', 'repeated_build_comparison',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def relative(value):
    path = PurePosixPath(value)
    require(value == str(path) and not path.is_absolute() and '..' not in path.parts
            and '\\' not in value and value not in ('', '.'), 'unsafe source path')
    return value


def indexed(rows, key):
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), 'duplicate ' + key)
    return result


def derive(documents, binding, source_hashes):
    """Validate independent maps before producing a deterministic build input."""
    dep, identities = documents['dependencies'], documents['identities']
    packages, construction = documents['packages'], documents['construction']
    platforms = indexed(documents['platforms']['profiles'], 'profile_id')
    native = indexed(dep['native_components'], 'path')
    recipes = indexed(packages['package_recipes'], 'id')
    dispositions = indexed(packages['source_root_dispositions'], 'source_root')
    roots = indexed(dep['component_roots'], 'path')
    require(len(roots) == len(dispositions) == 73 and roots.keys() == dispositions.keys(),
            'all 73 source roots must retain an explicit disposition')
    for path in roots:
        relative(path)
    require(set(construction['profiles']) == set(PROFILES), 'four construction profiles required')
    require(set(identities['required_profiles']) == set(PROFILES), 'four release profiles required')
    native_recipe_rows = [r for r in recipes.values() if r['kind'] == 'native_receipt_unit']
    native_recipes = {r['source_roots'][0]: r for r in native_recipe_rows}
    installable = {path for path, row in native.items() if row['installable']}
    require(len(native_recipe_rows) == len(native_recipes) == 59 and set(native_recipes) == installable,
            'all 59 native receipt units must be classified exactly once')
    core = {path for path, row in native_recipes.items() if row['proposed_selection'] in CORE_SELECTIONS}
    optional = {path for path, row in native_recipes.items()
                if row['proposed_selection'] == 'separately_selectable_native_unit'}
    require(len(core) == 51 and len(optional) == 8 and core | optional == installable,
            'native core/optional selection differs from accepted 51/8 boundary')
    order = dep['native_build_order']
    require(len(order) == len(set(order)) == len(native) and set(order) == set(native),
            'native build order must cover every mapped component once')
    seen = set()
    for path in order:
        row = native[path]
        dependencies = row['dependency_paths_in_build_order']
        require(len(dependencies) == len(set(dependencies)) and set(dependencies) <= seen,
                'native dependency order is incomplete, cyclic or reversed: ' + path)
        require(path not in core or set(dependencies) <= core, 'core native closure omitted dependency')
        seen.add(path)
        if path not in native_recipes:
            continue
        recipe = native_recipes[path]
        for a, b in [('project_version', 'project_version'), ('package_release_version', 'proposed_package_version'),
                     ('installed_options', 'installed_options'), ('artifact_targets', 'build_targets'),
                     ('exported_packages', 'sdk_exports'), ('qualification_group', 'qualification_group')]:
            require(row[a] == recipe[b], 'native recipe/map mismatch: ' + path + '/' + a)
        require(recipe['dependency_recipe_ids'] == [native_recipes[p]['id'] for p in dependencies],
                'native dependency recipe mismatch: ' + path)
        require(recipe['source_roots'] == [path], 'native unit must retain complete individual receipt')

    go_catalog = indexed(identities['go_artifacts'], 'component_id')
    go_recipe_rows = [r for r in recipes.values() if r['kind'] == 'go_command']
    go_recipes = {r['source_roots'][0]: r for r in go_recipe_rows}
    require(len(go_recipe_rows) == len(go_recipes) == len(go_catalog) == 7 and
            set(go_recipes) == {r['path'] for r in go_catalog.values()}, 'seven Go command catalog required')
    go_core = [row for row in go_catalog.values()
               if go_recipes[row['path']]['proposed_selection'] == 'include_in_core_delivery_set']
    go_optional = [row for row in go_catalog.values()
                   if go_recipes[row['path']]['proposed_selection'] == 'separately_selectable_protected_profile_admin']
    require(len(go_core) == 6 and len(go_optional) == 1 and
            go_optional[0]['component_id'] == 'sov-transport-profile-admin', 'Go 6/1 selection differs')
    sdk = documents['sdk']
    producers = indexed(sdk['sdk_producers'], 'path')
    require(len(producers) == 24, 'all 24 SDK producers must be retained')
    require(len(set(producers) & core) == 20, '20 selected SDK producers must be retained')
    for path, row in native.items():
        exports = [x['package'] for x in row['exported_packages']]
        require(not exports or path in producers, 'unclassified native SDK export')
        if path in producers:
            require(exports == producers[path]['exports'], 'SDK producer/export mapping differs')

    def native_record(path):
        row, recipe = native[path], native_recipes[path]
        return {'component_id': row['component_id'], 'recipe_id': recipe['id'], 'source_root': path,
                'version': row['package_release_version'], 'project_version': row['project_version'],
                'selection': recipe['proposed_selection'], 'installed_options': row['installed_options'],
                'build_targets': row['artifact_targets'], 'build_all_default_targets': True,
                'dependency_source_roots': row['dependency_paths_in_build_order'],
                'first_party_sdk_dependencies': row['first_party_sdk_dependencies'],
                'exported_packages': row['exported_packages'],
                'installed_sdk_consumer_checks': row['installed_sdk_consumer_checks'],
                'qualification_group': row['qualification_group'],
                'external_dependency_refs': recipe['external_dependency_refs'],
                'candidate_profiles': recipe['candidate_profiles'], 'receipt_scope': 'complete_native_receipt_v2'}

    def go_record(row):
        recipe = go_recipes[row['path']]
        require(recipe['proposed_package_version'] == row['package_version'] and
                recipe['binary_name'] == row['binary_name'] and recipe['main_package'] == row['main_package'],
                'Go recipe identity differs')
        return {**row, 'recipe_id': recipe['id'], 'source_root': row['path'],
                'candidate_profiles': recipe['candidate_profiles'], 'selection': recipe['proposed_selection']}

    profile_rows = {}
    for profile in PROFILES:
        selected = [native_record(path) for path in order if path in core]
        require(all(profile in row['candidate_profiles'] for row in selected), 'core native profile omitted')
        original = construction['profiles'][profile]
        require([r['source_root'] for r in original['native_build_order']] == [r['source_root'] for r in selected],
                'W12 construction/native order differs')
        for old, new in zip(original['native_build_order'], selected):
            for key in ('recipe_id', 'component_id', 'source_root', 'version', 'installed_options', 'build_targets',
                        'dependency_source_roots', 'external_dependency_refs'):
                require(old[key] == new[key], 'W12 native construction field differs: ' + key)
        commands = [go_record(row) for row in go_core]
        require(all(profile in row['candidate_profiles'] for row in commands), 'core Go profile omitted')
        require([r['id'] for r in original['go_commands']] == [r['recipe_id'] for r in commands],
                'W12 six-command construction differs')
        for old, new in zip(original['go_commands'], commands):
            for a, b in [('binary_name', 'binary_name'), ('main_package', 'main_package'),
                         ('proposed_package_version', 'package_version'), ('version_symbol', 'version_symbol')]:
                require(old[a] == new[b], 'W12 Go construction field differs')
        eligible = [native_recipes[path]['id'] for path in order if path in optional and
                    profile in native_recipes[path]['candidate_profiles']]
        eligible += [go_recipes[row['path']]['id'] for row in go_optional if profile in go_recipes[row['path']]['candidate_profiles']]
        profile_rows[profile] = {'platform_contract': platforms[profile], 'native_build_order': selected,
                                'go_commands': commands, 'separately_selectable_recipe_ids': eligible,
                                'sdk_producers': [row for row in sdk['sdk_producers'] if row['path'] in core],
                                'build_status': 'not_observed', 'final_stage_status': 'not_observed',
                                'fresh_host_accepted': False, 'release_supported': False}
    require(dep['go_workspace']['go'] == '1.26.5', 'exact Go toolchain changed')
    require(all(not row['module_replacements'] for row in dep['go_modules']), 'independent Go module replacement found')
    external = indexed(dep['external_dependencies'], 'id')
    require(len(external) == 14 and external['CURL']['version'] == '8.7.1' and
            external['zstd']['version'] == '1.5.7' and external['DuckDB']['version'] == '1.5.5',
            'retained external dependency catalog or exact pins changed')
    return {'protocol': 'symphony.distribution.d06-build-cohort.v1',
            'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
            'source_binding_digest': binding['binding_digest'], 'source_inputs': source_hashes,
            'scope': 'Frozen core 51 native receipts and six Go commands; optional units remain independently selectable.',
            'feature_freeze': True, 'core_source_mutated': False, 'supported_profiles': [],
            'profiles': profile_rows,
            'optional_native_units': [native_record(path) for path in order if path in optional],
            'optional_go_commands': [go_record(row) for row in go_optional],
            'source_root_dispositions': packages['source_root_dispositions'],
            'external_dependency_requirements': dep['external_dependencies'],
            'go_module_requirements': [{'path': row['path'], 'module': row['module'], 'go': row['go'],
                                        'direct_requirements': row['direct_requirements'],
                                        'resolved_graph': row['resolved_graph']} for row in dep['go_modules']],
            'sdk_contract': sdk,
            'build_policy': {'native_order': 'serial_topological', 'build_parallel_jobs': 2,
                'cmake_minimum': '3.30', 'go_exact': '1.26.5', 'go_workspace': 'off',
                'go_replacements_allowed': False, 'clean_private_home_and_state': True,
                'input_source': 'verified_privacy_reviewed_derived_export',
                'dependency_prefix': 'explicit_exact_reviewed_inputs_only',
                'build_system_package_registry': False,
                'final_stage_loader_paths': 'relative_package_or_explicit_platform_runtime_only',
                'development_absolute_rpath_allowed': False,
                'finalize_before_receipts': True, 'full_receipt_payload_required': True,
                'runtime_dependency_closure': 'derive_from_final_bytes_including_TLS_backend_and_transitives',
                'external_downloads_during_component_build': False,
                'source_tree_build_artifacts_shipped': False,
                'cleanup': 'only_owned_successful_intermediates_after_retaining_logs_and_hashes'},
            'required_final_stage_gates': list(REQUIRED_GATES),
            'retained_boundaries': {'source_roots': 73, 'core_native_units': 51, 'core_go_commands': 6,
                'optional_native_units': 8, 'optional_go_commands': 1, 'all_sdk_producers': 24,
                'selected_sdk_producers': 20, 'core_acceptance_cells': 36,
                'paper_criteria': 58, 'supplemental_requirements': 31},
            'separate_work': ['publisher_signing_and_public_trust', 'Anaconda_upload_and_retrieval',
                'Cloudflare_installer_distribution', 'four_profile_fresh_host_acceptance',
                'Swift_production_bundle', 'physical_DGX_Spark', 'supplemental_Cloudflare_Intel',
                'licensed_external_SDK_and_live_provider_qualification'],
            'release_acceptance_complete': False, 'publication_authorized': False}


def generate(core, binding):
    core = core.resolve()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(core), *args])
    require(re.fullmatch('[0-9a-f]{40}', binding['source_commit']), 'source commit must be exact')
    require(git('rev-parse', 'HEAD').decode().strip() == binding['source_commit'], 'core HEAD differs')
    require(git('rev-parse', 'HEAD^{tree}').decode().strip() == binding['source_tree'], 'core source tree differs')
    documents, source_hashes = {}, []
    for key, path in INPUTS.items():
        relative(path)
        target = core / path
        require(not any(p.is_symlink() for p in (target, *target.parents) if p != core.parent), 'symlink input refused')
        raw = target.read_bytes()
        require(raw == git('show', binding['source_commit'] + ':' + path), 'dirty source input refused: ' + path)
        documents[key] = read_json(raw)
        source_hashes.append({'path': path, 'sha256': digest(raw)})
    return derive(documents, binding, source_hashes)


def validate(plan, core, binding):
    require(plan == generate(core, binding), 'cohort differs from source-derived complete plan')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('generate', 'verify'))
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--binding', type=Path, default=ROOT / 'source-binding.json')
    parser.add_argument('--plan', type=Path, default=Path(__file__).with_name('cohort.json'))
    args = parser.parse_args()
    binding = read_json(args.binding.read_bytes())
    data = generate(args.core, binding)
    if args.operation == 'generate':
        args.plan.write_text(json.dumps(data, indent=2) + '\n')
    else:
        require(read_json(args.plan.read_bytes()) == data, 'cohort differs from exact source inputs')
    print(json.dumps({'status': 'passed', 'operation': args.operation, 'profiles': 4,
                      'native_per_profile': 51, 'go_per_profile': 6,
                      'release_acceptance_complete': False, 'publication_authorized': False}))


if __name__ == '__main__':
    main()
