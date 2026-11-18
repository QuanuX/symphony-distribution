#!/usr/bin/env python3
"""Assemble a beta or review candidate from unchanged qualified native/client bytes.

No native or bridge compilation occurs here. Original review records retain
their scope; exact assembly authority never implies unobserved qualification
or promotion of a review candidate into a published beta.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tomllib
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).parent))
from qualification import native_rewrap as native
from qualification import beta_artifacts as transport
from qualification import primary_client as client_gate
from qualification import d14_carrier_journeys as journeys
import corresponding_source as source_builder
import supplements

c, construct, gate, signing, reuse = native.c, native.construct, native.gate, native.signing, native.reuse
PROTOCOL = 'symphony.distribution.beta-assembly.v1'
SOURCE = 'symphony.distribution.beta-corresponding-source.v1'
VERSION = '0.2.0-beta.1'


def write(path, value):
    signing.write(path, value if isinstance(value, bytes) else signing.canonical(value), 0o644)


def helpers():
    return {**native.helpers(), **journeys.hashes(), **{name: gate.sha(ROOT / name) for name in
        ('installer_assembly/beta.py', 'installer_assembly/beta_signing.py', 'installer_assembly/corresponding_source.py',
         'delivery/bootstrap.py', '.github/workflows/d14-beta-assembly.yml',
         'qualification/beta_artifacts.py', 'qualification/primary_client.py', 'qualification/primary-client-tools.json')}}


def source_files(raw, binding):
    supplements.source_tree(raw, binding)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        return {row.name: (archive.extractfile(row).read(), row.mode) for row in archive}


def zip_files(path):
    data, total = {}, 0
    with zipfile.ZipFile(path) as archive:
        c.require(len(archive.infolist()) <= 5000 and archive.comment == b'', 'Unexpected client ZIP envelope')
        for row in archive.infolist():
            c.relative(row.filename)
            mode = row.external_attr >> 16
            c.require(row.filename not in data and not row.is_dir() and row.extra == row.comment == b'' and
                not row.flag_bits & 1 and stat.S_ISREG(mode) and stat.S_IMODE(mode) ==
                (0o755 if row.filename == 'bin/symphony-mcp' else 0o644) and row.file_size <= c.LIMIT,
                'Unexpected client ZIP member')
            total += row.file_size; c.require(total <= c.LIMIT, 'Client ZIP expanded size exceeds bound')
            data[row.filename] = (archive.read(row), stat.S_IMODE(mode))
    return data


def validate_client(client_root, base, base_root, original, client_source, *, proof_path=None):
    """Independently bind all derived files to the qualified original Git tree."""
    report = c.document(client_root / 'result.json'); derivation = c.document(client_root / 'derivation.json')
    inventory = c.document(client_root / 'package-inventory.json')
    package = client_root / 'symphony-client.zip'; files = zip_files(package)
    c.require(report['protocol'] == client_gate.PROTOCOL and report['state'] == 'primary_client_engineering_checks_passed' and
        report['profile'] == base['profile'] and report['sources']['plugin'] == client_gate.CLIENT and
        report['client_source_kind'] == 'explicit_derived_catalog_package' and report['package_is_original_git_tree'] is False and
        report['client_executed_from_verified_package'] is True and report['actual_codex_cases'] == 22 and
        report['connection_modes'] == ['stdio', 'same_user_ipc'] and report['real_client_qualification'] == ['Codex'] and
        set(report['fixture_suites']) == client_gate.REQUIRED_SUITES and
        report['independent_finalized_bridge_builds_equal'] is True and report['repeated_package_bytes_equal'] is True and
        report['native_inputs_unchanged'] is True and report['native_payload_rebuilt'] is False and
        report['publication_authorized'] is False and report['release_acceptance_complete'] is False,
        'Selected primary client qualification is incomplete or has different scope')
    core = base['selected_evidence']['source_binding']
    c.require(all(report['sources']['core'][key] == core[key] for key in ('commit', 'tree')) and
        all(report['original_native_lineage'][key] == original['lineage'][key] for key in
            ('source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256',
             'build_result_sha256', 'round_sha256', 'payload_inventory_sha256', 'sdk_closure_sha256')),
        'Client qualified a different core/native cohort')
    c.require(derivation['protocol'] == 'symphony.distribution.primary-client-derivation.v1' and
        derivation['origin'] == client_gate.CLIENT and derivation['profile'] == base['profile'] and
        derivation['is_original_git_tree'] is False and derivation['native_command_contracts_unchanged'] is True and
        set(derivation['generated_paths']) == client_gate.DERIVED and derivation['publication_authorized'] is False and
        gate.sha(client_root / 'derivation.json') == report['derivation_sha256'] and
        gate.sha(client_root / 'package-inventory.json') == report['package_inventory_sha256'],
        'Client derivation or inventory evidence differs')
    rows = derivation['files']; c.require(rows.keys() == client_source.keys(), 'Original client source membership differs')
    for name, (raw, mode) in client_source.items():
        row = rows[name]
        c.require(set(row) == {'original_sha256', 'derived_sha256', 'mode'} and row['original_sha256'] == c.sha(raw) and
                  row['mode'] == mode, 'Original client source bytes/modes differ')
        if name not in client_gate.DERIVED:
            c.require(row['derived_sha256'] == row['original_sha256'], 'Runtime source or adapter was changed')
    selected_names = {'README.md', 'LICENSE', 'CMakeLists.txt', 'plugin.json', 'mcp.json', '.mcp.json', '.gitignore'}
    selected_dirs = {'src', 'include', 'third_party', 'scripts', 'tests', 'skills', 'docs', 'adapters',
                     '.claude-plugin', '.codex-plugin', 'assets', 'catalog', 'schemas', 'ci'}
    selected_names = {name for name in client_source if name in selected_names or Path(name).parts[0] in selected_dirs}
    c.require(set(files) == selected_names | {'bin/symphony-mcp'} and
        {name: 'sha256:' + c.sha(raw) for name, (raw, _) in files.items()} == inventory,
        'Final client ZIP member closure differs')
    for name in selected_names:
        c.require(c.sha(files[name][0]) == rows[name]['derived_sha256'], 'Packaged derived source differs')
    qx_entry = next(row for row in base['entries'] if row['unit_id'] == 'go:qxctl')
    qx, _ = c.validate_recipe(base_root, qx_entry)
    binding = report['bindings']; legacy = report['legacy_verifier']
    c.require(legacy['schema'] == 'symphony.beta-compatibility.report.v1' and legacy['status'] == 'engineering_review_ready' and
        legacy['pending'] == [] and legacy['sources'] == report['sources'] and legacy['bindings'] == binding and
        legacy['distribution'] == 'pending' and legacy['publication_authorized'] is False and legacy['release_acceptance_complete'] is False,
        'Unchanged legacy client verifier did not complete')
    c.require(binding['qxctl_sha256'] == 'sha256:' + qx['provenance']['source_override']['sha256'] and
        binding['package_sha256'] == 'sha256:' + gate.sha(package) and
        binding['bridge_sha256'] == 'sha256:' + c.sha(files['bin/symphony-mcp'][0]) and
        binding['catalog_sha256'] == 'sha256:' + c.sha(files['catalog/tools.json'][0]), 'Qualified client byte binding differs')
    old_catalog = supplements.parse(client_source['catalog/tools.json'][0]); catalog = supplements.parse(files['catalog/tools.json'][0])
    c.require({k: v for k, v in old_catalog.items() if k != 'source_registry_digest'} ==
              {k: v for k, v in catalog.items() if k != 'source_registry_digest'} and
              catalog['source_registry_digest'] == binding['observed_registry_digest'], 'Catalog contract or observed binding differs')
    metadata = supplements.parse(files['catalog/beta-source.json'][0]); old_metadata = supplements.parse(client_source['catalog/beta-source.json'][0])
    allowed = {'core', 'qxctl_build', 'client_dependency', 'observed_registry_digest', 'catalog_sha256', 'original_git_source_binding'}
    c.require(metadata.keys() == old_metadata.keys() and all(metadata[k] == old_metadata[k] for k in metadata if k not in allowed) and
        metadata['client_dependency'] == client_gate.CLIENT and metadata['catalog_sha256'] == binding['catalog_sha256'] and
        metadata['observed_registry_digest'] == binding['observed_registry_digest'], 'Derived catalog metadata changed beyond bindings')
    proof_path = proof_path or base_root.parent / 'evidence/qxctl-source-proof.json'
    proof = c.document(proof_path)
    proof_sha = gate.sha(proof_path)
    c.require(metadata['qxctl_build'] == proof['build_info'] and derivation['qxctl_source_proof_sha256'] == proof_sha and
        metadata['core'] == {**old_metadata['core'], 'commit': core['commit'], 'tree': core['tree']} and
        all(proof['build_info']['source_' + key] == proof['original_source'][key] == core[key] for key in ('commit', 'tree')) and
        metadata['original_git_source_binding'] == {**old_metadata['original_git_source_binding'],
            'proof_sha256': 'sha256:' + proof_sha, 'compiled_input_count': len(proof['compiled_input_equivalence']['inputs']),
            'derived_source_export_digest': proof['cohort_source']['export_digest'], 'isolated_builds': proof['isolated_builds']},
        'Derived client metadata differs from actual qxctl proof')
    old_delta = supplements.parse(client_source['catalog/stamped-owner-delta.json'][0])
    expected_delta = {**old_delta, 'base_client_commit': client_gate.CLIENT['commit'],
        'old_qxctl_sha256': old_metadata['qxctl_build']['executable_sha256'], 'new_qxctl_sha256': proof['binary_sha256'],
        'scope': 'Primary platform artifact binding only; command records and tool descriptors unchanged'}
    c.require(supplements.parse(files['catalog/stamped-owner-delta.json'][0]) == expected_delta, 'Unreviewed owner delta')
    lock, asset = client_gate.codex_lock(base['profile'])
    c.require(report['codex']['asset'] == asset and report['codex']['version'] == lock['version'] and
              report['codex']['source_commit'] == lock['source_commit'], 'Actual Codex selection differs')
    return report, derivation, inventory, files


def add_client(base_root, client_root, output, original, client_source, privacy, *, version=VERSION):
    base = c.audit_cohort(base_root)
    c.require(len(base['entries']) == len(base['archives']) == 58 and not any(e['kind'] == 'client_bridge_bundle' for e in base['entries']),
              'Exactly the unchanged58 core carriers are required')
    report, derivation, inventory, files = validate_client(client_root, base, base_root, original, client_source)
    for name, (raw, _) in files.items(): privacy.scan(name, raw)
    output = gate.fresh(output, (base_root, client_root, ROOT))
    provenance = {'kind': 'qualified_primary_client_with_explicit_derived_catalog', 'source': report['sources']['plugin'],
        'source_kind': 'original_git_plus_three_recorded_catalog_derivations', 'profile': report['profile'],
        'upstream_client_version': supplements.parse(files['.claude-plugin/plugin.json'][0])['version'],
        'beta_delivery_version': version, 'qualification_sha256': gate.sha(client_root / 'result.json'),
        'derivation_sha256': gate.sha(client_root / 'derivation.json'), 'package_inventory_sha256': gate.sha(client_root / 'package-inventory.json'),
        'bindings': report['bindings'], 'private_profiles_or_transcripts_included': False}
    unit = {'unit_id': 'client:client', 'kind': 'client_bridge_bundle', 'component_id': 'client', 'native_version': '0.2.0',
        'payload_paths': [], 'dependency_units': ['go:qxctl'], 'external_dependency_units': [], 'sdk_exports': [],
        'provenance': provenance, 'optional_install': False}
    sources = {name: c.bounded(client_root / filename)[0] for name, filename in
        (('client.zip', 'symphony-client.zip'), ('qualification.json', 'result.json'),
         ('derivation.json', 'derivation.json'), ('package-inventory.json', 'package-inventory.json'))}
    directory = output / 'recipes/symphony-client-payload'
    entry = c.recipe(unit, directory, [c.file_row(name, raw) for name, raw in sorted(sources.items())],
        {name: lambda raw=raw: raw for name, raw in sources.items()}, base['profile'], base['selected_evidence'], privacy.scan)
    entry['recipe_path'] = directory.relative_to(output).as_posix()
    archive = supplements.write_archive(output, entry)
    for row in base['entries']: shutil.copytree(base_root / row['recipe_path'], output / row['recipe_path'])
    for row in base['archives']:
        destination = output / 'channel' / row['subdir'] / row['filename']; shutil.copyfile(base_root / 'channel' / row['subdir'] / row['filename'], destination)
    result = {key: value for key, value in base.items() if key != 'cohort_digest'}
    result.update(entries=base['entries'] + [entry], archives=base['archives'] + [archive],
        initial_selection=base['initial_selection'] + [unit['unit_id']], inherited_core_carrier_digest=base['cohort_digest'],
        client_qualification_sha256=gate.sha(client_root / 'result.json'), beta_assembler_sha256=gate.sha(Path(__file__)))
    result = c.sealed(result); write(output / 'cohort.json', c.canonical(result) + b'\n')
    c.require(c.audit_cohort(output) == result and c.audit_cohort(base_root) == base, 'Core archives changed while adding client')
    return result


def source_bundle(args, package_root, client_root, output, client_report, privacy, *, version=VERSION):
    """Compose existing verified source plus explicitly separated generated data."""
    output.mkdir(mode=0o700)
    proof_path = package_root / 'carrier-capsule/evidence/qxctl-source-proof.json'
    original_delivery = c.document(package_root / 'carrier-capsule/evidence/delivery-record.json')
    current_delivery = c.document(args.delivery / 'delivery-record.json')
    c.require(all(current_delivery[key] == original_delivery[key] for key in
        ('source_binding', 'build_result_sha256', 'round_result_sha256', 'payload_files')),
        'Source-only recollection differs from inherited native payload')
    composite = output / 'composite'
    source_builder.prepare(delivery=args.delivery / 'delivery-record.json', delivery_sha256=gate.sha(args.delivery / 'delivery-record.json'),
        proof=proof_path, proof_sha256=gate.sha(proof_path), core=args.repository, client=args.client_repository,
        client_commit=client_gate.CLIENT['commit'], toolkit=ROOT, toolkit_commit=args.toolkit_commit,
        policy=args.privacy_policy, output=composite)
    base_archive = composite / 'symphony-d08-corresponding-source.tar'
    supplements.validate_source(base_archive.read_bytes(), c.document(composite / 'source-index.json'), c.document(composite / 'source-privacy.json'))
    old_rows, old_identity = source_builder.committed_files(ROOT, client_report['executing_toolkit']['commit'], privacy, toolkit=True)
    c.require(old_identity['tree'] == client_report['executing_toolkit']['tree'], 'Qualified client toolkit tree differs')
    old_files = {name: raw for name, raw, mode in old_rows}
    c.require(all(c.sha(old_files[name]) == digest for name, digest in client_report['executing_helpers'].items()),
              'Qualified client toolkit helper source differs')
    source_builder.write_tar(output / 'qualified-client-toolkit.tar', old_rows)
    client_zip = zip_files(client_root / 'symphony-client.zip')
    generated = [(name, client_zip[name][0], client_zip[name][1]) for name in sorted(client_gate.DERIVED)]
    source_builder.write_tar(output / 'client-derived-catalog.tar', generated)
    scope = {'protocol': SOURCE, 'release_version': version, 'core_source_kind': 'verified_reviewed_derived_export',
        'client_source_kind': 'exact_original_git_export_plus_separate_generated_catalog', 'client_origin': client_gate.CLIENT,
        'client_derived_paths': sorted(client_gate.DERIVED), 'client_qualification_sha256': gate.sha(client_root / 'result.json'),
        'qualified_client_toolkit': client_report['executing_toolkit'], 'assembly_toolkit_commit': args.toolkit_commit,
        'native_or_client_recompiled': False, 'native_sdk_exports_preserved': 20,
        'unrelated_original_source_reconstruction_claimed': False, 'publisher_decision_sha256': args.publisher_decision_sha256}
    items = [('SOURCE-SCOPE.json', signing.canonical(scope), 0o644),
        ('source/native-go-external-and-original-client.tar', base_archive.read_bytes(), 0o644),
        ('source/native-go-source-index.json', (composite / 'source-index.json').read_bytes(), 0o644),
        ('source/native-go-source-privacy.json', (composite / 'source-privacy.json').read_bytes(), 0o644),
        ('source/client-derived-catalog.tar', (output / 'client-derived-catalog.tar').read_bytes(), 0o644),
        ('source/client-derivation.json', (client_root / 'derivation.json').read_bytes(), 0o644),
        ('source/client-qualification.json', (client_root / 'result.json').read_bytes(), 0o644),
        ('source/qualified-client-toolkit.tar', (output / 'qualified-client-toolkit.tar').read_bytes(), 0o644),
        ('source/inherited-wrapper-toolkit.tar', (package_root / 'wrapper-source/WRAPPER-TOOLKIT-SOURCE.tar').read_bytes(), 0o644),
        ('source/inherited-wrapper-toolkit-index.json', (package_root / 'wrapper-source/WRAPPER-TOOLKIT-SOURCE.json').read_bytes(), 0o644)]
    path = output / ('symphony-' + version + '-source.tar')
    rows = source_builder.write_tar(path, items)
    record = {**scope, 'archive': {'filename': path.name, 'sha256': gate.sha(path), 'size': path.stat().st_size}, 'files': rows}
    write(output / 'source-index.json', record)
    # Existing source collectors already scan nested source with their exact
    # recorded public-upstream exceptions. Scan every new derivation/scope record.
    for name, raw, mode in items:
        if name.endswith('.json') and 'source-privacy' not in name and 'toolkit-index' not in name:
            privacy.scan(name, raw)
    # These task-created intermediates are fully retained inside the final TAR.
    shutil.rmtree(composite)
    (output / 'qualified-client-toolkit.tar').unlink()
    (output / 'client-derived-catalog.tar').unlink()
    return record


def optional_source(base, source_root, output, *, version=VERSION):
    record = c.document(source_root / 'source-index.json'); path = source_root / record['archive']['filename']
    c.require(record['release_version'] == version and gate.sha(path) == record['archive']['sha256'] and
        path.stat().st_size == record['archive']['size'], 'Optional source archive or version differs')
    output.mkdir(mode=0o700)
    unit = {'unit_id': 'source:corresponding-source', 'kind': 'optional_corresponding_source',
        'component_id': 'corresponding-source', 'native_version': '0.2.0', 'payload_paths': [],
        'dependency_units': [], 'external_dependency_units': [], 'sdk_exports': [], 'optional_install': True,
        'provenance': {'kind': SOURCE, 'beta_delivery_version': version, 'source_index_sha256': gate.sha(source_root / 'source-index.json'),
            'client_origin': record['client_origin'], 'core_source_kind': record['core_source_kind'],
            'client_source_kind': record['client_source_kind'], 'default_installer_inclusion': False}}
    blobs = {'corresponding-source.tar': path.read_bytes(), 'source-index.json': (source_root / 'source-index.json').read_bytes()}
    directory = output / 'recipes/symphony-corresponding-source-payload'
    entry = c.recipe(unit, directory, [c.file_row(name, raw) for name, raw in sorted(blobs.items())],
        {name: lambda raw=raw: raw for name, raw in blobs.items()}, base['profile'], base['selected_evidence'], None)
    entry['recipe_path'] = directory.relative_to(output).as_posix(); archive = supplements.write_archive(output, entry)
    result = c.sealed({'protocol': 'symphony.distribution.d08-optional-source-carrier.v1', 'state': 'archives_audited',
        'base_carrier_cohort_digest': base['cohort_digest'], 'entries': [entry], 'archives': [archive], 'profile': base['profile'],
        'conda_subdir': base['conda_subdir'], 'default_installer_inclusion': False,
        'publisher_trust_accepted': False, 'publication_authorized': False, 'release_acceptance_complete': False})
    write(output / 'cohort.json', c.canonical(result) + b'\n'); supplements.audit_source(output)
    return result


def artifact_inventory(root):
    return reuse.tree_inventory(root)


def portable_modes(root):
    """Match the transport's fixed engineering envelope, never inner TAR modes."""
    before = artifact_inventory(root)
    for row in before:
        (root / row['path']).chmod(0o700 if row['kind'] == 'directory' else 0o644)
    after = artifact_inventory(root)
    c.require([{k: v for k, v in row.items() if k != 'mode'} for row in before] ==
        [{k: v for k, v in row.items() if k != 'mode'} for row in after], 'Portable envelope normalization changed bytes')


def qualify_retention(prefix, env, output, wrapper, interpreter, client_report, proof_path, *, setup=None):
    """Run the shipped opt-in helper and only read-only retained entrypoints."""
    script = signing.regular(prefix / 'share/symphony/installer/symphony-retain.py')
    index = signing.regular(prefix / 'share/symphony/installer/BOOTSTRAP-INDEX.json')
    c.require(gate.sha(script) == wrapper['retention_helper_sha256'] and
        gate.sha(index) == wrapper['retention_index_sha256'], 'Installed retention helper or selected index differs')
    output.mkdir(mode=0o700); retained = output / 'retained'
    logs = [reuse.consumer.invoke([interpreter, '-I', '-B', script, '--prefix', prefix,
        '--index-sha256', wrapper['retention_index_sha256'], '--output', retained, '--owners'], env, output / 'retain.log')]
    record = c.document(retained / 'CUSTODY.json')
    c.require(record['protocol'] == 'symphony.distribution.retained-candidates.v1' and record['state'] == 'retained_verified_candidates' and
        record['native_installation_performed'] is False and record['runtime_activation_changed'] is False,
        'Retention claimed native installation or activation')
    qxctl = signing.regular(retained / 'candidate/go/qxctl/bin/qxctl')
    bridge = signing.regular(retained / 'client/bin/symphony-mcp')
    c.require('sha256:' + gate.sha(qxctl) == client_report['bindings']['qxctl_sha256'] and
        'sha256:' + gate.sha(bridge) == client_report['bindings']['bridge_sha256'], 'Retained entrypoints differ from qualification')
    before = artifact_inventory(retained)
    for name, command in [('qxctl-version', [qxctl, 'version', '--json']),
                          ('qxctl-manifest', [qxctl, 'commands', 'manifest', '--json']),
                          ('client-help', [bridge, '--help'])]:
        logs.append(reuse.consumer.invoke(command, env, output / (name + '.json')))
    c.require(c.document(output / 'qxctl-version.json') == c.document(proof_path)['build_info'] and
        c.document(output / 'qxctl-manifest.json')['registry_digest'] == client_report['bindings']['observed_registry_digest'] and
        artifact_inventory(retained) == before, 'Retained read-only entrypoint results or custody changed')
    private = output / 'private-profile'; private.mkdir(mode=0o700)
    config, fragment = private / 'connection.json', private / 'codex.toml'
    catalog = retained / 'client/catalog/tools.json'
    logs.append(reuse.consumer.invoke([interpreter, '-I', '-B', retained / 'client/scripts/configure_connection.py',
        '--qxctl', qxctl, '--working-directory', env['HOME'], '--output', config], env, output / 'configure-connection.log'))
    logs.append(reuse.consumer.invoke([interpreter, '-I', '-B', retained / 'client/scripts/configure_clients.py',
        '--client', 'codex', '--binary', bridge, '--config', config, '--tool-catalog', catalog, '--output', fragment],
        env, output / 'configure-codex.log'))
    connection = c.document(config)
    c.require(connection == {'schema': 'symphony.agent.connection.v1', 'qxctl': str(qxctl),
        'qxctl_sha256': client_report['bindings']['qxctl_sha256'], 'working_directory': env['HOME'],
        'registry_digest': client_report['bindings']['observed_registry_digest'], 'enabled_nonread_commands': [],
        'inherit_environment': ['HOME', 'TMPDIR'], 'environment': {}, 'timeout_ms': 30000, 'max_output_bytes': 524288} and
        config.stat().st_mode & 0o777 == fragment.stat().st_mode & 0o777 == 0o600 and
        tomllib.loads(fragment.read_text()) == {'mcp_servers': {'symphony': {'command': str(bridge),
            'args': ['--config', str(config), '--tool-catalog', str(catalog)], 'startup_timeout_sec': 70,
            'tool_timeout_sec': 70, 'default_tools_approval_mode': 'writes'}}} and
        artifact_inventory(retained) == before, 'Private first-run profile or Codex fragment violates default-deny bindings')
    external = None
    if setup is not None:
        c.require(gate.sha(setup / 'symphony-retain.py') == wrapper['retention_helper_sha256'] and
            gate.sha(setup / 'BOOTSTRAP-INDEX.json') == wrapper['retention_index_sha256'], 'Explicit CLI download files differ')
        logs.append(reuse.consumer.invoke([interpreter, '-I', '-B', setup / 'symphony-retain.py', '--prefix', prefix,
            '--index', setup / 'BOOTSTRAP-INDEX.json', '--index-sha256', wrapper['retention_index_sha256'],
            '--output', output / 'cli-retained', '--owners'], env, output / 'cli-retain.log'))
        external = artifact_inventory(output / 'cli-retained')
        c.require(external == before, 'CLI and wrapper retention produced different candidates')
    return {'state': 'installed_retention_and_read_only_entrypoints_passed', 'index_sha256': gate.sha(index),
        'helper_sha256': gate.sha(script), 'custody_sha256': gate.sha(retained / 'CUSTODY.json'),
        'inventory_sha256': c.sha(c.canonical(before)), 'scope': 'explicit qxctl/client/Go owner retention; no native installation or activation',
        'native_installation_performed': False, 'runtime_activation_changed': False, 'logs': logs,
        'external_cli_index_route_passed': external is not None,
        'private_default_deny_profile_and_codex_fragment_passed': True,
        'private_connection_sha256': gate.sha(config), 'private_codex_fragment_sha256': gate.sha(fragment),
        'host_client_configuration_changed': False,
        'external_cli_inventory_sha256': c.sha(c.canonical(external)) if external is not None else None}, retained, before


def admit_delivery_authority(root, result):
    decision = construct.beta_authorization(root / 'publisher-decision.json', result['publisher_decision_sha256'], result['profile'])
    scope = construct.beta_delivery_scope(decision)
    c.require(result['protocol'] == PROTOCOL and result['state'] == scope['assembly_state'] and
        result['release_version'] == scope['release_version'] and result['carrier_count'] == 59 and result['original_core_archives_unchanged'] is True and
        result['native_payloads_and_receipts_changed'] is False and result['final_packaging_revision'] == 1 and
        result['native_or_client_recompiled'] is False and result['runtime_activated'] is False and
        result['publication_authorized'] is scope['publication_authorized'] and result['release_acceptance_complete'] is False,
        'Beta qualification or publication scope differs')
    return decision, scope


def admit_candidate(root, expected_result_sha256):
    root = c.safe_root(root)
    c.require(gate.sha(root / 'result.json') == c.digest(expected_result_sha256), 'Selected beta result differs')
    result = c.document(root / 'result.json')
    decision, scope = admit_delivery_authority(root, result)
    observed = [row for row in artifact_inventory(root) if row['path'] != 'result.json']
    c.require(observed == result['artifact_inventory'], 'Final beta artifact bytes or modes changed')
    cohort = c.audit_cohort(root / 'carriers')
    c.require(len(cohort['entries']) == len(cohort['archives']) == 59 and cohort['cohort_digest'] == result['cohort_digest'] and
        gate.sha(root / 'carriers/cohort.json') == result['cohort_sha256'], 'Final beta carrier identity differs')
    base = c.document(root / 'provenance/base-cohort.json'); c.check_seal(base)
    joined, revised = journeys.verify_revision(root / 'provenance/initial-carriers', root / 'carriers',
        result['initial_cohort_digest'], result['cohort_digest'])
    c.require(len(base['archives']) == 58 and joined['archives'][:58] == base['archives'] and joined['entries'][:58] == base['entries'],
        'Beta replaced a qualified core archive')
    origin = c.document(root / 'provenance/client-original-source.json')
    c.require(origin == result['client_original_source'] and all(origin[key] == client_gate.CLIENT[key] for key in ('commit', 'tree')),
              'Original client Git selection differs')
    original_files = source_files(c.bounded(root / 'provenance/client-original-source.tar')[0], origin)
    original = c.document(root / 'provenance/package-result.json')
    c.require(decision['decision']['source_binding'] == {'core_commit': original['lineage']['source_commit'],
        'client_commit': client_gate.CLIENT['commit']}, 'Assembly authority belongs to different source')
    client, derivation, inventory, files = validate_client(root / 'provenance/client', base, root / 'provenance/initial-carriers', original,
        original_files, proof_path=root / 'provenance/qxctl-source-proof.json')
    c.require(client['sources'] == result['client_sources'] and client['bindings'] == result['client_bindings'] and
        original['lineage'] == result['original_native_lineage'], 'Retained client/native provenance differs')
    entry = cohort['entries'][-1]
    c.require(entry['unit_id'] == 'client:client' and entry['kind'] == 'client_bridge_bundle', 'Final client carrier is absent')
    unit, _ = c.validate_recipe(root / 'carriers', entry)
    blobs = {name: c.bounded(root / 'provenance/client' / filename)[0] for name, filename in
        (('client.zip', 'symphony-client.zip'), ('qualification.json', 'result.json'),
         ('derivation.json', 'derivation.json'), ('package-inventory.json', 'package-inventory.json'))}
    with tarfile.open(root / 'carriers' / entry['recipe_path'] / 'payload/payload.tar', mode='r:') as archive:
        c.require({row.name: archive.extractfile(row).read() for row in archive} == blobs, 'Client carrier differs from qualified package')
    c.require(unit['provenance']['bindings'] == client['bindings'] and unit['provenance']['source'] == client_gate.CLIENT and
        unit['provenance']['beta_delivery_version'] == scope['release_version'] and unit['dependency_units'] == ['go:qxctl'],
        'Client carrier source/owner provenance differs')
    wrapper = c.document(root / 'wrappers/result.json')
    c.require(gate.sha(root / 'wrappers/result.json') == result['wrappers_result_sha256'] and
        wrapper['protocol'] == 'symphony.distribution.beta-installer.v1' and wrapper['state'] == scope['wrapper_state'] and
        wrapper['profile'] == result['profile'] and wrapper['cohort_digest'] == cohort['cohort_digest'] and
        wrapper['archives'] == construct.archive_records(cohort) and wrapper['publication_authorized'] is scope['publication_authorized'] and
        wrapper['release_version'] == scope['release_version'] and wrapper['trust_status'] == scope['trust_status'] and
        wrapper['publisher_decision_sha256'] == decision['sha256'] and wrapper['runtime_activated'] is False,
        'Final wrapper approval or carrier binding differs')
    retention_helper = construct.load_module('beta_retention_index_verify', ROOT / 'delivery/bootstrap.py')
    expected_index = construct.canonical(retention_helper.prepare_index(root / 'carriers', cohort)) + b'\n'
    c.require(c.bounded(root / 'setup/BOOTSTRAP-INDEX.json')[0] == expected_index and
        gate.sha(root / 'setup/BOOTSTRAP-INDEX.json') == wrapper['retention_index_sha256'] and
        gate.sha(root / 'setup/symphony-retain.py') == wrapper['retention_helper_sha256'] ==
        result['executing_helpers']['delivery/bootstrap.py'], 'Portable explicit setup helper or cohort index differs')
    installed_cohort = c.document(root / 'setup/COHORT.json')
    c.require(set(installed_cohort) == {'protocol', 'cohort_digest', 'profile', 'archives', 'publication_authorized',
        'release_acceptance_complete', 'runtime_activated', 'trust_status', 'release_version', 'publisher_decision_sha256',
        'apple_developer_id', 'notarization', 'retention_index_sha256', 'retention_helper_sha256', 'retention_python_requirement'} and
        all(value == wrapper[key] for key, value in installed_cohort.items()), 'Portable installer cohort metadata differs')
    expected_formats = {'pkg', 'sh'} if result['profile'] == 'macos15-arm64' else {'sh'}
    c.require({row['format'] for row in wrapper['wrappers']} == expected_formats and len(wrapper['wrappers']) == len(expected_formats),
        'Final wrapper formats differ')
    for row in wrapper['wrappers']:
        path = signing.regular(root / 'wrappers' / row['filename'])
        c.require(gate.sha(path) == row['sha256'] and path.stat().st_size == row['size'], 'Final wrapper bytes differ')
    shell = next(row for row in wrapper['wrappers'] if row['format'] == 'sh')
    construct.audit_sh(root / 'wrappers' / shell['filename'], construct.archive_records(cohort), shell['bootstrap_sha256'], [])
    optional = supplements.audit_source(root / 'source/carrier')
    c.require(optional['cohort_digest'] == result['optional_source_cohort_digest'] and
        optional['base_carrier_cohort_digest'] == cohort['cohort_digest'] and
        gate.sha(root / 'source/source-index.json') == result['source_index_sha256'], 'Optional source binding differs')
    source = c.document(root / 'source/source-index.json')
    c.require(source['protocol'] == SOURCE and source['release_version'] == scope['release_version'] and source['client_origin'] == client_gate.CLIENT and
        source['native_or_client_recompiled'] is False and source['publisher_decision_sha256'] == decision['sha256'] and
        gate.sha(root / 'source' / c.relative(source['archive']['filename'])) == source['archive']['sha256'], 'Optional source bytes or scope differ')
    c.audit_tar(root / 'source' / source['archive']['filename'], source['files'])
    maintained = c.document(root / 'provenance/carrier-journeys.json')
    c.require(maintained['protocol'] == journeys.PROTOCOL and
        maintained['state'] == 'packaging_revision_upgrade_swap_rollback_and_removal_passed' and
        maintained['original_cohort_digest'] == joined['cohort_digest'] and maintained['revised_cohort_digest'] == cohort['cohort_digest'] and
        maintained['carrier_count'] == 59 and maintained['transaction_count'] == 182 and
        maintained['native_payloads_and_receipts_identical'] is True and maintained['all_modules_independently_upgraded_and_rolled_back'] is True and
        gate.sha(root / 'provenance/carrier-journeys.json') == result['carrier_journeys_sha256'], 'Final59 maintenance qualification is incomplete')
    shell_proof = result['shell_qualification']
    c.require(shell_proof['state'] == 'installed_refusals_and_named_removal_passed' and shell_proof['carrier_count'] == 59 and
        shell_proof['linked_file_count'] == 177 and shell_proof['fresh_private_home_and_prefix'] is True and
        shell_proof['separate_fresh_machine_claimed'] is False, 'Final shell qualification is incomplete')
    retained = result['retention_qualification']
    c.require(retained['state'] == 'installed_retention_and_read_only_entrypoints_passed' and
        retained['index_sha256'] == wrapper['retention_index_sha256'] and retained['helper_sha256'] == wrapper['retention_helper_sha256'] and
        retained['native_installation_performed'] is False and retained['runtime_activation_changed'] is False and
        retained['retained_after_carrier_removal'] is True and retained['external_cli_index_route_passed'] is True,
        'Final first-run retention qualification is incomplete')
    c.require(retained['private_default_deny_profile_and_codex_fragment_passed'] is True and
        retained['host_client_configuration_changed'] is False, 'Final client first-run preparation is incomplete')
    return result, cohort, shell


def assemble(args):
    proof = transport.admit(args.artifact, args.selection, args.selection_sha256)
    selected = proof['selection']; c.require(set(selected['artifacts']) == {'package', 'client'}, 'Exact package and client selection required')
    package_root, client_root = (args.artifact / 'artifacts' / role for role in ('package', 'client'))
    original, base, _ = native.admit_package(package_root, selected['artifacts']['package']['result_sha256'])
    client_report = c.document(client_root / 'result.json')
    c.require(client_report['executing_toolkit']['commit'] == selected['artifacts']['client']['workflow_commit'], 'Client qualification toolkit differs from hosted source')
    decision = construct.beta_authorization(args.publisher_decision, args.publisher_decision_sha256, selected['profile'])
    scope = construct.beta_delivery_scope(decision)
    c.require(decision['decision']['source_binding'] == {'core_commit': original['lineage']['source_commit'],
        'client_commit': client_gate.CLIENT['commit']}, 'Publisher decision source selection differs')
    imported = helpers(); toolkit = client_gate.toolkit_identity(imported)
    c.require(toolkit['commit'] == args.toolkit_commit, 'Executing beta toolkit commit differs')
    host = reuse.custody(selected['profile'], args.output)
    out = gate.fresh(args.output, (args.artifact, args.selection, args.publisher_decision, args.privacy_policy, args.delivery, ROOT))
    artifact = out / 'artifact'; artifact.mkdir(mode=0o700)
    privacy = native.retention.scanner(args.privacy_policy)
    rows, source_identity = source_builder.committed_files(args.client_repository, client_gate.CLIENT['commit'], privacy)
    c.require(source_identity['tree'] == client_gate.CLIENT['tree'], 'Selected original client tree differs')
    originals = {name: (raw, mode) for name, raw, mode in rows}
    provenance = artifact / 'provenance'; provenance.mkdir(mode=0o700)
    source_builder.write_tar(provenance / 'client-original-source.tar', rows)
    write(provenance / 'client-original-source.json', source_identity)
    for name, path in [('base-cohort.json', package_root / 'carrier-capsule/carriers/cohort.json'),
                       ('package-result.json', package_root / 'result.json'),
                       ('qxctl-source-proof.json', package_root / 'carrier-capsule/evidence/qxctl-source-proof.json'),
                       ('transport-proof.json', args.artifact / 'transport-proof.json'), ('selection.json', args.selection)]:
        write(provenance / name, c.bounded(path)[0])
    reuse.copy_tree(client_root, provenance / 'client')
    write(artifact / 'publisher-decision.json', c.bounded(args.publisher_decision)[0])
    joined_root = provenance / 'initial-carriers'
    joined = add_client(package_root / 'carrier-capsule/carriers', client_root, joined_root, original, originals, privacy,
        version=scope['release_version'])
    prepared = journeys.prepare_revision(joined_root, out / 'revision-prepared', joined['cohort_digest'])
    cohort = c.build_cohort(out / 'revision-prepared', artifact / 'carriers', prepared['cohort_digest'])
    journeys.qualify(joined_root, artifact / 'carriers', out / 'carrier-journeys', joined['cohort_digest'], cohort['cohort_digest'], allow_ephemeral=True)
    write(provenance / 'carrier-journeys.json', c.bounded(out / 'carrier-journeys/result.json')[0])
    source = source_bundle(args, package_root, client_root, artifact / 'source', client_report, privacy,
        version=scope['release_version'])
    optional = optional_source(cohort, artifact / 'source', artifact / 'source/carrier', version=scope['release_version'])
    formats = ['pkg', 'sh'] if selected['profile'] == 'macos15-arm64' else ['sh']
    wrapped_work = out / 'wrapper-build'
    wrapper = construct.assemble(artifact / 'carriers', wrapped_work, interpreter=args.python, standalone=args.standalone,
        standalone_archive=args.standalone_archive, formats=formats, privacy_policy=args.privacy_policy,
        beta_decision=args.publisher_decision, beta_decision_sha256=args.publisher_decision_sha256)
    wrappers = artifact / 'wrappers'; wrappers.mkdir(mode=0o700)
    for name in ['result.json'] + [row['filename'] for row in wrapper['wrappers']]:
        shutil.copyfile(wrapped_work / name, wrappers / name); (wrappers / name).chmod(0o644)
    setup = artifact / 'setup'; setup.mkdir(mode=0o700)
    for name in ('BOOTSTRAP-INDEX.json', 'symphony-retain.py', 'COHORT.json'):
        write(setup / name, c.bounded(wrapped_work / 'work/config' / name)[0])
    expected = {}
    for entry in cohort['entries']:
        _, files = c.validate_recipe(artifact / 'carriers', entry)
        c.require(not expected.keys() & files.keys(), 'Final carrier ownership overlaps'); expected.update(files)
    c.require(len(expected) == 177, 'Exactly59 three-file inert carrier closures required')
    consumer = out / 'shell-consumer'; consumer.mkdir(mode=0o700)
    shell = next(row for row in wrapper['wrappers'] if row['format'] == 'sh')
    execution = reuse.snapshot_wrapper(wrappers / shell['filename'], shell, consumer)
    construct.audit_sh(execution, construct.archive_records(cohort), shell['bootstrap_sha256'], [])
    retained = []
    def after_install(prefix, env):
        retained.append(qualify_retention(prefix, env, out / 'retention-probe', wrapper, args.python, client_report,
            package_root / 'carrier-capsule/evidence/qxctl-source-proof.json', setup=setup))
    observations = reuse.exercise(execution, shell, cohort, expected, consumer, after_install=after_install)
    c.require(len(retained) == 1 and artifact_inventory(retained[0][1]) == retained[0][2],
        'Explicit retained custody changed after Conda removal')
    c.require(c.sha(c.canonical(artifact_inventory(out / 'retention-probe/cli-retained'))) == retained[0][0]['external_cli_inventory_sha256'],
        'CLI retained custody changed after Conda removal')
    retention_result = {**retained[0][0], 'retained_after_carrier_removal': True}
    c.require(transport.admit(args.artifact, args.selection, args.selection_sha256) == proof and
        native.admit_package(package_root, selected['artifacts']['package']['result_sha256'])[0] == original and
        helpers() == imported and client_gate.toolkit_identity(imported) == toolkit and
        c.audit_cohort(artifact / 'carriers') == cohort, 'Original artifacts, final carriers or executing source changed')
    portable_modes(artifact)
    result = {'protocol': PROTOCOL, 'state': scope['assembly_state'], 'release_version': scope['release_version'],
        'profile': selected['profile'], 'publisher_decision_sha256': args.publisher_decision_sha256,
        'selection_sha256': args.selection_sha256, 'input_artifacts': selected['artifacts'], 'original_native_lineage': original['lineage'],
        'client_sources': client_report['sources'], 'client_bindings': client_report['bindings'], 'cohort_digest': cohort['cohort_digest'],
        'cohort_sha256': gate.sha(artifact / 'carriers/cohort.json'), 'wrappers_result_sha256': gate.sha(wrappers / 'result.json'),
        'source_index_sha256': gate.sha(artifact / 'source/source-index.json'), 'optional_source_cohort_digest': optional['cohort_digest'],
        'carrier_count': 59, 'optional_source_carrier_count': 1, 'original_core_archives_unchanged': True,
        'final_packaging_revision': 1, 'final_carriers_repacked_with_explicit_maintenance_contract': True,
        'native_payloads_and_receipts_changed': False, 'initial_cohort_digest': joined['cohort_digest'],
        'carrier_journeys_sha256': gate.sha(provenance / 'carrier-journeys.json'),
        'native_or_client_recompiled': False, 'client_original_source': source_identity,
        'shell_qualification': {'state': 'installed_refusals_and_named_removal_passed', 'transactions': observations,
            'carrier_count': 59, 'linked_file_count': 177, 'fresh_private_home_and_prefix': True, 'separate_fresh_machine_claimed': False},
        'retention_qualification': retention_result,
        'host': host, 'executing_toolkit': toolkit, 'executing_helpers': imported,
        'runtime_activated': False, 'native_pkg_executed': False, 'publisher_integrity_signature_created': False,
        'apple_developer_id': False, 'notarization': False, 'publication_authorized': scope['publication_authorized'], 'release_acceptance_complete': False,
        'artifact_inventory': artifact_inventory(artifact)}
    privacy.scan('beta-result.json', signing.canonical(result)); write(artifact / 'result.json', result)
    admit_candidate(artifact, gate.sha(artifact / 'result.json'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('artifact', 'selection', 'publisher-decision', 'privacy-policy', 'repository', 'client-repository',
                 'delivery', 'output', 'python', 'standalone', 'standalone-archive'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('selection-sha256', 'publisher-decision-sha256', 'toolkit-commit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        result = assemble(args)
        print(json.dumps({'state': result['state'], 'profile': result['profile'], 'carrier_count': result['carrier_count']}))
    except BaseException as error:
        gate.failure_summary(args.output, error, args.privacy_policy)
        raise


if __name__ == '__main__': main()
