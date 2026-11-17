#!/usr/bin/env python3
"""Qualify selected delivered native owners in a new disposable unmanaged prefix.

No live service is started or removed. Same-candidate restoration is recovery,
not an upgrade, rollback, new release, or production installation grant.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
sys.path.insert(0, str(ROOT))
import carriers as carrier
from qualification.d06_sdk_closure import Runner, file_snapshot, compare_inventory, owned_paths

PROTOCOL = 'symphony.distribution.d09-native-maintenance.v1'
COMMIT = '5fd6cee1bae477048bf0045b691ee8bdf334e216'
TREE = '327edd0f22860e84d30fe745f5a2b0e602f4af88'
MARKERS = ('.symphony-lifecycle-ownership-v1.json',
           'share/symphony/receipts/symphony-root-ownership/1/install-receipt.json')
COMMON_SOURCE = ('cmake/SymphonyInstallReceiptV2.cmake', 'cmake/SymphonyInstallReceiptV2.cmake.in',
    'cmake/SymphonyInstallReceiptV2Preflight.cmake.in', 'cmake/SymphonyUninstallReceiptV2.cmake',
    'cmake/SymphonyReceiptV2Support.cmake', 'tests/native-sdk-distribution/inspect-uninstaller.cmake',
    'tools/qxctl/internal/knowledgelifecycle/native_owner.go')
require, sha, canonical = carrier.require, carrier.sha, carrier.canonical


def file_sha(path): return sha(carrier.bounded(path)[0])
def document(path): return carrier.document(path)
def write_json(path, value): Path(path).write_bytes(canonical(value) + b'\n')


def git(source, *args):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(source), *args],
        env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}, stderr=subprocess.PIPE, timeout=60)


def owner_sources(source, unit):
    root = unit['source_root']; primary = root + '/CMakeLists.txt'
    text = (source / primary).read_bytes(); template = root + '/cmake/uninstall.cmake.in'
    paths = [primary]
    if (source / template).is_file():
        paths.append(template); form = 'component_uninstall_template'
    elif b'SymphonySnvEngine.cmake' in text:
        paths.append('cmake/SymphonySnvEngine.cmake'); form = 'shared_snv_generated_owner'
    elif b'SymphonyScvEngine.cmake' in text:
        paths += ['cmake/SymphonyScvEngine.cmake', 'modules/scv-engine/cmake/uninstall.cmake.in']
        form = 'shared_scv_template_owner'
    elif unit['component_id'] in ('ssiag-provider-private-store', 'sov-cloudflare-adapter') and \
            b'file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"' in text:
        form = 'component_inline_generated_owner'
    else:
        raise ValueError('Unclassified generated uninstaller source: ' + unit['component_id'])
    for helper in ('cmake/SymphonyScvEngine.cmake', 'cmake/SymphonySqvAdministration.cmake'):
        if helper.encode().split(b'/')[-1] in text and helper not in paths: paths.append(helper)
    return paths, form


def source_register(source, cohort):
    return source_register_units(source, [row for row in cohort['entries'] if row['kind'] == 'native_receipt_unit'],
                                 cohort['selected_evidence']['source_binding'])


def source_register_units(source, selected_native_rows, source_binding):
    """Bind existing owner configuration to explicit verified native selection rows."""
    source = carrier.safe_root(source)
    require(git(source, 'rev-parse', 'HEAD').decode().strip() == COMMIT and
            git(source, 'rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'Selected native owner source differs')
    require(not git(source, 'status', '--porcelain=v1', '--untracked-files=all').strip(), 'Owner checkout is dirty')
    require(source_binding == {'commit': COMMIT, 'tree': TREE}, 'Carrier/core source binding differs')
    plan = document(ROOT / 'build-cohort/cohort.json')
    require((plan['source_commit'], plan['source_tree']) == (COMMIT, TREE), 'Build plan source differs')
    for row in plan['source_inputs']:
        path = source / carrier.relative(row['path'])
        require(file_sha(path) == row['sha256'] and path.read_bytes() == git(source, 'show', COMMIT + ':' + row['path']),
                'Core selection source differs')
    units = plan['profiles']['macos15-arm64']['native_build_order']
    selected = {row['component_id']: row for row in selected_native_rows}
    require(len(units) == len(selected) == len(selected_native_rows) == 51 and {u['component_id'] for u in units} == set(selected), 'Exact native51 selection differs')
    evidence = {}
    def bind(name):
        raw = carrier.bounded(source / carrier.relative(name))[0]
        require(raw == git(source, 'show', COMMIT + ':' + name), 'Owner source file differs')
        evidence[name] = sha(raw)
    for name in COMMON_SOURCE: bind(name)
    register = []
    for unit in units:
        entry = selected[unit['component_id']]
        require(entry['native_version'] == unit['version'] and entry['sdk_exports'] == unit['exported_packages'], 'Owner version/SDK selection differs')
        paths, form = owner_sources(source, unit)
        for name in paths: bind(name)
        register.append({'component_id': unit['component_id'], 'version': unit['version'], 'source_root': unit['source_root'],
            'owner_contract': 'source_configured_receipt_v2_cmake_unmanaged_prefix',
            'source_files': paths, 'configuration_form': form, 'dependency_source_roots': unit['dependency_source_roots'],
            'sdk_exports': unit['exported_packages'], 'installed_options': unit['installed_options'],
            'operations': {'immutable_version_preflight': 'source_implemented_pending_this_run',
                'exact_unmanaged_removal': 'source_implemented_pending_this_run',
                'interrupted_removal_retry': 'source_implemented_pending_this_run',
                'retained_same_candidate_restoration': 'disposable_harness_recovery_only',
                'live_use_retirement': 'not_qualified', 'shared_root_apply': 'not_qualified_by_this_campaign',
                'two_release_upgrade': 'missing_distinct_qualified_release', 'two_release_rollback': 'missing_distinct_qualified_release'},
            'native_install_execution_qualified': False, 'runtime_activation_supported': False})
    return units, register, evidence


def distinct_release_pair(prior, target):
    """Reject relabelled/rebuilt same candidates before any future transition."""
    for record in (prior, target):
        require(set(record) == {'component_id', 'version', 'source_commit', 'receipt_sha256', 'artifact_sha256'}, 'Incomplete release pair evidence')
        require(re.fullmatch('[a-z0-9][a-z0-9-]*', record['component_id']) and re.fullmatch('[0-9a-f]{40}', record['source_commit']), 'Invalid release identity')
        for field in ('receipt_sha256', 'artifact_sha256'): carrier.digest(record[field])
    require(prior['component_id'] == target['component_id'] and prior['version'] != target['version'] and
            prior['source_commit'] != target['source_commit'] and prior['receipt_sha256'] != target['receipt_sha256'] and
            prior['artifact_sha256'] != target['artifact_sha256'], 'Two independently qualified distinct releases are required; same-candidate recovery is not upgrade/rollback')
    return {'component_id': prior['component_id'], 'prior': prior, 'target': target,
            'compatibility_and_selection_qualified': False, 'upgrade_qualified': False, 'rollback_qualified': False}


def read_carrier(artifacts, cohort, entry, row, retained):
    path = artifacts / carrier.relative(row['filename'])
    require(path.name == row['filename'] and file_sha(path) == row['sha256'] and path.stat().st_size == row['size'], 'Delivered archive differs')
    entries, actual_sha, size = carrier.archive_entries(path)
    require(actual_sha == row['sha256'] and size == row['size'], 'Delivered archive changed while reading')
    destination = entry['carrier_destination']
    payload = entries[destination + '/payload.tar'][0]; raw_unit = entries[destination + '/unit.json'][0]
    raw_manifest = entries[destination + '/carrier-manifest.json'][0]
    require(sha(payload) == entry['payload_sha256'] and len(payload) == entry['payload_size'] and
            sha(raw_unit) == entry['unit_manifest_sha256'] and sha(raw_manifest) == entry['carrier_manifest_sha256'], 'Delivered nested carrier differs')
    unit, manifest = json.loads(raw_unit), json.loads(raw_manifest)
    require(unit['protocol'] == carrier.UNIT and unit['selected_evidence'] == cohort['selected_evidence'] and
            all(unit[k] == entry[k] for k in ('unit_id', 'kind', 'component_id', 'native_version', 'dependency_units', 'external_dependency_units', 'sdk_exports')) and
            all(unit[k] is False for k in ('native_runtime_install_supported', 'publisher_trust_accepted', 'publication_authorized', 'release_acceptance_complete')), 'Delivered unit identity/scope differs')
    require(manifest['protocol'] == 'symphony.distribution.d08-inert-carrier.v1' and manifest['unit_id'] == entry['unit_id'] and
            manifest['files'] == [carrier.file_row('payload.tar', payload), carrier.file_row('unit.json', raw_unit)] and
            manifest['destination'] == destination and manifest['runtime_install_supported'] is False and manifest['publication_authorized'] is False,
            'Delivered carrier manifest differs')
    expected = {destination + '/' + name: (data, 0o644) for name, data in
                [('payload.tar', payload), ('unit.json', raw_unit), ('carrier-manifest.json', raw_manifest)]}
    require(entries == expected | carrier.metadata_for(entry, expected), 'Extra archive files, hooks or prefix rewrites')
    tar_path = retained / (entry['component_id'] + '.tar'); tar_path.write_bytes(payload)
    carrier.audit_tar(tar_path, unit['files'])
    require(len(unit['files']) == entry['payload_entries'], 'Delivered unit inventory differs')
    return unit, tar_path


def materialize(artifacts, cohort, work):
    retained = work / 'retained'; retained.mkdir(mode=0o700)
    prefix = work / 'retained-prefix'; prefix.mkdir(mode=0o700)
    archives = {r['unit_id']: r for r in cohort['archives']}; assigned = {}; units = {}; expected = {}
    require(len(archives) == len(cohort['entries']) == 59, 'Selected default59 archive set required')
    for entry in cohort['entries']:
        unit, path = read_carrier(artifacts, cohort, entry, archives[entry['unit_id']], retained)
        units[entry['unit_id']] = unit
        selected = set(unit['payload_paths']); rows = carrier.rows_by_path(unit['files'])
        require(selected <= rows.keys(), 'Selected payload outside delivered unit')
        with tarfile.open(path) as source:
            for name in sorted(selected):
                require(name not in assigned, 'Two carriers claim the same payload'); assigned[name] = unit['unit_id']
                target = prefix / carrier.relative(name); target.parent.mkdir(parents=True, exist_ok=True)
                row = rows[name]
                if 'link' in row:
                    require(name.startswith('third-party/lib/libcurl') and '/' not in row['link'], 'Unqualified runtime link')
                    target.symlink_to(row['link']); expected[name] = {'link': row['link']}
                else:
                    data = source.extractfile(name).read(); require(sha(data) == row['sha256'], 'Retained bytes changed')
                    with target.open('xb') as output: output.write(data)
                    target.chmod(row['mode']); expected[name] = {'sha256': row['sha256'], 'mode': row['mode']}
    require(assigned == cohort['payload_assignment'] and len(assigned) == cohort['payload_entry_count'] == 1250, 'Delivered payload coverage differs')
    require(file_snapshot(prefix) == expected, 'Retained prefix differs')
    return prefix, units, expected


def restore_files(retained, target, paths):
    """Fixture recovery only: never overwrite or adopt an existing path."""
    for name in paths:
        p = target / carrier.relative(name)
        require(not p.exists() and not p.is_symlink(), 'Recovery refuses existing or aliased target')
        require(not any(a.is_symlink() for a in p.parents if a != target.parent), 'Recovery refuses linked ancestor')
    for name in paths:
        data, mode = carrier.bounded(retained / name)
        p = target / name; p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as stream: stream.write(data)
        p.chmod(mode)


def configure(source, prefix, work, units, args, runner):
    mapping = document(source / 'cmake/mvp-dependencies.json')
    definitions = {x['component_id']: x for x in mapping['native_components']}
    metadata = work / 'metadata'; metadata.mkdir(); output = work / 'owners'; output.mkdir()
    common = [f'-DCMAKE_C_COMPILER={args.cc}', f'-DCMAKE_CXX_COMPILER={args.cxx}', '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DCMAKE_INSTALL_LIBDIR=lib', f'-DCMAKE_INSTALL_PREFIX={prefix}',
        f'-DCMAKE_PREFIX_PATH={prefix};{prefix}/third-party', '-DBUILD_TESTING=OFF', '-DSYMPHONY_KVE_BUILD_TESTING=OFF',
        '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
        '-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON', '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON',
        '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF', '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
        f'-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={source}/tests/mvp-dependencies/prove-imports.cmake',
        f'-DMVP_SELECTED_PREFIX={prefix}', f'-DMVP_EXTERNAL_PREFIX={prefix}/third-party', f'-DMVP_REPOSITORY={source}']
    owners = {}
    for unit in units:
        cid = unit['component_id']; meta = metadata / (cid + '.json'); write_json(meta, definitions[cid])
        build = work / 'configure-only' / cid
        runner.run(cid + '-configure', [args.cmake, '-S', source / unit['source_root'], '-B', build, *common,
            *[f'-D{k}={v}' for k, v in unit['installed_options'].items()], f'-DMVP_COMPONENT_FILE={meta}',
            f'-DMVP_PROOF_LOG={work}/logs/{cid}-imports.txt'])
        destination = output / cid; destination.mkdir()
        identity = list(build.glob('symphony-receipt-v2-identity-*.cmake'))
        preflight = list(build.glob('symphony-install-receipt-v2-preflight-*.cmake'))
        require(len(identity) == len(preflight) == 1, 'Missing exact configured owner identity/preflight')
        originals = [build / n for n in ('uninstall.cmake', 'SymphonyUninstallReceiptV2.cmake', 'SymphonyReceiptV2Support.cmake')] + identity + preflight
        hashes = {}
        for path in originals:
            data = carrier.bounded(path)[0]; (destination / path.name).write_bytes(data); hashes[path.name] = sha(data)
        inventory = destination / 'configured-files.txt'
        runner.run(cid + '-inventory', [args.cmake, f'-DSDK_UNINSTALLER={destination}/uninstall.cmake',
            f'-DSDK_INVENTORY_OUTPUT={inventory}', '-P', source / 'tests/native-sdk-distribution/inspect-uninstaller.cmake'])
        receipt_name = f'share/symphony/receipts/{cid}/{unit["version"]}/install-receipt.json'
        receipt = document(prefix / receipt_name); paths = owned_paths(receipt, receipt_name)
        compare_inventory(inventory.read_text().split(';'), paths)
        unsigned = dict(receipt); seal = unsigned.pop('receipt_digest')
        require(seal == 'sha256:' + sha(canonical(unsigned)) and receipt['component_id'] == cid and receipt['version'] == unit['version'], 'Receipt identity differs')
        for row in receipt['files']:
            data, mode = carrier.bounded(prefix / row['path'])
            require(row['digest'] == 'sha256:' + sha(data) and row['size'] == len(data) and
                    (row['kind'] != 'executable' or mode & 0o111), 'Receipt bytes differ')
        owners[cid] = {'script': destination / 'uninstall.cmake', 'preflight': destination / preflight[0].name,
            'paths': paths, 'receipt': receipt, 'receipt_name': receipt_name, 'helper_hashes': hashes,
            'receipt_sha256': file_sha(prefix / receipt_name)}
        # Only this run's configure-only scratch is reclaimed, never old builds.
        shutil.rmtree(build)
    return owners


def campaign_snapshot(prefix, receipt_alias=None):
    """Observe one explicit negative-test alias without following it outside."""
    if receipt_alias is None:
        return file_snapshot(prefix)
    alias, target = receipt_alias
    require(alias.is_relative_to(prefix) and alias.is_symlink() and
            os.readlink(alias) == str(target), 'Receipt alias fixture changed')
    result = {}
    for path in sorted(prefix.rglob('*')):
        name = path.relative_to(prefix).as_posix()
        if path == alias:
            result[name] = {'link': os.readlink(path)}
        elif path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(prefix), 'Unexpected external fixture alias')
            result[name] = {'link': os.readlink(path)}
        elif path.is_file():
            result[name] = {'sha256': file_sha(path), 'mode': path.stat().st_mode & 0o777}
        else:
            require(path.is_dir(), 'Unexpected special fixture file')
    return result


def campaign(retained, work, units, owners, args, runner):
    prefix = work / 'disposable-prefix'; shutil.copytree(retained, prefix, symlinks=True)
    sentinel = prefix / 'unrelated-user-state.txt'; sentinel.write_bytes(b'preserve caller state\n')
    outside = work / 'outside-sentinel'; outside.write_bytes(b'preserve outside state\n')
    baseline = file_snapshot(prefix); checks = []
    for unit in reversed(units):
        cid = unit['component_id']; owner = owners[cid]; script = owner['script']
        def command(label, success, preflight=False, receipt_alias=None):
            argv = [args.cmake, f'-DCMAKE_INSTALL_PREFIX={prefix}' if preflight else f'-DINSTALL_PREFIX={prefix}',
                    '-P', owner['preflight'] if preflight else script]
            before = campaign_snapshot(prefix, receipt_alias)
            runner.run(cid + '-' + label, argv, success=success)
            if not success: require(campaign_snapshot(prefix, receipt_alias) == before, 'Refused native owner mutated delivered/user bytes')
        command('immutable-reinstall-refused', False, True)
        for index, name in enumerate(MARKERS):
            marker = prefix / name; marker.parent.mkdir(parents=True, exist_ok=True); marker.write_bytes(b'qualification-presence-marker\n')
            command('managed-root-' + str(index) + '-removal-refused', False)
            command('managed-root-' + str(index) + '-install-refused', False, True)
            marker.unlink()
        receipt = prefix / owner['receipt_name']; receipt_bytes = receipt.read_bytes(); mode = receipt.stat().st_mode & 0o777
        receipt.unlink(); receipt.symlink_to(outside)
        command('aliased-receipt-refused', False, receipt_alias=(receipt, outside))
        require(outside.read_bytes() == b'preserve outside state\n', 'Receipt symlink changed outside state')
        receipt.unlink(); receipt.write_bytes(receipt_bytes); receipt.chmod(mode)
        first = prefix / owner['receipt']['files'][0]['path']; data = first.read_bytes(); mode = first.stat().st_mode & 0o777
        first.write_bytes(data + b'\ncontrolled tamper\n'); first.chmod(mode)
        command('changed-owned-bytes-refused', False)
        first.write_bytes(data); first.chmod(mode)
        require(file_snapshot(prefix) == baseline, 'Refusal fixture restoration differs')
        first.unlink(); command('interrupted-removal-resumed', True)
        expected = {k: v for k, v in baseline.items() if k not in owner['paths']}
        require(file_snapshot(prefix) == expected, 'Removal changed another package or caller state')
        command('absent-removal-idempotent', True); require(file_snapshot(prefix) == expected, 'Retry changed unrelated state')
        command('empty-version-preflight', True, True); require(file_snapshot(prefix) == expected, 'Install preflight mutated prefix')
        restore_files(retained, prefix, owner['paths'])
        require(file_snapshot(prefix) == baseline, 'Exact same-candidate recovery differs')
        checks.append({'component_id': cid, 'version': unit['version'], 'receipt_sha256': owner['receipt_sha256'],
            'configured_helpers': owner['helper_hashes'], 'owned_paths': len(owner['paths']),
            'immutable_reinstall_refused': True, 'managed_root_marker_presence_refused': True,
            'aliased_receipt_refused': True, 'changed_owned_bytes_refused': True,
            'interrupted_removal_resumed': True, 'absent_removal_idempotent': True,
            'empty_version_preflight_passed': True, 'same_candidate_restoration_exact': True,
            'other_package_and_user_bytes_preserved': True, 'native_install_execution_qualified': False,
            'different_version_upgrade_qualified': False, 'rollback_qualified': False, 'live_retirement_qualified': False})
    require(file_snapshot(prefix) == baseline and outside.read_bytes() == b'preserve outside state\n', 'Final disposable state differs')
    return checks


def selected_tools(args):
    # Preserve driver aliases such as clang++; resolving them selects clang and
    # may silently omit its language-specific linker behavior.
    tools = {name: Path(os.path.abspath(getattr(args, name))) for name in ('cmake', 'cc', 'cxx')}
    require(all(p.is_file() for p in tools.values()), 'Explicit owner configuration tools required')
    return tools


def run(args):
    artifacts, source = carrier.safe_root(args.artifacts), carrier.safe_root(args.source)
    cohort_path = artifacts / 'CARRIER-COHORT.json'
    require(file_sha(cohort_path) == carrier.digest(args.cohort_sha256), 'Selected delivered cohort digest differs')
    cohort = document(cohort_path); carrier.check_seal(cohort)
    require(cohort['protocol'] == carrier.PROTOCOL and cohort['state'] == 'archives_audited' and
            cohort['runtime_install_supported'] is False, 'Unselected delivery authority')
    host = carrier.load_module('d09_host', ROOT / 'qualification/host_platform.py')
    require(host.profile_matches(cohort['profile'], host.observe_host()), 'Maintenance requires matching delivered native host')
    units, register, source_files = source_register(source, cohort)
    tools = selected_tools(args)
    for name, path in tools.items(): setattr(args, name, path)
    tool_hashes = {name: sha(path.read_bytes()) for name, path in tools.items()}
    require(all(p.is_absolute() and p.is_file() for p in tools.values()), 'Explicit owner configuration tools required')
    output = carrier.safe_root(args.output, exists=False)
    require(not output.exists() and all(p not in output.parents and output not in p.parents for p in (source, artifacts)), 'New separate disposable output required')
    output.mkdir(mode=0o700); write_json(output / 'maintenance-register.json', {'protocol': PROTOCOL,
        'source_commit': COMMIT, 'source_tree': TREE, 'source_files': source_files, 'units': register,
        'status': 'source_bound_requirements_pending_campaign', 'production_native_maintenance_qualified': False})
    for name in ('home', 'tmp'): (output / name).mkdir(mode=0o700)
    env = {'PATH': str(tools['cmake'].parent) + ':/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(output / 'home'),
        'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'USER': 'builder', 'LOGNAME': 'builder',
        'CMAKE_GENERATOR': 'Unix Makefiles', 'DEVELOPER_DIR': str(Path(args.developer_dir).resolve())}
    helper_paths = ('qualification/d09_maintenance.py', 'qualification/d06_sdk_closure.py',
        'qualification/native_campaign.py', 'installer_assembly/carriers.py', 'recipes/build_go_carriers.py',
        'build-cohort/cohort.json', 'build-cohort/build.py', 'build-cohort/plan.py',
        'qualification/host_platform.py', 'owner-catalog/native_owners.py',
        'recipes/go_generate.py', 'lifecycle/go_delivery.py')
    helper_hashes = {name: file_sha(ROOT / name) for name in helper_paths}
    runner = Runner(output, env, args.timeout)
    try:
        retained, delivered_units, retained_snapshot = materialize(artifacts, cohort, output)
        owners = configure(source, retained, output, units, args, runner)
        results = campaign(retained, output, units, owners, args, runner)
        require(file_snapshot(retained) == retained_snapshot, 'Retained candidate changed')
        require(file_sha(cohort_path) == args.cohort_sha256 and all(file_sha(artifacts / r['filename']) == r['sha256'] for r in cohort['archives']), 'Delivered inputs changed')
        _, _, after_source = source_register(source, cohort); require(after_source == source_files, 'Owner source changed')
        require(tool_hashes == {name: sha(path.read_bytes()) for name, path in tools.items()}, 'Configuration tools changed')
        require(helper_hashes == {name: file_sha(ROOT / name) for name in helper_paths}, 'Qualification helper changed during execution')
        result = {'protocol': PROTOCOL, 'state': 'passed_disposable_unmanaged_prefix_campaign', 'cohort_digest': cohort['cohort_digest'],
            'cohort_sha256': args.cohort_sha256, 'source_commit': COMMIT, 'source_tree': TREE,
            'source_files': source_files, 'helper_sha256': file_sha(Path(__file__)), 'imported_helpers': helper_hashes, 'observed_host': host.observe_host(),
            'configuration_tools': tool_hashes, 'native_unit_count': len(results),
            'units': results, 'logs': runner.logs, 'retained_payload_entry_count': len(retained_snapshot),
            'retained_payload_unchanged': True, 'delivered_archives_unchanged': True,
            'restoration_kind': 'same_exact_candidate_recovery_not_upgrade_or_rollback',
            'processes_or_services_started': False, 'external_runtime_ownership_qualified': False,
            'native_install_execution_qualified': False, 'live_retirement_qualified': False,
            'two_release_upgrade_qualified': False, 'two_release_rollback_qualified': False,
            'fresh_host_accepted': False, 'publisher_trust_accepted': False, 'publication_authorized': False,
            'remaining_blockers': ['51-owner process/use retirement closure', 'independently qualified distinct release per transition',
                'actual side-by-side install and explicit selection/rollback acceptance', 'shared-root authenticated lifecycle qualification',
                'external runtime ownership', 'native primary/fresh-host campaigns']}
        write_json(output / 'result.json', result); return result
    except BaseException as error:
        write_json(output / 'INCOMPLETE.json', {'protocol': PROTOCOL, 'state': 'incomplete', 'reason': str(error),
            'logs': runner.logs, 'publication_authorized': False})
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('artifacts', 'source', 'output', 'cmake', 'cc', 'cxx', 'developer-dir'): p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--cohort-sha256', required=True); p.add_argument('--timeout', type=int, default=180)
    args = p.parse_args()
    try:
        result = run(args); print(json.dumps({'state': result['state'], 'native_unit_count': result['native_unit_count'], 'live_retirement_qualified': False}))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error: p.exit(2, 'Maintenance qualification refused: ' + str(error) + '\n')

if __name__ == '__main__': main()
