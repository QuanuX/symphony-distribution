#!/usr/bin/env python3
"""Rewrap one explicitly selected completed primary carrier capsule.

Only wrappers are rebuilt. Inherited native/source/SDK evidence and all58 opaque
carriers remain unchanged. A separate hosted consumer executes a private checked
copy and removes only the named carriers; neither operation grants acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'installer_assembly'))
import carriers as c
import construct
import review_signing as signing
import supplements
from qualification import d09_platform as platform_gate
from qualification import d10_mac as consumer
from qualification import d10_mac_overlay as source_capture

PROTOCOL = 'symphony.distribution.primary-rewrap.v1'
CONSUMER_PROTOCOL = 'symphony.distribution.primary-rewrap-consumer.v1'
HELPERS = tuple(sorted(set(consumer.HELPERS) | set(platform_gate.CAPSULE_HELPERS) | {
    'qualification/primary_rewrap.py', 'qualification/primary_artifacts.py',
    'qualification/d09_platform_tools.py'}))
FALSE_FLAGS = ('publication_authorized', 'publisher_trust_accepted', 'independent_fresh_host_acceptance',
               'release_acceptance_complete', 'native_runtime_owner_invoked', 'runtime_activation',
               'native_pkg_executed', 'fresh_whole_cohort_build')


def helper_hashes():
    return {name: signing.digest(signing.regular(ROOT / name)) for name in HELPERS}


def records_equal(root, before):
    c.require(tree_inventory(root) == before, 'Selected input files or modes changed')


def tree_inventory(root):
    root = c.safe_root(root)
    rows = []
    for path in sorted(root.rglob('*')):
        info = path.lstat(); name = path.relative_to(root).as_posix(); c.relative(name)
        c.require(not path.is_symlink(), 'Linked retained artifact member refused')
        if path.is_dir():
            rows.append({'path': name, 'mode': stat.S_IMODE(info.st_mode), 'kind': 'directory'})
            continue
        c.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Special or shared retained artifact member refused')
        c.require(info.st_size <= construct.MAX_WRAPPER, 'Unbounded retained artifact member refused')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as stream:
            start = os.fstat(stream.fileno()); hashed = hashlib.sha256(); count = 0
            c.require(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and start.st_size == info.st_size,
                      'Artifact changed before inventory')
            while block := stream.read(1024 * 1024):
                count += len(block); c.require(count <= construct.MAX_WRAPPER, 'Artifact exceeds bound')
                hashed.update(block)
            end = os.fstat(stream.fileno())
        c.require((start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns, start.st_ctime_ns) ==
                  (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns) and count == start.st_size,
                  'Artifact changed during inventory')
        rows.append({'path': name, 'sha256': hashed.hexdigest(), 'size': count, 'mode': stat.S_IMODE(start.st_mode), 'kind': 'file'})
    c.require(any(row['kind'] == 'file' for row in rows), 'Empty retained artifact refused')
    return rows


def copy_tree(source, destination):
    before = tree_inventory(source)
    c.require(not destination.exists(), 'Artifact copy destination must be new')
    destination.mkdir(mode=0o700)
    for row in before:
        if row['kind'] == 'directory':
            path = destination / row['path']; path.mkdir(mode=row['mode'], parents=True, exist_ok=True)
            path.chmod(row['mode']); continue
        raw, mode = c.bounded(source / row['path'])
        c.require(c.sha(raw) == row['sha256'] and len(raw) == row['size'] and mode == row['mode'],
                  'Original artifact changed while copying')
        path = destination / row['path']; path.parent.mkdir(parents=True, exist_ok=True)
        signing.write(path, raw, mode)
    records_equal(source, before); records_equal(destination, before)
    return before


def selected_capsule(root, selection, expected_selection_sha256, proof_path):
    # Import only at execution so the transport implementation remains separately
    # testable; all of its bytes are in the executing helper closure.
    from qualification import primary_artifacts as transport
    transport.verify_transport(root, proof_path, selection, expected_selection_sha256)
    pins = selection['pins']
    record = platform_gate.verify_capsule(root, pins['primary_result_sha256'])
    c.require(record['profile'] == selection['profile'], 'Selected capsule profile differs')
    for key in ('source_commit', 'source_tree', 'source_export_digest', 'source_manifest_sha256',
                'build_result_sha256', 'round_result_sha256', 'sdk_closure_sha256',
                'delivery_record_sha256', 'fresh_host_requirements_sha256', 'cohort_digest'):
        c.require(record[key] == pins[key], 'Explicit capsule evidence selection differs: ' + key)
    c.require(record['original_toolkit_commit'] == selection['workflow_commit'], 'Original build workflow/toolkit identity differs')
    return record


def custody(profile, output):
    host = platform_gate.hosted_custody(profile, output, os.environ)
    job = os.environ.get('GITHUB_JOB', '')
    c.require(re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,99}', job), 'Hosted job identity absent')
    return {'repository': platform_gate.REPOSITORY, 'run_id': os.environ['GITHUB_RUN_ID'],
            'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job': job, 'host': host}


def verify_toolkit(root, expected_helpers, expected_identity):
    index = c.document(root / 'WRAPPER-TOOLKIT-SOURCE.json')
    raw, _ = c.bounded(root / 'WRAPPER-TOOLKIT-SOURCE.tar')
    c.require(set(expected_helpers) == set(HELPERS) and
              index['protocol'] == source_capture.SOURCE and index['privacy_scan'] == 'pass' and
              index['publication_authorized'] is False and index['source'] == expected_identity and
              index['executing_helpers'] == expected_helpers and index['archive_sha256'] == c.sha(raw),
              'New wrapper source/helper binding differs')
    c.require(all(re.fullmatch('[0-9a-f]{40}', expected_identity[k]) for k in ('commit', 'tree')),
              'Exact new wrapper Git identity required')
    supplements.source_tree(raw, expected_identity)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as stream:
        rows = []
        for member in stream:
            data = stream.extractfile(member).read()
            rows.append({'path': member.name, 'sha256': c.sha(data), 'size': len(data), 'mode': member.mode})
        c.require(rows == index['files'], 'New toolkit source inventory differs')
        for name, expected in expected_helpers.items():
            c.require(c.sha(stream.extractfile(name).read()) == c.digest(expected), 'Executing helper missing from selected source')
    return index


def wrapper_selection(cohort, wrapper):
    rows = construct.archive_records(cohort)
    c.require(cohort['profile'] in platform_gate.PROFILES and len(cohort['entries']) == len(rows) == 58,
              'Exactly58 primary inert carriers required')
    c.require(wrapper['protocol'] == construct.SCHEMA and wrapper['state'] == 'unsigned_wrappers_audited' and
              wrapper['profile'] == cohort['profile'] and wrapper['cohort_digest'] == cohort['cohort_digest'] and
              wrapper['archives'] == rows and all(wrapper[k] is False for k in
                  ('publication_authorized', 'release_acceptance_complete', 'runtime_activated')),
              'New wrapper does not preserve selected primary cohort')
    expected_formats = {'pkg', 'sh'} if cohort['profile'] == 'macos15-arm64' else {'sh'}
    c.require(len(wrapper['wrappers']) == len(expected_formats) and
              {r['format'] for r in wrapper['wrappers']} == expected_formats, 'Native wrapper format set differs')
    for row in wrapper['wrappers']:
        c.require(Path(row['filename']).name == row['filename'] and row['filename'].endswith('.' + row['format']) and
                  row['archive_count'] == 58 and type(row['size']) is int and 0 < row['size'] <= construct.MAX_WRAPPER,
                  'Unsafe or mismatched wrapper identity')
        c.digest(row['sha256']); c.digest(row['bootstrap_sha256'])
    return next(r for r in wrapper['wrappers'] if r['format'] == 'sh')


def snapshot_wrapper(selected, row, output):
    """Bounded nofollow read to a private execution copy, never the mutable input."""
    selected = signing.plain(selected)
    destination = output / 'selected-wrapper.sh'
    c.require(type(row['size']) is int and 0 < row['size'] <= construct.MAX_WRAPPER, 'Unbounded wrapper selection')
    c.digest(row['sha256'])
    descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        c.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row['size'],
                  'Execution source shape differs')
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        with os.fdopen(target, 'wb') as copy:
            hashed = hashlib.sha256(); count = 0
            while block := stream.read(min(1024 * 1024, row['size'] + 1 - count)):
                count += len(block); c.require(count <= row['size'], 'Execution source grew while copying')
                hashed.update(block); copy.write(block)
            os.fchmod(copy.fileno(), 0o400)
        after = os.fstat(stream.fileno())
        c.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                  (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                  count == row['size'] and hashed.hexdigest() == row['sha256'], 'Private execution snapshot differs')
    c.require(signing.digest(destination) == row['sha256'], 'Private snapshot changed after copying')
    return destination


def rewrap(args):
    from qualification import primary_artifacts as transport
    selection = transport.validate_selection(args.selection, args.selection_sha256)
    root = c.safe_root(args.artifact)
    record = selected_capsule(root, selection, args.selection_sha256, args.transport_proof)
    host = custody(record['profile'], args.output)
    helpers = helper_hashes(); original = tree_inventory(root)
    selection_raw = c.bounded(args.selection)[0]; proof_raw = c.bounded(args.transport_proof)[0]
    out = platform_gate.fresh(args.output, (root, args.selection, args.transport_proof, args.privacy_policy, ROOT))
    portable = out / 'artifact'; portable.mkdir(mode=0o700)
    copy_tree(root, portable / 'capsule')
    for name, raw in (('selection.json', selection_raw), ('transport-proof.json', proof_raw)):
        signing.write(portable / name, raw, 0o644)
    source = portable / 'wrapper-source'; source.mkdir(mode=0o700)
    source_record = source_capture.toolkit_source(source, args.toolkit_commit, args.privacy_policy, helpers)
    formats = ['pkg', 'sh'] if record['profile'] == 'macos15-arm64' else ['sh']
    wrapped = construct.assemble(portable / 'capsule/carriers', out / 'work', interpreter=args.python,
        standalone=args.standalone, standalone_archive=args.standalone_archive, formats=formats,
        privacy_policy=args.privacy_policy)
    cohort = c.audit_cohort(portable / 'capsule/carriers'); wrapper_selection(cohort, wrapped)
    wrappers = portable / 'wrappers'; wrappers.mkdir(mode=0o700)
    for name in ['result.json'] + [r['filename'] for r in wrapped['wrappers']]:
        # Constructor bounds final files; copying uses an exclusive new inode.
        source_file = signing.regular(out / 'work' / name)
        with source_file.open('rb') as incoming, (wrappers / name).open('xb') as target:
            while block := incoming.read(1024 * 1024): target.write(block)
        (wrappers / name).chmod(0o644)
        c.require(signing.digest(source_file) == signing.digest(wrappers / name), 'Audited wrapper changed during copy')
    records_equal(root, original); records_equal(portable / 'capsule', original)
    c.require(c.bounded(args.selection)[0] == selection_raw and c.bounded(args.transport_proof)[0] == proof_raw and
              helper_hashes() == helpers, 'Selection or executing helpers changed during wrapper assembly')
    verify_toolkit(source, helpers, source_record['source'])
    result = {'protocol': PROTOCOL, 'state': 'inherited_primary_carriers_new_wrappers_audited',
        'profile': record['profile'], 'selection_sha256': args.selection_sha256,
        'transport_proof_sha256': c.sha(proof_raw), 'inherited_primary_result_sha256': selection['pins']['primary_result_sha256'],
        'inherited_original_run': {k: selection[k] for k in ('repository', 'run_id', 'run_attempt', 'workflow_commit')},
        'inherited_capsule_inventory': original, 'inherited_build': record,
        'wrapper_toolkit_source': source_record['source'], 'executing_helpers': helpers,
        'wrapper_source_index_sha256': signing.digest(source / 'WRAPPER-TOOLKIT-SOURCE.json'),
        'wrapper_result_sha256': signing.digest(wrappers / 'result.json'), 'cohort_digest': cohort['cohort_digest'],
        'carrier_archives': cohort['archives'], 'carrier_count': 58, 'carrier_bytes_changed': False,
        'producer': host, 'client_included': False, 'signature_created': False,
        'scope': 'new wrapper assembly only; original native51 and Go6 build/SDK/source evidence inherited unchanged',
        **{key: False for key in FALSE_FLAGS}}
    signing.write(portable / 'result.json', signing.canonical(result), 0o644)
    admit_rewrap(portable, signing.digest(portable / 'result.json'))
    return result


def admit_rewrap(root, expected_result):
    root = c.safe_root(root)
    c.require(signing.digest(root / 'result.json') == c.digest(expected_result), 'Explicit repaired result selection differs')
    result = c.document(root / 'result.json')
    c.require(result['protocol'] == PROTOCOL and result['state'] == 'inherited_primary_carriers_new_wrappers_audited' and
              result['profile'] in platform_gate.PROFILES and result['carrier_count'] == 58 and
              result['carrier_bytes_changed'] is False and result['client_included'] is False and
              result['signature_created'] is False and all(result[k] is False for k in FALSE_FLAGS),
              'Repaired result changes inherited scope or authority')
    from qualification import primary_artifacts as transport
    selection = transport.validate_selection(root / 'selection.json', result['selection_sha256'])
    c.require(signing.digest(root / 'transport-proof.json') == result['transport_proof_sha256'], 'Transport evidence changed')
    record = selected_capsule(root / 'capsule', selection, result['selection_sha256'], root / 'transport-proof.json')
    c.require(record == result['inherited_build'] and result['profile'] == record['profile'] and
              result['inherited_primary_result_sha256'] == selection['pins']['primary_result_sha256'] and
              result['inherited_original_run'] == {k: selection[k] for k in ('repository', 'run_id', 'run_attempt', 'workflow_commit')},
              'Repaired result relabels inherited build')
    records_equal(root / 'capsule', result['inherited_capsule_inventory'])
    source = root / 'wrapper-source'
    c.require(signing.digest(source / 'WRAPPER-TOOLKIT-SOURCE.json') == result['wrapper_source_index_sha256'], 'New wrapper source index changed')
    verify_toolkit(source, result['executing_helpers'], result['wrapper_toolkit_source'])
    c.require(signing.digest(root / 'wrappers/result.json') == result['wrapper_result_sha256'], 'New wrapper audit changed')
    wrapper = c.document(root / 'wrappers/result.json'); cohort = c.audit_cohort(root / 'capsule/carriers')
    row = wrapper_selection(cohort, wrapper)
    c.require(result['carrier_archives'] == cohort['archives'] and result['cohort_digest'] == cohort['cohort_digest'],
              'Repaired carrier byte selection changed')
    c.require({p.name for p in root.iterdir()} == {'capsule', 'wrapper-source', 'wrappers', 'selection.json', 'transport-proof.json', 'result.json'} and
              {p.name for p in source.iterdir()} == {'WRAPPER-TOOLKIT-SOURCE.tar', 'WRAPPER-TOOLKIT-SOURCE.json'} and
              {p.name for p in (root / 'wrappers').iterdir()} == {'result.json'} | {r['filename'] for r in wrapper['wrappers']},
              'Unexpected portable artifact members')
    for item in wrapper['wrappers']:
        path = signing.regular(root / 'wrappers' / item['filename'])
        c.require(path.stat().st_size == item['size'] and signing.digest(path) == item['sha256'], 'New wrapper bytes changed')
    return result, cohort, row


def exercise(execution, row, cohort, expected, output, *, after_install=None):
    env = consumer.isolated_environment(output); env['CONDA_SUBDIR'] = cohort['conda_subdir']
    c.require('CONDA_SOLVER' not in env, 'Installer qualification must use its default explicit-install path')
    home_before = platform_gate.inventory(output / 'home')
    outside = output / 'outside-sentinel'; outside.write_bytes(b'outside caller state\n')
    prefix = output / 'prefix'; logs = []
    logs.append(consumer.invoke(['/bin/bash', execution, '-b', '-p', prefix], env, output / 'install.log'))
    c.require(consumer.carrier_namespace(prefix) == expected, 'Installed carrier bytes or modes differ')
    platform_gate.verify_wrapper_link(prefix, expected)
    names = consumer.installed_metadata(prefix, cohort['archives'])
    bootstrap = signing.regular(prefix / '_conda')
    c.require(signing.digest(bootstrap) == row['bootstrap_sha256'], 'Installed maintenance bootstrap differs')
    if after_install is not None:
        installed_before = platform_gate.inventory(prefix, allow_hardlinks=True)
        after_install(prefix, env)
        c.require(platform_gate.inventory(prefix, allow_hardlinks=True) == installed_before,
                  'Explicit retention probe changed installed prefix')
    auxiliary = platform_gate.inventory(prefix / 'share/symphony/installer')
    (prefix / 'user-state.txt').write_bytes(b'caller state survives removal\n')
    before = platform_gate.inventory(prefix, allow_hardlinks=True)
    for label, flags in (('existing', []), ('force', ['-f']), ('upgrade', ['-u'])):
        logs.append(consumer.invoke(['/bin/bash', execution, '-b', *flags, '-p', prefix], env, output / (label + '.log'), expected=1))
    dangling = output / 'dangling-prefix'; dangling.symlink_to(output / 'absent-target')
    logs.append(consumer.invoke(['/bin/bash', execution, '-b', '-p', dangling], env, output / 'dangling.log', expected=1))
    c.require(dangling.is_symlink() and not (output / 'absent-target').exists() and
              platform_gate.inventory(prefix, allow_hardlinks=True) == before, 'Refusal changed installed or destination state')
    c.require(platform_gate.inventory(output / 'home') == home_before and outside.read_bytes() == b'outside caller state\n',
              'Installation changed caller state')
    logs.append(consumer.invoke([bootstrap, 'remove', '--prefix', prefix, '--offline', '--yes', '--solver', 'classic', *names],
                               env, output / 'remove.log'))
    c.require(consumer.carrier_namespace(prefix) == {} and not list((prefix / 'conda-meta').glob('*.json')),
              'Named removal left carriers or package records')
    c.require((prefix / 'user-state.txt').read_bytes() == b'caller state survives removal\n' and
              outside.read_bytes() == b'outside caller state\n' and platform_gate.inventory(output / 'home') == home_before and
              platform_gate.inventory(prefix / 'share/symphony/installer') == auxiliary and
              signing.digest(bootstrap) == row['bootstrap_sha256'], 'Removal changed caller state or wrapper support files')
    return logs


def inspection_module(publisher, module, distribution):
    path = Path(module.__file__).resolve(strict=True)
    c.require(publisher in path.parents and path.is_file() and path.stat().st_size <= c.LIMIT,
              'Archive decoder loaded outside selected tool prefix')
    return {'version': importlib.metadata.version(distribution), 'module_sha256': platform_gate.sha(path)}


def inspection_runtime(publisher):
    """Identify the executing decoder inside the selected private tool prefix."""
    selected = (publisher / 'bin/python').resolve(strict=True)
    executing = Path(sys.executable).resolve(strict=True)
    c.require(selected == executing and publisher in selected.parents and Path(sys.prefix).resolve() == publisher and
              tuple(sys.version_info[:3]) == (3, 12, 16), 'Consumer must execute selected private Python3.12.16')
    import conda_package_streaming.package_streaming as streaming
    import backports.zstd as codec
    modules = {}
    for label, module, distribution in (
            ('conda_package_streaming', streaming, 'conda-package-streaming'),
            ('backports_zstd', codec, 'backports.zstd'),
            ('backports_zstd_native', codec._zstd, 'backports.zstd')):
        modules[label] = inspection_module(publisher, module, distribution)
    c.require(streaming.zstd is codec, 'Archive reader did not select the expected private codec')
    return {'python': '.'.join(str(n) for n in sys.version_info[:3]), 'executable_sha256': platform_gate.sha(executing),
            'decoder_modules': modules}


def inspection_tools(root, profile):
    root = c.safe_root(root)
    record = c.document(root / 'result.json')
    c.require(record['protocol'] == 'symphony.distribution.d09-publisher-tools.v1' and record['profile'] == profile and
              record['publication_authorized'] is False and record['resolved_transitive_closure_preapproved'] is False and
              record['helper_sha256'] == signing.digest(ROOT / 'qualification/d09_platform_tools.py') and
              record['resolved_tool_closure_sha256'] == signing.digest(root / 'publisher.explicit.txt'),
              'Selected inspection tool record or resolved closure differs')
    publisher = c.safe_root(root / 'publisher')
    runtime = inspection_runtime(publisher)
    return {'tool_record_sha256': signing.digest(root / 'result.json'),
            'resolved_tool_closure_sha256': record['resolved_tool_closure_sha256'],
            'preparation_helper_sha256': record['helper_sha256'], 'profile': profile,
            'runtime': runtime, 'resolved_transitive_closure_preapproved': False,
            'scope': 'private archive inspection only; no native owner or publisher operation'}


def fresh_user(args):
    c.require(args.allow_ephemeral_install is True, 'Explicit ephemeral installer opt-in required')
    root = c.safe_root(args.artifact); result, cohort, row = admit_rewrap(root, args.result_sha256)
    host = custody(result['profile'], args.output)
    c.require((host['run_id'], host['run_attempt'], host['job']) !=
              tuple(result['producer'][key] for key in ('run_id', 'run_attempt', 'job')),
              'Consumer must use a separate disposable hosted job')
    tools = inspection_tools(args.inspection_tools, result['profile'])
    helpers = helper_hashes(); before = tree_inventory(root)
    c.require(helpers == result['executing_helpers'], 'Consumer helpers differ from selected committed wrapper toolkit')
    expected = {}
    for entry in cohort['entries']:
        _, files = c.validate_recipe(root / 'capsule/carriers', entry)
        c.require(not expected.keys() & files.keys(), 'Carrier ownership overlap'); expected.update(files)
    c.require(len(expected) == 174, 'Exact58 carrier file closure required')
    out = platform_gate.fresh(args.output, (root, args.inspection_tools, ROOT))
    execution = snapshot_wrapper(root / 'wrappers' / row['filename'], row, out)
    construct.audit_sh(execution, construct.archive_records(cohort), row['bootstrap_sha256'], [])
    logs = exercise(execution, row, cohort, expected, out)
    records_equal(root, before)
    c.require(admit_rewrap(root, args.result_sha256)[0] == result and signing.digest(execution) == row['sha256'] and
              helper_hashes() == helpers and inspection_tools(args.inspection_tools, result['profile']) == tools,
              'Selected inputs, execution copy, inspection tools or helpers changed during consumer exercise')
    report = {'protocol': CONSUMER_PROTOCOL, 'state': 'primary_shell_install_refusals_and_named_removal_passed',
        'profile': result['profile'], 'observed_custody': host, 'selected_rewrap_result_sha256': args.result_sha256,
        'inherited_primary_result_sha256': result['inherited_primary_result_sha256'],
        'inherited_original_run': result['inherited_original_run'], 'wrapper_toolkit_source': result['wrapper_toolkit_source'],
        'cohort_digest': cohort['cohort_digest'], 'shell_wrapper_sha256': row['sha256'], 'bootstrap_sha256': row['bootstrap_sha256'],
        'private_execution_snapshot_sha256': signing.digest(execution), 'executing_helpers': helpers,
        'inspection_tools': tools, 'logs': logs,
        'carrier_count': 58, 'linked_file_count': 174, 'all_named_carriers_removed': True,
        'fresh_prefix_refusals': ['existing', 'force', 'upgrade', 'dangling'], 'original_artifacts_unchanged': True,
        'caller_state_preserved': True, 'wrapper_support_files_preserved': True, 'account_credentials_supplied': False,
        'cli_route_qualified_by_this_run': False, 'client_qualified': False, 'two_release_upgrade_qualified': False,
        'two_release_rollback_qualified': False, **{key: False for key in FALSE_FLAGS}}
    signing.write(out / 'result.json', signing.canonical(report), 0o644)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    producer = commands.add_parser('rewrap')
    for key in ('selection', 'artifact', 'transport-proof', 'output', 'python', 'standalone', 'standalone-archive', 'privacy-policy'):
        producer.add_argument('--' + key, required=True, type=Path)
    producer.add_argument('--selection-sha256', required=True); producer.add_argument('--toolkit-commit', required=True)
    fresh = commands.add_parser('fresh-user')
    for key in ('artifact', 'output', 'inspection-tools'): fresh.add_argument('--' + key, required=True, type=Path)
    fresh.add_argument('--result-sha256', required=True); fresh.add_argument('--allow-ephemeral-install', action='store_true')
    args = parser.parse_args()
    try:
        result = rewrap(args) if args.command == 'rewrap' else fresh_user(args)
        print(json.dumps({'state': result['state'], 'publication_authorized': False}))
    except BaseException as error:
        output = platform_gate.safe(args.output)
        owned = platform_gate.OWNED_OUTPUTS.get(output)
        info = output.stat() if output.is_dir() else None
        if info and owned == (info.st_dev, info.st_ino) and not (output / 'INCOMPLETE.json').exists():
            signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
                'error_class': type(error).__name__, 'private_logs_retained': True, 'publication_authorized': False}), 0o644)
        raise


if __name__ == '__main__': main()
