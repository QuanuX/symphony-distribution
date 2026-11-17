#!/usr/bin/env python3
"""Prepare an immutable installer input with only qxctl's identity repaired.

The selected D06 records remain unchanged. All native payloads and five other Go
commands are inherited exactly; the replacement qxctl is independently built
twice by the original Git recipe. This is provenance, not installer acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
QXCTL = 'go/qxctl/bin/qxctl'
PROTOCOL = 'symphony.distribution.installer-cohort.v1'
STATE = 'qxctl_identity_replaced_engineering_review_pending'


def require(ok, message):
    if not ok: raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Expected SHA256 is invalid')
    return value


def safe(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked custody path refused')
    return path


def relative(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and name and not path.is_absolute() and str(path) == name and
            '..' not in path.parts and '\\' not in name and not any(ord(c) < 32 for c in name),
            'Unsafe relative evidence path')
    return path


def regular(root, name):
    path = safe(root / relative(name))
    require(path.is_file(), 'Missing or nonregular selected evidence')
    return path


def read(path, expected=None):
    path = safe(path)
    require(path.is_file() and path.stat().st_size <= 32 * 1024 * 1024, 'Unbounded or absent JSON evidence')
    raw = path.read_bytes()
    if expected: require(hashlib.sha256(raw).hexdigest() == digest(expected), 'Selected evidence digest differs')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON key'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def unique(rows, key):
    require(isinstance(rows, list), 'Evidence inventory is not an array')
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), 'Duplicate evidence identity')
    return result


def snapshot(root):
    root = safe(root); require(root.is_dir(), 'Payload root absent')
    rows = []
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix(); relative(name)
        if path.is_symlink():
            link = os.readlink(path)
            require(not Path(link).is_absolute() and root in path.resolve(strict=True).parents,
                    'Payload link escapes selected prefix')
            rows.append({'path': name, 'link': link})
        elif path.is_dir(): continue
        else:
            require(path.is_file(), 'Nonregular payload member')
            rows.append({'path': name, 'sha256': sha(path), 'size': path.stat().st_size,
                         'mode': path.stat().st_mode & 0o777})
    return rows


def no_approval(record, keys):
    require(all(record.get(key) is False for key in keys), 'Unselected approval claim in evidence')


def validate_base(aggregate, round_record, delivery, hashes):
    require(aggregate['protocol'] == 'symphony.distribution.clean-cohort.v1' and
            aggregate['state'] == round_record['state'] == 'built_and_sdk_checked', 'Incomplete D06 cohort')
    require(delivery['protocol'] == 'symphony.distribution.d06-delivery-record.v1' and
            delivery['state'] == 'inventory_complete_publisher_review_pending', 'Incomplete D06 delivery inventory')
    no_approval(aggregate, ('acceptance_complete', 'publication_authorized'))
    no_approval(round_record, ('publication_authorized',))
    no_approval(delivery, ('publication_authorized', 'release_ready', 'fresh_host_accepted'))
    rounds = unique(aggregate['rounds'], 'directory')
    require(rounds['round-1']['result_sha256'] == hashes['round_sha256'] and
            delivery['build_result_sha256'] == hashes['aggregate_sha256'] and
            delivery['round_result_sha256'] == hashes['round_sha256'], 'D06 aggregate/delivery lineage differs')
    require(round_record['native_count'] == rounds['round-1']['native_count'] == 51 and
            len(unique(round_record['native_receipts'], 'component_id')) == 51 and
            len(unique(round_record['go_commands'], 'component_id')) == rounds['round-1']['go_count'] == 6,
            'D06 native/Go count differs')
    require(all(round_record[key]['status'] == 'passed' for key in ('sdk_audit', 'installed_owner_audit', 'loader_audit')),
            'D06 engineering gate incomplete')
    require(round_record['payload_inventory'] == delivery['payload_files'], 'D06 payload inventories differ')
    source = {'commit': aggregate['source_commit'], 'tree': aggregate['source_tree']}
    require(delivery['source_binding'] == source and
            aggregate['source_input']['kind'] == 'verified_reviewed_derived_export' and
            aggregate['source_input']['verified'] is True and
            delivery['source']['mode'] == 'verified_derived_public_export' and
            delivery['source']['matching_build_install_source_prepared'] is True and
            aggregate['source_input']['export_digest'] == delivery['source']['derived_export_digest'],
            'D06 reviewed source identity differs')
    return source


def validate_proof(proof, aggregate, manifest, map_sha256):
    require(proof['protocol'] == 'symphony.distribution.qxctl-original-source.v1' and
            proof['state'] == 'reproducible_stamped_original_git_source' and proof['component_id'] == 'qxctl' and
            proof['isolated_builds'] == 2, 'Original qxctl source proof incomplete')
    no_approval(proof, ('release_acceptance_complete', 'publication_authorized'))
    original = proof['original_source']; info = proof['build_info']; artifact = proof['artifact_identity']
    require(original['commit'] == aggregate['source_commit'] and original['tree'] == aggregate['source_tree'],
            'qxctl original source differs from selected D06 origin')
    require(proof['recipe']['id'] == 'symphony.qxctl.reproducible-build.v1' and proof['recipe']['modified'] is False and
            proof['network_policy'] == 'local_file_proxy_only_no_network_or_VCS_fallback', 'Unselected qxctl recipe/network policy')
    require(info['protocol'] == 'symphony.qxctl.build-info.v1' and info['source_state'] == 'stamped' and
            info['component_id'] == 'qxctl' and info['version'] == '0.1.0-dev' and
            info['source_commit'] == original['commit'] and info['source_tree'] == original['tree'] and
            info['source_date_epoch'] == original['source_date_epoch'] and
            info['build_recipe'] == proof['recipe']['id'] and info['executable_sha256'] == proof['binary_sha256'],
            'qxctl runtime stamp differs from original recipe proof')
    require(artifact['protocol'] == 'symphony.artifact-build-identity.v1' and artifact['isolated_builds'] == 2 and
            artifact['reproducibility'] == 'verified_on_recorded_profile' and artifact['publication_authorized'] is False,
            'Original qxctl repeated-build evidence differs')
    for key in ('component_id', 'version', 'source_commit', 'source_tree', 'source_date_epoch', 'dependency_map_sha256',
                'build_recipe', 'go_version', 'goos', 'goarch', 'executable_sha256'):
        require(artifact[key] == info[key], 'Original qxctl artifact/runtime field differs')
    require(info['go_version'] == 'go1.26.5' and info['goarch'] == aggregate['host']['architecture'] and
            info['goos'] == {'macos': 'darwin', 'linux': 'linux'}[aggregate['host']['os']], 'qxctl target differs from D06 native host')
    cohort = proof['cohort_source']; export_digest = aggregate['source_input']['export_digest']
    require(cohort['kind'] == 'verified_reviewed_derived_export' and cohort['is_original_git_tree'] is False and
            cohort['export_digest'] == export_digest == manifest['derived_export_digest'] and
            cohort['archive_sha256'] == aggregate['source_input']['archive_sha256'], 'qxctl reviewed cohort source differs')
    require(manifest['protocol'] == 'symphony.public-source-export.v2' and manifest['is_original_git_tree'] is False and
            manifest['origin_commit'] == original['commit'] and manifest['origin_tree'] == original['tree'], 'Reviewed export provenance differs')
    no_approval(manifest, ('release_acceptance_complete', 'publication_authorized'))
    entries = unique(manifest['source_files'], 'path')
    canonical_rows = [{'path': row['path'], 'mode': row['mode'], 'sha256': row['export_sha256']} for row in manifest['source_files']]
    require(canonical_rows == sorted(canonical_rows, key=lambda row: row['path']) and
            hashlib.sha256(canonical(canonical_rows)).hexdigest() == export_digest, 'Reviewed export digest differs')
    require(entries['cmake/mvp-dependencies.json']['export_sha256'] == map_sha256, 'Derived dependency map differs')
    require(entries['cmake/mvp-dependencies.json']['source_sha256'] == info['dependency_map_sha256'],
            'Stamped original dependency map differs from export provenance')
    recipe_entry = entries['tools/qxctl/tests/reproducible_build.cmake']
    require(recipe_entry['source_sha256'] == recipe_entry['export_sha256'] == proof['recipe']['sha256'],
            'Original recipe differs from reviewed source provenance')
    for name, field in (('go.mod', 'go_mod_sha256'), ('go.sum', 'go_sum_sha256')):
        entry = entries['tools/qxctl/' + name]
        require(entry['source_sha256'] == entry['export_sha256'] == artifact[field], 'qxctl module manifest provenance differs')
    closure = proof['compiled_input_equivalence']; files = closure['inputs']; unique(files, 'path')
    require(closure['method'] == 'native_go_list_deps_compiled_json_CGO0' and closure['original_matches_cohort_source'] is True and
            closure['goos'] == info['goos'] and closure['goarch'] == info['goarch'] and files and
            hashlib.sha256(canonical(files)).hexdigest() == closure['inventory_sha256'], 'qxctl compiled-input proof differs')
    for row in files:
        require(row['path'].startswith('tools/qxctl/') and row['path'] in entries, 'Unselected qxctl compiled input')
        exported = entries[row['path']]
        require(row['sha256'] == exported['source_sha256'] == exported['export_sha256'] and
                row['size'] == exported['source_size'] == exported['export_size'] and
                row['mode'] == (0o755 if exported['mode'] == '100755' else 0o644), 'Compiled input differs from original/public source')
    privacy = proof['privacy']
    require(privacy['private_build_paths_absent'] is True and privacy['publisher_policy_scanned'] is True and
            privacy['policy_digest'] == manifest['privacy_policy_digest'] and
            privacy['private_original_fixture_archive_distributable'] is False, 'qxctl source/payload privacy gate differs')


def only_qxctl_changed(before, after, expected_sha256):
    before, after = unique(before, 'path'), unique(after, 'path')
    require(before.keys() == after.keys(), 'Installer cohort payload membership changed')
    require(all(row == after[path] for path, row in before.items() if path != QXCTL),
            'Unselected payload changed during qxctl-only replacement')
    require(QXCTL in after and after[QXCTL].get('sha256') == expected_sha256 and
            after[QXCTL].get('mode') == before[QXCTL].get('mode') and after[QXCTL]['mode'] & 0o111,
            'Replacement qxctl bytes/mode differ')


def validate_record(record, aggregate, round_record, delivery, proof, manifest, mapping):
    require(record['protocol'] == PROTOCOL and record['state'] == STATE and record['payload_directory'] == 'prefix',
            'Unselected installer cohort protocol/state')
    no_approval(record, ('publication_authorized', 'release_acceptance_complete', 'fresh_host_accepted', 'installer_accepted'))
    source = validate_base(aggregate, round_record, delivery, record['base_d06'])
    require(record['source_binding'] == source and record['host'] == aggregate['host'] and
            record['derived_source_export_digest'] == aggregate['source_input']['export_digest'], 'Installer source/host binding differs')
    validate_proof(proof, aggregate, manifest, mapping)
    only_qxctl_changed(round_record['payload_inventory'], record['payload_inventory'], proof['binary_sha256'])
    require(record['native_receipts'] == round_record['native_receipts'] and
            record['inherited_native_count'] == 51 and record['inherited_go_count'] == 5 and
            record['new_qxctl_isolated_builds'] == 2, 'Inherited/rebuilt provenance counts differ')
    old = unique(round_record['go_commands'], 'component_id'); new = unique(record['go_commands'], 'component_id')
    require(old.keys() == new.keys() and all(old[c] == new[c] for c in old if c != 'qxctl'), 'Unselected Go command provenance changed')
    expected = {**old['qxctl'], 'sha256': proof['binary_sha256'],
                'qxctl_source_proof_sha256': record['qxctl_source_proof_sha256'],
                'source_kind': 'original_git_recipe_with_equal_cohort_compiled_inputs'}
    require(new['qxctl'] == expected, 'Replacement Go identity row differs')
    require(record['qxctl_original_git_override'] == {
        'component_id': 'qxctl', 'previous_sha256': old['qxctl']['sha256'], 'sha256': proof['binary_sha256'],
        'source_commit': proof['original_source']['commit'], 'source_tree': proof['original_source']['tree'],
        'dependency_map_sha256': proof['build_info']['dependency_map_sha256'],
        'recipe': proof['recipe']['id'], 'cohort_compiled_inputs_equal': True}, 'Original Git component override differs')


def verify_cohort(root, expected_sha256=None):
    """Read-only exact evidence/payload verification; caller pins cohort.json."""
    root = safe(root)
    record = read(root / 'cohort.json', expected_sha256)
    paths = {'aggregate': 'base-result.json', 'round': 'base-round.json', 'delivery': 'base-delivery.json',
             'proof': 'qxctl-source-proof.json', 'manifest': 'source-export.json'}
    hashes = {'aggregate': record['base_d06']['aggregate_sha256'], 'round': record['base_d06']['round_sha256'],
              'delivery': record['base_d06']['delivery_sha256'], 'proof': record['qxctl_source_proof_sha256'],
              'manifest': record['source_export_manifest_sha256']}
    documents = {key: read(root / 'evidence' / path, hashes[key]) for key, path in paths.items()}
    mapping = regular(root, 'evidence/mvp-dependencies.json')
    require(sha(mapping) == record['dependency_map_sha256'], 'Copied dependency map differs')
    validate_record(record, documents['aggregate'], documents['round'], documents['delivery'], documents['proof'],
                    documents['manifest'], sha(mapping))
    require(snapshot(root / 'prefix') == record['payload_inventory'], 'Installer cohort payload changed')
    inventory = unique(record['payload_inventory'], 'path')
    for row in record['native_receipts']:
        name = 'share/symphony/receipts/' + row['component_id'] + '/' + row['version'] + '/install-receipt.json'
        require(inventory[name]['sha256'] == row['receipt_sha256'], 'Inherited native receipt changed')
    expected_files = set(paths.values()) | {'mvp-dependencies.json'}
    for row in documents['delivery']['notices']:
        path = regular(root / 'evidence', row['path'])
        require(sha(path) == row['sha256'] and path.stat().st_size == row['size'], 'Retained legal notice differs')
        expected_files.add(row['path'])
    actual_files = set()
    for path in (root / 'evidence').rglob('*'):
        require(not path.is_symlink(), 'Linked installer evidence refused')
        if path.is_dir(): continue
        require(path.is_file(), 'Nonregular installer evidence')
        actual_files.add(path.relative_to(root / 'evidence').as_posix())
    require(actual_files == expected_files, 'Installer evidence membership differs')
    require({p.name for p in root.iterdir()} == {'prefix', 'evidence', 'cohort.json'}, 'Extra installer cohort root material')
    return record


def prepare_cohort(base_root, base_delivery, qxctl_proof_root, export, output, *,
                   expected_base_result_sha256, expected_round_result_sha256,
                   expected_delivery_sha256, expected_qxctl_proof_sha256):
    base_root, base_delivery, qxctl_proof_root, export = (safe(p) for p in (base_root, base_delivery, qxctl_proof_root, export))
    hashes = {'aggregate_sha256': digest(expected_base_result_sha256), 'round_sha256': digest(expected_round_result_sha256),
              'delivery_sha256': digest(expected_delivery_sha256)}
    aggregate = read(base_root / 'result.json', hashes['aggregate_sha256'])
    round_record = read(base_root / 'round-1/result.json', hashes['round_sha256'])
    delivery = read(base_delivery, hashes['delivery_sha256'])
    proof = read(qxctl_proof_root / 'result.json', expected_qxctl_proof_sha256)
    manifest = read(export / 'SOURCE-EXPORT.json')
    mapping = regular(export, 'source/cmake/mvp-dependencies.json')
    source = validate_base(aggregate, round_record, delivery, hashes)
    validate_proof(proof, aggregate, manifest, sha(mapping))
    original_prefix = safe(base_root / 'round-1/relocated-prefix')
    require(snapshot(original_prefix) == round_record['payload_inventory'], 'Retained D06 bytes changed')
    replacement = regular(qxctl_proof_root, proof['binary'])
    require(sha(replacement) == proof['binary_sha256'], 'Selected replacement binary changed')
    # Independently verify every original/derived compiled file and manifest,
    # not only the proof's JSON declarations. No original private fixture copied.
    rows = unique(manifest['source_files'], 'path')
    actual_source = snapshot(export / 'source')
    require({row['path'] for row in actual_source} == rows.keys(), 'Reviewed export membership changed')
    for row in actual_source:
        expected = rows[row['path']]
        require(row.get('sha256') == expected['export_sha256'] and row.get('size') == expected['export_size'] and
                row.get('mode') == (0o755 if expected['mode'] == '100755' else 0o644), 'Reviewed source bytes/modes changed')
    output = safe(output)
    require(not output.exists() and output.parent.is_dir(), 'Installer cohort output must be new')
    inputs = [base_root, base_delivery.parent, qxctl_proof_root, export, ROOT]
    require(all(output != p and output not in p.parents and p not in output.parents for p in inputs), 'Installer cohort output overlaps input')
    output.mkdir(mode=0o700)
    prefix, evidence = output / 'prefix', output / 'evidence'; evidence.mkdir(mode=0o700)
    shutil.copytree(original_prefix, prefix, symlinks=True, copy_function=shutil.copy2)
    for row in round_record['payload_inventory']:
        if 'link' in row: continue
        before, after = original_prefix / row['path'], prefix / row['path']
        require((before.stat().st_dev, before.stat().st_ino) != (after.stat().st_dev, after.stat().st_ino), 'Payload copy aliases original inode')
    old_mode = (prefix / QXCTL).stat().st_mode & 0o777
    shutil.copyfile(replacement, prefix / QXCTL); (prefix / QXCTL).chmod(old_mode)
    payload = snapshot(prefix); only_qxctl_changed(round_record['payload_inventory'], payload, proof['binary_sha256'])
    for source_path, name in ((base_root / 'result.json', 'base-result.json'),
                              (base_root / 'round-1/result.json', 'base-round.json'),
                              (base_delivery, 'base-delivery.json'), (qxctl_proof_root / 'result.json', 'qxctl-source-proof.json'),
                              (export / 'SOURCE-EXPORT.json', 'source-export.json'), (mapping, 'mvp-dependencies.json')):
        shutil.copyfile(source_path, evidence / name)
    for row in delivery['notices']:
        original = regular(base_delivery.parent, row['path'])
        require(sha(original) == row['sha256'] and original.stat().st_size == row['size'], 'Original legal notice differs')
        target = evidence / relative(row['path']); target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists(), 'Duplicate notice/evidence destination')
        shutil.copyfile(original, target)
    go = []
    old_qxctl = next(row for row in round_record['go_commands'] if row['component_id'] == 'qxctl')
    for row in round_record['go_commands']:
        go.append({**row, 'sha256': proof['binary_sha256'], 'qxctl_source_proof_sha256': expected_qxctl_proof_sha256,
                   'source_kind': 'original_git_recipe_with_equal_cohort_compiled_inputs'} if row['component_id'] == 'qxctl' else row)
    record = {'protocol': PROTOCOL, 'state': STATE, 'helper_sha256': sha(__file__), 'base_d06': hashes,
              'qxctl_source_proof_sha256': expected_qxctl_proof_sha256, 'source_binding': source,
              'derived_source_export_digest': manifest['derived_export_digest'],
              'source_export_manifest_sha256': sha(export / 'SOURCE-EXPORT.json'), 'dependency_map_sha256': sha(mapping),
              'host': aggregate['host'], 'payload_directory': 'prefix', 'payload_inventory': payload,
              'native_receipts': round_record['native_receipts'], 'go_commands': go,
              'inherited_native_count': 51, 'inherited_go_count': 5, 'new_qxctl_isolated_builds': 2,
              'qxctl_original_git_override': {'component_id': 'qxctl', 'previous_sha256': old_qxctl['sha256'],
                  'sha256': proof['binary_sha256'], 'source_commit': proof['original_source']['commit'],
                  'source_tree': proof['original_source']['tree'], 'dependency_map_sha256': proof['build_info']['dependency_map_sha256'],
                  'recipe': proof['recipe']['id'], 'cohort_compiled_inputs_equal': True},
              'publication_authorized': False, 'release_acceptance_complete': False,
              'fresh_host_accepted': False, 'installer_accepted': False,
              'limitations': ['D06 inherited qualification applies to its original bytes and scope.',
                  'Only qxctl was rebuilt; this is not a new full cohort build.',
                  'Original Git qxctl stamp does not label the derived whole-source export as original.',
                  'Publisher authentication and native installer lifecycle acceptance remain separate.']}
    (output / 'cohort.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    verify_cohort(output, sha(output / 'cohort.json'))
    require(snapshot(original_prefix) == round_record['payload_inventory'] and sha(replacement) == proof['binary_sha256'],
            'Original or replacement source bytes changed during assembly')
    for path, expected in ((base_root / 'result.json', hashes['aggregate_sha256']),
                           (base_root / 'round-1/result.json', hashes['round_sha256']),
                           (base_delivery, hashes['delivery_sha256']),
                           (qxctl_proof_root / 'result.json', expected_qxctl_proof_sha256)):
        require(sha(path) == expected, 'Selected input evidence changed during assembly')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    make = sub.add_parser('prepare')
    for name in ('base-root', 'base-delivery', 'qxctl-proof-root', 'export', 'output'):
        make.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-base-result-sha256', 'expected-round-result-sha256', 'expected-delivery-sha256', 'expected-qxctl-proof-sha256'):
        make.add_argument('--' + name, required=True)
    check = sub.add_parser('verify'); check.add_argument('--root', type=Path, required=True)
    check.add_argument('--expected-sha256')
    args = vars(parser.parse_args()); command = args.pop('command')
    record = prepare_cohort(**args) if command == 'prepare' else verify_cohort(**args)
    print(json.dumps({'state': record['state'], 'files': len(record['payload_inventory']), 'publication_authorized': False}))


if __name__ == '__main__': main()
