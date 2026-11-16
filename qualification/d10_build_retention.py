#!/usr/bin/env python3
"""Retain completed primary native bytes before later packaging can fail.

The capsule retains one complete final payload and the two original build
reports. It is engineering custody, not a delivery, approval, or new build.
No general build caches, original private source archives, or policy enter it.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib

import d09_platform as platform_gate
import d06_delivery_record as delivery

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = 'symphony.distribution.native-build-retention.v1'
ARCHIVE = 'native-cohort.tar.gz'
LIMIT_FILES = 25000
LIMIT_FILE = 512 * 1024 * 1024
LIMIT_TOTAL = 4 * 1024 * 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def sha(path):
    return delivery.sha(Path(path))


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Invalid selected digest')
    return value


def safe(path):
    result = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (result, *result.parents)), 'Linked custody path refused')
    return result


def relative(name):
    value = PurePosixPath(name)
    require(name and not value.is_absolute() and str(value) == name and
            '..' not in value.parts and '\\' not in name and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), 'Unsafe capsule member')
    return value


def fresh(path, inputs):
    path = safe(path)
    require(not os.path.lexists(path) and path.parent.is_dir(), 'Output must be new with an existing parent')
    require(all(path != p and path not in p.parents and p not in path.parents for p in inputs), 'Custody output overlaps input')
    path.mkdir(mode=0o700)
    return path


def scanner(policy):
    policy = safe(policy)
    require(policy.is_file() and policy.stat().st_mode & 0o777 == 0o600, 'Private policy must be a regular 0600 file')
    result = platform_gate.module('native_retention_scanner', 'source-export/export_source.py')
    result.configure_policy(policy)
    return result


def producer_record(run_id, run_attempt, commit):
    require(re.fullmatch('[1-9][0-9]{0,19}', str(run_id)) and
            re.fullmatch('[1-9][0-9]{0,5}', str(run_attempt)) and
            re.fullmatch('[0-9a-f]{40}', commit), 'Exact hosted producer identity required')
    return {'repository': 'QuanuX/symphony-distribution', 'run_id': str(run_id),
            'run_attempt': str(run_attempt), 'commit': commit,
            'authentication_scope': 'caller selected hosted provenance; consumer must independently select artifact API identity'}


def verify_producer_source(producer, aggregate):
    """The hosted identity must name the actual immutable selected builders."""
    environment = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    def git(*arguments):
        return subprocess.check_output(['git', '--no-replace-objects', '-C', str(ROOT), *arguments],
            env=environment, stderr=subprocess.PIPE, timeout=30)
    require(git('rev-parse', 'HEAD').decode().strip() == producer['commit'], 'Producer commit differs from selected checkout')
    selected = {**delivery.selected_helpers(aggregate), 'build-cohort/cohort.json': aggregate['plan_sha256'],
                'source-binding.json': sha(ROOT / 'source-binding.json'),
                'qualification/d10_build_retention.py': sha(__file__)}
    for name, expected in selected.items():
        require(hashlib.sha256(git('show', producer['commit'] + ':' + name)).hexdigest() == expected,
                'Producer Git source differs from selected helper: ' + name)


def inspect_completed(cohort, export, repository, privacy):
    """Validate both original final stages before selecting one for retention."""
    aggregate = delivery.read_json(delivery.regular(cohort, 'result.json'))
    profile = aggregate['host']['requested_profile']
    platform_gate.primary_build(aggregate, profile)
    require(aggregate['protocol'] == 'symphony.distribution.clean-cohort.v1' and
            not aggregate.get('repair_provenance'), 'Only completed primary whole-cohort builds may enter this capsule')
    plan_file = ROOT / 'build-cohort/cohort.json'
    plan = delivery.read_json(plan_file)
    require(sha(plan_file) == aggregate['plan_sha256'] and
            all(aggregate['source_' + key] == plan['source_' + key] for key in ('commit', 'tree')),
            'Frozen source/plan binding differs')
    delivery.verify_selected_helpers(delivery.selected_helpers(aggregate))
    export_proof = privacy.verify(export, repository)
    require(all(aggregate['source_input'][key] == export_proof[key] for key in ('export_digest', 'archive_sha256')),
            'Reviewed source selection differs')
    manifest = delivery.read_json(delivery.regular(export, 'SOURCE-EXPORT.json'))
    source_rows = [{'path': r['path'], 'sha256': r['export_sha256'], 'size': r['export_size'],
                    'mode': 0o755 if r['mode'] == '100755' else 0o644} for r in manifest['source_files']]
    delivery.verify_inventory(cohort / 'source', source_rows)
    units = plan['profiles'][profile]['native_build_order']
    require(len(units) == 51, 'Full native owner cohort required')
    sys.path.insert(0, str(ROOT / 'build-cohort'))
    import build as builder
    rounds = []
    for number in (1, 2):
        name = 'round-' + str(number)
        reference = next(r for r in aggregate['rounds'] if r['directory'] == name)
        record_path = delivery.regular(cohort, name + '/result.json')
        require(sha(record_path) == reference['result_sha256'] and
                reference['native_count'] == 51 and reference['go_count'] == 6, 'Completed round identity differs')
        record = delivery.read_json(record_path)
        require(record['state'] == 'built_and_sdk_checked' and record['native_count'] == 51 and
                len(record['go_commands']) == 6 and record['publication_authorized'] is False and
                all(record[key]['status'] == 'passed' for key in ('sdk_audit', 'installed_owner_audit', 'loader_audit')),
                'Completed round audits/counts differ')
        prefix = cohort / name / 'relocated-prefix'
        delivery.verify_inventory(prefix, record['payload_inventory'])
        require(builder.verify_receipts(prefix, units) == record['native_receipts'], 'Native ownership receipts differ')
        qxctl = [r for r in record['go_commands'] if r['component_id'] == 'qxctl']
        require(len(qxctl) == 1, 'Exactly one qxctl source identity required')
        delivery.go_build_provenance('qxctl', qxctl[0], aggregate, {'repair_provenance': None},
            cohort / name, cohort / 'source', prefix / 'go/qxctl/bin/qxctl', manifest)
        rounds.append(record)
    require(rounds[0]['payload_inventory'] == rounds[1]['payload_inventory'], 'Two actual final payload inventories differ')
    return aggregate, rounds, manifest, units


def select_files(cohort, export, external_report, aggregate, rounds, manifest, units):
    """Closed file selection, independent of unrelated files in a build root."""
    selected = {}
    def add(name, path):
        relative(name)
        require(name not in selected, 'Duplicate selected capsule path')
        selected[name] = Path(path)
    add('cohort/result.json', cohort / 'result.json')
    for number in (1, 2):
        add(f'cohort/round-{number}/result.json', cohort / f'round-{number}/result.json')
    for row in manifest['source_files']:
        add('cohort/source/' + row['path'], cohort / 'source' / relative(row['path']))
    for name in ('SOURCE-EXPORT.json', 'symphony-source.tar'):
        add('export/' + name, export / name)
    for row in rounds[0]['payload_inventory']:
        add('cohort/round-1/relocated-prefix/' + row['path'], cohort / 'round-1/relocated-prefix' / relative(row['path']))
    log_rows = {r['name']: r for r in rounds[0]['logs']}
    for unit in units:
        name = unit['component_id'] + '-configure.log'
        path = delivery.regular(cohort / 'round-1/logs', name)
        require(log_rows[name]['exit_code'] == 0 and sha(path) == log_rows[name]['sha256'], 'Configure provenance changed')
        add('cohort/round-1/logs/' + name, path)
    proof_root = cohort / 'round-1/qxctl-identity'
    proof = delivery.read_json(proof_root / 'result.json')
    names = ['result.json', 'recipe/artifact-identity.json', 'recipe/first-build-info.json', 'recipe/second-build-info.json',
             'recipe/first/bin/qxctl', 'recipe/second/bin/qxctl']
    names += ['recipe/first/' + r['path'] for r in proof['compiled_input_equivalence']['inputs']]
    for name in names:
        add('cohort/round-1/qxctl-identity/' + name, delivery.regular(proof_root, name))
    for name in sorted(set(delivery.selected_helpers(aggregate)) | {'build-cohort/cohort.json', 'source-binding.json'}):
        add('toolkit/' + name, delivery.regular(ROOT, name))
    require(sha(external_report) == aggregate['external_evidence_sha256'], 'Exact external build report differs')
    add('external/external-build.json', external_report)
    return selected


def validate_payload_links(rows):
    """Admit exact recorded file-link chains, never directories or new paths."""
    expected = {r['path']: r for r in rows}
    require(len(expected) == len(rows), 'Duplicate link inventory membership')
    namespace = 'cohort/round-1/relocated-prefix/'
    link_count = sum('link' in r for r in rows)
    for row in rows:
        if 'link' not in row:
            continue
        current, visited = row['path'], set()
        for _ in range(link_count + 1):
            require(current.startswith(namespace) and current in expected, 'Escaping or dangling payload link chain')
            require(current not in visited, 'Cyclic payload link chain')
            visited.add(current)
            selected = expected[current]
            if 'link' not in selected:
                require(set(selected) == {'path', 'sha256', 'size', 'mode'}, 'Payload link target must be a selected regular file')
                break
            link = selected['link']
            require(isinstance(link, str) and link and not PurePosixPath(link).is_absolute() and
                    '\\' not in link and not any(ord(c) < 32 or ord(c) == 127 for c in link),
                    'Unsafe payload link target')
            current = os.path.normpath((PurePosixPath(current).parent / link).as_posix())
        else:
            raise ValueError('Payload link chain exceeds selected membership bound')


def file_inventory(selected, privacy):
    require(0 < len(selected) <= LIMIT_FILES, 'Capsule membership exceeds bound')
    rows, total = [], 0
    for name, path in sorted(selected.items()):
        relative(name)
        if path.is_symlink():
            require(name.startswith('cohort/round-1/relocated-prefix/'), 'Only selected final-payload links may be retained')
            safe(path.parent)
            link = os.readlink(path)
            privacy.scan(name, link.encode())
            rows.append({'path': name, 'link': link})
        else:
            safe(path)
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= LIMIT_FILE,
                    'Nonregular, aliased, or oversized selected file')
            require(info.st_mode & 0o777 in (0o600, 0o644, 0o755), 'Unexpected selected file mode')
            raw = path.read_bytes()
            if name.startswith('toolkit/'):
                delivery.scan_toolkit_source(privacy, name.removeprefix('toolkit/'), raw)
            else:
                privacy.scan(name, raw)
            total += len(raw)
            rows.append({'path': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                         'mode': info.st_mode & 0o777})
    require(total <= LIMIT_TOTAL, 'Capsule uncompressed size exceeds bound')
    validate_payload_links(rows)
    return rows


def write_tar(stream, rows, selected):
    with tarfile.open(fileobj=stream, mode='w|', format=tarfile.PAX_FORMAT) as bundle:
        for row in rows:
            info = tarfile.TarInfo(row['path'])
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            if 'link' in row:
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, row['link'], 0o777
                bundle.addfile(info)
            else:
                info.size, info.mode = row['size'], row['mode']
                with selected[row['path']].open('rb') as source:
                    bundle.addfile(info, source)


def write_archive(path, rows, selected):
    with Path(path).open('xb') as output, gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
        write_tar(compressed, rows, selected)


def uncompressed_digest(path):
    """Require one bounded gzip member; reject ignored bytes after its EOF."""
    result, total = hashlib.sha256(), 0
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    with Path(path).open('rb') as stream:
        header = stream.read(10)
        require(header[:8] == b'\x1f\x8b\x08\x00\x00\x00\x00\x00' and
                header[8] in (0, 2, 4) and header[9] == 255, 'Nonneutral gzip metadata')
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            require(not decompressor.eof, 'Noncanonical gzip trailer or concatenated stream')
            pending = chunk
            while pending:
                raw = decompressor.decompress(pending, 1024 * 1024)
                total += len(raw); result.update(raw)
                require(total <= LIMIT_TOTAL + LIMIT_FILES * 4096, 'Expanded archive exceeds bound')
                require(not decompressor.unused_data, 'Noncanonical gzip trailer or concatenated stream')
                pending = decompressor.unconsumed_tail
        require(decompressor.eof, 'Truncated gzip archive')
    return result.hexdigest()


def validate_members(bundle, rows):
    require(0 < len(rows) <= LIMIT_FILES and sum(r.get('size', 0) for r in rows) <= LIMIT_TOTAL,
            'Capsule size/membership exceeds bound')
    expected = {r['path']: r for r in rows}
    require(len(expected) == len(rows) and rows == sorted(rows, key=lambda r: r['path']), 'Noncanonical capsule inventory')
    validate_payload_links(rows)
    seen = set()
    for member in bundle:
        relative(member.name)
        require(member.name in expected and member.name not in seen, 'Unexpected or duplicate archive member')
        seen.add(member.name)
        row = expected[member.name]
        require(member.uid == member.gid == member.mtime == member.devmajor == member.devminor == 0 and
                member.uname == member.gname == '', 'Publisher metadata in archive header')
        require(all((k == 'path' and v == member.name) or (k == 'linkpath' and v == member.linkname)
                    for k, v in member.pax_headers.items()), 'Unselected extended archive metadata')
        if 'link' in row:
            require(member.issym() and member.size == 0 and member.mode == 0o777 and
                    member.linkname == row['link'] and not Path(row['link']).is_absolute() and
                    member.name.startswith('cohort/round-1/relocated-prefix/'), 'Unselected or escaping archive link')
        else:
            require(member.isfile() and member.mode == row['mode'] and member.size == row['size'] and
                    0 <= member.size <= LIMIT_FILE and member.mode in (0o600, 0o644, 0o755), 'Archive file shape differs')
            require(hashlib.sha256(bundle.extractfile(member).read()).hexdigest() == digest(row['sha256']), 'Archive bytes differ')
        # No real member can serve as a directory, even if ordered later.
        require(not any(str(p) in expected for p in PurePosixPath(member.name).parents if str(p) != '.'),
                'Archive parent/file collision')
    require(seen == set(expected), 'Archive membership incomplete')


def retain(cohort, export, repository, external_report, privacy_policy, output, *, producer):
    cohort, export, repository, external_report = map(safe, (cohort, export, repository, external_report))
    require(producer == producer_record(producer['run_id'], producer['run_attempt'], producer['commit']), 'Invalid producer record')
    privacy = scanner(privacy_policy)
    aggregate, rounds, manifest, units = inspect_completed(cohort, export, repository, privacy)
    verify_producer_source(producer, aggregate)
    selected = select_files(cohort, export, external_report, aggregate, rounds, manifest, units)
    rows = file_inventory(selected, privacy)
    output = fresh(output, [cohort, export, repository, external_report, safe(privacy_policy), ROOT])
    archive = output / ARCHIVE
    write_archive(archive, rows, selected)
    with tarfile.open(archive, 'r:gz') as bundle:
        validate_members(bundle, rows)
    require(file_inventory(selected, privacy) == rows, 'Selected inputs changed during retention')
    report = {'protocol': PROTOCOL, 'state': 'complete_primary_native_bytes_retained',
        'profile': aggregate['host']['requested_profile'], 'producer': producer,
        'source_commit': aggregate['source_commit'], 'source_tree': aggregate['source_tree'],
        'source_export_digest': aggregate['source_input']['export_digest'],
        'source_manifest_sha256': sha(export / 'SOURCE-EXPORT.json'),
        'aggregate_sha256': sha(cohort / 'result.json'),
        'round_sha256': {r['directory']: r['result_sha256'] for r in aggregate['rounds']},
        'selected_payload_round': 'round-1', 'both_original_payloads_verified': True,
        'second_round_payload_retained': False, 'native_count': 51, 'go_count': 6,
        'payload_inventory_sha256': hashlib.sha256(canonical(rounds[0]['payload_inventory'])).hexdigest(),
        'privacy_policy_digest': privacy.POLICY_DIGEST, 'privacy_scan': 'passed_all_selected_bytes_and_paths',
        'helper_sha256': sha(__file__), 'archive': {'path': ARCHIVE, 'sha256': sha(archive), 'size': archive.stat().st_size},
        'files': rows, 'inventory_sha256': hashlib.sha256(canonical(rows)).hexdigest(),
        'omitted': ['duplicate round-2 payload', 'general build and process logs', 'Go and compiler caches',
                    'private original Git source fixture archives', 'publisher tooling binaries', 'private policy and credentials'],
        'reuse_requirements': ['independently authenticate producer run and artifact API digest',
                              'exact matching primary host and frozen helper identities',
                              'prepare exact public Go dependencies and external source archives again',
                              'complete delivery collection, supplemental SDK closure and wrapper qualification'],
        'publication_authorized': False, 'release_acceptance_complete': False, 'wrapper_qualified': False}
    raw = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
    privacy.scan('capsule.json', raw)
    with (output / 'capsule.json').open('xb') as stream:
        stream.write(raw)
    return report


def restore(capsule_root, output, expected_capsule_sha256, expected_archive_sha256, privacy_policy):
    """Restore exact retained inputs; rechecking downstream gates remains mandatory."""
    capsule_root = safe(capsule_root)
    report_file = delivery.regular(capsule_root, 'capsule.json')
    require(sha(report_file) == digest(expected_capsule_sha256), 'Independently selected capsule differs')
    report = delivery.read_json(report_file)
    require(report['protocol'] == PROTOCOL and report['state'] == 'complete_primary_native_bytes_retained' and
            report['profile'] in platform_gate.PROFILES and report['selected_payload_round'] == 'round-1' and
            report['both_original_payloads_verified'] is True and report['second_round_payload_retained'] is False and
            report['publication_authorized'] is False and report['release_acceptance_complete'] is False and
            report['wrapper_qualified'] is False, 'Unsupported retention state or approval')
    archive = delivery.regular(capsule_root, ARCHIVE)
    require(report['archive']['path'] == ARCHIVE and sha(archive) == digest(expected_archive_sha256) == report['archive']['sha256'] and
            archive.stat().st_size == report['archive']['size'], 'Independently selected archive differs')
    require(hashlib.sha256(canonical(report['files'])).hexdigest() == report['inventory_sha256'], 'Retention inventory seal differs')
    privacy = scanner(privacy_policy)
    require(privacy.POLICY_DIGEST == report['privacy_policy_digest'], 'Selected privacy policy differs')
    privacy.scan('capsule.json', report_file.read_bytes())
    with tarfile.open(archive, 'r:gz') as bundle:
        validate_members(bundle, report['files'])
    tar_digest = uncompressed_digest(archive)
    output = fresh(output, [capsule_root, safe(privacy_policy), ROOT])
    selected = {}
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            target = output / relative(member.name)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            selected[member.name] = target
            if member.isfile():
                with target.open('xb') as stream:
                    shutil.copyfileobj(bundle.extractfile(member), stream)
                target.chmod(member.mode)
        # Create only validated links after all regular bytes are in custody.
        for row in report['files']:
            if 'link' in row:
                target = output / row['path']
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.symlink_to(row['link'])
    require(file_inventory(selected, privacy) == report['files'], 'Restored bytes differ from retained inventory')
    # Compare the entire canonical TAR stream, independent of compressor
    # version; the single gzip member was separately checked for any trailer.
    with tempfile.TemporaryDirectory(dir=output) as check:
        canonical_archive = Path(check) / 'canonical.tar'
        with canonical_archive.open('xb') as stream:
            write_tar(stream, report['files'], selected)
        require(sha(canonical_archive) == tar_digest, 'Noncanonical archive padding or trailer')
    shutil.copytree(output / 'cohort/source', output / 'export/source')
    shutil.copyfile(report_file, output / 'capsule.json')
    return {'cohort': output / 'cohort', 'export': output / 'export', 'toolkit': output / 'toolkit',
            'external_report': output / 'external/external-build.json', 'capsule': report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    keep = sub.add_parser('retain')
    for name in ('cohort', 'export', 'repository', 'external-report', 'privacy-policy', 'output',
                 'producer-run-id', 'producer-run-attempt', 'producer-commit'):
        keep.add_argument('--' + name, required=True)
    unpack = sub.add_parser('restore')
    for name in ('capsule-root', 'output', 'expected-capsule-sha256', 'expected-archive-sha256', 'privacy-policy'):
        unpack.add_argument('--' + name, required=True)
    args = vars(parser.parse_args()); command = args.pop('command')
    if command == 'retain':
        args['producer'] = producer_record(args.pop('producer_run_id'), args.pop('producer_run_attempt'), args.pop('producer_commit'))
        result = retain(**args)
        print(json.dumps({'state': result['state'], 'profile': result['profile'], 'archive': result['archive'],
                          'publication_authorized': False}))
    else:
        result = restore(**args)
        print(json.dumps({'state': 'retained_inputs_restored_not_requalified', 'profile': result['capsule']['profile'],
                          'publication_authorized': False}))


if __name__ == '__main__':
    main()
