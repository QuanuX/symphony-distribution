#!/usr/bin/env python3
"""Compose reviewed corresponding source without exporting publisher build state."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'symphony.distribution.d08-corresponding-source.v1'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


common = load('d08_source_common', ROOT / 'qualification/d06_delivery_record.py')
require, sha, canonical = common.require, common.sha, common.canonical


def git(repository, *args):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(repository), *args],
        env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'},
        stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)


def committed_files(repository, commit, scanner, toolkit=False):
    require(re.fullmatch('[0-9a-f]{40}', commit or ''), 'Exact selected source commit required')
    require(git(repository, 'rev-parse', commit + '^{commit}').decode().strip() == commit, 'Selected commit differs')
    rows, exceptions = [], []
    for entry in git(repository, 'ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0'):
        if not entry: continue
        metadata, name = entry.split(b'\t', 1); mode, kind, blob = metadata.decode().split(); name = name.decode()
        (common.toolkit_path if toolkit else common.relative)(name)
        require(kind == 'blob' and mode in ('100644', '100755'), 'Nonregular source member refused')
        data = git(repository, 'cat-file', 'blob', blob)
        require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == blob, 'Git blob differs')
        if toolkit:
            exception = common.scan_toolkit_source(scanner, name, data)
            if exception: exceptions.append(exception)
        else: scanner.scan(name, data)
        rows.append((name, data, 0o755 if mode == '100755' else 0o644))
    require(rows, 'Empty selected source')
    return rows, {'commit': commit, 'tree': git(repository, 'rev-parse', commit + '^{tree}').decode().strip(),
                  'file_count': len(rows), 'scanner_exceptions': exceptions}


def write_tar(path, rows):
    require(not path.exists(), 'Preserve existing source archive')
    names = [name for name, data, mode in rows]
    require(names and len(set(names)) == len(names), 'Duplicate or empty source inventory')
    with path.open('xb') as stream, tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in sorted(rows):
            common.relative(name)
            entry = tarfile.TarInfo(name); entry.size = len(data); entry.mode = mode
            entry.uid = entry.gid = entry.mtime = 0; entry.uname = entry.gname = ''
            archive.addfile(entry, io.BytesIO(data))
    return [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': mode}
            for name, data, mode in sorted(rows)]


def verify_compiled_source(raw, identity):
    closure = identity['compiled_input_equivalence']; inputs = closure['inputs']
    require(closure['method'] == 'native_go_list_deps_compiled_json_CGO0' and inputs and
            len(inputs) == len({row['path'] for row in inputs}) and
            hashlib.sha256(canonical(inputs)).hexdigest() == closure['inventory_sha256'],
            'Compiled input ledger is absent, repeated or inconsistent')
    expected = {}
    for row in inputs:
        common.relative(row['path'])
        require(row['path'].startswith('tools/qxctl/') and set(row) == {'path', 'size', 'mode', 'sha256'} and
                row['mode'] in (0o644, 0o755) and type(row['size']) is int and 0 <= row['size'] <= 64 * 1024 * 1024 and
                re.fullmatch('[0-9a-f]{64}', row['sha256']), 'Invalid compiled source entry')
        expected['symphony-source/' + row['path']] = row
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            if member.name not in expected: continue
            row = expected[member.name]
            require(member.name not in seen and member.isfile() and not member.linkname and
                    member.size == row['size'] and member.mode == row['mode'], 'Packaged compiled source shape differs')
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256'],
                    'Packaged compiled source bytes differ')
            seen.add(member.name)
    require(seen == set(expected), 'Packaged compiled source is incomplete')


def prepare(*, delivery, delivery_sha256, proof, proof_sha256, core, client, client_commit,
            toolkit, toolkit_commit, policy, output):
    output = Path(os.path.abspath(output))
    require(not any(p.is_symlink() for p in (output, *output.parents)), 'Linked output path refused')
    require(not os.path.lexists(output) and output.parent.is_dir(), 'New source output directory required')
    for selected in (Path(core), Path(client), Path(toolkit), Path(delivery).parent, Path(proof).parent, Path(policy)):
        selected = selected.resolve()
        require(output != selected and selected not in output.parents and output not in selected.parents,
                'Source output overlaps a selected input')
    delivery, proof = Path(delivery), Path(proof)
    require(sha(delivery) == delivery_sha256 and sha(proof) == proof_sha256, 'Selected evidence digest differs')
    delivery_bytes, proof_bytes = delivery.read_bytes(), proof.read_bytes()
    require(hashlib.sha256(delivery_bytes).hexdigest() == delivery_sha256 and
            hashlib.sha256(proof_bytes).hexdigest() == proof_sha256, 'Selected evidence changed while read')
    record, identity = json.loads(delivery_bytes), json.loads(proof_bytes)
    source = record['source']; old = source['corresponding_source_archive']
    archive = common.regular(delivery.parent, old['path'])
    require(source['mode'] == 'verified_derived_public_export' and source['verification']['verified'] is True and
            record['publication_authorized'] is False and sha(archive) == old['sha256'] and
            archive.stat().st_size == old['size'], 'Inherited reviewed source differs')
    archive_bytes = archive.read_bytes()
    require(hashlib.sha256(archive_bytes).hexdigest() == old['sha256'] and len(archive_bytes) == old['size'],
            'Inherited source archive changed while read')
    require(identity['protocol'] == 'symphony.distribution.qxctl-original-source.v1' and
            identity['state'] == 'reproducible_stamped_original_git_source' and identity['isolated_builds'] == 2 and
            identity['publication_authorized'] is False and identity['release_acceptance_complete'] is False and
            identity['original_source']['commit'] == source['origin_commit'] and
            identity['original_source']['tree'] == source['origin_tree'] and
            identity['cohort_source']['export_digest'] == source['derived_export_digest'] and
            identity['compiled_input_equivalence']['original_matches_cohort_source'] is True,
            'qxctl source closure differs')
    verify_compiled_source(archive_bytes, identity)
    scanner = load('d08_composite_scanner', ROOT / 'source-export/export_source.py'); scanner.configure_policy(Path(policy))
    selected_policy_sha256 = sha(Path(policy))
    require(scanner.POLICY_DIGEST == identity['privacy']['policy_digest'],
            'Source privacy policy differs from selected qxctl/export proof')
    for helper in ('installer_assembly/corresponding_source.py', 'qualification/d06_delivery_record.py', 'source-export/export_source.py'):
        require(git(toolkit, 'show', toolkit_commit + ':' + helper) == (ROOT / helper).read_bytes(),
                'Executing source helper differs from selected toolkit commit')
    client_rows, client_identity = committed_files(client, client_commit, scanner)
    toolkit_rows, toolkit_identity = committed_files(toolkit, toolkit_commit, scanner, toolkit=True)
    recipe = git(core, 'show', source['origin_commit'] + ':tools/qxctl/tests/reproducible_build.cmake')
    require(hashlib.sha256(recipe).hexdigest() == identity['recipe']['sha256'], 'Original recipe differs')
    scanner.scan('qxctl-original-source-proof.json', proof_bytes); scanner.scan('reproducible_build.cmake', recipe)
    output.mkdir(mode=0o700)
    write_tar(output / 'client-source.tar', client_rows); write_tar(output / 'distribution-toolkit-source.tar', toolkit_rows)
    rows = [('d06/corresponding-source.tar', archive_bytes, 0o644),
            ('d06/delivery-record.json', delivery_bytes, 0o644),
            ('d08/client-source.tar', (output / 'client-source.tar').read_bytes(), 0o644),
            ('d08/distribution-toolkit-source.tar', (output / 'distribution-toolkit-source.tar').read_bytes(), 0o644),
            ('d08/qxctl-original-source-proof.json', proof_bytes, 0o644),
            ('d08/reproducible_build.cmake', recipe, 0o644)]
    bindings = {'core': identity['original_source'], 'client': client_identity, 'distribution_toolkit': toolkit_identity}
    scope = {'protocol': SCHEMA, 'source_bindings': bindings,
        'inherited_reviewed_source_archive_sha256': old['sha256'], 'inherited_delivery_record_sha256': delivery_sha256,
        'qxctl_source_proof_sha256': proof_sha256,
        'exact_original_full_tree_reconstruction': False,
        'compiled_input_equivalence': {'input_count': len(identity['compiled_input_equivalence']['inputs']),
            'inventory_sha256': identity['compiled_input_equivalence']['inventory_sha256'], 'original_matches_cohort_source': True},
        'reproduction_scope': 'Reviewed derived source and all selected compiled inputs retained; exact original Git recipe requires separately selecting the original clean Git tree. Private original test fixtures and local build state are not exported.',
        'publication_authorized': False, 'release_acceptance_complete': False}
    scanner.scan('source-scope.json', canonical(scope)); scanner.scan('delivery-record.json', delivery_bytes)
    rows.append(('SOURCE-SCOPE.json', canonical(scope), 0o644))
    final = output / 'symphony-d08-corresponding-source.tar'; members = write_tar(final, rows)
    index = {**scope, 'state': 'prepared_review_only', 'privacy_scan': 'pass',
        'archive': {'name': final.name, 'sha256': sha(final), 'size': final.stat().st_size}, 'members': members}
    require(sha(Path(policy)) == selected_policy_sha256, 'Source privacy policy changed during collection')
    privacy = {'protocol': 'symphony.distribution.d08-source-privacy.v1', 'state': 'pass',
        'archive_sha256': sha(final), 'policy_file_sha256': selected_policy_sha256, 'policy_digest': scanner.POLICY_DIGEST,
        'new_source_files_scanned': len(client_rows) + len(toolkit_rows),
        'inherited_source_scan': 'exact previously reviewed D06 archive and its bounded public-upstream/scanner exceptions retained unchanged',
        'publication_authorized': False}
    (output / 'source-index.json').write_bytes(canonical(index) + b'\n')
    (output / 'source-privacy.json').write_bytes(canonical(privacy) + b'\n')
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('delivery', 'delivery-sha256', 'proof', 'proof-sha256', 'core', 'client', 'client-commit',
                 'toolkit', 'toolkit-commit', 'policy', 'output'):
        parser.add_argument('--' + name, required=True)
    result = prepare(**vars(parser.parse_args()))
    print(json.dumps({'state': result['state'], 'archive': result['archive']}))


if __name__ == '__main__': main()
