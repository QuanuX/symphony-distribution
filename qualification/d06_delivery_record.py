#!/usr/bin/env python3
"""Prepare exact D06 source, dependency, file and notice records read-only.

This is a versioned machine-readable inventory, not a claim of SPDX/CycloneDX
conformance or legal approval. Product executables are never run. Raw CI source
and a verified privacy-reviewed public source export remain distinct states.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def read_json(path):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def relative(value):
    p = PurePosixPath(value)
    require(value and not p.is_absolute() and str(p) == value and '..' not in p.parts and
            '\\' not in value and not any(ord(c) < 32 for c in value), 'Unsafe relative inventory path')
    return p


def regular(root, value):
    path = root / relative(value)
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Regular nonlinked input required: ' + value)
    require(root.resolve() in path.resolve().parents, 'Input escapes selected root')
    return path


def module_escape(value):
    require(value and '..' not in value and not value.startswith('/') and '\\' not in value,
            'Unsafe module identity')
    return ''.join('!' + c.lower() if 'A' <= c <= 'Z' else c for c in value)


def legal_files(root):
    found = []
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE', 'PATENTS', 'UNLICENSE')):
            relative_path = path.relative_to(root).as_posix()
            regular(root, relative_path)
            found.append(relative_path)
    return found


def toolkit_path(name):
    parts = relative(name).parts
    require(not any(p in {'.git', '__pycache__', '.pytest_cache', '.DS_Store', 'node_modules', '.venv',
                          'private-evidence', 'private-results', 'go-cache', 'gomodcache'} for p in parts),
            'Private evidence/cache is not corresponding source')
    return name


def verify_module_cache_sum(cache, module):
    checksum_name = 'cache/download/' + module_escape(module['path']) + '/@v/' + module_escape(module['version']) + '.ziphash'
    require(regular(cache, checksum_name).read_text().strip() == module['sum'],
            'Verified module cache checksum differs from executable and source sum')


def verify_inventory(prefix, inventory):
    expected = {r['path']: r for r in inventory}
    require(len(expected) == len(inventory), 'Duplicate final payload path')
    observed = set()
    for path in prefix.rglob('*'):
        name = path.relative_to(prefix).as_posix()
        if path.is_dir() and not path.is_symlink():
            continue
        require(name in expected, 'Uninventoried final payload file: ' + name)
        observed.add(name)
        row = expected[name]
        if 'link' in row:
            require(path.is_symlink() and os.readlink(path) == row['link'] and
                    prefix.resolve() in path.resolve(strict=True).parents, 'Changed/escaping final payload link')
        else:
            regular(prefix, name)
            require(sha(path) == row['sha256'] and path.stat().st_size == row['size'] and
                    path.stat().st_mode & 0o777 == row['mode'], 'Changed final payload bytes/mode: ' + name)
    require(observed == set(expected), 'Final payload inventory is incomplete')
    return expected


def native_records(prefix, units, inventory):
    records, owned = [], {}
    for unit in units:
        cid, version = unit['component_id'], unit['version']
        name = f'share/symphony/receipts/{cid}/{version}/install-receipt.json'
        receipt = read_json(regular(prefix, name))
        body = dict(receipt)
        seal = body.pop('receipt_digest')
        require(seal == 'sha256:' + digest(canonical(body)), 'Native receipt digest differs')
        require(receipt['component_id'] == cid and receipt['version'] == version, 'Native receipt identity differs')
        require(name not in owned, 'Receipt owner collision')
        owned[name] = cid
        files, notices = [], []
        for row in receipt['files']:
            path = row['path']
            require(path in inventory and path not in owned, 'Missing or multiply owned native payload file')
            selected = inventory[path]
            require(row['digest'] == 'sha256:' + selected['sha256'] and row['size'] == selected['size'], 'Receipt/file inventory mismatch')
            owned[path] = cid
            files.append(path)
            if path.startswith('share/licenses/'):
                notices.append(path)
        require(notices, 'Native receipt lacks installed license material: ' + cid)
        records.append({'id': 'native:' + cid, 'component_id': cid, 'version': version,
                        'source_root': unit['source_root'], 'receipt_path': name,
                        'receipt_sha256': inventory[name]['sha256'], 'receipt_digest': seal,
                        'files': sorted(files), 'notice_paths': sorted(notices),
                        'first_party_sdk_dependencies': unit['first_party_sdk_dependencies'],
                        'external_dependency_refs': unit['external_dependency_refs'],
                        'runtime_ownership_scope': 'source-owned native receipt v2'})
    return records, owned


def go_modules(info, graph, sums):
    require(info['GoVersion'] == 'go1.26.5', 'Go artifact toolchain differs')
    require(info['Main']['Path'] == graph['module'] and not info['Main'].get('Replace'), 'Go main module differs')
    resolved = {row['Path']: row for row in graph['resolved_graph']}
    result = []
    for module in info.get('Deps', []):
        require(not module.get('Replace'), 'Replaced linked Go module refused')
        path, version, checksum = module['Path'], module['Version'], module['Sum']
        module_escape(path)
        require('/' not in version and version.startswith('v') and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', checksum), 'Invalid linked Go identity/sum')
        require(path in resolved and resolved[path].get('Version') == version, 'Linked module differs from frozen source graph')
        require(not resolved[path].get('Sum') or resolved[path]['Sum'] == checksum, 'Linked module sum differs from source graph')
        require(sums.get((path, version)) == checksum, 'Linked module sum absent/different in corresponding source go.sum')
        result.append({'path': path, 'version': version, 'sum': checksum,
                       'scope': 'actual linked executable module; not every package in module'})
    settings = {r['Key']: r['Value'] for r in info.get('Settings', [])}
    require(settings.get('-trimpath') == 'true' and settings.get('CGO_ENABLED') == '0', 'Go payload is outside clean non-CGO cohort')
    return result


def safe_archive(output, entries):
    """Deterministic regular-file archive; callers supply only verified source."""
    require(not output.exists(), 'Preserve prior corresponding-source archive')
    names = set()
    expected = {name: sha(path) for name, path, _ in entries}
    with tarfile.open(output, 'w', format=tarfile.PAX_FORMAT) as archive:
        for name, path, mode in sorted(entries, key=lambda x: x[0]):
            relative(name)
            require(name not in names and path.is_file() and not path.is_symlink(), 'Invalid source archive membership')
            names.add(name)
            metadata = tarfile.TarInfo(name)
            metadata.size = path.stat().st_size
            metadata.mode = mode
            metadata.uid = metadata.gid = metadata.mtime = 0
            metadata.uname = metadata.gname = ''
            with path.open('rb') as stream:
                archive.addfile(metadata, stream)
    with tarfile.open(output) as archive:
        for member in archive:
            require(digest(archive.extractfile(member).read()) == expected[member.name], 'Source changed while archiving')
    require(all(sha(path) == expected[name] for name, path, _ in entries), 'Source changed during archive creation')
    return {'sha256': sha(output), 'size': output.stat().st_size, 'file_count': len(names)}


def collect(build_root, repository, go, gomodcache, output, export=None, privacy_policy=None, round_name='round-1', external_sources=None):
    build_root, repository, go, gomodcache, output = [Path(x).resolve() for x in (build_root, repository, go, gomodcache, output)]
    require(round_name in ('round-1', 'round-2'), 'Unknown build round')
    require(not output.exists() and output.parent.is_dir(), 'Output must be new with an existing parent')
    for selected in (build_root, repository, gomodcache, ROOT):
        require(output != selected and selected not in output.parents and output not in selected.parents, 'Output overlaps an input')
    build = read_json(build_root / 'result.json')
    round_root = build_root / round_name
    result = read_json(round_root / 'result.json')
    require(build['state'] == result['state'] == 'built_and_sdk_checked', 'Completed exact cohort build evidence is required')
    plan = read_json(ROOT / 'build-cohort/cohort.json')
    require(build['source_commit'] == plan['source_commit'] and build['source_tree'] == plan['source_tree'] and
            build['plan_sha256'] == sha(ROOT / 'build-cohort/cohort.json'), 'Cohort source/plan identity differs')
    rounds = {row['directory']: row for row in build['rounds']}
    require(round_name in rounds and rounds[round_name]['result_sha256'] == sha(round_root / 'result.json'), 'Build round digest differs')
    for name, expected_hash in build['build_helpers'].items():
        require(sha(regular(ROOT / 'build-cohort', name)) == expected_hash, 'Packaging helper differs from actual build: ' + name)
    source, prefix = build_root / 'source', round_root / 'relocated-prefix'
    inventory = verify_inventory(prefix, result['payload_inventory'])
    profile = plan['profiles'][build['host']['requested_profile']]
    native, owned = native_records(prefix, profile['native_build_order'], inventory)
    require(len(native) == result['native_count'] == 51 and len(profile['go_commands']) == 6, 'Full D06 core cohort required')
    require(subprocess.check_output(['git', '--no-replace-objects', '-C', str(repository), 'rev-parse', plan['source_commit'] + '^{tree}'], text=True, timeout=30).strip() == plan['source_tree'], 'Origin Git tree differs')
    source_record = {'origin_commit': plan['source_commit'], 'origin_tree': plan['source_tree'],
                     'source_url': 'https://github.com/QuanuX/Symphony/tree/' + plan['source_commit'],
                     'matching_build_install_source_prepared': False, 'publisher_review': 'pending'}
    scanner = None
    source_entries = []
    if export:
        require(privacy_policy is not None, 'Reviewed export requires its private scan policy')
        spec = importlib.util.spec_from_file_location('d06_source_exporter', ROOT / 'source-export/export_source.py')
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        scanner.configure_policy(privacy_policy)
        export = Path(export).resolve()
        verification = scanner.verify(export, repository)
        manifest = read_json(export / 'SOURCE-EXPORT.json')
        require(build['source_input']['kind'] == 'verified_reviewed_derived_export', 'A raw CI build cannot be rebound to a different public source export')
        expected = {r['path']: r for r in manifest['source_files']}
        actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
        require(actual == set(expected), 'Build source membership differs from reviewed public export')
        for name, row in expected.items():
            path = regular(source, name)
            require(sha(path) == row['export_sha256'] and path.stat().st_size == row['export_size'], 'Built source differs from reviewed public export: ' + name)
            scanner.scan(name, path.read_bytes())
            source_entries.append(('symphony-source/' + name, path, 0o755 if row['mode'] == '100755' else 0o644))
        source_entries.append(('symphony-source/SOURCE-EXPORT.json', regular(export, 'SOURCE-EXPORT.json'), 0o644))
        source_record.update(mode='verified_derived_public_export', derived_export_digest=manifest['derived_export_digest'],
                             export_archive_sha256=sha(export / 'symphony-source.tar'), verification=verification)
    else:
        require(privacy_policy is None and build['source_input']['kind'] == 'exact_committed_source_archive', 'Derived source needs its exact verified export inputs')
        archive = regular(build_root, 'committed-source.tar')
        require(sha(archive) == build['source_input']['archive_sha256'], 'Raw source archive differs from build input')
        seen = set()
        with tarfile.open(archive) as original:
            for member in original:
                relative(member.name.rstrip('/'))
                if member.isdir():
                    continue
                require(member.isfile() and member.name not in seen, 'Unsafe raw source archive member')
                seen.add(member.name)
                require(sha(regular(source, member.name)) == digest(original.extractfile(member).read()), 'Raw build source changed after archive extraction')
        require(seen == {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}, 'Raw build source membership differs')
        source_record.update(mode='raw_commit_ci_qualification_only', raw_archive_sha256=sha(archive),
                             public_source_archive_prepared=False,
                             blocker='A privacy-reviewed matching public export must be built and qualified before source distribution')
    output.mkdir(mode=0o700)
    for name in ('home', 'logs', 'notices', 'tmp'):
        (output / name).mkdir(mode=0o700)
    report = {'protocol': 'symphony.distribution.d06-delivery-record.v1', 'state': 'incomplete',
              'publication_authorized': False, 'release_ready': False, 'publisher_review': 'pending',
              'fresh_host_accepted': False, 'source': source_record, 'source_binding': {'commit': plan['source_commit'], 'tree': plan['source_tree']},
              'host': build['host'], 'build_result_sha256': sha(build_root / 'result.json'),
              'round_result_sha256': sha(round_root / 'result.json'), 'tool_sha256': sha(Path(__file__)),
              'native_components': native, 'go_artifacts': [], 'notices': [], 'payload_files': result['payload_inventory']}
    def save():
        (output / 'delivery-record.json').write_text(json.dumps(report, indent=2) + '\n')
    def retain(path, name, component, scope):
        relative(name)
        data = path.read_bytes()
        if scanner:
            scanner.scan(name, data)
        destination = output / 'notices' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            require(destination.read_bytes() == data, 'Notice collision')
        else:
            destination.write_bytes(data)
        row = {'path': 'notices/' + name, 'sha256': digest(data), 'size': len(data), 'component': component, 'scope': scope}
        if row not in report['notices']:
            report['notices'].append(row)
        return row
    env = {'PATH': str(go.parent) + ':/usr/bin:/bin', 'HOME': str(output / 'home'), 'TMPDIR': str(output / 'tmp'),
           'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOAUTH': 'off',
           'GOVCS': '*:off', 'GOTELEMETRY': 'off', 'GOMODCACHE': str(gomodcache), 'GOCACHE': str(output / 'go-cache')}
    def command(label, argv, cwd=None):
        completed = subprocess.run([str(x) for x in argv], cwd=cwd or output / 'tmp', env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        log = output / 'logs' / (label + '.log')
        log.write_bytes(completed.stdout + completed.stderr)
        require(completed.returncode == 0, 'Read-only notice step failed: ' + label)
        return completed.stdout
    save()
    try:
        mapping = read_json(source / 'cmake/mvp-dependencies.json')
        graphs = {r['path']: r for r in mapping['go_modules']}
        toolchain = command('go-version', [go, 'env', 'GOVERSION', 'GOROOT']).decode().splitlines()
        require(toolchain[0] == 'go1.26.5', 'Exact Go toolchain required')
        goroot = Path(toolchain[1]).resolve()
        for component in native:
            for name in component['notice_paths']:
                retain(regular(prefix, name), 'installed/' + name, component['id'], 'verified final native receipt-owned notice')
        retain(regular(source, 'LICENSE'), 'symphony/LICENSE', 'Symphony', 'exact built-source main license; publisher approval pending')
        linked_source = {}
        for row in profile['go_commands']:
            cid = row['component_id']
            name = 'go/' + cid + '/bin/' + row['binary_name']
            path = regular(prefix, name)
            require(name in inventory and name not in owned, 'Go payload ownership collision')
            owned[name] = 'go:' + cid
            module_root = source / row['source_root']
            command(cid + '-module-cache-verify', [go, 'mod', 'verify'], module_root)
            info = json.loads(command(cid + '-buildinfo', [go, 'version', '-m', '-json', path]))
            sums = {}
            sum_file = module_root / 'go.sum'
            if sum_file.is_file():
                for line in sum_file.read_text().splitlines():
                    fields = line.split()
                    require(len(fields) == 3, 'Malformed corresponding source go.sum')
                    require(tuple(fields[:2]) not in sums or sums[tuple(fields[:2])] == fields[2], 'Conflicting corresponding source go.sum')
                    sums[tuple(fields[:2])] = fields[2]
            linked = go_modules(info, graphs[row['source_root']], sums)
            for module in linked:
                verify_module_cache_sum(gomodcache, module)
                cache_path = gomodcache / (module_escape(module['path']) + '@' + module_escape(module['version']))
                require(cache_path.is_dir() and not cache_path.is_symlink(), 'Linked module cache is absent')
                material = legal_files(cache_path)
                require(material, 'Linked module legal material absent')
                key = digest((module['path'] + '@' + module['version']).encode())
                module['notices'] = [retain(regular(cache_path, n), 'go/' + key + '/' + n, module['path'] + '@' + module['version'],
                    'exact verified module legal files; applicability to linked packages needs review') for n in material]
                if scanner and key not in linked_source:
                    files = []
                    for cached_file in sorted(cache_path.rglob('*')):
                        if cached_file.is_dir() and not cached_file.is_symlink():
                            continue
                        n = cached_file.relative_to(cache_path).as_posix()
                        cached_file = regular(cache_path, n)
                        scanner.scan(n, cached_file.read_bytes())
                        mode = 0o755 if cached_file.stat().st_mode & 0o111 else 0o644
                        source_entries.append(('go-modules/' + key + '/' + n, cached_file, mode))
                        files.append({'path': n, 'sha256': sha(cached_file), 'mode': mode})
                    linked_source[key] = {'path': module['path'], 'version': module['version'], 'sum': module['sum'],
                                          'archive_directory': 'go-modules/' + key, 'files': files}
            report['go_artifacts'].append({'id': 'go:' + cid, 'version': row['package_version'], 'path': name,
                'sha256': inventory[name]['sha256'], 'main_module': info['Main'], 'go_version': info['GoVersion'],
                'settings': info.get('Settings', []), 'linked_modules': linked,
                'resolved_graph_not_all_linked': graphs[row['source_root']]['resolved_graph'],
                'source_root': row['source_root'], 'runtime_ownership_scope': 'staged Go payload; no runtime receipt inferred'})
            save()
        require(regular(goroot, 'VERSION').read_text().splitlines()[0] == 'go1.26.5', 'Go notice source version differs')
        for name in ('LICENSE', 'PATENTS'):
            retain(regular(goroot, name), 'go-toolchain/' + name, 'go1.26.5', 'matching Go runtime/toolchain legal material')
        for name in legal_files(goroot / 'src/vendor'):
            retain(regular(goroot / 'src/vendor', name), 'go-toolchain/vendor/' + name, 'go1.26.5', 'standard library vendor legal material superset; not all linked')
        external = read_json(regular(prefix, 'third-party/share/symphony/dependency-evidence/curl-zstd.json'))
        pins = read_json(regular(source, 'cmake/notices/sources.json'))['components']
        selected = {r['id']: r for r in external['components']}
        require(set(selected) == {r['id'] for r in pins} == {'curl', 'zstd'}, 'External input set differs')
        external_rows = []
        for pin in pins:
            require(all(selected[pin['id']][k] == pin[k] for k in ('version', 'source_sha256', 'notice_sha256')), 'External source/notice identity differs')
            name = f'third-party/share/licenses/{pin["id"]}/{pin["version"]}/LICENSE'
            notice = regular(prefix, name)
            require(sha(notice) == pin['notice_sha256'], 'Final external notice differs')
            external_rows.append({**pin, 'notice': retain(notice, 'external/' + pin['id'] + '/LICENSE', pin['id'], 'exact selected upstream notice')})
        report['external_dependencies'] = {'selected': external_rows, 'build_selection': external,
            'runtime_ownership_scope': 'separate distribution build inventory; not admitted native receipt ownership'}
        external_archive_records = []
        if external_sources:
            external_sources = Path(external_sources).resolve()
            for pin in pins:
                archive_name = pin['source_url'].rsplit('/', 1)[-1]
                archive_path = regular(external_sources, archive_name)
                require(sha(archive_path) == pin['source_sha256'], 'External corresponding source archive differs')
                external_archive_records.append({'component': pin['id'], 'version': pin['version'],
                    'archive_path': 'external-source/' + archive_name, 'sha256': sha(archive_path)})
                if scanner:
                    with tarfile.open(archive_path) as upstream:
                        for member in upstream:
                            relative(member.name.rstrip('/'))
                            if member.isfile():
                                scanner.scan(member.name, upstream.extractfile(member).read())
                    source_entries.append(('external-source/' + archive_name, archive_path, 0o644))
        report['source']['external_source_archives'] = external_archive_records
        leftovers = sorted(set(inventory) - set(owned))
        require(all(name.startswith('third-party/') for name in leftovers), 'Final payload has an unclassified owner')
        report['external_dependencies']['files'] = leftovers
        report['optional_external_exclusions'] = ['DuckDB connectors and their runtime', 'PDFium caller-selected decoder', 'licensed IBKR SDK 10.45', 'private data, credentials and user plugins']
        report['vendored_dependencies'] = [r for r in mapping['external_dependencies'] if r['id'] == 'nlohmann-json']
        if source_entries:
            # Include the complete external packaging toolkit snapshot, including
            # this increment's new files. Git-ignored evidence/cache is excluded.
            paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], timeout=30).decode().split('\0')
            toolkit = []
            for name in sorted(set(paths) - {''}):
                toolkit_path(name)
                path = regular(ROOT, name)
                scanner.scan(name, path.read_bytes())
                mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                source_entries.append(('distribution-toolkit/' + name, path, mode))
                toolkit.append({'path': name, 'sha256': sha(path), 'mode': mode})
            report['source']['toolkit_files'] = toolkit
            report['source']['toolkit_snapshot'] = {
                'kind': 'explicit_working_tree_byte_snapshot_including_new_D06_source',
                'git_baseline_commit': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True, timeout=30).strip(),
                'files_are_not_claimed_to_belong_to_baseline_commit': True,
                'file_inventory_sha256': digest(canonical(toolkit))}
            report['source']['linked_go_source_modules'] = sorted(linked_source.values(), key=lambda r: (r['path'], r['version']))
            source_index = output / 'corresponding-source-index.json'
            source_index.write_text(json.dumps({'protocol': 'symphony.distribution.corresponding-source-index.v1',
                'origin_commit': plan['source_commit'], 'origin_tree': plan['source_tree'],
                'derived_export_digest': source_record['derived_export_digest'], 'toolkit_files': toolkit,
                'linked_go_modules': report['source']['linked_go_source_modules'], 'external_archives': external_archive_records,
                'publisher_review': 'pending', 'publication_authorized': False}, indent=2) + '\n')
            scanner.scan(source_index.name, source_index.read_bytes())
            source_entries.append(('corresponding-source-index.json', source_index, 0o644))
            archive = safe_archive(output / 'corresponding-source.tar', source_entries)
            report['source'].update(matching_build_install_source_prepared=True,
                corresponding_source_archive={'path': 'corresponding-source.tar', **archive},
                scope='complete verified built Symphony source, exact linked Go module source and distribution build/install toolkit; available exact external source archives retained')
        verify_inventory(prefix, result['payload_inventory'])
        report.update(state='inventory_complete_publisher_review_pending', sbom_format='symphony.distribution.d06-delivery-record.v1',
            blockers=['Publisher review and redistribution approval pending', 'External runtime ownership must be integrated into delivery carriers',
                      'System TLS/OS runtime legal and source review remains separate', 'Fresh-host acceptance and final signing remain open'])
        if not source_entries:
            report['blockers'].append(source_record['blocker'])
        elif len(external_archive_records) != len(pins):
            report['blockers'].append('Exact curl/zstd source archives are pinned but not included in corresponding-source delivery')
        save()
        if scanner:
            scanner.scan('delivery-record.json', (output / 'delivery-record.json').read_bytes())
        return report
    except BaseException:
        report['state'] = 'failed'
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build-root', 'repository', 'go', 'gomodcache', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--export')
    parser.add_argument('--privacy-policy')
    parser.add_argument('--external-sources')
    parser.add_argument('--round', default='round-1', choices=('round-1', 'round-2'))
    args = parser.parse_args()
    report = collect(args.build_root, args.repository, args.go, args.gomodcache, args.output,
                     args.export, args.privacy_policy, args.round, args.external_sources)
    print(json.dumps({'state': report['state'], 'native_components': len(report['native_components']),
                      'go_artifacts': len(report['go_artifacts']), 'publication_authorized': False}))


if __name__ == '__main__':
    main()
