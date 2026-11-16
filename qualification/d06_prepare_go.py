#!/usr/bin/env python3
"""Hydrate the frozen Go graph, then prove its closure with networking disabled.

Bare `go mod download` only fetches explicit requirements for modern modules.
The cohort also inspects `go list -m all`, so preparation must hydrate that full
graph. Extra public checksums belong to private manifest copies, never core.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def objects(raw):
    decoder = json.JSONDecoder()
    text, rows = raw.decode(), []
    while text.strip():
        text = text.lstrip()
        row, end = decoder.raw_decode(text)
        require(isinstance(row, dict), 'Go output is not a module record')
        rows.append(row)
        text = text[end:]
    return rows


def regular(root, name):
    relative = PurePosixPath(name)
    require(name and not relative.is_absolute() and str(relative) == name and
            '..' not in relative.parts and '\\' not in name and
            not any(ord(c) < 32 for c in name), 'Unsafe module source path')
    path = root / relative
    require(path.is_file() and root in path.resolve().parents and
            not any(p.is_symlink() for p in (path, *path.parents)), 'Linked or absent module input')
    return path


def read_sums(raw):
    result = {}
    for line in raw.decode().splitlines():
        fields = line.split()
        require(len(fields) == 3 and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', fields[2]), 'Malformed module checksum')
        key = tuple(fields[:2])
        require(key not in result or result[key] == fields[2], 'Conflicting module checksum')
        result[key] = fields[2]
    return result


def graph(module):
    require(module['go'] == '1.26.5' and not module.get('module_replacements'), 'Unreviewed Go version or replacement')
    rows = module['resolved_graph']
    main = [row for row in rows if row.get('Main')]
    require(len(main) == 1 and main[0]['Path'] == module['module'], 'Frozen main module identity differs')
    require(not any(row.get('Replace') or row.get('Error') for row in rows), 'Replaced or incomplete frozen graph')
    selected = {(row['Path'], row['Version']): row for row in rows if not row.get('Main')}
    require(len(selected) + 1 == len(rows), 'Duplicate frozen graph entry')
    return selected


def verify_download(module, records, sums):
    expected = graph(module)
    actual = {(row.get('Path'), row.get('Version')): row for row in records}
    require(len(actual) == len(records) and set(actual) == set(expected), 'Downloaded module graph differs from source')
    result = []
    for key in sorted(expected):
        row, frozen = actual[key], expected[key]
        require(not row.get('Error') and not row.get('Replace'), 'Incomplete or replaced downloaded module')
        checks = {}
        for field, suffix in (('Sum', ''), ('GoModSum', '/go.mod')):
            value = row.get(field, '')
            require(isinstance(value, str) and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', value),
                    'Downloaded module lacks verified checksum')
            known = [item for item in (frozen.get(field), sums.get((key[0], key[1] + suffix))) if item]
            require(all(item == value for item in known), 'Downloaded checksum differs from frozen source')
            checks[field] = value
            checks[field + '_authority'] = 'frozen_source' if known else 'public_sum_golang_org'
        result.append({'path': key[0], 'version': key[1], **checks})
    return result


def verify_graph(module, records):
    require(not any(row.get('Replace') or row.get('Error') for row in records), 'Offline graph has replacement or error')
    main = [row for row in records if row.get('Main')]
    require(len(main) == 1 and main[0]['Path'] == module['module'], 'Offline main module differs')
    actual = {(row.get('Path'), row.get('Version')): row for row in records if not row.get('Main')}
    expected = graph(module)
    require(len(actual) + 1 == len(records) and set(actual) == set(expected), 'Offline graph differs from frozen source')
    for key, row in expected.items():
        for field in ('Sum', 'GoModSum'):
            if row.get(field):
                require(actual[key].get(field) == row[field], 'Offline checksum differs from frozen source')


def clean_env(go, work, cache, *, online):
    return {'PATH': str(go.parent) + ':/usr/bin:/bin', 'HOME': str(work / 'home'),
            'TMPDIR': str(work / 'tmp'), 'GOCACHE': str(work / 'go-cache'), 'GOMODCACHE': str(cache),
            'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off',
            'GOAUTH': 'off', 'GOVCS': '*:off', 'GOPRIVATE': '', 'GONOPROXY': '', 'GONOSUMDB': '',
            'CGO_ENABLED': '0', 'GOPROXY': 'https://proxy.golang.org' if online else 'off',
            'GOSUMDB': 'sum.golang.org' if online else 'off'}


def transient_network_error(raw):
    if re.search(rb'checksum mismatch|SECURITY ERROR|verifying module:.*mismatch', raw, re.I):
        return False
    return bool(re.search(rb'timeout|timed out|temporary failure|no such host|connection reset|unexpected EOF|'
                          rb'network is unreachable|TLS handshake|(?:429|500|502|503|504) ', raw, re.I))


def command(go, args, cwd, env, work, label, logs, *, network_retry=False, timeout=300):
    for attempt in range(1, 4 if network_retry else 2):
        try:
            result = subprocess.run([str(go), *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            result = subprocess.CompletedProcess([], 124, exc.stdout or b'',
                                                 (exc.stderr or b'') + b'\nnetwork preparation timed out')
        data = result.stdout + result.stderr
        name = label + '-' + str(attempt) + '.log'
        (work / 'logs' / name).write_bytes(data)
        logs.append({'name': name, 'sha256': hashlib.sha256(data).hexdigest(),
                     'exit_code': result.returncode, 'network_preparation': network_retry})
        if result.returncode == 0:
            return result.stdout
        if not network_retry or attempt == 3 or not transient_network_error(data):
            raise ValueError('Go preparation step failed: ' + label + '; private log retained')
        time.sleep(2 ** (attempt - 1))


def fresh_directory(path):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'Preparation directory must be new')
    require(path.parent.is_dir() and not any(p.is_symlink() for p in (path.parent, *path.parent.parents)),
            'Preparation parent must be an existing nonlinked directory')
    path.mkdir(mode=0o700)
    return path.resolve()


def prepare(source, work, go, cache):
    source, go = Path(source).resolve(strict=True), Path(go).resolve(strict=True)
    work_path, cache_path = Path(work).absolute(), Path(cache).absolute()
    require(go.is_file(), 'Selected Go tool is absent')
    require(all(source != p and source not in p.parents and p not in source.parents for p in (work_path, cache_path)),
            'Preparation overlaps core source')
    require(work_path != cache_path and work_path not in cache_path.parents and cache_path not in work_path.parents,
            'Preparation and module-cache directories overlap')
    mapping_path = regular(source, 'cmake/mvp-dependencies.json')
    modules = json.loads(mapping_path.read_text())['go_modules']
    require(modules and len({row['path'] for row in modules}) == len(modules), 'Empty or duplicate source module set')
    inputs, selected = {}, []
    for module in modules:
        graph(module)
        files = {}
        for name in ('go.mod', 'go.sum'):
            rel = module['path'] + '/' + name
            if name == 'go.sum' and not (source / rel).exists():
                require(not (source / rel).is_symlink(), 'Linked module input refused')
                inputs[rel] = None
                continue
            path = regular(source, rel)
            inputs[rel] = path.read_bytes()
            files[name] = inputs[rel]
        require('go.mod' in files, 'Source go.mod absent')
        selected.append((module, files))
    work = fresh_directory(work_path)
    cache = fresh_directory(cache_path)
    for name in ('home', 'tmp', 'logs', 'modules'):
        (work / name).mkdir(mode=0o700)
    report = {'protocol': 'symphony.distribution.d06-go-preparation.v1', 'status': 'incomplete',
              'helper_sha256': sha(Path(__file__)), 'source_map_sha256': sha(mapping_path), 'go_binary_sha256': sha(go),
              'download_scope': 'complete frozen module graph, including graph-only dependencies',
              'network_scope': 'public proxy and checksum database during preparation only; no VCS/auth fallback',
              'source_manifests_unchanged': False, 'modules': [], 'logs': [],
              'release_acceptance_complete': False, 'publication_authorized': False}
    def save():
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def unchanged():
        require(sha(mapping_path) == report['source_map_sha256'], 'Source dependency map changed')
        for name, raw in inputs.items():
            path = source / name
            require(not path.exists() and not path.is_symlink() if raw is None else regular(source, name).read_bytes() == raw,
                    'Core module manifest changed during preparation')
    save()
    online, offline = clean_env(go, work, cache, online=True), clean_env(go, work, cache, online=False)
    try:
        version = command(go, ['env', 'GOVERSION'], work, offline, work, 'toolchain', report['logs'])
        require(version.strip() == b'go1.26.5', 'Exact Go 1.26.5 is required')
        for index, (module, files) in enumerate(selected):
            report['active_module'] = module['path']; save()
            copy = work / 'modules' / str(index); copy.mkdir(mode=0o700)
            for name, raw in files.items():
                (copy / name).write_bytes(raw)
            label = 'module-' + str(index)
            data = command(go, ['mod', 'download', '-json', 'all'], copy, online, work, label + '-download',
                           report['logs'], network_retry=True)
            require((copy / 'go.mod').read_bytes() == files['go.mod'], 'Preparation changed module selection')
            sums = read_sums(files.get('go.sum', b''))
            downloads = verify_download(module, objects(data), sums)
            copy_sums = read_sums((copy / 'go.sum').read_bytes()) if (copy / 'go.sum').exists() else {}
            require(all(copy_sums.get(key) == value for key, value in sums.items()), 'Preparation rewrote a frozen checksum')
            # Check the exact original manifests with the same offline policy as
            # the long cohort build; copied additions cannot hide missing inputs.
            listing = command(go, ['list', '-mod=readonly', '-m', '-json', 'all'], source / module['path'],
                              offline, work, label + '-offline-closure', report['logs'])
            verify_graph(module, objects(listing))
            command(go, ['mod', 'verify'], copy, offline, work, label + '-verify', report['logs'])
            unchanged()
            report['modules'].append({'path': module['path'], 'module': module['module'], 'go_version': 'go1.26.5',
                'source_manifests': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                'downloaded': downloads, 'private_checksum_additions': len(set(copy_sums) - set(sums)),
                'offline_graph_verified': True, 'module_archives_verified': True})
            save()
        report.pop('active_module', None)
        report['status'] = 'full_graph_cached_and_offline_verified'
        return report
    except BaseException:
        report['status'] = 'failed'
        raise
    finally:
        try:
            unchanged()
            report['source_manifests_unchanged'] = True
        except BaseException:
            report['status'] = 'failed'
            raise
        finally:
            save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'go', 'gomodcache'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = prepare(args.source, args.work, args.go, args.gomodcache)
    print(json.dumps({'status': result['status'], 'modules': len(result['modules']),
                      'source_manifests_unchanged': result['source_manifests_unchanged']}))


if __name__ == '__main__':
    main()
