#!/usr/bin/env python3
"""Build qxctl from its exact Git recipe and bind its public compiled inputs.

The cohort can use a reviewed derived source export. qxctl's existing stamp,
however, names an original Git tree and its unchanged two-build recipe. Build
that component from the original archive, and prove that every selected local
compiled/embedded input also exists unchanged in the cohort source. Private
recipe archives/logs are retained locally; result.json contains no source bytes.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification.native_campaign import bounded_run

MODULE = 'tools/qxctl'
MODULE_ID = 'github.com/QuanuX/Symphony/tools/qxctl'
RECIPE_PATH = MODULE + '/tests/reproducible_build.cmake'
RECIPE = 'symphony.qxctl.reproducible-build.v1'
INPUT_FIELDS = ('GoFiles', 'CompiledGoFiles', 'CgoFiles', 'CFiles', 'CXXFiles',
                'HFiles', 'FFiles', 'SFiles', 'SwigFiles', 'SwigCXXFiles', 'SysoFiles', 'EmbedFiles')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def safe(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked input/output path refused')
    require(not any(ord(c) < 32 for c in str(path)) and ';' not in str(path), 'Unsafe tool argument path')
    return path


def relative(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and str(path) == name and
            '..' not in path.parts and '\\' not in name and
            not any(ord(c) < 32 for c in name), 'Unsafe relative source path')
    return path


def regular(root, name):
    path = safe(root / relative(name))
    require(path.is_file(), 'Source input is not a regular file')
    return path


def inventory(root):
    result = []
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'Source links refused')
        if path.is_dir():
            continue
        require(path.is_file(), 'Nonregular source input refused')
        name = path.relative_to(root).as_posix(); relative(name)
        result.append({'path': name, 'sha256': sha(path), 'size': path.stat().st_size,
                       'mode': path.stat().st_mode & 0o777})
    require(result, 'Empty source tree')
    return result


def fresh(path, inputs):
    path = safe(path)
    require(not path.exists() and path.parent.is_dir(), 'Output must be a new directory with existing parent')
    require(all(path != p and path not in p.parents and p not in path.parents for p in inputs),
            'Output overlaps a selected input')
    path.mkdir(mode=0o700)
    return path


def git(repository, *args):
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(repository), *args],
                                   env={'PATH': '/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
                                        'GIT_CONFIG_GLOBAL': os.devnull}, timeout=60)


def identity(repository, commit, tree):
    require(re.fullmatch('[0-9a-f]{40}', commit) and re.fullmatch('[0-9a-f]{40}', tree), 'Invalid selected Git identity')
    require(git(repository, 'rev-parse', 'HEAD').decode().strip() == commit and
            git(repository, 'rev-parse', commit + '^{tree}').decode().strip() == tree,
            'Selected original Git identity differs')
    require(not git(repository, 'status', '--porcelain', '--untracked-files=normal').strip(),
            'Original source checkout must be clean')
    epoch = git(repository, 'show', '-s', '--format=%ct', commit).decode().strip()
    require(re.fullmatch('0|[1-9][0-9]*', epoch), 'Invalid original commit epoch')
    return epoch


def clean_environment(work, go, cmake, cache):
    # The unchanged recipe creates its own empty module cache. Its only proxy
    # is this selected local file tree; there is no comma/pipe network fallback.
    proxy = safe(cache / 'cache/download')
    require(proxy.is_dir(), 'Prepared local module proxy absent')
    return {'PATH': str(go.parent) + ':' + str(cmake.parent) + ':/usr/bin:/bin',
            'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C',
            'GOCACHE': str(work / 'preflight-cache'), 'GOMODCACHE': str(cache),
            'GOPATH': str(work / 'gopath'), 'GOENV': 'off', 'GOWORK': 'off',
            'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off', 'CGO_ENABLED': '0',
            'GOPROXY': proxy.as_uri(), 'GOSUMDB': 'off', 'GOAUTH': 'off', 'GOVCS': '*:off',
            'GOPRIVATE': '', 'GONOPROXY': '', 'GONOSUMDB': '', 'GOINSECURE': '',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}


class Runner:
    def __init__(self, work, env, timeout):
        self.work, self.env, self.timeout, self.logs = work, env, timeout, []

    def run(self, label, argv, cwd=None, env=None):
        out, err = (self.work / 'logs' / (label + suffix) for suffix in ('.stdout', '.stderr'))
        with out.open('xb') as stdout, err.open('xb') as stderr:
            code = bounded_run([str(x) for x in argv], cwd=cwd or self.work,
                               env=env or self.env, stdout=stdout, stderr=stderr, timeout=self.timeout)
        self.logs.append({'step': label, 'exit_code': code, 'stdout_sha256': sha(out), 'stderr_sha256': sha(err)})
        require(code == 0, 'qxctl identity step failed: ' + label + '; private logs retained')
        require(out.stat().st_size <= 32 * 1024 * 1024, 'Tool output exceeds bound')
        return out.read_bytes()


def objects(raw):
    result, text, decoder = [], raw.decode(), json.JSONDecoder()
    while text.strip():
        text = text.lstrip(); row, end = decoder.raw_decode(text); text = text[end:]
        require(isinstance(row, dict), 'Invalid Go package/module record')
        result.append(row)
    return result


def compiled_inputs(records, source):
    files, packages = {}, set()
    for row in records:
        require(not row.get('Error') and not row.get('DepsErrors') and not row.get('Incomplete'),
                'Incomplete selected Go package closure')
        module = row.get('Module', {})
        require(not module.get('Replace'), 'Go module replacement refused')
        if not module.get('Main'):
            continue
        require(module['Path'] == MODULE_ID and row['ImportPath'] not in packages,
                'Unexpected or duplicate main-module package')
        packages.add(row['ImportPath'])
        directory = safe(row['Dir'])
        require(directory == source / MODULE or source / MODULE in directory.parents,
                'Main-module package escapes original archive')
        for field in INPUT_FIELDS:
            for name in row.get(field, []):
                path = Path(name) if Path(name).is_absolute() else directory / relative(name)
                path = safe(path)
                require(source / MODULE in path.parents and path.is_file(), 'Selected compiler input escapes module')
                rel = path.relative_to(source).as_posix()
                files[rel] = {'path': rel, 'sha256': sha(path), 'size': path.stat().st_size,
                              'mode': path.stat().st_mode & 0o777}
    require(MODULE_ID + '/cmd/qxctl' in packages and files, 'qxctl executable closure absent')
    return [files[name] for name in sorted(files)]


def equal_inputs(original, selected):
    require(original == selected, 'Original and cohort compiled/embedded input closures differ')


def graph_matches(records, frozen):
    require(not any(r.get('Replace') or r.get('Error') for r in records), 'Invalid module graph')
    actual = {r['Path']: r for r in records}; expected = {r['Path']: r for r in frozen}
    require(len(actual) == len(records) and len(expected) == len(frozen) and set(actual) == set(expected),
            'Module graph membership differs from original source map')
    for name, row in expected.items():
        for field in ('Version', 'Main', 'Sum', 'GoModSum'):
            if field in row:
                require(actual[name].get(field) == row[field], 'Frozen module graph/checksum differs')


def raw_source_matches(repository, source, commit):
    expected = {}
    for record in git(repository, 'ls-tree', '-r', '-z', commit).split(b'\0'):
        if not record: continue
        header, name = record.split(b'\t'); mode, kind, blob = header.decode().split(); name = name.decode()
        relative(name)
        require(kind == 'blob' and mode in ('100644', '100755'), 'Raw source contains unselected Git entry')
        expected[name] = {'blob': blob, 'mode': 0o755 if mode == '100755' else 0o644}
    actual = {}
    for row in inventory(source):
        raw = regular(source, row['path']).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        actual[row['path']] = {'blob': blob, 'mode': row['mode']}
    require(actual == expected, 'Raw cohort source differs from exact Git tree')


def extract(archive, destination):
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:') as stream:
        names = set()
        for item in stream.getmembers():
            relative(item.name.rstrip('/'))
            require(item.name == MODULE or item.name.startswith(MODULE + '/') or
                    item.name == 'tools', 'Unexpected original module archive member')
            require((item.isdir() or item.isfile()) and item.name not in names,
                    'Linked, duplicate or nonregular archive member')
            names.add(item.name)
        stream.extractall(destination, filter='data')


def validate_artifact(evidence, build_info, expected, binary_sha256):
    require(evidence['protocol'] == 'symphony.artifact-build-identity.v1' and
            evidence['component_id'] == 'qxctl' and evidence['version'] == '0.1.0-dev' and
            evidence['isolated_builds'] == 2 and evidence['reproducibility'] == 'verified_on_recorded_profile' and
            evidence['publication_authorized'] is False, 'Unexpected original recipe evidence')
    require(build_info['protocol'] == 'symphony.qxctl.build-info.v1' and
            build_info['component_id'] == 'qxctl' and build_info['version'] == '0.1.0-dev' and
            build_info['source_state'] == 'stamped', 'qxctl stamp is absent or invalid')
    for key, value in {**expected, 'executable_sha256': binary_sha256}.items():
        require(evidence.get(key) == value, 'Recipe artifact identity differs: ' + key)
        if key not in ('go_mod_sha256', 'go_sum_sha256', 'release_identity_catalog_sha256'):
            require(build_info.get(key) == value, 'Executable source identity differs: ' + key)


def build_identity(repository, source, output, *, go, cmake, gomodcache, commit, tree,
                   export=None, privacy_policy=None, timeout=1800):
    repository, source, cache = (safe(p) for p in (repository, source, gomodcache))
    go, cmake = (Path(p).resolve(strict=True) for p in (go, cmake))
    require(all(p.is_file() and os.access(p, os.X_OK) for p in (go, cmake)), 'Selected build tool absent')
    require(repository.is_dir() and source.is_dir() and cache.is_dir(), 'Selected source/cache absent')
    epoch = identity(repository, commit, tree)
    recipe = regular(repository, RECIPE_PATH)
    require(recipe.read_bytes() == git(repository, 'show', commit + ':' + RECIPE_PATH), 'Working recipe differs from committed source')
    scanner = None
    source_identity = {'kind': 'exact_committed_source_archive', 'commit': commit, 'tree': tree}
    if export:
        export = safe(export)
        require(privacy_policy is not None, 'Reviewed export requires its private privacy policy')
        spec = importlib.util.spec_from_file_location('qxctl_exporter', ROOT / 'source-export/export_source.py')
        scanner = importlib.util.module_from_spec(spec); spec.loader.exec_module(scanner)
        scanner.configure_policy(privacy_policy)
        proof = scanner.verify(export, repository)
        require(inventory(source) == inventory(export / 'source'), 'Cohort source differs from reviewed export')
        source_identity = {'kind': 'verified_reviewed_derived_export', 'export_digest': proof['export_digest'],
                           'archive_sha256': proof['archive_sha256'], 'is_original_git_tree': False}
    else:
        require(privacy_policy is None, 'Privacy policy requires an explicit reviewed export')
    protected = [repository, source, cache, go, cmake, ROOT]
    if export: protected.append(export)
    if privacy_policy: protected.append(safe(privacy_policy))
    work = fresh(output, protected)
    for name in ('home', 'tmp', 'logs'):
        (work / name).mkdir(mode=0o700)
    runner = Runner(work, clean_environment(work, go, cmake, cache), timeout)
    result = {'protocol': 'symphony.distribution.qxctl-original-source.v1', 'state': 'incomplete',
              'component_id': 'qxctl', 'helper_sha256': sha(__file__), 'cohort_source': source_identity,
              'original_source': {'commit': commit, 'tree': tree, 'source_date_epoch': epoch},
              'recipe': {'id': RECIPE, 'path': RECIPE_PATH, 'sha256': sha(recipe), 'modified': False},
              'network_policy': 'local_file_proxy_only_no_network_or_VCS_fallback',
              'toolchain_binaries': {'go_sha256': sha(go), 'cmake_sha256': sha(cmake)},
              'logs': runner.logs, 'release_acceptance_complete': False, 'publication_authorized': False}
    def save():
        (work / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    save()
    try:
        target = runner.run('native-toolchain', [go, 'env', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH']).decode().splitlines()
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
        require(target == ['go1.26.5', {'Darwin': 'darwin', 'Linux': 'linux'}.get(platform.system()), arch] and
                arch is not None, 'Exact native Go1.26.5 target required')
        original = work / 'original-source'; archive = work / 'original-module.tar'
        archive.write_bytes(git(repository, 'archive', '--format=tar', commit, MODULE))
        extract(archive, original)
        original_module = inventory(original / MODULE)
        cohort_module = inventory(source / MODULE)
        original_paths = {r['path']: r for r in original_module}; cohort_paths = {r['path']: r for r in cohort_module}
        require(original_paths.keys() == cohort_paths.keys(), 'Cohort qxctl module membership differs')
        differences = [name for name in original_paths if original_paths[name] != cohort_paths[name]]
        if not export:
            # A raw CI source is admitted only when its entire source tree is
            # byte/mode-identical to the selected commit, not just this module.
            raw_source_matches(repository, source, commit)
        offline = dict(runner.env, GOPROXY='off')
        mapping = json.loads(git(repository, 'show', commit + ':cmake/mvp-dependencies.json'))
        frozen = next(r for r in mapping['go_modules'] if r['path'] == MODULE)['resolved_graph']
        rows = objects(runner.run('offline-module-graph', [go, 'list', '-mod=readonly', '-m', '-json', 'all'], original / MODULE, offline))
        graph_matches(rows, frozen)
        runner.run('offline-module-verification', [go, 'mod', 'verify'], original / MODULE, offline)
        closures = []
        for label, root in (('original', original), ('cohort', source)):
            records = objects(runner.run(label + '-compiled-inputs', [go, 'list', '-mod=readonly', '-deps', '-compiled', '-json', './cmd/qxctl'], root / MODULE, offline))
            closures.append(compiled_inputs(records, root))
        equal_inputs(*closures)
        for name in ('go.mod', 'go.sum'):
            require(regular(original, MODULE + '/' + name).read_bytes() == regular(source, MODULE + '/' + name).read_bytes(),
                    'Original and cohort Go manifests differ')
        result['compiled_input_equivalence'] = {'method': 'native_go_list_deps_compiled_json_CGO0',
            'goos': target[1], 'goarch': target[2], 'inputs': closures[0],
            'inventory_sha256': hashlib.sha256(canonical(closures[0])).hexdigest(),
            'original_matches_cohort_source': True, 'uncompiled_module_differences': differences}
        expected = {'source_commit': commit, 'source_tree': tree, 'source_date_epoch': epoch,
                    'dependency_map_sha256': hashlib.sha256(git(repository, 'show', commit + ':cmake/mvp-dependencies.json')).hexdigest(),
                    'release_identity_catalog_sha256': hashlib.sha256(git(repository, 'show', commit + ':cmake/mvp-release-identities.json')).hexdigest(),
                    'go_mod_sha256': sha(original / MODULE / 'go.mod'), 'go_sum_sha256': sha(original / MODULE / 'go.sum'),
                    'build_recipe': RECIPE, 'go_version': target[0], 'goos': target[1], 'goarch': target[2]}
        save()
        runner.run('original-two-build-recipe', [cmake, '-DQXCTL_MODULE=' + str(repository / MODULE),
                   '-DQXCTL_GO=' + str(go), '-DQXCTL_WORK=' + str(work / 'recipe'), '-P', recipe])
        require(sha(archive) == sha(work / 'recipe/source.tar'), 'Recipe source archive differs from inspected original inputs')
        binaries = [regular(work, 'recipe/' + name + '/bin/qxctl') for name in ('first', 'second')]
        hashes = [sha(p) for p in binaries]
        require(hashes[0] == hashes[1], 'Original recipe builds differ')
        evidence = json.loads(regular(work, 'recipe/artifact-identity.json').read_bytes())
        info = json.loads(runner.run('selected-binary-identity', [binaries[0], 'version', '--json'], env=offline))
        validate_artifact(evidence, info, expected, hashes[0])
        require(inventory(original / MODULE) == original_module and inventory(source / MODULE) == cohort_module,
                'Inspected module source changed during build')
        for name in ('first', 'second'):
            require(inventory(work / 'recipe' / name / MODULE) == original_module, 'Recipe extracted source changed')
        for binary in binaries:
            raw = binary.read_bytes()
            require(not any(str(p).encode() in raw for p in (work, repository, source, cache, go.parent.parent)) and
                    not any(s in raw for s in (b'/Users/', b'/home/runner/', b'/opt/homebrew/')),
                    'Private build path retained in qxctl')
            if scanner: scanner.scan('go/qxctl/bin/qxctl', raw)
        identity(repository, commit, tree)
        require(sha(recipe) == result['recipe']['sha256'] and sha(__file__) == result['helper_sha256'],
                'Build helper or original recipe changed')
        result.update(state='reproducible_stamped_original_git_source', binary='recipe/first/bin/qxctl',
                      binary_sha256=hashes[0], isolated_builds=2, build_info=info, artifact_identity=evidence,
                      artifact_identity_sha256=sha(work / 'recipe/artifact-identity.json'),
                      original_module_archive_sha256=sha(archive),
                      original_module_inventory_sha256=hashlib.sha256(canonical(original_module)).hexdigest(),
                      privacy={'private_build_paths_absent': True, 'publisher_policy_scanned': bool(scanner),
                               'policy_digest': scanner.POLICY_DIGEST if scanner else None,
                               'private_original_fixture_archive_distributable': False})
        if scanner: scanner.scan('qxctl-identity.json', canonical(result))
        save()
        return result
    except BaseException:
        result['state'] = 'failed'; save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'source', 'go', 'cmake', 'gomodcache', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--export', type=Path)
    parser.add_argument('--privacy-policy', type=Path)
    parser.add_argument('--timeout', type=int, default=1800)
    args = parser.parse_args()
    binding = json.loads((ROOT / 'source-binding.json').read_text())
    result = build_identity(**vars(args), commit=binding['source_commit'], tree=binding['source_tree'])
    print(json.dumps({'state': result['state'], 'binary_sha256': result['binary_sha256'],
                      'compiled_inputs': len(result['compiled_input_equivalence']['inputs']),
                      'publication_authorized': False}))


if __name__ == '__main__':
    main()
