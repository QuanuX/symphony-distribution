#!/usr/bin/env python3
"""Build a derived primary client and qualify exact bytes with native Codex.

The selected client Git tree remains unchanged. Three generated catalog binding
files are explicitly derived, not represented as original Git blobs. Existing
fixture suites and the legacy real-client verifier are executed unchanged.
Private profiles/transcripts never enter the distributable package or summary.
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
import stat
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_rewrap as native
from qualification import d09_platform as gate
from qualification import d10_build_retention as retention

CLIENT = {'repository': 'QuanuX/symphony-codex-ipc-mcp-and-skills',
          'commit': '572627e939250763756167a9dc05d8cb37ab4e30',
          'tree': '83a5aad51f809358b72d2cb9f96833b8977b57a0'}
PROTOCOL = 'symphony.distribution.primary-client.v1'
DERIVED = {'catalog/tools.json', 'catalog/beta-source.json', 'catalog/stamped-owner-delta.json'}
LIMIT = 512 * 1024 * 1024
REQUIRED_SUITES = {'transport', 'bounded-hashing', 'mcp-integration', 'public-operation-tools',
    'client-adapters', 'qualification-report', 'beta-compatibility', 'distribution-compatibility', 'catalog-contract'}
OWNED_OUTPUTS = {}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(path, raw, mode=0o600):
    path = gate.safe(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    path.chmod(mode)


def sha(path):
    return retention.sha(path)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def helpers():
    return {**native.helpers(), **{name: sha(ROOT / name) for name in
        ('qualification/primary_client.py', 'qualification/primary-client-tools.json')}}


def toolkit_identity(selected_helpers):
    commit = os.environ.get('GITHUB_SHA', '')
    need(re.fullmatch('[0-9a-f]{40}', commit) and git(ROOT, 'rev-parse', 'HEAD').decode().strip() == commit,
         'Exact committed executing workflow source required')
    for name, digest in selected_helpers.items():
        need(hashlib.sha256(git(ROOT, 'show', commit + ':' + name)).hexdigest() == digest,
             'Executing helper differs from committed workflow source')
    return {'repository': 'QuanuX/symphony-distribution', 'commit': commit,
            'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}').decode().strip()}


def clean_environment(root, tools=(), developer_dir=None):
    for name in ('home', 'tmp', 'cache'):
        (root / name).mkdir(mode=0o700)
    paths = list(dict.fromkeys([str(Path(p).absolute().parent) for p in tools] + ['/usr/bin', '/bin', '/usr/sbin', '/sbin']))
    env = {'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'), 'XDG_CACHE_HOME': str(root / 'cache'),
           'PATH': os.pathsep.join(paths), 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
           'SOURCE_DATE_EPOCH': '0', 'ZERO_AR_DATE': '1', 'CMAKE_BUILD_PARALLEL_LEVEL': '2'}
    if developer_dir:
        selected = gate.safe(developer_dir)
        need(selected.is_dir(), 'Explicit Apple developer directory absent')
        env['DEVELOPER_DIR'] = str(selected)
    return env


def command(argv, env, output, label, timeout=900):
    need(re.fullmatch('[a-z0-9-]+', label), 'Invalid log label')
    path = output / (label + '.log')
    with path.open('xb') as stream:
        result = subprocess.run(list(map(str, argv)), env=env, cwd=output, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    need(result.returncode == 0, 'Command failed: ' + label)
    need(path.stat().st_size <= 16 * 1024 * 1024, 'Command log exceeds bound')
    return path


def read_json_command(argv, env, output, label):
    return gate.read(command(argv, env, output, label, 60))


def git(repository, *args):
    return subprocess.check_output(['git', '-C', str(repository), *args], stdin=subprocess.DEVNULL, timeout=60)


def export_client(repository, destination, privacy):
    need(git(repository, 'rev-parse', 'HEAD').decode().strip() == CLIENT['commit'] and
         git(repository, 'rev-parse', 'HEAD^{tree}').decode().strip() == CLIENT['tree'], 'Exact selected client Git checkout required')
    raw = git(repository, 'archive', '--format=tar', CLIENT['commit'])
    need(len(raw) <= 32 * 1024 * 1024, 'Client source archive exceeds bound')
    expected = {}
    for item in git(repository, 'ls-tree', '-rz', '--full-tree', CLIENT['commit']).split(b'\0'):
        if not item:
            continue
        metadata, name = item.split(b'\t', 1); mode, kind, blob = metadata.decode().split()
        name = name.decode(); retention.relative(name)
        need(kind == 'blob' and mode in ('100644', '100755') and name not in expected, 'Unsupported client Git entry')
        expected[name] = (int(mode[-3:], 8), blob)
    destination.mkdir(mode=0o700)
    observed, files = set(), {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/') if member.isdir() else member.name
            retention.relative(name)
            if member.isdir():
                continue
            need(member.isfile() and name in expected and name not in observed and 0 <= member.size <= 8 * 1024 * 1024,
                 'Unexpected client source archive member')
            content = archive.extractfile(member).read(member.size + 1)
            mode, blob = expected[name]
            need(len(content) == member.size and hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == blob,
                 'Client source Git blob differs')
            privacy.scan(name, content)
            path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
            write(path, content, mode); observed.add(name)
            files[name] = {'sha256': hashlib.sha256(content).hexdigest(), 'mode': mode, 'git_blob': blob}
    need(observed == expected.keys(), 'Incomplete client source export')
    return {'source': CLIENT, 'git_archive_sha256': hashlib.sha256(raw).hexdigest(), 'files': files}


def verify_export(root, record):
    actual = {p.relative_to(root).as_posix(): p for p in root.rglob('*') if not p.is_dir()}
    need(actual.keys() == record['files'].keys(), 'Original client export membership changed')
    for name, path in actual.items():
        row = record['files'][name]
        need(not path.is_symlink() and path.stat().st_nlink == 1 and stat.S_IMODE(path.stat().st_mode) == row['mode'] and
             sha(path) == row['sha256'], 'Original client source changed')


def codex_lock(profile):
    lock = gate.read(ROOT / 'qualification/primary-client-tools.json')
    need(lock['repository'] == 'openai/codex' and lock['version'] == '0.169.0' and profile in gate.PROFILES,
         'Unselected Codex release or platform')
    row = lock['profiles'][profile]
    need(row['url'] == 'https://github.com/openai/codex/releases/download/' + lock['release_tag'] + '/' + row['filename'] and
         '/' not in row['member'] and row['filename'] == row['member'] + '.tar.gz', 'Codex asset route differs')
    gate.digest(row['sha256'])
    return lock, row


def extract_codex(archive, destination, row):
    need(archive.stat().st_size == row['size'] and sha(archive) == row['sha256'], 'Official Codex asset bytes differ')
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, mode='r:gz') as stream:
        members = stream.getmembers()
        need(len(members) == 1 and members[0].name == row['member'] and members[0].isfile() and
             0 < members[0].size <= LIMIT and not members[0].pax_headers.get('linkpath'), 'Unexpected Codex archive layout')
        member = members[0]
        data = stream.extractfile(member).read(member.size + 1)
        need(len(data) == member.size, 'Truncated Codex executable')
    path = destination / 'codex'; write(path, data, 0o755)
    return path


def verify_codex_unchanged(archive, executable, asset, executable_sha256):
    need(not archive.is_symlink() and not executable.is_symlink() and
         archive.stat().st_size == asset['size'] and sha(archive) == asset['sha256'] and
         sha(executable) == executable_sha256 and stat.S_IMODE(executable.stat().st_mode) == 0o755,
         'Selected Codex archive or executable changed')


def derive_catalog(source, derived, qxctl, proof, expected_profile, env, work):
    shutil.copytree(source, derived, copy_function=shutil.copyfile)
    for original in source.rglob('*'):
        if original.is_file():
            (derived / original.relative_to(source)).chmod(stat.S_IMODE(original.stat().st_mode))
    old_catalog = gate.read(source / 'catalog/tools.json')
    old_metadata = gate.read(source / 'catalog/beta-source.json')
    version = read_json_command([qxctl, 'version', '--json'], env, work, 'qxctl-version')
    observed = read_json_command([qxctl, 'commands', 'manifest', '--json'], env, work, 'observed-registry')
    expected = gate.read(source / 'catalog/beta-expected-registry.json')
    goos, goarch = ('darwin', 'arm64') if expected_profile == 'macos15-arm64' else ('linux', 'arm64' if expected_profile.endswith('arm64') else 'amd64')
    need(version == proof['build_info'] and version['source_state'] == 'stamped' and version['goos'] == goos and version['goarch'] == goarch and
         all(version['source_' + key] == proof['original_source'][key] for key in ('commit', 'tree')) and
         version['executable_sha256'] == sha(qxctl) == proof['binary_sha256'], 'Selected primary qxctl identity differs')
    need(expected['commands'] == observed['commands'] and observed['executable_digest'] == 'sha256:' + sha(qxctl),
         'Primary native registry differs from frozen client contracts')
    generated = work / 'generated-catalog.json'
    command([sys.executable, '-B', source / 'scripts/build_tool_catalog.py', '--qxctl', qxctl, '--output', generated], env, work, 'catalog', 600)
    catalog = gate.read(generated)
    need({k: v for k, v in catalog.items() if k != 'source_registry_digest'} ==
         {k: v for k, v in old_catalog.items() if k != 'source_registry_digest'},
         'Primary catalog command/help/descriptor contract changed')
    metadata = dict(old_metadata)
    metadata.update(core={**old_metadata['core'], 'commit': version['source_commit'], 'tree': version['source_tree']},
                    qxctl_build=version, client_dependency=CLIENT,
                    observed_registry_digest=observed['registry_digest'], catalog_sha256='sha256:' + sha(generated))
    metadata['original_git_source_binding'] = {**old_metadata['original_git_source_binding'],
        'proof_sha256': 'sha256:' + hashlib.sha256(canonical(proof)).hexdigest(),
        'compiled_input_count': len(proof['compiled_input_equivalence']['inputs']),
        'derived_source_export_digest': proof['cohort_source']['export_digest'], 'isolated_builds': proof['isolated_builds']}
    delta = gate.read(source / 'catalog/stamped-owner-delta.json')
    delta.update(base_client_commit=CLIENT['commit'], old_qxctl_sha256=old_metadata['qxctl_build']['executable_sha256'],
                 new_qxctl_sha256=version['executable_sha256'], scope='Primary platform artifact binding only; command records and tool descriptors unchanged')
    contents = {'catalog/tools.json': generated.read_bytes(), 'catalog/beta-source.json': canonical(metadata),
                'catalog/stamped-owner-delta.json': canonical(delta)}
    for name, raw in contents.items():
        (derived / name).unlink(); write(derived / name, raw, 0o644)
    return version, expected, observed, contents


def derivation_proof(source, derived, export, generated, profile, qxctl_proof_sha256):
    need(set(generated) == DERIVED, 'Unreviewed generated source paths')
    verify_export(source, export)
    actual = {p.relative_to(derived).as_posix(): p for p in derived.rglob('*') if not p.is_dir()}
    need(actual.keys() == export['files'].keys(), 'Derived source membership differs')
    rows = {}
    for name, path in actual.items():
        need(not path.is_symlink() and path.stat().st_nlink == 1, 'Derived source alias refused')
        original = export['files'][name]
        need(stat.S_IMODE(path.stat().st_mode) == original['mode'], 'Derived source mode differs')
        expected = generated[name] if name in DERIVED else (source / name).read_bytes()
        need(path.read_bytes() == expected, 'Unreviewed derived source change')
        rows[name] = {'original_sha256': original['sha256'], 'derived_sha256': sha(path), 'mode': original['mode']}
    return {'protocol': 'symphony.distribution.primary-client-derivation.v1', 'origin': CLIENT,
        'profile': profile, 'is_original_git_tree': False, 'generated_paths': sorted(DERIVED),
        'original_git_archive_sha256': export['git_archive_sha256'],
        'qxctl_source_proof_sha256': qxctl_proof_sha256, 'files': rows,
        'native_command_contracts_unchanged': True, 'publication_authorized': False}


def finalize_bridge_copy(built, work, env, index, host):
    need(index in (0, 1) and host in ('macos', 'ubuntu'), 'Unsupported bridge finalization selection')
    path = work / ('final-bridge-' + str(index))
    if host == 'macos':
        # Apple strip rebuilds the linker ad-hoc signature using the output
        # basename. Separate roots must retain the same shipped filename.
        path.mkdir(mode=0o700)
        path = path / 'symphony-mcp'
    write(path, built.read_bytes(), 0o755)
    command(['/usr/bin/strip', '-S' if host == 'macos' else '--strip-unneeded', path], env, work, 'strip-' + str(index))
    if host == 'macos':
        command(['/usr/bin/codesign', '--verify', '--strict', path], env, work, 'verify-adhoc-' + str(index))
    return path


def finalized_bridge(source, work, env, compiler, cmake, ctest, profile, developer_dir):
    host = 'macos' if profile.startswith('macos') else 'ubuntu'
    arch = 'arm64' if profile.endswith('arm64') else 'x86_64'
    first = work / 'fixture-build'
    build_env = dict(env, CXXFLAGS=f'-ffile-prefix-map={source}=/symphony-client -ffile-prefix-map={work}=/symphony-build')
    args = [sys.executable, '-B', source / 'ci/qualify_local.py', '--source', source, '--out', first,
            '--compiler', compiler, '--cmake', cmake, '--ctest', ctest, '--expected-os', host,
            '--expected-arch', arch, '--host-kind', 'vm', '--jobs', '2']
    args += ['--macos-deployment-target', '14.0'] if host == 'macos' else ['--ubuntu-version', profile[6:11]]
    command(args, build_env, work, 'focused-nine-suites', 1800)
    report = gate.read(first / 'RESULTS.json')
    need(report['status'] == 'bridge_tests_passed_on_observed_host' and set(report['passed_test_suites']) == REQUIRED_SUITES,
         'Required native client suites did not all pass')
    second = work / 'repeat-build'
    configure = [cmake, '-S', source, '-B', second, '-G', 'Unix Makefiles', '-DCMAKE_BUILD_TYPE=Release',
                 '-DCMAKE_CXX_COMPILER=' + str(compiler), '-DBUILD_TESTING=OFF']
    if host == 'macos':
        configure += ['-DCMAKE_OSX_ARCHITECTURES=arm64', '-DCMAKE_OSX_DEPLOYMENT_TARGET=14.0']
    command(configure, build_env, work, 'repeat-configure')
    command([cmake, '--build', second, '--parallel', '2'], build_env, work, 'repeat-build')
    binaries = []
    for index, built in enumerate((first / 'build/symphony-mcp', second / 'symphony-mcp')):
        binaries.append(finalize_bridge_copy(built, work, env, index, host))
    need(sha(binaries[0]) == sha(binaries[1]), 'Independent finalized bridge bytes differ')
    raw = binaries[0].read_bytes()
    need(not any(str(p).encode() in raw for p in (source, work, ROOT, Path(env['HOME']))), 'Private path in final bridge')
    command([binaries[0], '--version'], env, work, 'final-bridge-version')
    loader = command(['/usr/bin/otool', '-L', binaries[0]] if host == 'macos' else ['/usr/bin/ldd', binaries[0]], env, work, 'final-loader')
    text = loader.read_text()
    need('not found' not in text and not any(str(p) in '\n'.join(text.splitlines()[1:]) for p in (source, work, ROOT)),
         'Final bridge has unresolved or private loader dependency')
    return binaries[0], report


def package_inventory(path):
    rows, total = {}, 0
    with zipfile.ZipFile(path) as archive:
        need(len(archive.infolist()) <= 5000, 'Client package member bound')
        for item in archive.infolist():
            retention.relative(item.filename)
            need(item.filename not in rows and stat.S_ISREG(item.external_attr >> 16) and item.file_size <= LIMIT,
                 'Client package nonregular/duplicate member')
            total += item.file_size
            need(total <= LIMIT, 'Client package expanded size bound')
            rows[item.filename] = 'sha256:' + hashlib.sha256(archive.read(item)).hexdigest()
    return rows


def unpack_package(package, output, inventory):
    need(package_inventory(package) == inventory, 'Selected final package inventory differs')
    output.mkdir(mode=0o700)
    with zipfile.ZipFile(package) as archive:
        for member in archive.infolist():
            mode = stat.S_IMODE(member.external_attr >> 16)
            need(mode == (0o755 if member.filename == 'bin/symphony-mcp' else 0o644), 'Final package mode differs')
            path = output / member.filename; path.parent.mkdir(parents=True, exist_ok=True)
            write(path, archive.read(member), mode)
    verify_package_tree(output, inventory)


def verify_package_tree(output, inventory):
    paths = {p.relative_to(output).as_posix(): p for p in output.rglob('*') if not p.is_dir()}
    need(paths.keys() == inventory.keys(), 'Extracted package membership differs')
    for name, path in paths.items():
        need(not path.is_symlink() and path.stat().st_nlink == 1 and
             stat.S_IMODE(path.stat().st_mode) == (0o755 if name == 'bin/symphony-mcp' else 0o644) and
             'sha256:' + sha(path) == inventory[name], 'Extracted final package bytes or modes differ')


def compatibility_packet(source, stage, package, bridge, qxctl, version, expected, observed, identities, actual, work):
    sys.path.insert(0, str(source / 'scripts'))
    verifier = load_module('primary_client_legacy_verifier', source / 'scripts/verify_beta_compatibility.py')
    packet = work / 'packet'; packet.mkdir(mode=0o700)
    attachments = {}
    def attach(key, raw, filename=None):
        filename = filename or key + '.json'; write(packet / filename, raw)
        attachments[key] = {'path': filename, 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()}
    for key, path in (('qxctl', qxctl), ('bridge', bridge), ('catalog', stage / 'catalog/tools.json'), ('package', package)):
        attach(key, path.read_bytes(), key + '.bin')
    inventory = package_inventory(package)
    for key, value in (('qxctl_version', version), ('expected_registry', expected), ('observed_registry', observed),
                       ('package_inventory', inventory), ('source_inventory', {'source': CLIENT, 'files': {k: v for k, v in inventory.items() if k != 'bin/symphony-mcp'}})):
        attach(key, canonical(value))
    clients, reports = [], {}
    for mode in ('stdio', 'same_user_ipc'):
        report = gate.read(actual / mode / 'RESULTS.json'); clients.append(report['client']); reports[mode] = mode + '-report'
        attach(mode + '-report', canonical(report))
        for suffix, filename in (('config', 'connection.json'), ('assertions', 'ASSERTIONS.json'),
                                 ('readonly', 'readonly.jsonl'), ('enabled', 'enabled.jsonl'), ('restarted', 'restarted.jsonl')):
            attach(mode + '-' + suffix, (actual / mode / filename).read_bytes())
    requirements = {'schema': 'symphony.beta-compatibility.requirements.v1', **identities, 'artifacts': attachments, 'clients': clients}
    observations = {'schema': 'symphony.beta-compatibility.observations.v1', **identities, 'clients': reports,
                    'distribution': 'pending', 'release_acceptance_complete': False, 'publication_authorized': False}
    for name, value in (('requirements', requirements), ('observations', observations)):
        write(packet / (name + '.json'), canonical(value))
    result = verifier.verify(requirements, observations, packet)
    need(result['status'] == 'engineering_review_ready' and not result['pending'], 'Legacy actual-client verifier did not pass')
    write(packet / 'result.json', canonical(result))
    return result, {'requirements_sha256': sha(packet / 'requirements.json'), 'observations_sha256': sha(packet / 'observations.json'),
                    'result_sha256': sha(packet / 'result.json'), 'attachment_count': len(attachments)}


def qualify(args):
    imported = helpers()
    toolkit = toolkit_identity(imported)
    selected_tools = {name: sha(tool) for name, tool in (('compiler', args.compiler), ('cmake', args.cmake), ('ctest', args.ctest))}
    restored = gate.safe(args.restored)
    result, selection = native.admit_restore(restored, args.restore_result_sha256, args.repository, args.privacy_policy)
    profile = selection['profile']; custody = native.reuse.custody(profile, args.output)
    out = retention.fresh(args.output, [restored, gate.safe(args.client_repository), gate.safe(args.repository), ROOT])
    info = out.stat(); OWNED_OUTPUTS[out] = (info.st_dev, info.st_ino)
    privacy = retention.scanner(args.privacy_policy)
    source = out / 'original-source'; exported = export_client(args.client_repository, source, privacy)
    write(out / 'original-source.json', canonical(exported))
    env = clean_environment(out, (sys.executable, args.compiler, args.cmake, args.ctest), args.developer_dir)
    lock, asset = codex_lock(profile)
    archive = out / asset['filename']
    command(['/usr/bin/curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https', '--retry', '3',
             '--connect-timeout', '30', '--max-time', '600', asset['url'], '--output', archive], env, out, 'download-codex', 660)
    codex = extract_codex(archive, out / 'codex', asset)
    codex_sha256 = sha(codex)
    version_path = command([codex, '--version'], env, out, 'codex-version', 30)
    need(version_path.read_text().strip() == 'codex-cli ' + lock['version'], 'Selected Codex executable version differs')
    qxctl = restored / 'restored/cohort/round-1/relocated-prefix/go/qxctl/bin/qxctl'
    proof_path = restored / 'restored/cohort/round-1/qxctl-identity/result.json'; proof = gate.read(proof_path)
    bridge, fixtures = finalized_bridge(source, out, env, args.compiler, args.cmake, args.ctest, profile, args.developer_dir)
    stage = out / 'derived-source'
    version, expected, observed, generated = derive_catalog(source, stage, qxctl, proof, profile, env, out)
    # Bind the exact retained proof bytes, not a reserialized substitute.
    metadata = json.loads(generated['catalog/beta-source.json']); metadata['original_git_source_binding']['proof_sha256'] = 'sha256:' + sha(proof_path)
    generated['catalog/beta-source.json'] = canonical(metadata)
    (stage / 'catalog/beta-source.json').unlink(); write(stage / 'catalog/beta-source.json', generated['catalog/beta-source.json'], 0o644)
    derivation = derivation_proof(source, stage, exported, generated, profile, sha(proof_path))
    for name, row in derivation['files'].items(): privacy.scan(name, (stage / name).read_bytes())
    privacy.scan('bin/symphony-mcp', bridge.read_bytes())
    # Re-run only the generated metadata boundary; unchanged native suites were tested above.
    command([sys.executable, '-B', stage / 'tests/test_catalog.py'], env, out, 'derived-catalog-contract', 120)
    artifact = out / 'artifact'; artifact.mkdir(mode=0o700)
    package = artifact / 'symphony-client.zip'
    for label, destination in (('package', package), ('package-repeat', out / 'repeat.zip')):
        command([sys.executable, '-B', stage / 'scripts/package_release.py', '--binary', bridge, '--output', destination], env, out, label)
    need(sha(package) == sha(out / 'repeat.zip'), 'Repeated client package bytes differ')
    inventory = package_inventory(package)
    need(all(name == 'bin/symphony-mcp' or inventory[name] == 'sha256:' + derivation['files'][name]['derived_sha256'] for name in inventory),
         'Packaged member differs from admitted derivation')
    frozen = gate.read(ROOT / 'source-binding.json')
    identities = {'sources': {'core': {'repository': 'QuanuX/Symphony', 'commit': frozen['source_commit'], 'tree': frozen['source_tree']}, 'plugin': CLIENT},
        'bindings': {'qxctl_sha256': 'sha256:' + sha(qxctl), 'catalog_sha256': 'sha256:' + sha(stage / 'catalog/tools.json'),
                     'bridge_sha256': 'sha256:' + sha(bridge), 'package_sha256': 'sha256:' + sha(package),
                     'expected_registry_digest': expected['registry_digest'], 'observed_registry_digest': observed['registry_digest']}}
    write(out / 'identities.json', canonical(identities))
    installed = out / 'extracted-client'; unpack_package(package, installed, inventory)
    actual = out / 'actual-codex'
    verify_codex_unchanged(archive, codex, asset, codex_sha256)
    command([sys.executable, '-B', installed / 'scripts/qualify_beta_client.py', '--codex', codex, '--qxctl', qxctl, '--bridge', installed / 'bin/symphony-mcp',
             '--catalog', installed / 'catalog/tools.json', '--identities', out / 'identities.json', '--out', actual], env, out, 'actual-codex', 1500)
    legacy, packet = compatibility_packet(source, installed, package, installed / 'bin/symphony-mcp', qxctl, version, expected, observed, identities, actual, out)
    verify_codex_unchanged(archive, codex, asset, codex_sha256)
    client_record = gate.read(actual / 'CLIENT.json')
    need(client_record['executable_sha256'] == 'sha256:' + codex_sha256 and client_record['version'] == 'codex-cli ' + lock['version'],
         'Actual Codex harness executable record differs')
    packet['client_record_sha256'] = sha(actual / 'CLIENT.json')
    verify_package_tree(installed, inventory)
    need(package_inventory(package) == inventory and 'sha256:' + sha(package) == identities['bindings']['package_sha256'],
         'Final client package changed during qualification')
    need(derivation_proof(source, stage, exported, generated, profile, sha(proof_path)) == derivation and helpers() == imported,
         'Client source or qualification helpers changed')
    need(native.admit_restore(restored, args.restore_result_sha256, args.repository, args.privacy_policy)[0] == result,
         'Original native inputs changed')
    need({name: sha(tool) for name, tool in (('compiler', args.compiler), ('cmake', args.cmake), ('ctest', args.ctest))} == selected_tools,
         'Selected build tools changed during client qualification')
    write(artifact / 'derivation.json', canonical(derivation), 0o644)
    write(artifact / 'package-inventory.json', canonical(inventory), 0o644)
    summary = {'protocol': PROTOCOL, 'state': 'primary_client_engineering_checks_passed', 'profile': profile,
        'sources': identities['sources'], 'bindings': identities['bindings'], 'client_source_kind': 'explicit_derived_catalog_package',
        'client_origin_is_unchanged_git_tree': True, 'package_is_original_git_tree': False,
        'original_native_lineage': result['lineage'], 'restore_result_sha256': args.restore_result_sha256,
        'native_payload_rebuilt': False, 'codex': {'version': lock['version'], 'release_tag': lock['release_tag'], 'source_commit': lock['source_commit'],
            'asset': asset, 'executable_sha256': codex_sha256}, 'host': custody,
        'fixture_suites': sorted(fixtures['passed_test_suites']), 'actual_codex_cases': 22, 'connection_modes': ['stdio', 'same_user_ipc'],
        'client_executed_from_verified_package': True,
        'compiler_version': fixtures['compiler_version'],
        'build_tool_sha256': selected_tools, 'executing_toolkit': toolkit,
        'legacy_verifier': legacy, 'private_packet': packet, 'derivation_sha256': sha(artifact / 'derivation.json'),
        'package_inventory_sha256': sha(artifact / 'package-inventory.json'), 'executing_helpers': imported,
        'independent_finalized_bridge_builds_equal': True, 'repeated_package_bytes_equal': True,
        'native_inputs_unchanged': True, 'maintained_adapters': ['Claude Code', 'Antigravity', 'generic stdio', 'explicit WSL'],
        'real_client_qualification': ['Codex'], 'symphony_provider_operations_requested': False, 'model_turns': 0,
        'fresh_physical_host_acceptance': False, 'native_pkg_execution': False, 'public_channel_retrieval': False,
        'publication_authorized': False, 'release_acceptance_complete': False}
    privacy.scan('result.json', canonical(summary))
    write(artifact / 'result.json', canonical(summary), 0o644)
    return summary


def failure_summary(output, error):
    output = gate.safe(output)
    if output not in OWNED_OUTPUTS or not output.is_dir():
        return
    info = output.stat()
    if (info.st_dev, info.st_ino) != OWNED_OUTPUTS[output] or (output / 'INCOMPLETE.json').exists():
        return
    logs = sorted(output.glob('*.log'), key=lambda p: p.stat().st_mtime_ns)
    logs = [p for p in logs if not p.is_symlink() and p.is_file() and p.stat().st_nlink == 1]
    record = {'protocol': PROTOCOL, 'state': 'incomplete', 'error_type': type(error).__name__,
              'last_command': logs[-1].stem if logs else None, 'last_log_sha256': sha(logs[-1]) if logs else None,
              'publication_authorized': False, 'release_acceptance_complete': False}
    write(output / 'INCOMPLETE.json', canonical(record), 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('restored', 'repository', 'client-repository', 'privacy-policy', 'output', 'compiler', 'cmake', 'ctest'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--restore-result-sha256', required=True)
    parser.add_argument('--developer-dir', type=Path)
    args = parser.parse_args()
    try:
        result = qualify(args)
        print(json.dumps({'state': result['state'], 'profile': result['profile'], 'actual_codex_cases': result['actual_codex_cases']}))
    except Exception as error:
        # No raw command output, credentials, profiles or transcripts in public diagnostics.
        failure_summary(args.output, error)
        raise


if __name__ == '__main__':
    main()
