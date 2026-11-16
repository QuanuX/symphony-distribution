"""Closed, source-bound S05 Go delivery policy; no package-supplied argv."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {'macos15-arm64': ('darwin', 'arm64', 'osx-arm64'),
            'ubuntu24.04-amd64': ('linux', 'amd64', 'linux-64'),
            'ubuntu26.04-amd64': ('linux', 'amd64', 'linux-64'),
            'ubuntu24.04-arm64': ('linux', 'arm64', 'linux-aarch64')}
FIXTURE_PROFILE = 'local-macos-amd64-fixture'
PROFILES[FIXTURE_PROFILE] = ('darwin', 'amd64', 'osx-64')
RETIREMENT = 'symphony.package-retirement.v1'
DISPATCH = 'symphony.package-owner-dispatch.v1'
RECEIPT = 'symphony.knowledge.install-receipt.v2'


def policy(component, binary, version, source, package, contract, kind, selection):
    return {'component_id': component, 'binary_name': binary, 'native_version': version,
            'source_root': source, 'build_package': package, 'owner_contract': contract,
            'kind': 'go_command', 'runtime_owner_kind': kind, 'selection_owner': selection,
            'critical': True, 'contract_version': 1,
            'runtime_receipt': RECEIPT if kind == 'module_receipt_owner' else None,
            'live_raw_cleanup_supported': False, 'automatic_activation': False,
            'automatic_privilege': False, 'runtime_dependencies': []}


OWNERS = {p['component_id']: p for p in [
    policy('secure-identity-access-governance', 'symphony-ssiag', '0.1.0-dev',
           'modules/secure-identity-access-governance', './cmd/symphony-ssiag',
           'ssiag.package-owner.v1', 'module_receipt_owner', 'ssiag_foundation_lifecycle'),
    policy('stav-append-authority', 'symphony-stav-append-authority', '0.2.1',
           'modules/stav-append-authority', './cmd/symphony-stav-append-authority',
           'stav.package-owner.v1', 'module_receipt_owner', 'stav_foundation_lifecycle'),
    policy('accordare-stav-producer', 'symphony-accordare-stav-producer', '0.1.0-dev',
           'modules/accordare-stav-producer', './cmd/symphony-accordare-stav-producer',
           'accordare.package-owner.v1', 'module_receipt_owner', 'accordare_enrollment_supervision'),
    policy('qxctl', 'qxctl', '0.1.0-dev', 'tools/qxctl', './cmd/qxctl',
           'qxctl.executable-and-host-owner.v1', 'raw_executable_host_binding', 'explicit_client_or_linux_host_binding'),
    policy('sov-ssh-adapter', 'sov-ssh-adapter', '0.1.0-dev', 'tools/sov-ssh-adapter', '.',
           'sov-ssh.exact-invocation-owner.v1', 'raw_executable_invocation', 'sov_endpoint_or_qualified_transport_profile'),
    policy('sov-stdio-adapter', 'sov-stdio-adapter', '0.1.0-dev', 'tools/sov-stdio-adapter', '.',
           'sov-stdio.exact-invocation-owner.v1', 'raw_executable_invocation', 'sov_target_and_invocation'),
    policy('sov-transport-profile-admin', 'sov-transport-profile-admin', '0.1.0-dev',
           'tools/sov-transport-profile-admin', '.', 'sov-admin.protected-host-provisioning.v1',
           'protected_host_provisioning', 'protected_host_policy'),
]}
SERVICE_IDS = {name for name, p in OWNERS.items() if p['runtime_receipt']}


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    require(len(data) <= 2 * 1024 * 1024, 'document exceeds bound')
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'duplicate JSON field')
            result[k] = v
        return result
    def number(_):
        raise ValueError('noninteger JSON number')
    return json.loads(data, object_pairs_hook=pairs, parse_float=number, parse_constant=number)


def sealed(value, field):
    return {**value, field: 'sha256:' + sha(canonical(value))}


def validate_seal(value, field, expected):
    require(isinstance(expected, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', expected), 'independent digest required')
    require(value.get(field) == expected and sealed({k: v for k, v in value.items() if k != field}, field)[field] == expected,
            'document digest differs')


def reviewed_binding():
    value = strict_json((ROOT / 'source-binding.json').read_bytes())
    require(set(value) == {'protocol', 'source_commit', 'source_tree', 'source_evidence', 'binding_digest'}, 'source binding fields differ')
    require(value['protocol'] == 'symphony.distribution.go-owner-source.v1', 'source binding protocol differs')
    require(all(re.fullmatch(r'[0-9a-f]{40}', value[k]) for k in ('source_commit', 'source_tree')), 'source object identity invalid')
    validate_seal(value, 'binding_digest', value['binding_digest'])
    return value


def bind_source(repository, commit):
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'exact source commit required')
    repo = Path(repository).resolve(strict=True)
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-C', str(repo), *args], timeout=15)
    tree = git('rev-parse', commit + '^{tree}').decode().strip()
    identities = strict_json(git('show', commit + ':cmake/mvp-release-identities.json'))
    for component, unit in OWNERS.items():
        rows = [p for p in identities['components'] if p['component_id'] == component]
        require(len(rows) == 1 and rows[0]['path'] == unit['source_root'] and rows[0]['kind'] == 'go_command' and
                rows[0]['package_version'] == unit['native_version'], 'source delivery catalog differs from closed owner policy')
    require(b'"native-owner"' in git('show', commit + ':tools/qxctl/cmd/qxctl/commands.go') and
            DISPATCH.encode() in git('show', commit + ':tools/qxctl/internal/knowledgelifecycle/native_owner.go'),
            'selected source lacks native owner dispatch')
    paths = ['LICENSE', 'go.work', 'cmake/mvp-dependencies.json', 'cmake/mvp-release-identities.json',
             'cmake/SymphonyGoCandidateIdentities.cmake', 'cmake/mvp-go-owner-closure.json',
             'tools/qxctl/tests/reproducible_build.cmake', 'tools/qxctl/cmd/qxctl/lifecycle_apply.go',
             'tools/qxctl/internal/knowledgelifecycle/executor.go',
             'tests/launch-acceptance/go-candidate-closure.go', 'tests/launch-acceptance/qualify-go-owners.go']
    for p in OWNERS.values():
        paths.append(p['source_root'] + '/go.mod')
        sum_path = p['source_root'] + '/go.sum'
        if subprocess.run(['git', '--no-replace-objects', '-C', str(repo), 'cat-file', '-e', commit + ':' + sum_path],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15).returncode == 0:
            paths.append(sum_path)
        entry = p['build_package'].removeprefix('./')
        paths.append(p['source_root'] + '/' + (entry + '/' if entry != '.' else '') + 'main.go')
    # Include the complete reviewed native owner implementation, not only its CLI.
    for component in sorted(SERVICE_IDS):
        root = OWNERS[component]['source_root']
        listed = git('ls-tree', '-r', '--name-only', commit, root + '/internal').decode().splitlines()
        paths += [p for p in listed if p.endswith('.go')]
    paths += [p for p in git('ls-tree', '-r', '--name-only', commit, 'tools/qxctl/internal/knowledgelifecycle').decode().splitlines() if p.endswith('.go')]
    paths.append('tools/qxctl/cmd/qxctl/commands.go')
    evidence = [{'path': p, 'sha256': sha(git('show', commit + ':' + p))} for p in sorted(set(paths))]
    return sealed({'protocol': 'symphony.distribution.go-owner-source.v1', 'source_commit': commit,
                   'source_tree': tree, 'source_evidence': evidence}, 'binding_digest')


def catalog(binding=None):
    binding = reviewed_binding() if binding is None else binding
    units = []
    for name, p in sorted(OWNERS.items()):
        row = {**p, 'unit_id': 'PKG-GO-' + name, 'source_commit': binding['source_commit'],
               'source_tree': binding['source_tree'], 'profiles': sorted(k for k in PROFILES if k != FIXTURE_PROFILE),
               'conda_name': 'symphony-' + name + '-payload',
               'conda_version': p['native_version'].replace('-dev', 'dev0'),
               'owner_invocation_implemented': name in SERVICE_IDS,
               'system_removal_qualified': False, 'fresh_host_accepted': False}
        units.append(sealed(row, 'definition_digest'))
    return sealed({'schema': 'symphony.distribution.go-owner-catalog.v2', 'format_version': 2,
                   'source_binding_digest': binding['binding_digest'],
                   'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
                   'units': units, 'runtime_selection_changed': False, 'publication_authorized': False,
                   'release_acceptance_complete': False}, 'catalog_digest')


def validate_catalog(value, expected, binding=None):
    validate_seal(value, 'catalog_digest', expected)
    require(value == catalog(binding), 'owner policy, critical version, or source identity substituted')
    return value


def unit(value, component):
    require(component in OWNERS, 'unknown Go owner; no fallback dispatch')
    found = [p for p in value['units'] if p['component_id'] == component]
    require(len(found) == 1, 'Go owner coverage differs')
    return found[0]


def install_argv(component, executable, prefix):
    require(component in SERVICE_IDS, 'raw executable has no native receipt installer')
    p = OWNERS[component]
    argv = [str(executable)]
    if component == 'secure-identity-access-governance':
        argv += ['package']
    argv += ['install', '--prefix', str(prefix), '--version', p['native_version']]
    if component == 'stav-append-authority':
        argv += ['--scope', 'user']
    return argv


def receipt_expected(component, binary_size, binary_digest, goos, goarch):
    require(component in SERVICE_IDS, 'raw custody is not a native receipt')
    p = OWNERS[component]
    rel = f"libexec/symphony/{component}/{p['native_version']}/{p['binary_name']}"
    entries = {'secure-identity-access-governance': [('ssiag.foundation-lifecycle', 'adapter', ['symphony.foundation.lifecycle-command.v1'])],
               'stav-append-authority': [('stav.append-authority', 'executable', ['symphony.stav.local.v1']), ('stav.foundation-lifecycle', 'adapter', ['symphony.foundation.lifecycle-command.v1'])],
               'accordare-stav-producer': [('accordare.stav-producer', 'executable', ['symphony.accordare.stav-producer.local.v1', 'symphony.accordare.stav-producer.supervisor.v1'])]}[component]
    caps = {'secure-identity-access-governance': ['symphony.foundation.lifecycle-adapter.v1', RETIREMENT],
            'stav-append-authority': ['symphony.foundation.lifecycle-adapter.v1', 'symphony.stav.append-authority.v1', RETIREMENT],
            'accordare-stav-producer': ['symphony.accordare.stav-producer.v1', 'symphony.accordare.stav-producer.native-supervision.v1', RETIREMENT]}[component]
    caps.append(DISPATCH)
    value = {'protocol': RECEIPT, 'format_version': 2, 'component_id': component, 'component_kind': 'service',
             'module_id': component, 'vector_id': None, 'engine_id': None, 'package_id': component,
             'version': p['native_version'], 'install_scope': 'prefix', 'prefix_mode': 'installation_prefix',
             'files': [{'path': rel, 'kind': 'executable', 'size': binary_size, 'digest': 'sha256:' + binary_digest}],
             'entry_points': [{'entry_point_id': i, 'kind': k, 'path': rel, 'protocols': protocols} for i, k, protocols in entries],
             'provides_capabilities': caps,
             'requires_capabilities': ['symphony.stav.append-authority.v1', 'symphony.ssiag.authorization.v1'] if component == 'accordare-stav-producer' else [],
             'compatible_receptors': [], 'platform_requirements': [{'os': 'macos' if goos == 'darwin' else goos,
                 'architecture': goarch, 'kernel_abi': None, 'critical': True}]}
    return sealed(value, 'receipt_digest')
