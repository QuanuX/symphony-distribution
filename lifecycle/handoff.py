#!/usr/bin/env python3
"""Prepare one exact package effect; never invoke a runtime owner.

All output is a private proposal. Source support, exact executable identity and
supplied build provenance are checked separately from runtime negotiation, which
this preparation-only helper does not perform or claim.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import contracts as contract
import go_delivery
import journeys
import qualified_sources
from schema import Registry

require = contract.require
without = contract.without
SCHEMA_NAMES = ['lifecycle-profile', 'lifecycle-desired-state', 'lifecycle-observation',
                'lifecycle-boot-result', 'lifecycle-boot-journal', 'lifecycle-plan',
                'lifecycle-execution-scope', 'lifecycle-apply-result', 'lifecycle-applied-state']
SCHEMA_PATHS = ['knowledge/schemas/v1/' + name + '.schema.json' for name in SCHEMA_NAMES]
SCHEMA_PATHS.append('knowledge/schemas/v2/install-receipt.schema.json')
SCHEMA_PATHS.append('knowledge/schemas/v2/lifecycle-boot-journal.schema.json')
CAPABILITY_PATHS = {
    'tools/qxctl/cmd/qxctl/commands.go': ('execution-scope',),
    'tools/qxctl/internal/knowledgelifecycle/execution_scope.go': ('ExecutionScopeProtocol', 'ValidateDesired'),
    'modules/knowledge-session-coordinator/src/lifecycle_journal.cpp':
        ('symphony.knowledge.lifecycle-apply-command.v2', 'scoped-apply-v1'),
}
REQUEST_FIELDS = '''protocol format_version unit_id component_id scope_id operation_id
    expected_apply_journal_digest expected_applied_state_digest state_root state_scope'''.split()
BUILD_FIELDS = 'protocol format_version source_commit source_tree qxctl_sha256 coordinator_sha256'.split()
CUSTODY_FIELDS = '''protocol component_id native_version owner_contract manifest_digest catalog_digest build_number
    source_commit source_tree retained_executable executable_sha256 executable_size retained_claim_ids selection_owner
    custody_only native_receipt_created runtime_installation runtime_selection_changed runtime_activation_changed
    administrator_provisioned live_raw_cleanup_supported external_claim_coverage private_operator_evidence
    publication_authorized release_acceptance_complete custody_digest'''.split()


def native_bytes(value):
    contract.canonical(value)  # Reject floats, nonfinite values and oversized integers.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def native_digest(value):
    return 'sha256:' + sha(native_bytes(value))


def strict_json(data):
    require(len(data) <= contract.MAX_BYTES, 'JSON input exceeds size bound')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    def invalid_number(_):
        raise ValueError('Nonintegral or nonfinite JSON number')
    value = json.loads(data, object_pairs_hook=pairs, parse_float=invalid_number,
                       parse_constant=invalid_number)
    native_bytes(value)
    return value


def clean_absolute(path):
    path = Path(path)
    require(contract.safe_path(str(path)), 'A normalized absolute path is required')
    return path


def open_directory(path):
    """Walk from / without following directory links, including ancestors."""
    path = clean_absolute(path)
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=current)
            os.close(current)
            current = following
        result = current
        current = None
        return result
    finally:
        if current is not None:
            os.close(current)


def read_regular(path, expected=None, *, executable=False, limit=contract.MAX_BYTES):
    """Hash a stable, nonlinked regular file through no-follow descriptors."""
    path = clean_absolute(path)
    parent = open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'A nonlinked regular file is required')
        require(before.st_uid in (0, os.getuid()) and before.st_mode & 0o022 == 0,
                'Input ownership or write permissions are not trusted')
        require(before.st_size <= limit, 'File exceeds bound')
        require(not executable or before.st_mode & 0o111 != 0, 'Selected controller is not executable')
        data = bytearray()
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= limit, 'File grew beyond bound')
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'File changed during preparation')
        data = bytes(data)
        if expected is not None:
            require(re.fullmatch(r'[0-9a-f]{64}', expected) is not None and sha(data) == expected,
                    'Selected input SHA-256 differs')
        return data
    finally:
        os.close(fd)


def bound_source(repository, commit, tree):
    """Read immutable Git objects only. Never use WORKTREE as source identity."""
    repository = clean_absolute(repository)
    fd = open_directory(repository)
    os.close(fd)
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None and
            re.fullmatch(r'[0-9a-f]{40}', tree) is not None, 'Exact candidate commit/tree required')
    def git(*args):
        return subprocess.check_output(['git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
                                        '-C', str(repository), *args],
                                       stderr=subprocess.DEVNULL, timeout=15)
    require(git('rev-parse', commit + '^{commit}').decode().strip() == commit and
            git('rev-parse', commit + '^{tree}').decode().strip() == tree,
            'Candidate commit/tree differs')
    # The reviewable command will use this checkout. Do not silently substitute a
    # different checkout or uncommitted source while binding immutable objects.
    require(git('rev-parse', 'HEAD').decode().strip() == commit, 'Checkout HEAD differs from candidate')
    require(not git('status', '--porcelain=v1', '--untracked-files=normal').strip(), 'Candidate checkout is dirty')
    schemas, evidence = [], []
    for path in SCHEMA_PATHS + list(CAPABILITY_PATHS):
        data = git('show', commit + ':' + path)
        evidence.append({'path': path, 'sha256': sha(data)})
        if path in SCHEMA_PATHS:
            schemas.append(strict_json(data))
        else:
            require(all(marker in data.decode('utf-8') for marker in CAPABILITY_PATHS[path]),
                    'Selected candidate lacks the scoped apply contract')
    return Registry(schemas), {'commit': commit, 'tree': tree, 'files': evidence}


def stable_inventory(observation):
    normalized = copy.deepcopy(observation)
    for key in ('observed_at', 'observation_digest'):
        normalized.pop(key)
    normalized['configured_roots'].sort(key=native_bytes)
    normalized['platform']['provider_availability'].sort(key=native_bytes)
    for component in normalized['components']:
        component['packages'].sort(key=native_bytes)
        component['capabilities'].sort(key=native_bytes)
    normalized['components'].sort(key=native_bytes)
    normalized['unknown_packages'].sort(key=native_bytes)
    return native_digest(normalized)


def semantic_plan_digest(plan, inventory_digest):
    """Match native reviewed plan semantics, excluding observation wall time."""
    require(contract.tagged(inventory_digest), 'Stable inventory digest is invalid')
    value = copy.deepcopy(without(plan, 'plan_digest'))
    value['observation_digest'] = inventory_digest
    return native_digest(value)


def validate_owner(catalog_value, expected_digest, request, receipt):
    if catalog_value.get('schema') == 'symphony.distribution.go-owner-catalog.v2':
        owners = go_delivery.owners
        qualified_sources.resolve(catalog_value, expected_digest)
        unit = owners.unit(catalog_value, request['component_id'])
        require(unit['component_id'] in owners.SERVICE_IDS and request['state_scope'] == 'user',
                'Native Go receipt owners require explicit user scope; raw commands have separate custody')
        require(unit['unit_id'] == request['unit_id'] and unit['component_id'] == receipt['component_id'] and
                unit['native_version'] == receipt['version'], 'Go delivery identity/version substitution')
        require(owners.DISPATCH in receipt['provides_capabilities'], 'Native receipt lacks qualified owner dispatch')
        require(len(receipt['files']) == 1 and len(receipt['platform_requirements']) == 1, 'Native receipt shape differs')
        binary, platform = receipt['files'][0], receipt['platform_requirements'][0]
        expected = owners.receipt_expected(unit['component_id'], binary['size'], binary['digest'].removeprefix('sha256:'),
                                          'darwin' if platform['os'] == 'macos' else platform['os'], platform['architecture'])
        require(receipt == expected, 'Native receipt differs from closed owner contract')
        return {'unit_id': unit['unit_id'], 'definition_sha256': unit['definition_digest'].removeprefix('sha256:'),
                'owner_contract': unit['owner_contract'], 'catalog_digest': expected_digest,
                'source_commit': catalog_value['source_commit'], 'source_tree': catalog_value['source_tree'],
                'explicit_native_owner_required': True}
    # This sibling is code-owned. No path or argv from a package is imported.
    path = Path(__file__).parent.parent / 'owner-catalog/catalog.py'
    spec = importlib.util.spec_from_file_location('d05_owner_catalog', path)
    owners = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owners)
    owners.validate(catalog_value, expected_digest)
    units = [item for item in catalog_value['units'] if item['unit_id'] == request['unit_id']]
    require(len(units) == 1, 'Unknown delivery unit')
    unit = units[0]
    require(unit['kind'] == 'native_receipt_unit' and
            unit['runtime_owner']['contract'] == 'native.receipt-v2.classification.v1',
            'GO_OWNER_CONTRACT_REQUIRED: this increment cannot invoke Go runtime owners')
    require(unit['component_id'] == request['component_id'] == receipt['component_id'] and
            unit['native_version'] == receipt['version'], 'Delivery identity/version substitution')
    return {'unit_id': unit['unit_id'], 'definition_sha256': unit['definition_sha256'],
            'owner_contract': unit['runtime_owner']['contract'], 'catalog_digest': expected_digest}


def native_owner_arguments(bindings, owner, request, receipt, profile, source, *, catalog=None, manifest_digest=None, fixture=False,
                           custody_root=None, custody_digest=None, conda_owned_roots=()):
    """Select exactly one retained native controller; never discover via PATH."""
    if not owner.get('explicit_native_owner_required'):
        require(not bindings and manifest_digest is None and not fixture and custody_root is None and custody_digest is None,
                'Native binding supplied for an unrelated owner route')
        return [], None
    require(len(bindings) == 1 and bindings[0].count('=') == 1, 'One explicit component=/absolute/retained/path binding required')
    component, path = bindings[0].split('=', 1)
    require(component == request['component_id'] and component in go_delivery.owners.SERVICE_IDS,
            'Unknown or unrelated native owner binding')
    executable = clean_absolute(path)
    for root in profile['configured_roots']:
        root = clean_absolute(root)
        require(executable != root and root not in executable.parents, 'Native owner controller must be retained outside installation roots')
    require(len(receipt['files']) == 1 and receipt['files'][0]['kind'] == 'executable', 'Native owner receipt must own one exact executable')
    item = receipt['files'][0]
    data = read_regular(executable, item['digest'].removeprefix('sha256:'), executable=True, limit=256 * 1024 * 1024)
    require(len(data) == item['size'], 'Native owner controller size differs')
    require(catalog is not None and manifest_digest is not None, 'Independently selected retained carrier manifest digest required')
    binding = qualified_sources.resolve(catalog, owner['catalog_digest'], source)
    require(owner['source_commit'] == binding['source_commit'] and owner['source_tree'] == binding['source_tree'],
            'Native owner and qualified catalog source differ')
    manifest, _ = go_delivery.verify_carrier(catalog, owner['catalog_digest'], executable.parent, manifest_digest, fixture=fixture, binding=binding)
    unit = go_delivery.owners.unit(catalog, component)
    require(manifest['component_id'] == component and executable.name == unit['binary_name'], 'Retained native owner carrier differs')
    custody_evidence = None
    if request.get('protocol') == journeys.PROTOCOL or custody_root is not None or custody_digest is not None:
        require(custody_root is not None and custody_digest is not None, 'V2 package handoff requires independently selected retained custody root and digest')
        custody_root = clean_absolute(custody_root)
        for root in [*profile['configured_roots'], *conda_owned_roots]:
            require(not journeys.overlap(custody_root, clean_absolute(root)),
                    'Retained custody overlaps configured runtime or known Conda-owned roots')
        # A private retention record must not sit inside an environment which a
        # package transaction could remove. Known cache/carrier roots are explicit
        # caller inputs; an arbitrary external cache cannot be inferred globally.
        for ancestor in (custody_root, *custody_root.parents):
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) if ancestor == Path('/') else open_directory(ancestor)
            try:
                try:
                    os.stat('conda-meta', dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('Retained custody is inside a Conda environment')
            finally:
                os.close(fd)
        record = go_delivery.inspect_custody(catalog, owner['catalog_digest'], custody_root, custody_digest,
                                             fixture=fixture, binding=binding)
        contract.exact(record, CUSTODY_FIELDS, 'retained controller custody')
        require(record['custody_only'] is True and record['native_receipt_created'] is False,
                'V2 handoff needs independent controller-only custody, not a record coupled to an installation')
        require(record['selection_owner'] == unit['selection_owner'] and record['private_operator_evidence'] is True,
                'Retained custody selection authority or evidence boundary differs')
        require(record['component_id'] == component and record['retained_executable'] == str(executable) and
                record['manifest_digest'] == manifest_digest and executable == custody_root / 'retained-carrier' / unit['binary_name'],
                'Selected controller differs from exact retained custody identity/path')
        custody_evidence = {'root': str(custody_root), 'custody_digest': custody_digest,
                            'controller_only': True, 'known_conda_owned_roots': [str(clean_absolute(x)) for x in conda_owned_roots],
                            'arbitrary_external_cache_ownership_inferred': False}
    return ['--native-owner', component + '=' + str(executable)], {
        'component_id': component, 'retained_executable': str(executable), 'executable_sha256': sha(data),
        'manifest_digest': manifest_digest, 'publisher_trust_accepted': False,
        'catalog_digest': owner['catalog_digest'], 'source_commit': binding['source_commit'], 'source_tree': binding['source_tree'],
        'receipt_digest': receipt['receipt_digest'], 'qualified_retained_claim_coverage': False,
        'custody': custody_evidence,
        'maintenance_environment': 'inherit_real_operator_HOME_and_XDG', 'private_staging_home_for_maintenance': False}


def make_scope(profile, observation, boot, apply_status, receipt, request, registry, *, prior_receipt=None):
    """Pure proposal construction; complete profile and native plan stay intact."""
    journeys.validate_request(request, REQUEST_FIELDS)
    for field in ('unit_id', 'component_id', 'scope_id'):
        require(contract.token(request[field]), 'Invalid request identity')
    require(isinstance(request['operation_id'], str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', request['operation_id']) is not None,
            'Explicit bounded operation identity required')
    require(request['state_scope'] in ('user', 'system') and contract.safe_path(request['state_root']),
            'Explicit native state scope/root required')
    for field in ('expected_apply_journal_digest', 'expected_applied_state_digest'):
        require(request[field] == 'absent' or contract.tagged(request[field]), 'Exact initial CAS required')
    for value, identity in [(profile, 'lifecycle-profile:v1'), (observation, 'lifecycle-observation:v1'),
                            (boot, 'lifecycle-boot-result:v1'), (apply_status, 'lifecycle-apply-result:v1'),
                            (receipt, 'install-receipt:v2')]:
        registry.validate(value, 'urn:symphony:knowledge:' + identity)
    desired, observed = contract.validate_inputs(profile, observation)
    require(profile['boot_mode'] == 'apply-compatible', 'Existing profile policy does not allow apply')
    require(request['component_id'] in desired, 'Requested component is absent from full profile')
    component = desired[request['component_id']]
    contract.validate_receipt(receipt, component)
    require(not observation['unknown_packages'], 'Unknown inventory prevents safe preparation')
    current = observed.get(component['component_id'])
    effect_kind = journeys.validate_state(request, component, current, receipt, prior_receipt, registry)
    journal, plan = boot.get('journal'), boot.get('plan')
    require(boot['journal_present'] is True and isinstance(journal, dict) and isinstance(plan, dict),
            'Native boot result must contain the exact source journal and complete plan')
    require(boot['compatibility']['mode'] == 'full' and not boot['compatibility']['missing_capabilities'],
            'Source boot compatibility is incomplete')
    require(boot['journal_digest'] == journal['journal_digest'] == native_digest(without(journal, 'journal_digest')),
            'Source journal digest differs')
    bindings = {'profile_id': profile['profile_id'], 'tops_id': profile['tops_id'],
                'profile_digest': profile['profile_digest'], 'desired_state_digest': profile['desired_state']['desired_state_digest'],
                'mode': 'apply-compatible', 'current_observation_digest': observation['observation_digest'],
                'current_stable_inventory_digest': stable_inventory(observation)}
    for key, wanted in bindings.items():
        require(journal[key] == wanted, 'Source journal differs from full input: ' + key)
    require(apply_status['operation'] == 'lifecycle_apply_status' and apply_status['read_only'] is True and
            apply_status['apply_authorized'] is False and apply_status['compatibility']['mode'] == 'full' and
            not apply_status['compatibility']['missing_capabilities'], 'Exact compatible read-only apply status required')
    existing = apply_status['journal']
    if existing is not None:
        require(apply_status['journal_digest'] == existing['journal_digest'] == native_digest(without(existing, 'journal_digest')),
                'Initial apply journal digest differs')
        require(existing['profile_id'] == profile['profile_id'] and existing['tops_id'] == profile['tops_id'],
                'Initial apply journal identity differs')
        # An in-flight or scoped predecessor needs explicit native recovery, never
        # a guessed new transaction or silent supersession in this first helper.
        require(existing['state'] == 'closed', 'Existing apply transaction requires recovery or closure')
        require(not any(item['extension_id'] == 'scoped-apply-v1' for item in existing['extensions']),
                'Scoped predecessor requires its exact scope/status/recovery flow')
    require((apply_status['journal_digest'] or 'absent') == request['expected_apply_journal_digest'],
            'Initial apply-journal CAS differs from status evidence')
    applied = apply_status['applied_state']
    if applied is not None:
        require(applied['applied_state_digest'] == native_digest(without(applied, 'applied_state_digest')) and
                applied['profile_id'] == profile['profile_id'] and applied['tops_id'] == profile['tops_id'],
                'Initial applied-state binding differs')
    require((applied['applied_state_digest'] if applied else 'absent') == request['expected_applied_state_digest'],
            'Initial applied-state CAS differs from status evidence')
    require(plan['plan_digest'] == journal['current_plan_digest'] == native_digest(without(plan, 'plan_digest')),
            'Full native plan digest differs')
    require(plan['revision'] == 1 and plan['previous_plan_digest'] is None,
            'Replanned report evidence requires a separately bound fresh native plan; this first helper accepts initial boot plans only')
    require(plan['desired_state_digest'] == bindings['desired_state_digest'] and
            plan['observation_digest'] == observation['observation_digest'] and
            plan['observation_key'] == journal['observation_key'] and
            plan['revision'] == journal['current_plan_revision'] and
            plan['prior_applied_state_digest'] == journal['prior_applied_state_digest'],
            'Native plan/source journal input bindings differ')
    require((plan['prior_applied_state_digest'] or 'absent') == request['expected_applied_state_digest'],
            'Initial applied-state CAS differs from native source evidence')
    require(not plan['fatal_blockers'] and plan['compatibility']['mode'] == 'full' and
            plan['compatibility']['two_way_procedural_compatibility'] is True and
            not plan['compatibility']['missing_capabilities'], 'Native plan is incompatible or fatal')
    action_ids = [item['action_id'] for item in plan['actions']]
    require(len(action_ids) == len(set(action_ids)), 'Duplicate native action identity')
    candidates = [item for item in plan['actions'] if item['component_id'] == component['component_id'] and item['kind'] == effect_kind]
    require(len(candidates) == 1, 'Exactly one requested native package action is required')
    action = candidates[0]
    require(action['direction'] == 'forward' and action['target_receptor_id'] is None and
            action['expected_artifact_digests'] == [receipt['receipt_digest']] and
            action['prerequisite_action_ids'] == [], 'Package prerequisites or artifacts require separate review')
    if request.get('protocol') == journeys.PROTOCOL:
        require(action['expected_before_digest'] == (current['observation_digest'] if effect_kind == 'uninstall' else None),
                'Native package action before-state binding differs')
    blockers = action['blockers']
    staged_wait = (effect_kind == 'install' and action['disposition'] == 'blocked' and len(blockers) == 1 and
                   blockers[0]['class'] == 'dependency_wait' and blockers[0]['retryable'] is True and
                   blockers[0]['component_id'] == action['component_id'] and
                   blockers[0]['action_id'] == action['action_id'])
    require((action['disposition'] == 'ready' and not blockers and action['action_id'] in plan['ready_action_ids']) or
            (staged_wait and action['action_id'] in plan['blocked_action_ids']),
            'Requested package effect is not ready or the exact absent-staged-package exception')
    effect = {key: copy.deepcopy(action[key]) for key in ('component_id', 'kind', 'target_state_digest',
                                                        'target_receptor_id', 'expected_artifact_digests')}
    effect['install_root'] = component['install_root']
    scope = {'protocol': 'symphony.knowledge.lifecycle-execution-scope.v1', 'format_version': 1,
             'scope_id': request['scope_id'], 'tops_id': profile['tops_id'], 'profile_id': profile['profile_id'],
             'profile_digest': profile['profile_digest'], 'desired_state_digest': bindings['desired_state_digest'],
             'source_report_journal_digest': journal['journal_digest'],
             'initial_plan_digest': semantic_plan_digest(plan, stable_inventory(observation)),
             'initial_stable_inventory_digest': stable_inventory(observation),
             'expected_apply_journal_digest': request['expected_apply_journal_digest'],
             'expected_applied_state_digest': request['expected_applied_state_digest'],
             'components': [component['component_id']], 'effects': [effect],
             'ownership_effects': [{'install_root': component['install_root'], 'component_id': component['component_id'],
                                    'receipt_digest': receipt['receipt_digest'], 'disposition': 'release' if effect_kind == 'uninstall' else 'retained'}],
             'canonical': False}
    scope['scope_digest'] = native_digest(scope)
    registry.validate(scope, 'urn:symphony:knowledge:lifecycle-execution-scope:v1')
    return scope


def verify_payload(root, receipt_path, receipt, profile):
    root, receipt_path = clean_absolute(root), clean_absolute(receipt_path)
    expected_receipt = root / 'share/symphony/receipts' / receipt['module_id'] / receipt['version'] / 'install-receipt.json'
    require(receipt_path == expected_receipt, 'Receipt is outside its exact staged discovery path')
    for install_root in profile['configured_roots']:
        installed = Path(install_root)
        require(root != installed and root not in installed.parents and installed not in root.parents,
                'Staging and installed profile roots must not overlap')
    inventory = []
    for item in receipt['files']:
        data = read_regular(root / item['path'], item['digest'].removeprefix('sha256:'),
                            executable=item['kind'] == 'executable', limit=256 * 1024 * 1024)
        require(len(data) == item['size'], 'Staged payload size differs')
        inventory.append({'path': item['path'], 'sha256': sha(data), 'size': len(data)})
    return {'receipt_path': str(receipt_path.relative_to(root)), 'files': inventory,
            'receipt_owned_bytes_verified': True, 'publisher_signature_verified': False,
            'runtime_installation_performed': False}


def verify_build(build, source, observation, qxctl_sha, coordinator_sha):
    contract.exact(build, BUILD_FIELDS, 'controller build binding')
    require(build['protocol'] == 'symphony.distribution.controller-build-binding.v1' and
            type(build['format_version']) is int and build['format_version'] == 1,
            'Unsupported controller build binding')
    require(build['source_commit'] == source['commit'] and build['source_tree'] == source['tree'] and
            build['qxctl_sha256'] == qxctl_sha and build['coordinator_sha256'] == coordinator_sha,
            'Supplied build binding differs from exact candidate and controller bytes')
    platform = observation['platform']
    require(platform['qxctl_identity']['component_id'] == 'qxctl' and
            platform['qxctl_identity']['executable_digest'] == 'sha256:' + qxctl_sha,
            'Observation was not bound to this qxctl executable')
    identity = platform['coordinator_identity']
    require(isinstance(identity, dict) and identity['executable_digest'] == 'sha256:' + coordinator_sha,
            'Observation was not bound to this coordinator executable')


def write_proposal(output, scope, handoff, inputs):
    output = clean_absolute(output)
    parent_fd = open_directory(output.parent)
    try:
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        out_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        for name, value in [('execution-scope.json', scope), ('handoff.json', handoff), *inputs.items()]:
            require('/' not in name, 'Invalid private output name')
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out_fd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(native_bytes(value) + b'\n')
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(out_fd)
    finally:
        os.close(out_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'source-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'source-tree', 'catalog-digest'):
        parser.add_argument('--' + name, required=True)
    names = ('profile', 'observation', 'boot', 'apply-status', 'receipt', 'request', 'build-binding', 'catalog', 'qxctl', 'coordinator')
    for name in names:
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--reviewed-scope', type=Path)
    parser.add_argument('--reviewed-scope-sha256')
    parser.add_argument('--native-owner', action='append', default=[], metavar='COMPONENT=/ABSOLUTE/RETAINED/PATH')
    parser.add_argument('--native-owner-manifest-digest')
    parser.add_argument('--native-owner-fixture', action='store_true')
    parser.add_argument('--native-owner-custody', type=Path)
    parser.add_argument('--native-owner-custody-digest')
    parser.add_argument('--prior-receipt', type=Path)
    parser.add_argument('--prior-receipt-sha256')
    parser.add_argument('--prior-native-owner', action='append', default=[], metavar='COMPONENT=/ABSOLUTE/RETAINED/PATH')
    parser.add_argument('--prior-native-owner-manifest-digest')
    parser.add_argument('--prior-native-owner-custody', type=Path)
    parser.add_argument('--prior-native-owner-custody-digest')
    parser.add_argument('--conda-owned-root', action='append', default=[], type=Path,
                        help='Explicit known carrier/cache/environment root excluded from retained custody')
    parser.add_argument('--prior-catalog', type=Path)
    parser.add_argument('--prior-catalog-sha256')
    parser.add_argument('--prior-catalog-digest')
    args = parser.parse_args()
    try:
        registry, source = bound_source(args.repository, args.source_commit, args.source_tree)
        inputs, bindings = {}, {}
        for name in names:
            field = name.replace('-', '_')
            data = read_regular(getattr(args, field), getattr(args, field + '_sha256'),
                                executable=name in ('qxctl', 'coordinator'), limit=256 * 1024 * 1024 if name in ('qxctl', 'coordinator') else contract.MAX_BYTES)
            bindings[name] = {'sha256': sha(data)}
            if name not in ('qxctl', 'coordinator'):
                inputs[name] = strict_json(data)
        request = inputs['request']
        operation = journeys.validate_request(request, REQUEST_FIELDS)
        prior_selected = (args.prior_receipt is not None, args.prior_receipt_sha256 is not None,
                          bool(args.prior_native_owner), args.prior_native_owner_manifest_digest is not None,
                          args.prior_native_owner_custody is not None, args.prior_native_owner_custody_digest is not None)
        require(all(prior_selected) if operation in journeys.TRANSITIONS else not any(prior_selected),
                'Transitions require exact prior receipt, retained controller, and carrier manifest; other operations must omit them')
        prior_catalog_selected = (args.prior_catalog is not None, args.prior_catalog_sha256 is not None,
                                  args.prior_catalog_digest is not None)
        require(not any(prior_catalog_selected) or (operation in journeys.TRANSITIONS and all(prior_catalog_selected)),
                'Prior catalog path, file hash, and catalog digest must be selected together for a transition')
        prior_catalog, prior_catalog_digest = inputs['catalog'], args.catalog_digest
        if all(prior_catalog_selected):
            data = read_regular(args.prior_catalog, args.prior_catalog_sha256)
            inputs['prior-catalog'] = prior_catalog = strict_json(data)
            bindings['prior-catalog'] = {'sha256': sha(data)}
            prior_catalog_digest = args.prior_catalog_digest
        prior_receipt = None
        if operation in journeys.TRANSITIONS:
            data = read_regular(args.prior_receipt, args.prior_receipt_sha256)
            inputs['prior-receipt'] = prior_receipt = strict_json(data)
            bindings['prior-receipt'] = {'sha256': sha(data)}
        scope = make_scope(inputs['profile'], inputs['observation'], inputs['boot'], inputs['apply-status'], inputs['receipt'], request, registry,
                           prior_receipt=prior_receipt)
        owner = validate_owner(inputs['catalog'], args.catalog_digest, inputs['request'], inputs['receipt'])
        owner_args, native_binding = native_owner_arguments(args.native_owner, owner, inputs['request'], inputs['receipt'], inputs['profile'], source,
            catalog=inputs['catalog'], manifest_digest=args.native_owner_manifest_digest, fixture=args.native_owner_fixture,
            custody_root=args.native_owner_custody, custody_digest=args.native_owner_custody_digest, conda_owned_roots=args.conda_owned_root)
        prior_binding = None
        if prior_receipt is not None:
            prior_owner = validate_owner(prior_catalog, prior_catalog_digest, request, prior_receipt)
            _, prior_binding = native_owner_arguments(args.prior_native_owner, prior_owner, request, prior_receipt, inputs['profile'], source,
                catalog=prior_catalog, manifest_digest=args.prior_native_owner_manifest_digest, fixture=args.native_owner_fixture,
                custody_root=args.prior_native_owner_custody, custody_digest=args.prior_native_owner_custody_digest, conda_owned_roots=args.conda_owned_root)
        journey = journeys.describe(request, scope, inputs['receipt'], native_binding, prior_binding)
        verify_build(inputs['build-binding'], source, inputs['observation'], args.qxctl_sha256, args.coordinator_sha256)
        payload = verify_payload(args.source_root, args.receipt, inputs['receipt'], inputs['profile'])
        supplied_scope = False
        require(bool(args.reviewed_scope) == bool(args.reviewed_scope_sha256), 'Scope path and hash must be supplied together')
        if args.reviewed_scope:
            supplied = strict_json(read_regular(args.reviewed_scope, args.reviewed_scope_sha256))
            require(native_bytes(supplied) == native_bytes(scope), 'Supplied scope differs from exact package-effect proposal')
            supplied_scope = True
            bindings['supplied-scope'] = {'sha256': args.reviewed_scope_sha256}
        output = clean_absolute(args.output)
        protected = [clean_absolute(args.repository), clean_absolute(args.source_root), Path(inputs['request']['state_root'])]
        protected += [Path(root) for root in inputs['profile']['configured_roots']]
        protected += [Path(item['retained_executable']).parent for item in (native_binding, prior_binding) if item is not None]
        protected += [Path(item['custody']['root']) for item in (native_binding, prior_binding)
                      if item is not None and item.get('custody') is not None]
        require(all(output != root and root not in output.parents and output not in root.parents for root in protected),
                'Private proposal output overlaps source, installed, or native state roots')
        argv = [str(clean_absolute(args.qxctl)), 'knowledge', 'lifecycle', 'apply', '--tops-id', scope['tops_id'],
                '--profile-id', scope['profile_id'], '--scope', request['state_scope'], '--state-root', request['state_root'],
                '--repo', str(clean_absolute(args.repository)), '--json', '--operation-id', request['operation_id'],
                '--source-journal-digest', scope['source_report_journal_digest'],
                '--expected-apply-journal-digest', scope['expected_apply_journal_digest'],
                '--expected-applied-state-digest', scope['expected_applied_state_digest'], '--max-actions', '1',
                '--source-root', str(clean_absolute(args.source_root)), '--execution-scope', str(output / 'execution-scope.json')]
        argv += owner_args
        handoff = {'protocol': 'symphony.distribution.scoped-install-handoff.v1', 'format_version': 1,
                   'status': 'proposal_only', 'source': source, 'inputs': bindings, 'owner': owner,
                   'scope_digest': scope['scope_digest'], 'supplied_scope_matches_proposal': supplied_scope,
                   'payload': payload, 'apply_argv_proposal': argv, 'native_owner_binding': native_binding,
                   'maintenance_environment': 'inherit_real_operator_HOME_and_XDG',
                   'full_native_plan_retained': True,
                   'excluded_action_ids': [item['action_id'] for item in inputs['boot']['plan']['actions']
                       if not (item['component_id'] == request['component_id'] and item['kind'] == scope['effects'][0]['kind'])],
                   'controller_build_binding_status': 'caller_selected_and_hash_checked_not_independently_attested',
                   'required_runtime_capabilities': ['scoped-apply-v1', 'symphony.knowledge.lifecycle-apply-command.v2'],
                   'runtime_capability_validation': 'pending_native_negotiation',
                   'review_status': 'pending_user_review', 'execution_authorized': False,
                   'owner_invoked': False, 'automatic_retry': False, 'fallback_to_unscoped_apply': False,
                   'runtime_selection_changed': False, 'runtime_activation_changed': False,
                   'live_removal_qualified': False, 'platform_accepted': False,
                   'publication_authorized': False, 'private_operator_evidence': True,
                   'release_acceptance_complete': False}
        if journey is not None:
            handoff.update(protocol='symphony.distribution.scoped-package-handoff.v2', format_version=2, journey=journey)
        write_proposal(output, scope, handoff, {name + '.json': value for name, value in inputs.items()})
        print(json.dumps({'status': 'proposal_only', 'scope_digest': scope['scope_digest'], 'execution_authorized': False}))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, 'REFUSED: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
