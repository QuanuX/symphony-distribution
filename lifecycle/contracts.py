"""Bounded profile/receipt validation copied from the preserved D05 compiler.

Only pure validators are retained. No old D05 helper is imported or changed.
Native execution scope uses its separate UTF-8 digest in handoff.py.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
import uuid

PROFILE = 'symphony.knowledge.lifecycle-profile.v1'
DESIRED = 'symphony.knowledge.lifecycle-desired-state.v1'
OBSERVATION = 'symphony.knowledge.lifecycle-observation.v1'
RECEIPT = 'symphony.knowledge.install-receipt.v2'
COMPONENT_KEYS = set('component_id component_kind module_id vector_id engine_id presence selected_package required install_scope install_root activation docking dependencies compatibility extensions'.split())
RECEIPT_KEYS = set('protocol format_version component_id component_kind module_id vector_id engine_id package_id version install_scope prefix_mode files entry_points provides_capabilities requires_capabilities compatible_receptors platform_requirements receipt_digest'.split())
MAX_BYTES = 16 * 1024 * 1024

def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    """Go encoding/json-compatible map encoding for bounded integral JSON."""
    def check(item, depth=0):
        require(depth <= 64, 'JSON nesting exceeds bound')
        if isinstance(item, dict):
            require(all(isinstance(k, str) for k in item), 'JSON key must be text')
            for v in item.values():
                check(v, depth + 1)
        elif isinstance(item, list):
            for v in item:
                check(v, depth + 1)
        elif type(item) is int:
            require(abs(item) <= 9007199254740991, 'JSON integer exceeds exact bound')
        else:
            require(item is None or type(item) in (str, bool), 'Unsupported numeric or JSON type; preserve through native owner')
    check(value)
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    for raw, escaped in [('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'), ('\u2028', '\\u2028'), ('\u2029', '\\u2029')]:
        encoded = encoded.replace(raw, escaped)
    return encoded.encode('utf-8')


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def without(value, field):
    return {k: v for k, v in value.items() if k != field}


def tagged(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + ' fields differ from frozen native contract')


def token(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,256}', value) is not None


def version(value):
    return isinstance(value, str) and value not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9.+-]{1,64}', value) is not None


def safe_path(value):
    return isinstance(value, str) and value.startswith('/') and value != '/' and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts and '\\' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def extensions(values):
    require(isinstance(values, list) and len(values) <= 64, 'Invalid extension collection')
    seen = set()
    for e in values:
        exact(e, 'extension_id extension_version critical payload payload_digest'.split(), 'extension')
        require(token(e['extension_id']) and version(e['extension_version']) and type(e['critical']) is bool, 'Invalid extension identity')
        pair = (e['extension_id'], e['extension_version'])
        require(pair not in seen, 'Duplicate extension identity')
        seen.add(pair)
        require(e['payload_digest'] == digest(e['payload']), 'Extension payload digest mismatch')


def normalize_desired(value):
    value = copy.deepcopy(value)
    for c in value['components']:
        c['dependencies'].sort(key=canonical)
        c['compatibility']['required_capabilities'].sort()
        c['compatibility']['platform_requirements'].sort()
        c['extensions'].sort(key=canonical)
    value['components'].sort(key=canonical)
    value['extensions'].sort(key=canonical)
    return value


def normalize_observation(value):
    value = copy.deepcopy(value)
    value['configured_roots'].sort(key=canonical)
    if isinstance(value['platform']['provider_availability'], list):
        value['platform']['provider_availability'].sort(key=canonical)
    for c in value['components']:
        c['packages'].sort(key=canonical)
        c['capabilities'].sort(key=canonical)
    value['components'].sort(key=canonical)
    value['unknown_packages'].sort(key=canonical)
    return value


def validate_inputs(profile, observation):
    canonical(profile); canonical(observation)
    require(len(canonical(profile)) <= MAX_BYTES and len(canonical(observation)) <= MAX_BYTES, 'Input exceeds size bound')
    exact(profile, 'protocol format_version profile_id tops_id generation previous_profile_digest configured_roots boot_mode desired_state canonical profile_digest'.split(), 'profile')
    exact(observation, 'protocol format_version profile_id tops_id configured_roots platform binding_registry_digest components unknown_packages observed_at canonical observation_digest'.split(), 'observation')
    require(profile['protocol'] == PROFILE and observation['protocol'] == OBSERVATION and type(profile['format_version']) is int and type(observation['format_version']) is int and profile['format_version'] == observation['format_version'] == 1, 'Unsupported owner protocol')
    require(profile['canonical'] is False and observation['canonical'] is False, 'Native derived evidence cannot claim canonical authority')
    require(token(profile['profile_id']) and profile['profile_id'] == observation['profile_id'] and profile['tops_id'] == observation['tops_id'], 'Profile/observation identity mismatch')
    require(str(uuid.UUID(profile['tops_id'])) == profile['tops_id'] and int(uuid.UUID(profile['tops_id'])) != 0, 'Invalid TOPS identity')
    roots = profile['configured_roots']
    require(isinstance(roots, list) and 0 < len(roots) <= 64 and all(safe_path(p) for p in roots) and len(set(roots)) == len(roots), 'Invalid configured roots')
    require(sorted(roots) == sorted(observation['configured_roots']), 'Observation root scope differs from profile')
    require(profile['boot_mode'] in ('report', 'apply-compatible'), 'Invalid owner boot mode')
    require(type(profile['generation']) is int and profile['generation'] > 0, 'Invalid profile generation')
    require((profile['generation'] == 1 and profile['previous_profile_digest'] is None) or (profile['generation'] > 1 and tagged(profile['previous_profile_digest'])), 'Invalid profile predecessor')
    desired = profile['desired_state']
    exact(desired, 'protocol format_version profile_id tops_id generation previous_desired_state_digest components extensions canonical desired_state_digest'.split(), 'desired state')
    require(desired['protocol'] == DESIRED and type(desired['format_version']) is int and desired['format_version'] == 1 and desired['canonical'] is False, 'Unsupported desired state')
    require(all(desired[k] == profile[k] for k in ('profile_id', 'tops_id', 'generation')), 'Embedded desired state binding mismatch')
    require((desired['generation'] == 1 and desired['previous_desired_state_digest'] is None) or (desired['generation'] > 1 and tagged(desired['previous_desired_state_digest'])), 'Invalid desired predecessor')
    require(isinstance(desired['components'], list) and len(desired['components']) <= 4096, 'Invalid desired component collection')
    by_id = {}
    for c in desired['components']:
        exact(c, COMPONENT_KEYS, 'desired component')
        require(token(c['component_id']) and token(c['module_id']) and c['component_id'] not in by_id, 'Invalid or duplicate desired component')
        require(c['component_kind'] in ('coordinator', 'vector_engine', 'module', 'adapter', 'ui', 'service'), 'Unknown component kind')
        require(c['install_root'] in roots and c['install_scope'] in ('prefix', 'user', 'system', 'tops'), 'Component root/scope mismatch')
        require(c['presence'] in ('present', 'absent') and c['activation'] in ('active', 'inactive', 'unmanaged'), 'Invalid desired lifecycle state')
        require(type(c['required']) is bool and all(c[k] is None or token(c[k]) for k in ('vector_id', 'engine_id')), 'Invalid desired identity')
        exact(c['docking'], ('disposition', 'receptor_id'), 'docking')
        require(c['docking']['disposition'] in ('docked', 'undocked', 'unmanaged'), 'Invalid docking')
        require((c['docking']['disposition'] == 'docked') == (c['docking']['receptor_id'] is not None), 'Docking receptor mismatch')
        if c['presence'] == 'present':
            exact(c['selected_package'], ('package_id', 'version', 'receipt_protocol', 'receipt_digest'), 'selected package')
            require(token(c['selected_package']['package_id']) and version(c['selected_package']['version']) and tagged(c['selected_package']['receipt_digest']) and c['selected_package']['receipt_protocol'] in ('symphony.knowledge.install-receipt.v1', RECEIPT), 'Invalid selected package')
        else:
            require(c['selected_package'] is None and c['activation'] != 'active' and c['docking']['disposition'] != 'docked', 'Absent component carries active state')
        exact(c['compatibility'], ('required_capabilities', 'platform_requirements'), 'compatibility')
        for values in c['compatibility'].values():
            require(isinstance(values, list) and len(values) <= 128 and all(token(v) for v in values) and len(values) == len(set(values)), 'Invalid compatibility set')
        require(isinstance(c['dependencies'], list) and len(c['dependencies']) <= 256, 'Invalid dependency set')
        deps = set()
        for dep in c['dependencies']:
            exact(dep, ('target_component_id', 'condition', 'critical'), 'dependency')
            key = (dep['target_component_id'], dep['condition'])
            require(token(dep['target_component_id']) and dep['target_component_id'] != c['component_id'] and type(dep['critical']) is bool and key not in deps, 'Invalid dependency')
            require(dep['condition'] in ('present', 'absent', 'installed', 'active', 'inactive', 'docked', 'undocked', 'compatible'), 'Unknown dependency predicate')
            deps.add(key)
        extensions(c['extensions'])
        by_id[c['component_id']] = c
    extensions(desired['extensions'])
    norm = normalize_desired(desired)
    require(desired['desired_state_digest'] == digest(without(norm, 'desired_state_digest')), 'Desired state digest mismatch')
    norm_profile = copy.deepcopy(profile); norm_profile['configured_roots'].sort(); norm_profile['desired_state'] = norm
    require(profile['profile_digest'] == digest(without(norm_profile, 'profile_digest')), 'Profile digest mismatch')
    observed = {}
    require(isinstance(observation['components'], list) and len(observation['components']) <= 4096, 'Invalid observed components')
    for c in observation['components']:
        exact(c, 'component_id component_kind module_id vector_id engine_id packages selected_package_digest activation docking receptor_id capabilities platform_compatibility observation_digest'.split(), 'observed component')
        require(token(c['component_id']) and c['component_id'] not in observed, 'Invalid or duplicate observation component')
        require(isinstance(c['packages'], list) and isinstance(c['capabilities'], list), 'Invalid observed package collection')
        n = copy.deepcopy(c); n['packages'].sort(key=canonical); n['capabilities'].sort()
        require(c['observation_digest'] == digest(without(n, 'observation_digest')), 'Observed component digest mismatch')
        observed[c['component_id']] = c
    require(observation['observation_digest'] == digest(without(normalize_observation(observation), 'observation_digest')), 'Observation digest mismatch')
    return by_id, observed


def validate_receipt(receipt, component):
    exact(receipt, RECEIPT_KEYS, 'target receipt')
    require(receipt['protocol'] == RECEIPT and type(receipt['format_version']) is int and receipt['format_version'] == 2, 'Native receipt-v2 required; Go owner adapters are outside this helper')
    require(receipt['receipt_digest'] == digest(without(receipt, 'receipt_digest')), 'Target receipt digest mismatch')
    for key in ('component_id', 'component_kind', 'module_id', 'vector_id', 'engine_id'):
        require(receipt[key] == component[key], 'Target receipt changes component identity: ' + key)
    require(receipt['install_scope'] == component['install_scope'] and receipt['prefix_mode'] == 'installation_prefix', 'Target receipt scope mismatch')
    require(token(receipt['package_id']) and version(receipt['version']), 'Invalid target package identity')
    require(isinstance(receipt['files'], list) and 0 < len(receipt['files']) <= 4096, 'Target receipt has no bounded payload')
    names = set()
    for f in receipt['files']:
        exact(f, ('path', 'kind', 'size', 'digest'), 'receipt file')
        p = f['path']
        require(isinstance(p, str) and p not in names and not p.startswith('/') and '..' not in PurePosixPath(p).parts and str(PurePosixPath(p)) == p and '\\' not in p and p not in ('', '.') and not any(ord(c) < 32 or ord(c) == 127 for c in p), 'Unsafe receipt path')
        require(not p.startswith('.symphony-') and not p.startswith('share/symphony/receipts/'), 'Receipt owns a protected control path')
        require(f['kind'] in ('regular', 'executable') and type(f['size']) is int and f['size'] >= 0 and tagged(f['digest']), 'Invalid receipt file record')
        names.add(p)
    for k in ('entry_points', 'provides_capabilities', 'requires_capabilities', 'compatible_receptors', 'platform_requirements'):
        require(isinstance(receipt[k], list) and len(receipt[k]) <= 128, 'Invalid receipt collection ' + k)
    for k in ('provides_capabilities', 'requires_capabilities', 'compatible_receptors'):
        require(all(token(v) for v in receipt[k]) and len(set(receipt[k])) == len(receipt[k]), 'Invalid receipt token set')
    entries = set()
    for entry in receipt['entry_points']:
        exact(entry, ('entry_point_id', 'kind', 'path', 'protocols'), 'receipt entry point')
        require(token(entry['entry_point_id']) and entry['entry_point_id'] not in entries and entry['kind'] in ('executable', 'descriptor', 'adapter') and entry['path'] in names, 'Invalid receipt entry point')
        require(isinstance(entry['protocols'], list) and len(entry['protocols']) <= 64 and all(token(v) for v in entry['protocols']), 'Invalid entry protocols')
        entries.add(entry['entry_point_id'])
    for requirement in receipt['platform_requirements']:
        exact(requirement, ('os', 'architecture', 'kernel_abi', 'critical'), 'receipt platform requirement')
        require(requirement['os'] in ('linux', 'macos') and token(requirement['architecture']) and (requirement['kernel_abi'] is None or token(requirement['kernel_abi'])) and type(requirement['critical']) is bool, 'Invalid platform requirement')
