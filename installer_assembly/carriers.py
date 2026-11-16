#!/usr/bin/env python3
"""Assemble complete, inert review carriers; never install native runtime state.

These are deliberately not signed release candidates or native owner receipts.
Conda owns only opaque archives. Existing trusted owner flows stay separate.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = 'symphony.distribution.d08-review-carriers.v1'
UNIT = 'symphony.distribution.d08-inert-unit.v1'
PROFILES = {'local-macos-amd64-fixture': ('osx-64', 'macos', 'amd64'),
            'macos15-arm64': ('osx-arm64', 'macos', 'arm64'),
            'ubuntu24.04-amd64': ('linux-64', 'linux', 'amd64'),
            'ubuntu26.04-amd64': ('linux-64', 'linux', 'amd64'),
            'ubuntu24.04-arm64': ('linux-aarch64', 'linux', 'arm64')}
LIMIT = 256 * 1024 * 1024


def require(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'Invalid exact SHA256')
    return value


def relative(value):
    require(isinstance(value, str) and 0 < len(value) < 1024 and all(32 <= ord(c) < 127 for c in value), 'Invalid payload name')
    p = PurePosixPath(value)
    require(not p.is_absolute() and str(p) == value and '..' not in p.parts and '\\' not in value and value != '.', 'Unsafe payload name')
    require(not set(p.parts) & {'.git', '.DS_Store', '__pycache__', 'CMakeCache.txt', 'compile_commands.json'}, 'Developer state in payload')
    return p


def safe_root(path, *, exists=True):
    p = Path(path).absolute()
    for item in (p, *p.parents):
        require(not item.is_symlink(), 'Linked input or output root')
    require(p == p.resolve(strict=exists), 'Noncanonical input or output root')
    if exists:
        require(p.is_dir(), 'Input root absent')
    return p


def bounded(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit, 'Unbounded, linked, or nonregular input')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == st.st_size == after.st_size and st.st_mtime_ns == after.st_mtime_ns, 'Input changed during read')
        return raw, stat.S_IMODE(st.st_mode)


def document(path):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'Duplicate JSON field'); result[k] = v
        return result
    return json.loads(bounded(path, 16 * 1024 * 1024)[0], object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'Nonfinite JSON'))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sealed(value):
    return {**value, 'cohort_digest': 'sha256:' + sha(canonical(value))}


def check_seal(value):
    require(value.get('cohort_digest') == sealed({k: v for k, v in value.items() if k != 'cohort_digest'})['cohort_digest'], 'Cohort seal differs')


def rows_by_path(rows):
    require(isinstance(rows, list) and len(rows) <= 20000, 'Invalid file inventory')
    result = {}
    for row in rows:
        relative(row['path']); require(row['path'] not in result, 'Duplicate file inventory path')
        if 'link' in row:
            require(set(row) == {'path', 'link'}, 'Invalid link inventory')
            relative(row['link'])
        else:
            require(set(row) == {'path', 'sha256', 'size', 'mode'} and type(row['size']) is int and 0 <= row['size'] <= LIMIT and
                    row['mode'] in (0o444, 0o555, 0o644, 0o755), 'Invalid regular inventory')
            digest(row['sha256'])
        result[row['path']] = row
    return result


def read_entry(root, row):
    p = root / relative(row['path'])
    for parent in p.parents:
        if parent == root: break
        require(not parent.is_symlink(), 'Linked payload ancestor')
    if 'link' in row:
        require(p.is_symlink() and os.readlink(p) == row['link'] and root in p.resolve(strict=True).parents, 'Payload link differs or escapes')
        return None
    raw, mode = bounded(p)
    require(mode == row['mode'] and len(raw) == row['size'] and sha(raw) == row['sha256'], 'Payload bytes or mode differ')
    return raw


def file_row(name, data, mode=0o644):
    return {'path': name, 'sha256': sha(data), 'size': len(data), 'mode': mode}


def native_units(prefix, delivery, inventory, dependency_map):
    components = delivery['native_components']
    require(len(components) == 51 and len({x['component_id'] for x in components}) == 51, 'Native cohort is incomplete')
    source_map = {x['component_id']: x for x in dependency_map['native_components']}
    source_paths = {x['source_root']: x['component_id'] for x in components}
    units, assigned = [], {}
    for component in components:
        cid, version = component['component_id'], component['version']
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]*', cid), 'Unsafe component identity')
        receipt_name = f'share/symphony/receipts/{cid}/{version}/install-receipt.json'
        require(component['receipt_path'] == receipt_name, 'Receipt path differs')
        receipt_raw = read_entry(prefix, inventory[receipt_name]); receipt = json.loads(receipt_raw)
        body = dict(receipt); seal = body.pop('receipt_digest')
        require(seal == 'sha256:' + sha(canonical(body)) and sha(receipt_raw) == component['receipt_sha256'] and
                (receipt['protocol'], receipt['format_version'], receipt['component_id'], receipt['version']) ==
                ('symphony.knowledge.install-receipt.v2', 2, cid, version), 'Native receipt identity or seal differs')
        files = receipt['files']; names = [x['path'] for x in files]
        require(len(names) == len(set(names)) and set(names) == set(component['files']), 'Receipt file closure differs')
        for row in files:
            path = row['path']; require(path in inventory and 'link' not in inventory[path], 'Native file absent or linked')
            require(row['kind'] in ('regular', 'executable') and
                    (row['kind'] != 'executable' or inventory[path]['mode'] & 0o111) and
                    row['digest'] == 'sha256:' + inventory[path]['sha256'] and row['size'] == inventory[path]['size'],
                    'Receipt does not match final payload')
        names.append(receipt_name)
        uid = 'native:' + cid
        for name in names:
            require(name not in assigned, 'Two native units own the same file'); assigned[name] = uid
        mapping = source_map[cid]
        require(mapping['path'] == component['source_root'] and mapping['package_release_version'] == version, 'Dependency map identity differs')
        deps = ['native:' + source_paths[p] for p in mapping['dependency_paths_in_build_order']]
        require(uid not in deps and len(deps) == len(set(deps)), 'Invalid native dependency closure')
        units.append({'unit_id': uid, 'kind': 'native_receipt_unit', 'component_id': cid, 'native_version': version,
                      'payload_paths': sorted(names), 'dependency_units': sorted(deps),
                      'external_dependency_units': ['external:curl-zstd'] if component['external_dependency_refs'] else [],
                      'sdk_exports': mapping['exported_packages'], 'provenance': component['build_provenance'],
                      'native_receipt_sha256': sha(receipt_raw), 'receipt_digest': seal})
    return units, assigned


def partition(prefix, delivery, candidate, dependency_map):
    inventory = rows_by_path(candidate['payload_inventory'])
    units, assigned = native_units(prefix, delivery, inventory, dependency_map)
    commands = {x['component_id']: x for x in candidate['go_commands']}
    require(len(commands) == 6 and len(delivery['go_artifacts']) == 6, 'Six Go commands required')
    for artifact in delivery['go_artifacts']:
        cid = artifact['id'].removeprefix('go:'); command = commands[cid]; name = artifact['path']
        require(name.startswith('go/' + cid + '/bin/') and name in inventory and name not in assigned and
                'link' not in inventory[name] and inventory[name]['sha256'] == command['sha256'] and
                command['version'] == artifact['version'], 'Go carrier payload differs')
        uid = 'go:' + cid; assigned[name] = uid
        provenance = artifact['build_provenance']
        if cid == 'qxctl':
            override = candidate['qxctl_original_git_override']
            proof_sha = digest(candidate['qxctl_source_proof_sha256'])
            require(command['source_kind'] == 'original_git_recipe_with_equal_cohort_compiled_inputs' and
                    command['qxctl_source_proof_sha256'] == proof_sha and override['component_id'] == cid and
                    override['sha256'] == command['sha256'] and override['cohort_compiled_inputs_equal'] is True,
                    'Original Git qxctl source override differs')
            provenance = {'kind': command['source_kind'], 'source_override': override,
                          'qxctl_source_proof_sha256': proof_sha}
        units.append({'unit_id': uid, 'kind': 'go_command', 'component_id': cid, 'native_version': artifact['version'],
                      'payload_paths': [name], 'dependency_units': [], 'external_dependency_units': [], 'sdk_exports': [],
                      'provenance': provenance,
                      'linked_modules': artifact['linked_modules']})
    external = delivery['external_dependencies']['files']
    require(external and len(external) == len(set(external)) and set(external) == {p for p in inventory if p.startswith('third-party/')}, 'External inventory incomplete')
    for name in external:
        require(name not in assigned, 'External/native double ownership'); assigned[name] = 'external:curl-zstd'
        if 'link' in inventory[name]:
            target = (PurePosixPath(name).parent / inventory[name]['link']).as_posix()
            require(name.startswith('third-party/lib/libcurl') and target in external, 'Unselected external link')
    units.append({'unit_id': 'external:curl-zstd', 'kind': 'external_inert_runtime_and_sdk', 'component_id': 'external-curl-zstd',
                  'native_version': '8.7.1', 'external_versions': {'curl': '8.7.1', 'zstd': '1.5.7'},
                  'payload_paths': sorted(external), 'dependency_units': [], 'external_dependency_units': [], 'sdk_exports': [],
                  'provenance': delivery['external_dependencies']['build_selection'], 'native_runtime_owner': None})
    require(set(assigned) == set(inventory) and len(units) == 58, 'Unassigned payload or incomplete carrier cohort')
    available = {u['unit_id'] for u in units}
    for unit in units:
        require(set(unit['dependency_units'] + unit['external_dependency_units']) <= available, 'Unresolved carrier dependency')
    complete, active = set(), set()
    mapping = {u['unit_id']: u for u in units}
    def visit(uid):
        require(uid not in active, 'Cyclic carrier dependency')
        if uid in complete: return
        active.add(uid)
        for dep in mapping[uid]['dependency_units'] + mapping[uid]['external_dependency_units']: visit(dep)
        active.remove(uid); complete.add(uid)
    for uid in mapping: visit(uid)
    for row in inventory.values(): read_entry(prefix, row)
    return units, assigned, inventory


def write_tar(path, rows, sources):
    """Neutral USTAR preserves original relative paths and complete receipt units."""
    with tarfile.open(path, 'x', format=tarfile.USTAR_FORMAT) as archive:
        for row in sorted(rows, key=lambda r: r['path']):
            info = tarfile.TarInfo(row['path']); info.uid = info.gid = 0; info.uname = info.gname = ''; info.mtime = 0
            if 'link' in row:
                info.type = tarfile.SYMTYPE; info.linkname = row['link']; info.mode = 0o777; archive.addfile(info)
            else:
                raw = sources[row['path']](); require(sha(raw) == row['sha256'] and len(raw) == row['size'], 'Source changed before archiving')
                info.size = len(raw); info.mode = row['mode']; archive.addfile(info, io.BytesIO(raw))
    audit_tar(path, rows)


def audit_tar(path, rows):
    expected = rows_by_path(rows); seen = set()
    with tarfile.open(path, 'r:') as archive:
        require(not archive.pax_headers, 'Global TAR metadata forbidden')
        for member in archive:
            name = member.name; relative(name)
            require(name in expected and name not in seen and member.uid == member.gid == member.mtime == 0 and
                    member.uname == member.gname == '' and not member.pax_headers, 'Unexpected TAR member or publisher metadata')
            seen.add(name); row = expected[name]
            if 'link' in row:
                require(member.issym() and member.linkname == row['link'] and member.mode == 0o777 and member.size == 0, 'TAR link differs')
            else:
                require(member.isfile() and member.mode == row['mode'] and member.size == row['size'], 'TAR file shape differs')
                raw = archive.extractfile(member).read(member.size + 1)
                require(len(raw) == row['size'] and sha(raw) == row['sha256'], 'TAR content differs')
        require(seen == set(expected), 'Missing TAR member')
    # Reconstruct the entire canonical stream, including all headers and every
    # member's padding. A digest of visible files alone cannot expose hidden data.
    rendered = io.BytesIO()
    with tarfile.open(path, 'r:') as original, tarfile.open(fileobj=rendered, mode='w', format=tarfile.USTAR_FORMAT) as rebuilt:
        for row in sorted(rows, key=lambda r: r['path']):
            member = tarfile.TarInfo(row['path']); member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ''
            if 'link' in row:
                member.type = tarfile.SYMTYPE; member.linkname = row['link']; member.mode = 0o777
                rebuilt.addfile(member)
            else:
                member.mode = row['mode']; member.size = row['size']
                rebuilt.addfile(member, original.extractfile(row['path']))
    require(bounded(path)[0] == rendered.getvalue(), 'Noncanonical TAR headers, padding, order or hidden tail')


def dependency_selection(units, requested):
    mapping = {u['unit_id']: u for u in units}; selected = set(requested)
    require(selected and selected <= mapping.keys(), 'Unknown or empty carrier selection')
    pending = list(selected)
    while pending:
        unit = mapping[pending.pop()]
        for dep in unit['dependency_units'] + unit['external_dependency_units']:
            require(dep in mapping, 'Unresolved selected dependency')
            if dep not in selected: selected.add(dep); pending.append(dep)
    return sorted(selected)


def conda_version(version):
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-dev)?', version), 'Unreviewed native version mapping')
    return version[:-4] + 'dev0' if version.endswith('-dev') else version


def recipe(unit, recipe_root, rows, sources, profile, evidence, scan):
    payload = recipe_root / 'payload'; payload.mkdir(parents=True)
    for row in rows:
        if 'link' not in row and scan: scan(row['path'], sources[row['path']]())
    write_tar(payload / 'payload.tar', rows, sources)
    unit_doc = {**unit, 'protocol': UNIT, 'files': rows, 'selected_evidence': evidence,
                'native_runtime_install_supported': False, 'publisher_trust_accepted': False,
                'publication_authorized': False, 'release_acceptance_complete': False}
    unit_raw = canonical(unit_doc) + b'\n'
    if scan: scan('unit.json', unit_raw)
    (payload / 'unit.json').write_bytes(unit_raw)
    files = [file_row(name, bounded(payload / name)[0]) for name in ('payload.tar', 'unit.json')]
    name = 'symphony-' + unit['component_id'] + '-payload'; version = conda_version(unit['native_version'])
    stage = (ROOT / 'recipes/stage_payload.py').read_bytes()
    build = 'd08_' + sha(canonical({'files': files, 'stage_sha256': sha(stage), 'generator_sha256': sha(Path(__file__).read_bytes()), 'profile': profile}))[:20] + '_0'
    destination = f'share/symphony/carriers/{unit["component_id"]}/{unit["native_version"]}/{build}'
    manifest = {'protocol': 'symphony.distribution.d08-inert-carrier.v1', 'unit_id': unit['unit_id'], 'files': files,
                'conda_name': name, 'conda_version': version, 'build': build, 'build_number': 0, 'subdir': PROFILES[profile][0],
                'destination': destination, 'runtime_install_supported': False, 'publication_authorized': False}
    manifest_raw = canonical(manifest) + b'\n'; (payload / 'carrier-manifest.json').write_bytes(manifest_raw)
    (recipe_root / 'stage_payload.py').write_bytes(stage)
    command = '"$SYS_PYTHON" "$RECIPE_DIR/stage_payload.py" "$SRC_DIR" "$PREFIX" ' + sha(manifest_raw) + ' ' + destination
    meta = '\n'.join(['package:', '  name: ' + name, '  version: ' + json.dumps(version), 'source:', '  path: payload',
        'build:', '  number: 0', '  string: ' + build, '  include_recipe: false', '  binary_relocation: false',
        '  detect_binary_files_with_prefix: false', '  ignore_prefix_files: true', '  script: ' + json.dumps(command),
        'about:', '  license: LicenseRef-Complete-Embedded-Notices', '  summary: Inert review carrier; no runtime installation or publisher trust', ''])
    (recipe_root / 'meta.yaml').write_text(meta)
    return {k: unit[k] for k in ('unit_id', 'kind', 'component_id', 'native_version', 'dependency_units', 'external_dependency_units', 'sdk_exports')} | {
        'conda_name': name, 'conda_version': version, 'build_string': build, 'build_number': 0, 'conda_subdir': PROFILES[profile][0],
        'carrier_destination': destination, 'carrier_manifest_sha256': sha(manifest_raw), 'unit_manifest_sha256': sha(bounded(payload / 'unit.json')[0]),
        'payload_sha256': files[0]['sha256'], 'payload_size': files[0]['size'], 'payload_entries': len(rows),
        'recipe_files': {n: sha(bounded(recipe_root / n)[0]) for n in ('meta.yaml', 'stage_payload.py')}}


def prepare(input_root, expected_input_sha256, output, *, profile, privacy_policy):
    input_root = safe_root(input_root); output = safe_root(output, exists=False)
    require(not output.exists() and input_root not in output.parents and output not in input_root.parents, 'Output must be new and separate')
    require(profile in PROFILES, 'Unreviewed profile')
    binding = load_module('d08_input_cohort', Path(__file__).with_name('cohort.py'))
    candidate = binding.verify_cohort(input_root, expected_sha256=expected_input_sha256)
    delivery = document(input_root / 'evidence/base-delivery.json')
    dependency_map = document(input_root / 'evidence/mvp-dependencies.json')
    host = delivery['host']; route = PROFILES[profile]
    require((host['os'], host['architecture']) == route[1:], 'Selected package platform differs from observed host')
    if host.get('scope') == 'supplemental_local_build':
        require(profile == 'local-macos-amd64-fixture', 'Supplemental bytes cannot become a primary platform')
    else:
        require(host.get('scope') == 'native_profile_build' and host.get('requested_profile') == profile,
                'Profile build identity differs')
    prefix = safe_root(input_root / 'prefix')
    units, assigned, inventory = partition(prefix, delivery, candidate, dependency_map)
    exporter = load_module('d08_privacy', ROOT / 'source-export/export_source.py'); exporter.configure_policy(privacy_policy)
    output.mkdir(mode=0o700)
    evidence = {'input_cohort_sha256': digest(expected_input_sha256), 'source_binding': candidate['source_binding'],
                'base_d06': candidate['base_d06'], 'qxctl_source_proof_sha256': candidate['qxctl_source_proof_sha256']}
    entries = []
    notices = {row['path']: row for row in delivery['notices']}
    require(len(notices) == len(delivery['notices']), 'Duplicate legal notice path')
    for unit in units:
        rows = [inventory[name] for name in unit['payload_paths']]
        sources = {row['path']: (lambda row=row: read_entry(prefix, row)) for row in rows if 'link' not in row}
        selected_notices = []
        if unit['kind'] == 'go_command':
            selected_notices = [row for row in notices.values() if row['component'] in ('Symphony', 'go1.26.5')]
            for module in unit['linked_modules']:
                selected_notices.extend(module['notices'])
            require(any(row['component'] == 'Symphony' for row in selected_notices) and
                    any(row['component'] == 'go1.26.5' for row in selected_notices), 'Missing Go/Symphony legal closure')
        elif unit['kind'] == 'external_inert_runtime_and_sdk':
            selected_notices = [row for row in notices.values() if row['component'] in ('curl', 'zstd')]
            require({row['component'] for row in selected_notices} == {'curl', 'zstd'}, 'External legal closure incomplete')
        for name, row in sorted({r['path']: r for r in selected_notices}.items()):
            require(name in notices and row == notices[name], 'Unbound module notice')
            raw, _ = bounded(input_root / 'evidence' / relative(name))
            require(sha(raw) == row['sha256'] and len(raw) == row['size'], 'Legal notice bytes differ')
            archive_name = 'delivery-notices/' + name
            rows.append(file_row(archive_name, raw)); sources[archive_name] = lambda raw=raw: raw
        directory = output / 'recipes' / ('symphony-' + unit['component_id'] + '-payload')
        entry = recipe(unit, directory, rows, sources, profile, evidence, exporter.scan)
        entry['recipe_path'] = directory.relative_to(output).as_posix(); entries.append(entry)
    result = sealed({'protocol': PROTOCOL, 'state': 'prepared', 'profile': profile, 'conda_subdir': route[0],
        'selected_evidence': evidence, 'entries': entries, 'payload_assignment': assigned,
        'payload_entry_count': len(inventory), 'initial_selection': [u['unit_id'] for u in units],
        'sdk_selection': dependency_selection(units, [u['unit_id'] for u in units if u['sdk_exports']]),
        'archives': [], 'permanent_metapackage': False, 'runtime_install_supported': False,
        'publisher_trust_accepted': False, 'publication_authorized': False, 'release_acceptance_complete': False})
    binding.verify_cohort(input_root, expected_sha256=expected_input_sha256)
    (output / 'cohort.json').write_bytes(canonical(result) + b'\n')
    return result


def validate_recipe(root, entry):
    recipe_root = root / relative(entry['recipe_path'])
    require(set(p.name for p in recipe_root.iterdir()) == {'payload', 'meta.yaml', 'stage_payload.py'}, 'Extra recipe inputs')
    for name, expected in entry['recipe_files'].items():
        require(sha(bounded(recipe_root / relative(name))[0]) == expected, 'Recipe implementation changed')
    payload = recipe_root / 'payload'
    require(set(p.name for p in payload.iterdir()) == {'payload.tar', 'unit.json', 'carrier-manifest.json'}, 'Extra carrier payload')
    raw = bounded(payload / 'carrier-manifest.json')[0]
    require(sha(raw) == entry['carrier_manifest_sha256'], 'Carrier manifest differs')
    manifest = document(payload / 'carrier-manifest.json')
    require(manifest['protocol'] == 'symphony.distribution.d08-inert-carrier.v1' and manifest['unit_id'] == entry['unit_id'] and
            manifest['runtime_install_supported'] is False and manifest['publication_authorized'] is False, 'Invalid inert carrier scope')
    for key, other in (('conda_name', 'conda_name'), ('conda_version', 'conda_version'), ('build', 'build_string'),
                       ('build_number', 'build_number'), ('subdir', 'conda_subdir'), ('destination', 'carrier_destination')):
        require(manifest[key] == entry[other], 'Carrier Conda identity differs')
    require({row['path'] for row in manifest['files']} == {'payload.tar', 'unit.json'}, 'Carrier file closure differs')
    for row in rows_by_path(manifest['files']).values(): read_entry(payload, row)
    unit = document(payload / 'unit.json')
    require(all(unit[k] == entry[k] for k in ('unit_id', 'kind', 'component_id', 'native_version',
            'dependency_units', 'external_dependency_units', 'sdk_exports')), 'Unit/entry identity or dependency closure differs')
    require(unit['protocol'] == UNIT and unit['unit_id'] == entry['unit_id'] and unit['kind'] == entry['kind'] and
            all(unit[k] is False for k in ('native_runtime_install_supported', 'publisher_trust_accepted',
                                           'publication_authorized', 'release_acceptance_complete')), 'Unit promotes unsupported runtime/trust')
    require(sha(bounded(payload / 'unit.json')[0]) == entry['unit_manifest_sha256'] and
            sha(bounded(payload / 'payload.tar')[0]) == entry['payload_sha256'] and
            (payload / 'payload.tar').stat().st_size == entry['payload_size'] and len(unit['files']) == entry['payload_entries'], 'Unit artifact differs')
    audit_tar(payload / 'payload.tar', unit['files'])
    expected = {entry['carrier_destination'] + '/' + name: (bounded(payload / name)[0], 0o644)
                for name in ('payload.tar', 'unit.json', 'carrier-manifest.json')}
    return unit, expected


def archive_entries(path):
    # Reuse the strict streaming ZIP/TAR parser, without changing the existing
    # Go owner's four-file protocol or signed native candidate gate.
    parser = load_module('d08_conda_parser', ROOT / 'recipes/build_go_carriers.py')
    return parser.archive_entries(path)


def index_for(entry):
    platform, arch = {'osx-64': ('osx', 'x86_64'), 'osx-arm64': ('osx', 'arm64'),
                      'linux-64': ('linux', 'x86_64'), 'linux-aarch64': ('linux', 'aarch64')}[entry['conda_subdir']]
    return {'name': entry['conda_name'], 'version': entry['conda_version'], 'build': entry['build_string'],
            'build_number': entry['build_number'], 'subdir': entry['conda_subdir'], 'platform': platform, 'arch': arch,
            'depends': [], 'license': 'LicenseRef-Complete-Embedded-Notices', 'timestamp': 0}


def metadata_for(entry, expected):
    paths = [{'_path': name, 'path_type': 'hardlink', 'sha256': sha(raw), 'size_in_bytes': len(raw)}
             for name, (raw, _) in sorted(expected.items())]
    return {'info/index.json': (canonical(index_for(entry)) + b'\n', 0o644),
            'info/paths.json': (canonical({'paths_version': 1, 'paths': paths}) + b'\n', 0o644),
            'info/files': (''.join(name + '\n' for name in sorted(expected)).encode(), 0o644),
            'info/about.json': (canonical({'summary': 'Inert review carrier; explicit native owner installation is separate',
                'license': 'LicenseRef-Complete-Embedded-Notices', 'runtime_install_supported': False,
                'publisher_trust_accepted': False, 'publication_authorized': False}) + b'\n', 0o644)}


def audit_archive(path, root, entry):
    _, expected = validate_recipe(Path(root), entry)
    wanted = expected | metadata_for(entry, expected)
    entries, archive_sha, size = archive_entries(path)
    filename = entry['conda_name'] + '-' + entry['conda_version'] + '-' + entry['build_string'] + '.conda'
    require(Path(path).name == filename and entries == wanted, 'Final Conda bytes/modes/metadata differ; hooks and rewrites forbidden')
    # The only Conda payload is the opaque nested archive and its two manifests.
    # Exact comparison also rejects prefix placeholders, scripts and extra files.
    return {'unit_id': entry['unit_id'], 'filename': filename, 'sha256': archive_sha,
            'md5': hashlib.md5(bounded(path)[0], usedforsecurity=False).hexdigest(), 'size': size,
            'name': entry['conda_name'], 'version': entry['conda_version'], 'build': entry['build_string'],
            'build_number': entry['build_number'], 'subdir': entry['conda_subdir'], 'depends': [],
            'carrier_manifest_sha256': entry['carrier_manifest_sha256']}


def validate_prepared(root, expected_digest=None):
    root = safe_root(root); record = document(root / 'cohort.json'); check_seal(record)
    if expected_digest is not None: require(record['cohort_digest'] == expected_digest, 'Selected cohort digest differs')
    require(record['protocol'] == PROTOCOL and record['state'] in ('prepared', 'archives_audited') and
            all(record[k] is False for k in ('runtime_install_supported', 'publisher_trust_accepted',
                  'publication_authorized', 'release_acceptance_complete', 'permanent_metapackage')), 'Wrong review cohort or authority claim')
    entries = record['entries']; ids = [e['unit_id'] for e in entries]
    require(len(ids) == len(set(ids)) and len(entries) >= 58 and
            sum(e['kind'] == 'native_receipt_unit' for e in entries) == 51 and sum(e['kind'] == 'go_command' for e in entries) == 6 and
            sum(e['kind'] == 'external_inert_runtime_and_sdk' for e in entries) == 1,
            'Incomplete carrier cohort')
    require(set(record['initial_selection']) == set(ids) and len(record['initial_selection']) == len(ids), 'Initial cohort selection differs')
    assignment = {}
    for entry in entries:
        unit, _ = validate_recipe(root, entry)
        require(unit['selected_evidence'] == record['selected_evidence'], 'Unit/cohort source evidence differs')
        for name in unit.get('payload_paths', []):
            require(name not in assignment, 'Duplicate cross-carrier ownership'); assignment[name] = unit['unit_id']
    require(assignment == record['payload_assignment'] and len(assignment) == record['payload_entry_count'], 'Payload coverage differs')
    require(record['sdk_selection'] == dependency_selection(entries, [e['unit_id'] for e in entries if e['sdk_exports']]), 'SDK closure differs')
    return record


def audit_cohort(root):
    root = safe_root(root); record = validate_prepared(root)
    require(record['state'] == 'archives_audited' and len(record['archives']) == len(record['entries']), 'Cohort archives not assembled')
    entries = {e['unit_id']: e for e in record['entries']}; seen = set()
    for row in record['archives']:
        require(row['unit_id'] in entries and row['unit_id'] not in seen, 'Duplicate or unknown archive')
        seen.add(row['unit_id']); relative(row['filename'])
        require(row == audit_archive(root / 'channel' / record['conda_subdir'] / row['filename'], root, entries[row['unit_id']]), 'Recorded archive identity differs')
    require({p.name for p in (root / 'channel' / record['conda_subdir']).iterdir()} == {r['filename'] for r in record['archives']}, 'Unexpected channel material')
    return record


def build_cohort(prepared, output, expected_digest):
    """Use Conda's official archive writer; this is not a conda-build run."""
    import conda_package_handling as cph
    import conda_package_handling.api as package_api
    require(cph.__version__ == '2.6.0', 'Unreviewed Conda archive writer version')
    prepared = safe_root(prepared); record = validate_prepared(prepared, expected_digest)
    require(record['state'] == 'prepared' and record['archives'] == [], 'Expected unassembled prepared cohort')
    output = safe_root(output, exists=False)
    require(not output.exists() and prepared not in output.parents and output not in prepared.parents, 'Archive output must be new and separate')
    output.mkdir(mode=0o700); shutil.copytree(prepared / 'recipes', output / 'recipes')
    channel = output / 'channel' / record['conda_subdir']; channel.mkdir(parents=True)
    scratch = output / 'private-assembly'; scratch.mkdir(mode=0o700)
    archives = []
    for entry in record['entries']:
        _, expected = validate_recipe(output, entry); files = expected | metadata_for(entry, expected)
        stage = scratch / entry['component_id']; stage.mkdir()
        for name, (data, mode) in files.items():
            path = stage / relative(name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(mode)
        filename = entry['conda_name'] + '-' + entry['conda_version'] + '-' + entry['build_string'] + '.conda'
        package_api.create(str(stage), sorted(files), filename, out_folder=str(channel))
        archives.append(audit_archive(channel / filename, output, entry))
        # Only this invocation's verified intermediate copy is reclaimed.
        shutil.rmtree(stage)
    scratch.rmdir()
    validate_prepared(prepared, expected_digest)
    result = {k: v for k, v in record.items() if k != 'cohort_digest'}
    result.update(state='archives_audited', archives=archives,
        archive_assembly={'method': 'conda_package_handling.api.create', 'writer_version': cph.__version__,
                         'writer_module_sha256': sha(Path(cph.__file__).read_bytes()),
                         'conda_build_executed': False, 'native_binaries_rebuilt': False,
                         'carrier_builder_sha256': sha(Path(__file__).read_bytes())})
    result = sealed(result); (output / 'cohort.json').write_bytes(canonical(result) + b'\n')
    return audit_cohort(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_subparsers(dest='operation', required=True)
    prepare_parser = modes.add_parser('prepare')
    prepare_parser.add_argument('--input', type=Path, required=True); prepare_parser.add_argument('--input-sha256', required=True)
    prepare_parser.add_argument('--output', type=Path, required=True); prepare_parser.add_argument('--profile', required=True)
    prepare_parser.add_argument('--privacy-policy', type=Path, required=True)
    build_parser = modes.add_parser('build')
    build_parser.add_argument('--prepared', type=Path, required=True); build_parser.add_argument('--cohort-digest', required=True)
    build_parser.add_argument('--output', type=Path, required=True)
    audit_parser = modes.add_parser('audit'); audit_parser.add_argument('--cohort', type=Path, required=True)
    a = p.parse_args()
    try:
        if a.operation == 'prepare':
            result = prepare(a.input, a.input_sha256, a.output, profile=a.profile, privacy_policy=a.privacy_policy)
        elif a.operation == 'build': result = build_cohort(a.prepared, a.output, a.cohort_digest)
        else: result = audit_cohort(a.cohort)
        print(json.dumps({'state': result['state'], 'carrier_count': len(result['entries']), 'cohort_digest': result['cohort_digest']}))
    except (ValueError, KeyError, OSError) as e:
        p.exit(2, 'Carrier preparation refused: ' + str(e) + '\n')


if __name__ == '__main__':
    main()
