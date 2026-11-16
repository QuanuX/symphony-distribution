#!/usr/bin/env python3
"""Bind reviewed client/source additions to inert carriers without changing core archives."""
from __future__ import annotations
import argparse
import io
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import tarfile
import zipfile

import carriers as c


def checked(path, expected):
    raw, _ = c.bounded(path); c.require(c.sha(raw) == c.digest(expected), 'Selected supplement input digest differs')
    return raw


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            c.require(key not in result, 'Duplicate supplement JSON field'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def source_tree(raw, binding):
    """Reconstruct Git's tree identity from every unchanged source byte/mode."""
    tree = {}; files = {}; rendered = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        c.require(not archive.pax_headers, 'Global inner source metadata')
        for member in archive:
            path = c.relative(member.name)
            c.require(member.name not in files and member.isfile() and not member.linkname and
                member.uid == member.gid == member.mtime == 0 and member.uname == member.gname == '' and
                member.mode in (0o644, 0o755) and set(member.pax_headers) <= {'path'} and member.size <= c.LIMIT,
                'Inner source member metadata differs')
            data = archive.extractfile(member).read(member.size + 1)
            c.require(len(data) == member.size, 'Truncated inner source member')
            files[member.name] = (data, member.mode)
            node = tree
            for part in path.parts[:-1]:
                node = node.setdefault(part, {})
                c.require(isinstance(node, dict), 'Source path/file collision')
            c.require(path.name not in node, 'Source path collision')
            node[path.name] = (data, member.mode)
    def object_hash(kind, data):
        return hashlib.sha1(kind + b' ' + str(len(data)).encode() + b'\0' + data).digest()
    def tree_hash(node):
        records = []
        for name, value in sorted(node.items(), key=lambda x: (x[0] + ('/' if isinstance(x[1], dict) else '')).encode()):
            if isinstance(value, dict): mode, hashed = b'40000', tree_hash(value)
            else:
                data, permissions = value; mode = b'100755' if permissions == 0o755 else b'100644'
                hashed = object_hash(b'blob', data)
            records.append(mode + b' ' + name.encode() + b'\0' + hashed)
        return object_hash(b'tree', b''.join(records))
    with tarfile.open(fileobj=rendered, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            member = tarfile.TarInfo(name); member.size = len(data); member.mode = mode
            archive.addfile(member, io.BytesIO(data))
    c.require(files and rendered.getvalue() == raw, 'Inner source is not canonical')
    c.require(tree_hash(tree).hex() == binding['tree'] and len(files) == binding['file_count'], 'Inner source Git tree/count differs')


def validate_source(archive, index, privacy):
    c.require(index['protocol'] == 'symphony.distribution.d08-corresponding-source.v1' and
        index['state'] == 'prepared_review_only' and index['privacy_scan'] == 'pass' and
        index['publication_authorized'] is False and index['release_acceptance_complete'] is False and
        index['exact_original_full_tree_reconstruction'] is False, 'Source scope or review status differs')
    c.require(index['archive']['sha256'] == c.sha(archive) and index['archive']['size'] == len(archive) and
        privacy['protocol'] == 'symphony.distribution.d08-source-privacy.v1' and privacy['state'] == 'pass' and
        privacy['archive_sha256'] == c.sha(archive) and privacy['publication_authorized'] is False, 'Source archive/index/privacy binding differs')
    members = index['members']; wanted = {}
    required_names = {'SOURCE-SCOPE.json', 'd06/corresponding-source.tar', 'd06/delivery-record.json',
        'd08/client-source.tar', 'd08/distribution-toolkit-source.tar', 'd08/qxctl-original-source-proof.json',
        'd08/reproducible_build.cmake'}
    c.require({r['path'] for r in members} == required_names and len(members) == 7, 'Corresponding-source member set is incomplete')
    for row in members:
        c.relative(row['path']); c.digest(row['sha256'])
        c.require(row['path'] not in wanted and type(row['size']) is int and 0 <= row['size'] <= c.LIMIT and
                  row['mode'] == 0o644 and set(row) == {'path', 'sha256', 'size', 'mode'}, 'Unreviewed source member shape')
        wanted[row['path']] = row
    actual = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as source:
        c.require(not source.pax_headers, 'Source contains global archive metadata')
        for member in source:
            c.relative(member.name)
            c.require(member.name in wanted and member.name not in actual and member.isfile() and
                not member.pax_headers and not member.linkname and member.uid == member.gid == member.mtime == 0 and
                member.uname == member.gname == '' and member.mode == 0o644, 'Source archive contains unselected metadata/member')
            raw = source.extractfile(member).read(member.size + 1)
            row = wanted[member.name]
            c.require(len(raw) == member.size == row['size'] and c.sha(raw) == row['sha256'], 'Source member differs from index')
            actual[member.name] = raw
    c.require(set(actual) == set(wanted) and actual, 'Source archive member closure differs')
    rebuilt = io.BytesIO()
    with tarfile.open(fileobj=rebuilt, mode='w', format=tarfile.PAX_FORMAT) as target:
        for name, raw in sorted(actual.items()):
            member = tarfile.TarInfo(name); member.mode = 0o644; member.size = len(raw)
            target.addfile(member, io.BytesIO(raw))
    c.require(rebuilt.getvalue() == archive, 'Source archive has hidden/noncanonical metadata or padding')
    equivalence = index['compiled_input_equivalence']
    c.require(equivalence['original_matches_cohort_source'] is True and type(equivalence['input_count']) is int and
              equivalence['input_count'] > 0, 'Compiled source equivalence is absent')
    c.digest(equivalence['inventory_sha256'])
    bindings = index['source_bindings']
    for name in ('core', 'client', 'distribution_toolkit'):
        c.require(re.fullmatch('[0-9a-f]{40}', bindings[name]['commit']) and re.fullmatch('[0-9a-f]{40}', bindings[name]['tree']), 'Source Git binding incomplete')
    c.require(parse(actual['SOURCE-SCOPE.json']) == {k: v for k, v in index.items() if k not in
        ('state', 'privacy_scan', 'archive', 'members')}, 'Embedded source scope differs from index')
    c.require(c.sha(actual['d06/corresponding-source.tar']) == index['inherited_reviewed_source_archive_sha256'] and
        c.sha(actual['d06/delivery-record.json']) == index['inherited_delivery_record_sha256'] and
        c.sha(actual['d08/qxctl-original-source-proof.json']) == index['qxctl_source_proof_sha256'], 'Embedded source evidence digest differs')
    proof = parse(actual['d08/qxctl-original-source-proof.json']); delivery = parse(actual['d06/delivery-record.json'])
    c.require(proof['protocol'] == 'symphony.distribution.qxctl-original-source.v1' and
        proof['state'] == 'reproducible_stamped_original_git_source' and proof['publication_authorized'] is False and
        proof['release_acceptance_complete'] is False and proof['original_source'] == bindings['core'] and
        delivery['source']['corresponding_source_archive']['sha256'] == index['inherited_reviewed_source_archive_sha256'] and
        delivery['source']['origin_commit'] == bindings['core']['commit'] and delivery['source']['origin_tree'] == bindings['core']['tree'],
        'Embedded source provenance differs')
    c.require(c.sha(actual['d08/reproducible_build.cmake']) == proof['recipe']['sha256'] and
        equivalence == {'input_count': len(proof['compiled_input_equivalence']['inputs']),
            'inventory_sha256': proof['compiled_input_equivalence']['inventory_sha256'], 'original_matches_cohort_source': True},
        'Embedded recipe or compiled closure differs')
    verifier = c.load_module('d08_compiled_source_verifier', Path(__file__).with_name('corresponding_source.py'))
    verifier.verify_compiled_source(actual['d06/corresponding-source.tar'], proof)
    source_tree(actual['d08/client-source.tar'], bindings['client'])
    source_tree(actual['d08/distribution-toolkit-source.tar'], bindings['distribution_toolkit'])
    return bindings


def validate_client(package, inventory, export, report, core):
    c.require(set(export) == {'source', 'files'} and isinstance(export['files'], dict), 'Client source inventory shape differs')
    c.require(re.fullmatch('[0-9a-f]{40}', export['source']['commit']) and re.fullmatch('[0-9a-f]{40}', export['source']['tree']), 'Client source identity incomplete')
    c.require(report['schema'] == 'symphony.beta-compatibility.report.v1' and report['status'] == 'engineering_review_ready' and
        report['pending'] == [] and report['distribution'] == 'pending' and report['release_acceptance_complete'] is False and
        report['publication_authorized'] is False, 'Legacy real-client source-stamp qualification incomplete')
    c.require(report['sources']['plugin'] == export['source'] and
        all(report['sources']['core'][k] == core['selected_evidence']['source_binding'][k] for k in ('commit', 'tree')),
        'Client source pair differs from selected cohort')
    c.require(report['bindings']['package_sha256'] == 'sha256:' + c.sha(package), 'Qualified client package differs')
    actual = {}; modes = {}
    with zipfile.ZipFile(io.BytesIO(package)) as source:
        c.require(source.comment == b'', 'Client ZIP comment is forbidden')
        for member in source.infolist():
            c.relative(member.filename)
            c.require(member.filename not in actual and not member.is_dir() and member.extra == member.comment == b'' and
                not member.flag_bits & 1 and member.file_size <= c.LIMIT, 'Unreviewed client ZIP member')
            mode = member.external_attr >> 16
            c.require(stat.S_ISREG(mode) and stat.S_IMODE(mode) in (0o644, 0o755), 'Unreviewed client ZIP file type/mode')
            actual[member.filename] = source.read(member); modes[member.filename] = stat.S_IMODE(mode)
    c.require({n: 'sha256:' + c.sha(raw) for n, raw in actual.items()} == inventory, 'Client ZIP inventory differs')
    c.require('bin/symphony-mcp' in actual and 'LICENSE' in actual and 'catalog/tools.json' in actual, 'Client package incomplete')
    for name, raw in actual.items():
        if name == 'bin/symphony-mcp': continue
        c.require(export['files'][name] == 'sha256:' + c.sha(raw), 'Client package source bytes/modes differ')
    c.require(set(export['files']) == set(actual) - {'bin/symphony-mcp'}, 'Client source inventory closure differs')
    c.require(report['bindings']['bridge_sha256'] == 'sha256:' + c.sha(actual['bin/symphony-mcp']) and
        report['bindings']['catalog_sha256'] == 'sha256:' + c.sha(actual['catalog/tools.json']), 'Client binary/catalog binding differs')
    plugin = parse(actual['.claude-plugin/plugin.json'])
    return plugin['version'], actual


def write_archive(root, entry):
    import conda_package_handling as cph
    import conda_package_handling.api as api
    c.require(cph.__version__ == '2.6.0', 'Unreviewed Conda archive writer')
    _, expected = c.validate_recipe(root, entry); files = expected | c.metadata_for(entry, expected)
    stage = root / 'private-assembly'; stage.mkdir(mode=0o700)
    for name, (raw, mode) in files.items():
        path = stage / c.relative(name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(mode)
    channel = root / 'channel' / entry['conda_subdir']; channel.mkdir(parents=True, exist_ok=True)
    filename = entry['conda_name'] + '-' + entry['conda_version'] + '-' + entry['build_string'] + '.conda'
    api.create(str(stage), sorted(files), filename, out_folder=str(channel))
    record = c.audit_archive(channel / filename, root, entry); shutil.rmtree(stage)
    return record


def prepare(base, output, *, expected_base_digest, kind, payload, payload_sha256, index, index_sha256,
            evidence, evidence_sha256, export=None, export_sha256=None, privacy_policy=None):
    base = c.safe_root(base); core = c.audit_cohort(base)
    c.require(core['cohort_digest'] == expected_base_digest, 'Selected base carrier cohort differs')
    payload_raw = checked(payload, payload_sha256); index_raw = checked(index, index_sha256)
    evidence_raw = checked(evidence, evidence_sha256)
    index_doc, evidence_doc = parse(index_raw), parse(evidence_raw)
    sources = {'payload': payload_raw, 'index.json': index_raw, 'qualification.json': evidence_raw}
    if kind == 'source':
        bindings = validate_source(payload_raw, index_doc, evidence_doc)
        c.require(all(bindings['core'][k] == core['selected_evidence']['source_binding'][k] for k in ('commit', 'tree')) and
            index_doc['qxctl_source_proof_sha256'] == core['selected_evidence']['qxctl_source_proof_sha256'] and
            index_doc['inherited_delivery_record_sha256'] == core['selected_evidence']['base_d06']['delivery_sha256'], 'Source/core binding differs')
        client_entry = [e for e in core['entries'] if e['kind'] == 'client_bridge_bundle']
        c.require(len(client_entry) == 1, 'Corresponding source requires selected client-inclusive cohort')
        client_unit, _ = c.validate_recipe(base, client_entry[0])
        c.require(all(bindings['client'][k] == client_unit['provenance']['source'][k] for k in ('commit', 'tree')), 'Source/client binding differs')
        component, version, payload_name = 'corresponding-source-review', '1.0.0', 'corresponding-source.tar'
        provenance = {'kind': 'reviewed_corresponding_source_composite', 'source_bindings': bindings,
            'index_sha256': index_sha256, 'privacy_evidence_sha256': evidence_sha256,
            'exact_original_full_tree_reconstruction': False, 'independent_privacy_rescan_performed': False}
    else:
        c.require(kind == 'client' and export is not None and export_sha256 is not None and privacy_policy is not None, 'Client qualification inputs incomplete')
        export_raw = checked(export, export_sha256); sources['source-export.json'] = export_raw
        client_version, client_members = validate_client(payload_raw, index_doc, parse(export_raw), evidence_doc, core)
        qxctl_entry = next(e for e in core['entries'] if e['unit_id'] == 'go:qxctl')
        qxctl, _ = c.validate_recipe(base, qxctl_entry)
        c.require(evidence_doc['bindings']['qxctl_sha256'] == 'sha256:' + qxctl['provenance']['source_override']['sha256'],
                  'Client qualified a different qxctl')
        scan = c.load_module('d08_supplement_privacy', c.ROOT / 'source-export/export_source.py'); scan.configure_policy(privacy_policy)
        for name, raw in client_members.items(): scan.scan(name, raw)
        for name, raw in sources.items():
            if name != 'payload': scan.scan(name, raw)
        # The review-carrier format has an independent stable version. Preserve
        # the exact upstream prerelease identity without altering core mappings.
        component, version, payload_name = 'client-bridge-review', '1.0.0', 'client.zip'
        provenance = {'kind': 'committed_client_with_legacy_stamp_qualification', 'client_version': client_version,
            'review_carrier_version': version, 'version_scope': 'Independent inert delivery format; upstream client version retained separately', 'source': evidence_doc['sources']['plugin'],
            'qualification_report_sha256': evidence_sha256, 'source_inventory_sha256': export_sha256,
            'package_inventory_sha256': index_sha256, 'bindings': evidence_doc['bindings']}
    sources[payload_name] = sources.pop('payload')
    output = c.safe_root(output, exists=False)
    c.require(not output.exists() and base not in output.parents and output not in base.parents, 'Supplement output must be new and separate')
    output.mkdir(mode=0o700)
    unit = {'unit_id': kind + ':' + component, 'kind': 'optional_corresponding_source' if kind == 'source' else 'client_bridge_bundle',
        'component_id': component, 'native_version': version, 'payload_paths': [],
        'dependency_units': ['go:qxctl'] if kind == 'client' else [], 'external_dependency_units': [], 'sdk_exports': [],
        'provenance': provenance, 'optional_install': kind == 'source'}
    rows = [c.file_row(name, raw) for name, raw in sorted(sources.items())]
    directory = output / 'recipes' / ('symphony-' + component + '-payload')
    entry = c.recipe(unit, directory, rows, {name: lambda raw=raw: raw for name, raw in sources.items()},
                     core['profile'], core['selected_evidence'], None)
    entry['recipe_path'] = directory.relative_to(output).as_posix()
    archive = write_archive(output, entry)
    if kind == 'client':
        c.require(not any(e['kind'] == 'client_bridge_bundle' for e in core['entries']), 'Client already present')
        for old in core['entries']:
            shutil.copytree(base / old['recipe_path'], output / old['recipe_path'])
        for old in core['archives']:
            shutil.copyfile(base / 'channel' / old['subdir'] / old['filename'], output / 'channel' / old['subdir'] / old['filename'])
        record = {k: v for k, v in core.items() if k != 'cohort_digest'}
        record.update(entries=core['entries'] + [entry], archives=core['archives'] + [archive],
                      initial_selection=core['initial_selection'] + [unit['unit_id']],
                      inherited_core_carrier_digest=core['cohort_digest'],
                      client_qualification_sha256=evidence_sha256, supplement_builder_sha256=c.sha(Path(__file__).read_bytes()))
    else:
        record = {'protocol': 'symphony.distribution.d08-optional-source-carrier.v1', 'state': 'archives_audited',
            'base_carrier_cohort_digest': core['cohort_digest'], 'entries': [entry], 'archives': [archive],
            'profile': core['profile'], 'conda_subdir': core['conda_subdir'], 'default_installer_inclusion': False,
            'source_index_sha256': index_sha256, 'source_privacy_sha256': evidence_sha256,
            'supplement_builder_sha256': c.sha(Path(__file__).read_bytes()),
            'publisher_trust_accepted': False, 'publication_authorized': False, 'release_acceptance_complete': False}
    record = c.sealed(record); (output / 'cohort.json').write_bytes(c.canonical(record) + b'\n')
    c.require(c.audit_cohort(base) == core, 'Base carrier cohort changed during supplementation')
    if kind == 'client': c.audit_cohort(output)
    else: audit_source(output)
    return record


def audit_source(root):
    root = c.safe_root(root); record = c.document(root / 'cohort.json'); c.check_seal(record)
    c.require(record['protocol'] == 'symphony.distribution.d08-optional-source-carrier.v1' and record['state'] == 'archives_audited' and
              len(record['entries']) == len(record['archives']) == 1 and record['default_installer_inclusion'] is False and
              all(record[k] is False for k in ('publisher_trust_accepted', 'publication_authorized', 'release_acceptance_complete')),
              'Optional source carrier scope differs')
    entry = record['entries'][0]; row = record['archives'][0]
    c.require(entry['kind'] == 'optional_corresponding_source' and
              row == c.audit_archive(root / 'channel' / row['subdir'] / row['filename'], root, entry), 'Source carrier archive differs')
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'output', 'payload', 'index', 'evidence'): p.add_argument('--' + name, type=Path, required=True)
    for name in ('base-digest', 'payload-sha256', 'index-sha256', 'evidence-sha256'): p.add_argument('--' + name, required=True)
    p.add_argument('--kind', choices=('client', 'source'), required=True)
    p.add_argument('--export', type=Path); p.add_argument('--export-sha256'); p.add_argument('--privacy-policy', type=Path)
    a = p.parse_args()
    try:
        r = prepare(a.base, a.output, expected_base_digest=a.base_digest, kind=a.kind, payload=a.payload, payload_sha256=a.payload_sha256,
            index=a.index, index_sha256=a.index_sha256, evidence=a.evidence, evidence_sha256=a.evidence_sha256,
            export=a.export, export_sha256=a.export_sha256, privacy_policy=a.privacy_policy)
        print(json.dumps({'state': r['state'], 'cohort_digest': r['cohort_digest'], 'archive_count': len(r['archives'])}))
    except (ValueError, KeyError, OSError) as error: p.exit(2, 'Supplement refused: ' + str(error) + '\n')

if __name__ == '__main__': main()
