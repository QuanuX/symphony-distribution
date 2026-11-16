#!/usr/bin/env python3
"""Rewrap unchanged signed carriers with separately signed, source-bound repairs.

Original D09 delivery/staging evidence stays immutable. This local wrapper
supplement does not upload packages, alter native payloads or approve release.
"""
from __future__ import annotations
import argparse
import io
import json
import re
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
sys.path.insert(0, str(ROOT))
import carriers as c
import construct
import review_signing as signing
import supplements
from channel import install_qualification as original
from qualification import d09_platform as inspection

PROTOCOL = 'symphony.distribution.d10-local-wrapper-overlay.v1'
SOURCE = 'symphony.distribution.d10-wrapper-toolkit-source.v1'
HELPERS = tuple(sorted(set(original.HELPERS) | {
    'qualification/d10_mac_overlay.py', 'qualification/d09_platform.py',
    'installer_assembly/construct.py', 'installer_assembly/constructor_runner.py',
    'installer_assembly/pkg_finalize.py', 'installer_assembly/supplements.py',
    'installer_assembly/corresponding_source.py', 'installer_assembly/tool-lock.json',
    'qualification/d06_delivery_record.py', 'qualification/d06_upstream_source.py',
    'source-export/export_source.py', 'recipes/stage_payload.py'}))


def recipe_metadata(entry):
    stage = (ROOT / 'recipes/stage_payload.py').read_bytes()
    command = '"$SYS_PYTHON" "$RECIPE_DIR/stage_payload.py" "$SRC_DIR" "$PREFIX" ' + entry['carrier_manifest_sha256'] + ' ' + entry['carrier_destination']
    meta = '\n'.join(['package:', '  name: ' + entry['conda_name'], '  version: ' + json.dumps(entry['conda_version']),
        'source:', '  path: payload', 'build:', '  number: 0', '  string: ' + entry['build_string'],
        '  include_recipe: false', '  binary_relocation: false', '  detect_binary_files_with_prefix: false',
        '  ignore_prefix_files: true', '  script: ' + json.dumps(command), 'about:',
        '  license: LicenseRef-Complete-Embedded-Notices',
        '  summary: Inert review carrier; no runtime installation or publisher trust', '']).encode()
    result = {'meta.yaml': meta, 'stage_payload.py': stage}
    c.require({name: c.sha(raw) for name, raw in result.items()} == entry['recipe_files'], 'Original recipe metadata cannot be reproduced exactly')
    return result


def reconstruct(artifacts, cohort, output):
    """Recover only signed bytes and hash-identical metadata; never rebuild a carrier."""
    output = inspection.fresh(output, (artifacts, ROOT)); entries = {r['unit_id']: r for r in cohort['entries']}
    channel = output / 'channel' / cohort['conda_subdir']; channel.mkdir(parents=True)
    for row in cohort['archives']:
        entry = entries[row['unit_id']]
        raw, _ = c.bounded(artifacts / row['filename'])
        c.require(c.sha(raw) == row['sha256'] and len(raw) == row['size'], 'Signed carrier changed before reconstruction')
        parsed, digest, size = c.archive_entries(artifacts / row['filename'])
        c.require(digest == row['sha256'] and size == row['size'], 'Carrier changed during reconstruction')
        payload = original.expected_carrier(parsed, entry, row)
        recipe = output / c.relative(entry['recipe_path']); (recipe / 'payload').mkdir(parents=True)
        for name, data in recipe_metadata(entry).items(): (recipe / name).write_bytes(data)
        for name, (data, mode) in payload.items():
            path = recipe / 'payload' / Path(name).name; path.write_bytes(data); path.chmod(mode)
        (channel / row['filename']).write_bytes(raw)
    (output / 'cohort.json').write_bytes(c.canonical(cohort) + b'\n')
    c.require(c.audit_cohort(output) == cohort, 'Reconstructed audit layout differs')
    return output


def toolkit_source(output, commit, policy, helpers):
    source = c.load_module('d10_source_composer', ROOT / 'installer_assembly/corresponding_source.py')
    scanner = c.load_module('d10_source_scan', ROOT / 'source-export/export_source.py'); scanner.configure_policy(policy)
    rows, identity = source.committed_files(ROOT, commit, scanner, toolkit=True)
    contents = {name: data for name, data, mode in rows}
    c.require(all(name in contents and c.sha(contents[name]) == digest for name, digest in helpers.items()),
              'Executing wrapper helpers are not the selected committed source')
    archive = output / 'WRAPPER-TOOLKIT-SOURCE.tar'; files = source.write_tar(archive, rows)
    supplements.source_tree(c.bounded(archive)[0], identity)
    index = {'protocol': SOURCE, 'source': identity, 'files': files, 'archive_sha256': signing.digest(archive),
             'executing_helpers': helpers, 'privacy_scan': 'pass', 'publication_authorized': False}
    signing.write(output / 'WRAPPER-TOOLKIT-SOURCE.json', signing.canonical(index), 0o644)
    return index


def admit(root, expected_manifest, certificate, openssl, plan, cohort, *, original_wrapper_audit_sha256):
    root = c.safe_root(root); c.digest(expected_manifest)
    artifacts = c.safe_root(root / 'artifacts')
    signing.verify(root / 'signature', artifacts, certificate, openssl)
    c.require(signing.digest(root / 'signature/review-manifest.json') == expected_manifest, 'Selected overlay manifest differs')
    manifest = c.document(root / 'signature/review-manifest.json'); signed = {r['name']: r for r in manifest['artifacts']}
    def read_signed(name):
        c.require(name in signed, 'Required overlay file is not signed')
        raw, _ = c.bounded(artifacts / name)
        c.require(c.sha(raw) == signed[name]['sha256'] and len(raw) == signed[name]['size'], 'Signed overlay bytes changed')
        return raw
    binding = supplements.parse(read_signed('WRAPPER-REPAIR.json')); wrapper = supplements.parse(read_signed('WRAPPER-AUDIT.json'))
    source = supplements.parse(read_signed('WRAPPER-TOOLKIT-SOURCE.json'))
    c.require(set(signed) == {'WRAPPER-REPAIR.json', 'WRAPPER-AUDIT.json', 'WRAPPER-TOOLKIT-SOURCE.json', 'WRAPPER-TOOLKIT-SOURCE.tar'} |
              {r['filename'] for r in wrapper['wrappers']}, 'Exact wrapper/source overlay set required')
    c.require(binding['protocol'] == PROTOCOL and binding['state'] == 'local_review_wrapper_repair' and
              binding['base_signed_manifest_sha256'] == plan['signed_manifest_sha256'] and
              binding['base_plan_sha256'] == plan['plan_sha256'] and binding['base_source_bindings'] == plan['source_bindings'] and
              binding['carrier_cohort_digest'] == cohort['cohort_digest'] and binding['unchanged_carrier_archives'] == cohort['archives'] and
              binding['original_wrapper_audit_sha256'] == c.digest(original_wrapper_audit_sha256) and
              all(binding[k] is False for k in ('carrier_bytes_changed', 'public_channel_mutated', 'publication_authorized', 'release_acceptance_complete')),
              'Overlay relabels source/carriers or grants unselected authority')
    c.require(binding['wrapper_audit_sha256'] == signing.digest(artifacts / 'WRAPPER-AUDIT.json') and
              binding['toolkit_source_index_sha256'] == signing.digest(artifacts / 'WRAPPER-TOOLKIT-SOURCE.json'),
              'Overlay evidence binding differs')
    c.require(set(binding['executing_helpers']) == set(HELPERS), 'Exact committed executing-helper closure required')
    c.require(all(re.fullmatch('[0-9a-f]{40}', source['source'][key]) for key in ('commit', 'tree')), 'Exact toolkit Git identity required')
    archive = read_signed('WRAPPER-TOOLKIT-SOURCE.tar')
    c.require(source['protocol'] == SOURCE and source['privacy_scan'] == 'pass' and source['publication_authorized'] is False and
              source['archive_sha256'] == c.sha(archive) and source['executing_helpers'] == binding['executing_helpers'] and
              source['source'] == binding['repair_toolkit_source'], 'Overlay source closure differs')
    supplements.source_tree(archive, source['source'])
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        observed = []
        for member in stream:
            data = stream.extractfile(member).read()
            observed.append({'path': member.name, 'sha256': c.sha(data), 'size': len(data), 'mode': member.mode})
        c.require(observed == source['files'], 'Overlay source inventory differs')
        for name, digest in binding['executing_helpers'].items():
            c.require(c.sha(stream.extractfile(name).read()) == c.digest(digest), 'Overlay executing helper absent from source')
    return artifacts, wrapper, binding


def prepare(args):
    helper_hashes = {name: signing.digest(ROOT / name) for name in HELPERS}
    plan_raw, stage_raw = c.bounded(args.plan)[0], c.bounded(args.stage_record)[0]
    plan, stage = supplements.parse(plan_raw), supplements.parse(stage_raw)
    original.validate_plan(plan, args.plan_sha256, stage)
    original.admit_delivery(plan, args.delivery, args.certificate_sha256, args.openssl)
    artifacts = c.safe_root(args.delivery / 'artifacts')
    manifest_raw = c.bounded(args.delivery / 'signature/review-manifest.json')[0]
    c.require(c.sha(manifest_raw) == plan['signed_manifest_sha256'], 'Original selected manifest changed')
    signed = {r['name']: r for r in supplements.parse(manifest_raw)['artifacts']}
    def original_bytes(name):
        c.require(name in signed, 'Required original evidence is not signed')
        raw = c.bounded(artifacts / name)[0]
        c.require(c.sha(raw) == signed[name]['sha256'] and len(raw) == signed[name]['size'], 'Original signed evidence changed')
        return raw
    cohort = supplements.parse(original_bytes('CARRIER-COHORT.json'))
    original_audit_sha = c.sha(original_bytes('WRAPPER-AUDIT.json'))
    c.require(cohort['profile'] == 'local-macos-amd64-fixture' and len(cohort['archives']) == 59, 'Selected Mac default59 required')
    output = inspection.fresh(args.output, (args.delivery, args.plan, args.stage_record, args.custody, args.privacy_policy, ROOT)); public = output / 'artifacts'; public.mkdir(mode=0o700)
    source = toolkit_source(public, args.toolkit_commit, args.privacy_policy, helper_hashes)
    reconstructed = reconstruct(artifacts, cohort, output / 'reconstructed-carriers')
    wrapped = construct.assemble(reconstructed, output / 'wrapper-build', interpreter=args.python,
        standalone=args.standalone, standalone_archive=args.standalone_archive, formats=['pkg', 'sh'],
        privacy_policy=args.privacy_policy, supplemental=True)
    for row in wrapped['wrappers']:
        raw, _ = c.bounded(output / 'wrapper-build' / row['filename']); c.require(c.sha(raw) == row['sha256'], 'Final wrapper changed')
        (public / row['filename']).write_bytes(raw)
    audit_raw = c.bounded(output / 'wrapper-build/result.json')[0]
    (public / 'WRAPPER-AUDIT.json').write_bytes(audit_raw)
    binding = {'protocol': PROTOCOL, 'state': 'local_review_wrapper_repair',
        'reason': 'restore_pinned_standalone_constructor_entrypoint_without_ambient_plugins',
        'base_plan_sha256': plan['plan_sha256'], 'base_signed_manifest_sha256': plan['signed_manifest_sha256'],
        'base_source_bindings': plan['source_bindings'], 'carrier_cohort_digest': cohort['cohort_digest'],
        'unchanged_carrier_archives': cohort['archives'], 'original_wrapper_audit_sha256': original_audit_sha,
        'wrapper_audit_sha256': c.sha(audit_raw), 'toolkit_source_index_sha256': signing.digest(public / 'WRAPPER-TOOLKIT-SOURCE.json'),
        'repair_toolkit_source': source['source'], 'executing_helpers': helper_hashes,
        'carrier_bytes_changed': False, 'public_channel_mutated': False, 'publication_authorized': False, 'release_acceptance_complete': False}
    signing.write(public / 'WRAPPER-REPAIR.json', signing.canonical(binding), 0o644)
    c.require(helper_hashes == {name: signing.digest(ROOT / name) for name in HELPERS}, 'Wrapper helper changed during assembly')
    signing.sign(list(public.iterdir()), args.custody, args.certificate_sha256, output / 'signature', args.openssl)
    selected = signing.digest(output / 'signature/review-manifest.json')
    admit(output, selected, args.certificate_sha256, args.openssl, plan, cohort, original_wrapper_audit_sha256=original_audit_sha)
    original.admit_delivery(plan, args.delivery, args.certificate_sha256, args.openssl)
    c.require(c.bounded(args.plan)[0] == plan_raw and c.bounded(args.stage_record)[0] == stage_raw, 'Original staging records changed')
    result = {'protocol': PROTOCOL, 'state': 'separately_signed_local_wrapper_overlay_verified',
        'overlay_manifest_sha256': selected, 'review_certificate_sha256': args.certificate_sha256,
        'binding_sha256': signing.digest(public / 'WRAPPER-REPAIR.json'), 'carrier_cohort_digest': cohort['cohort_digest'],
        'repair_toolkit_source': source['source'], 'original_delivery_unchanged': True,
        'public_channel_mutated': False, 'publication_authorized': False}
    signing.write(output / 'result.json', signing.canonical(result)); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'stage-record', 'delivery', 'output', 'openssl', 'custody', 'privacy-policy', 'python', 'standalone', 'standalone-archive'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('plan-sha256', 'certificate-sha256', 'toolkit-commit'): parser.add_argument('--' + name, required=True)
    result = prepare(parser.parse_args()); print(json.dumps(result))

if __name__ == '__main__': main()
