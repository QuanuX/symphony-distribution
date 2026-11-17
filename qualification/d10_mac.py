#!/usr/bin/env python3
"""Exercise the explicitly selected supplemental Mac shell wrapper in private state.

Never invokes Apple's system installer, native owners, application selection,
account credentials or system trust. Local evidence is not primary/fresh-host
or independent acceptance, and cannot grant legal or beta release approval.
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installer_assembly'))
sys.path.insert(0, str(ROOT))
import carriers as c
import construct
import review_signing as signing
from channel import install_qualification as delivery_check
from qualification import d09_platform as inspection
from qualification.native_campaign import bounded_run
from qualification import host_platform
from qualification import d10_mac_overlay as overlay

PROTOCOL = 'symphony.distribution.d10-supplemental-mac-shell.v1'
PROFILE = 'local-macos-amd64-fixture'
HELPERS = tuple(sorted(set(delivery_check.HELPERS) | set(overlay.HELPERS) | {
    'qualification/d10_mac.py', 'qualification/d09_platform.py',
    'qualification/native_campaign.py', 'installer_assembly/construct.py'}))


def host_admission(profile, observed):
    c.require(profile == PROFILE and observed.get('system') == 'darwin' and
              observed.get('architecture') == 'amd64' and host_platform.profile_matches(profile, observed),
              'Only the explicitly selected supplemental Intel Mac build is admitted')


def signed_artifact(artifacts, signed, name):
    c.require(name in signed and Path(name).name == name, 'Required selected file is not in the signed manifest')
    path = signing.regular(artifacts / name)
    c.require(signing.digest(path) == signed[name]['sha256'] and path.stat().st_size == signed[name]['size'],
              'Signed file bytes or size differ')
    return path


def wrapper_selection(cohort, wrapper):
    c.require(cohort['profile'] == PROFILE and cohort['conda_subdir'] == 'osx-64' and
              len(cohort['archives']) == len(cohort['entries']) == 59, 'Exact supplemental default59 required')
    rows = construct.archive_records(cohort)
    c.require(wrapper['protocol'] == 'symphony.distribution.d08-unsigned-wrapper.v1' and
              wrapper['state'] == 'unsigned_wrappers_audited' and wrapper['profile'] == PROFILE and
              wrapper['cohort_digest'] == cohort['cohort_digest'] and wrapper['archives'] == rows and
              all(wrapper[key] is False for key in ('publication_authorized', 'release_acceptance_complete', 'runtime_activated')),
              'Signed wrapper evidence differs from selected inert cohort')
    shells = [row for row in wrapper['wrappers'] if row['format'] == 'sh']
    c.require(len(shells) == 1 and shells[0]['archive_count'] == 59 and
              Path(shells[0]['filename']).name == shells[0]['filename'] and shells[0]['filename'].endswith('.sh'),
              'Exactly one selected native shell wrapper required')
    c.digest(shells[0]['sha256']); c.digest(shells[0]['bootstrap_sha256'])
    return shells[0]


def carrier_namespace(prefix):
    result = {}
    base = prefix / 'share/symphony/carriers'
    c.require(not base.is_symlink(), 'Linked carrier namespace refused')
    for path in base.rglob('*'):
        c.require(not path.is_symlink(), 'Linked carrier member refused')
        if path.is_file(): result[path.relative_to(prefix).as_posix()] = c.bounded(path)
        else: c.require(path.is_dir(), 'Special carrier member refused')
    return result


def snapshot_wrapper(selected, row, output):
    raw, _ = c.bounded(selected)
    c.require(c.sha(raw) == row['sha256'] and len(raw) == row['size'], 'Signed execution snapshot differs')
    path = output / 'selected-wrapper.sh'
    signing.write(path, raw, 0o400)
    c.require(signing.digest(path) == row['sha256'], 'Execution snapshot changed while copied')
    return path


def isolated_environment(output):
    for name in ('home', 'tmp', 'cache', 'pkgs', 'envs'):
        (output / name).mkdir(mode=0o700)
    home = output / 'home'
    for name in ('.conda', '.config'): (home / name).mkdir(mode=0o700)
    for name in ('.condarc', '.bashrc', '.zshrc', '.conda/environments.txt', '.config/user-sentinel'):
        (home / name).write_bytes(b'# isolated caller state must survive\n')
    config = home / 'condarc'
    config.write_text('channels: []\ndefault_channels: []\ncreate_default_packages: []\nreport_errors: false\n'
        'register_envs: false\nanaconda_upload: false\nadd_anaconda_token: false\nssl_verify: true\n')
    return {'HOME': str(home), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(output / 'tmp'),
        'TMP': str(output / 'tmp'), 'TEMP': str(output / 'tmp'), 'XDG_CONFIG_HOME': str(home / '.config'),
        'XDG_CACHE_HOME': str(output / 'cache'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'USER': 'builder', 'LOGNAME': 'builder',
        'CONDARC': str(config), 'CONDA_ALWAYS_COPY': 'true', 'CONDA_OFFLINE': 'true', 'CONDA_SUBDIR': 'osx-64', 'CONDA_NO_PLUGINS': 'true',
        'CONDA_REGISTER_ENVS': 'false', 'CONDA_ADD_ANACONDA_TOKEN': 'false',
        'CONDA_REPORT_ERRORS': 'false', 'CONDA_PKGS_DIRS': str(output / 'pkgs'), 'CONDA_ENVS_PATH': str(output / 'envs'),
        'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}


def invoke(command, env, log, *, expected=0):
    with log.open('xb') as stream:
        code = bounded_run([str(x) for x in command], env=env, stdin=subprocess.DEVNULL,
            stdout=stream, stderr=subprocess.STDOUT, timeout=600)
    c.require(code == expected, 'Selected installer command had an unexpected outcome; private log retained')
    return {'name': log.name, 'sha256': signing.digest(log), 'exit_code': code}


def installed_metadata(prefix, rows):
    files = list((prefix / 'conda-meta').glob('*.json'))
    actual = [c.document(path) for path in files]
    selected = {(r['name'], r['version'], r['build'], r['subdir']) for r in rows}
    c.require(len(actual) == len(rows) and
              {(r['name'], r['version'], r['build'], r['subdir']) for r in actual} == selected,
              'Installed package selection differs')
    return sorted(r['name'] for r in rows)


def qualify(args):
    c.require(args.allow_selected_mac is True, 'Explicit selected-Mac opt-in required')
    helpers = {name: signing.digest(ROOT / name) for name in HELPERS}
    plan_path, stage_path, delivery = map(signing.plain, (args.plan, args.stage_record, args.delivery))
    plan_raw, stage_raw = c.bounded(plan_path)[0], c.bounded(stage_path)[0]
    plan, stage = c.document(plan_path), c.document(stage_path)
    delivery_check.validate_plan(plan, args.plan_sha256, stage)
    observed = host_platform.observe_host(); host_admission(plan['profile'], observed)
    # Verify every signed byte and all60 independent carrier metadata records.
    complete = delivery_check.admit_delivery(plan, delivery, args.certificate_sha256, args.openssl)
    artifacts = delivery / 'artifacts'
    signed = {r['name']: r for r in c.document(delivery / 'signature/review-manifest.json')['artifacts']}
    cohort, wrapper = (c.document(signed_artifact(artifacts, signed, name))
                       for name in ('CARRIER-COHORT.json', 'WRAPPER-AUDIT.json'))
    original_audit_sha = signing.digest(artifacts / 'WRAPPER-AUDIT.json')
    overlay_binding = None
    overlay_root = getattr(args, 'wrapper_overlay', None); overlay_manifest = getattr(args, 'wrapper_manifest_sha256', None)
    c.require(bool(overlay_root) == bool(overlay_manifest), 'Wrapper overlay and independently selected manifest are required together')
    if overlay_root:
        wrapper_artifacts, wrapper, overlay_binding = overlay.admit(overlay_root, overlay_manifest,
            args.certificate_sha256, args.openssl, plan, cohort, original_wrapper_audit_sha256=original_audit_sha)
        signed = {r['name']: r for r in c.document(overlay_root / 'signature/review-manifest.json')['artifacts']}
    else: wrapper_artifacts = artifacts
    row = wrapper_selection(cohort, wrapper); selected = signed_artifact(wrapper_artifacts, signed, row['filename'])
    c.require(signing.digest(selected) == row['sha256'] and selected.stat().st_size == row['size'], 'Selected wrapper changed')
    construct.audit_sh(selected, cohort['archives'], row['bootstrap_sha256'], [])
    destinations = {entry['carrier_destination'] for entry in cohort['entries']}
    expected = {name: value for name, value in complete.items() if str(Path(name).parent) in destinations}
    c.require(len(expected) == 177, 'Exact default59 linked-file closure required')
    output = inspection.fresh(args.output, (delivery, plan_path, stage_path, ROOT, *([overlay_root] if overlay_root else [])))
    execution = snapshot_wrapper(selected, row, output)
    construct.audit_sh(execution, cohort['archives'], row['bootstrap_sha256'], [])
    env = isolated_environment(output); home_before = inspection.inventory(output / 'home')
    outside = output / 'outside-sentinel'; outside.write_bytes(b'outside caller state\n')
    prefix = output / 'prefix'; logs = []
    try:
        logs.append(invoke(['/bin/bash', execution, '-b', '-p', prefix], env, output / 'install.log'))
        c.require(carrier_namespace(prefix) == expected, 'Installed carrier bytes or modes differ')
        inspection.verify_wrapper_link(prefix, expected)
        names = installed_metadata(prefix, cohort['archives'])
        bootstrap = signing.regular(prefix / '_conda')
        c.require(signing.digest(bootstrap) == row['bootstrap_sha256'], 'Installed maintenance bootstrap differs')
        auxiliary = inspection.inventory(prefix / 'share/symphony/installer')
        (prefix / 'user-state.txt').write_bytes(b'caller state survives removal\n')
        before = inspection.inventory(prefix, allow_hardlinks=True)
        for label, flags in (('existing', []), ('force', ['-f']), ('upgrade', ['-u'])):
            logs.append(invoke(['/bin/bash', execution, '-b', *flags, '-p', prefix], env, output / (label + '.log'), expected=1))
        dangling = output / 'dangling-prefix'; dangling.symlink_to(output / 'absent-target')
        logs.append(invoke(['/bin/bash', execution, '-b', '-p', dangling], env, output / 'dangling.log', expected=1))
        c.require(dangling.is_symlink() and not (output / 'absent-target').exists(), 'Dangling refusal changed destination')
        c.require(inspection.inventory(prefix, allow_hardlinks=True) == before, 'Refusal changed installed or caller bytes')
        c.require(inspection.inventory(output / 'home') == home_before and outside.read_bytes() == b'outside caller state\n',
                  'Installer changed private caller state')
        logs.append(invoke([bootstrap, 'remove', '--prefix', prefix, '--offline', '--yes', '--solver', 'classic', *names],
                           env, output / 'remove.log'))
        c.require(carrier_namespace(prefix) == {} and not list((prefix / 'conda-meta').glob('*.json')),
                  'Carrier files or installed package records remain')
        c.require((prefix / 'user-state.txt').read_bytes() == b'caller state survives removal\n' and
                  outside.read_bytes() == b'outside caller state\n' and inspection.inventory(output / 'home') == home_before,
                  'Removal changed caller or outside state')
        c.require(inspection.inventory(prefix / 'share/symphony/installer') == auxiliary and
                  signing.digest(bootstrap) == row['bootstrap_sha256'], 'Removal changed wrapper notices/bootstrap')
        c.require(delivery_check.admit_delivery(plan, delivery, args.certificate_sha256, args.openssl) == complete and
                  signing.digest(selected) == row['sha256'], 'Original signed delivery changed')
        c.require(signing.digest(execution) == row['sha256'], 'Private execution snapshot changed')
        if overlay_root:
            c.require(overlay.admit(overlay_root, overlay_manifest, args.certificate_sha256, args.openssl, plan, cohort, original_wrapper_audit_sha256=original_audit_sha)[2] == overlay_binding,
                      'Selected wrapper overlay changed')
        c.require(c.bounded(plan_path)[0] == plan_raw and c.bounded(stage_path)[0] == stage_raw and
                  helpers == {name: signing.digest(ROOT / name) for name in HELPERS}, 'Selected records or executing helpers changed')
        result = {'protocol': PROTOCOL, 'state': 'supplemental_mac_shell_install_refusals_and_removal_passed',
            'profile': PROFILE, 'observed_host': observed, 'user_selected_local_build': True,
            'plan_sha256': args.plan_sha256, 'plan_file_sha256': c.sha(plan_raw), 'stage_record_sha256': c.sha(stage_raw),
            'source_bindings': plan['source_bindings'], 'signed_manifest_sha256': plan['signed_manifest_sha256'],
            'review_certificate_sha256': args.certificate_sha256, 'cohort_digest': cohort['cohort_digest'],
            'wrapper_audit_sha256': signing.digest(wrapper_artifacts / 'WRAPPER-AUDIT.json'), 'shell_wrapper_sha256': row['sha256'],
            'bootstrap_sha256': row['bootstrap_sha256'], 'executed_snapshot_sha256': signing.digest(execution),
            'private_execution_snapshot_verified': True, 'wrapper_overlay_manifest_sha256': overlay_manifest,
            'wrapper_overlay_binding': overlay_binding, 'imported_helpers': helpers, 'logs': logs,
            'default_carrier_count': 59, 'linked_file_count': 177, 'all_selected_carriers_removed': True,
            'fresh_prefix_only_refusals': ['existing', 'force', 'upgrade', 'dangling'], 'private_home_state_preserved': True,
            'outside_state_preserved': True, 'wrapper_notices_and_bootstrap_preserved': True,
            'original_signed_inputs_unchanged': True, 'account_credentials_supplied': False,
            'native_pkg_executed': False, 'native_runtime_owner_invoked': False, 'runtime_activation': False,
            'system_trust_changed': False, 'primary_platform_qualified': False, 'fresh_host_accepted': False,
            'independent_acceptance_complete': False, 'legal_review_approved': False, 'publisher_trust_accepted': False,
            'two_release_upgrade_qualified': False, 'two_release_rollback_qualified': False,
            'release_acceptance_complete': False, 'beta_release_authorized': False, 'publication_authorized': False}
        signing.write(output / 'result.json', signing.canonical(result)); return result
    except BaseException as error:
        signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
            'error_class': type(error).__name__, 'logs': logs, 'private_logs_retained': True,
            'runtime_activation': False, 'publication_authorized': False}))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'stage-record', 'delivery', 'output', 'openssl'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('plan-sha256', 'certificate-sha256'): parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-selected-mac', action='store_true')
    parser.add_argument('--wrapper-overlay', type=Path); parser.add_argument('--wrapper-manifest-sha256')
    args = parser.parse_args(); result = qualify(args)
    print(json.dumps({'state': result['state'], 'linked_file_count': result['linked_file_count'], 'publication_authorized': False}))

if __name__ == '__main__': main()
