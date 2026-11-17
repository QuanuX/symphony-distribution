#!/usr/bin/env python3
"""Exercise an explicitly selected PKG only on a disposable hosted Apple runner.

Apple installer uses the normal account on that disposable VM. This
checks native package installation and exact inert carrier removal; it neither
changes system trust nor claims GUI, Gatekeeper, notarization or runtime setup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import socket
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_rewrap as native
from qualification import d09_platform as gate
from qualification import d06_failure_summary as diagnostics

c, reuse, signing, construct = native.c, native.reuse, native.signing, native.construct
PROTOCOL = 'symphony.distribution.native-pkg-qualification.v1'
PROFILE = 'macos15-arm64'
PHASES = {}
INSTALL_STARTED = set()
ALLOWED_PHASES = ('admit_selected_inputs', 'copy_private_inputs', 'audit_private_cohort', 'verify_inspection_tools',
    'inspect_native_pkg', 'admit_current_home', 'native_pkg_install', 'verify_installed_carriers',
    'named_carrier_removal', 'verify_removal', 'verify_original_inputs', 'complete')

HELPERS = tuple(sorted(set(native.HELPERS) | {'qualification/d14_pkg.py', 'qualification/d06_failure_summary.py', '.github/workflows/d14-native-pkg.yml'}))


def helper_identity():
    commit = os.environ.get('GITHUB_SHA', '')
    c.require(re.fullmatch('[0-9a-f]{40}', commit), 'Exact hosted workflow revision required')
    # Only the explicitly selected checkout is admitted; never alter
    # the global Git safe-directory setting or adopt another working directory.
    command = ['/usr/bin/git', '--no-replace-objects', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT)]
    env = {'PATH': '/usr/bin:/bin', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}
    def git(*args):
        return subprocess.check_output(command + list(args), env=env, stderr=subprocess.PIPE, timeout=30)
    c.require(git('rev-parse', 'HEAD').decode().strip() == commit, 'Hosted checkout identity differs')
    hashes = {name: signing.digest(ROOT / name) for name in HELPERS}
    for name, digest in hashes.items():
        c.require(c.sha(git('show', commit + ':' + name)) == digest, 'Executing PKG helper differs from committed source')
    return {'commit': commit, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(), 'helpers': hashes}


def select_pkg(cohort, audit, expected):
    c.digest(expected)
    c.require(cohort['profile'] == audit['profile'] == PROFILE and
              audit['cohort_digest'] == cohort['cohort_digest'] and audit['archives'] == cohort['archives'],
              'PKG audit belongs to another selected cohort')
    rows = [row for row in audit['wrappers'] if row['format'] == 'pkg']
    c.require(len(rows) == 1 and rows[0]['sha256'] == expected, 'Exactly one selected native PKG required')
    row = rows[0]
    c.require(Path(row['filename']).name == row['filename'] and row['filename'].endswith('.pkg') and
              row['archive_count'] == len(cohort['archives']) and
              row['nested_archives_sha256'] == {r['filename']: r['sha256'] for r in cohort['archives']},
              'Selected PKG member identity differs')
    return row


def package_layout(expanded):
    """Admit the existing current-home package route, not arbitrary installer destinations."""
    def xml(path):
        raw, _ = c.bounded(path)
        c.require(len(raw) <= 1024 * 1024 and b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,
                  'Unsupported installer XML')
        return ET.fromstring(raw)
    distribution = xml(expanded / 'Distribution')
    domains = distribution.findall('domains')
    c.require(len(domains) == 1 and domains[0].attrib == {
        'enable_anywhere': 'false', 'enable_currentUserHome': 'true', 'enable_localSystem': 'false'},
        'PKG must be restricted to the current user home domain')
    packages = sorted(expanded.glob('*.pkg'))
    c.require({p.name for p in packages} == {'prepare_installation.pkg', 'run_installation.pkg'},
              'Unreviewed native installer component')
    names, identifiers = set(), []
    expected_scripts = {'prepare_installation.pkg': {'preinstall', 'postinstall'},
                        'run_installation.pkg': {'postinstall'}}
    for package in packages:
        info = xml(package / 'PackageInfo')
        c.require(info.tag == 'pkg-info' and info.get('auth') == 'root' and
                  info.get('relocatable') == 'false' and not info.get('install-location'),
                  'Unreviewed native installer destination or authority')
        identifier = info.get('identifier', '')
        c.require(re.fullmatch(r'org\.quanux\.symphony\.[a-z0-9._-]+', identifier) and identifier not in identifiers,
                  'Unreviewed native package identifier')
        identifiers.append(identifier)
        scripts = {p.name: p for p in (package / 'Scripts').iterdir() if p.is_file()}
        c.require(set(scripts) == expected_scripts[package.name], 'Unexpected native installer script')
        for path in scripts.values():
            raw, _ = c.bounded(path)
            matches = re.findall(rb'^PREFIX="\$2/([a-z0-9][a-z0-9_-]{0,63})"$', raw, re.M)
            c.require(len(matches) == 1, 'Native installer prefix is not a single home child')
            names.add(matches[0].decode())
    c.require(len(names) == 1, 'Native installer scripts disagree on the destination')
    return {'prefix_basename': names.pop(), 'package_identifiers': identifiers,
            'target_domain': 'CurrentUserHomeDirectory'}


def current_account():
    uid = os.getuid()
    c.require(uid == os.geteuid() and uid != 0, 'Native home installation requires the unelevated hosted account')
    account = pwd.getpwuid(uid)
    c.require(account.pw_name == 'runner' and Path(account.pw_dir) == Path('/Users/runner') and
              os.environ.get('HOME') == account.pw_dir, 'Unexpected hosted runner account or HOME')
    home = c.safe_root(Path(account.pw_dir))
    c.require(home.stat().st_uid == uid, 'Hosted home is not owned by the executing account')
    return home, account.pw_name


def current_home_prefix(basename):
    home, _ = current_account()
    c.require(re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', basename), 'Unsafe native install prefix')
    prefix = home / basename
    c.require(not os.path.lexists(prefix), 'Native PKG qualification refuses an existing prefix')
    return home, prefix


def progress(output, phase):
    c.require(phase in ALLOWED_PHASES, 'Unknown native installer phase')
    PHASES[output] = phase
    if phase == 'native_pkg_install': INSTALL_STARTED.add(output)
    record = {'protocol': PROTOCOL, 'profile': PROFILE, 'phase': phase}
    fd = os.open(output / 'progress.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'ab') as stream:
        info = os.fstat(stream.fileno())
        c.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and info.st_size < 32768,
                  'Invalid progress evidence file')
        stream.write(signing.canonical(record)); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps(record, sort_keys=True), flush=True)


def sanitized_log_tail(path):
    """Retain a bounded sanitized tail from explicitly selected installer logs."""
    if not path.exists(): return {'state': 'absent'}
    try:
        path = signing.plain(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            c.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
                      before.st_size <= 16 * 1024 * 1024, 'Diagnostic log outside bounded ownership')
            hashed = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''): hashed.update(block)
            stream.seek(max(0, before.st_size - 32768)); raw = stream.read(32768)
            after = os.fstat(stream.fileno())
            c.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Diagnostic log changed')
        aliases = [(path.parent, 'diagnostic-directory'), (ROOT, 'distribution-source'),
                   (Path('/Users/runner'), 'hosted-home')]
        if os.environ.get('RUNNER_TEMP'): aliases.append((Path(os.environ['RUNNER_TEMP']), 'runner-temporary'))
        clean = diagnostics.sanitize(raw.decode('utf-8', 'replace'), aliases,
            [pwd.getpwuid(os.getuid()).pw_name, socket.gethostname()])
        tail = clean.splitlines()[-40:]
        return {'state': 'bounded_tail_sanitized', 'size': before.st_size, 'sha256': hashed.hexdigest(),
                'tail': tail, 'raw_text_retained_publicly': False, 'max_tail_input_bytes': 32768}
    except (OSError, ValueError):
        return {'state': 'unavailable_or_changed', 'raw_text_retained_publicly': False}


def caller_files(home):
    """Observe selected account state without reading keychains or other secrets."""
    result = {}
    for name in ('.condarc', '.bashrc', '.bash_profile', '.zshrc', '.zprofile', '.conda/environments.txt'):
        path = home / name
        c.require(not any(p.is_symlink() for p in (path, *path.parents)), 'Aliased account configuration refused')
        result[name] = None if not path.exists() else {'sha256': signing.digest(path), 'mode': stat.S_IMODE(path.stat().st_mode)}
    return result


def installed_carriers(prefix):
    """Read default Conda links only when every inode alias stays in this new prefix."""
    prefix = gate.safe(prefix)
    links = {}
    paths = list(prefix.rglob('*'))
    c.require(len(paths) <= 50000, 'Installed prefix inventory exceeds bound')
    for path in paths:
        info = path.lstat()
        c.require(not path.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                  'Unexpected installed prefix alias or special file')
        if stat.S_ISREG(info.st_mode):
            links.setdefault((info.st_dev, info.st_ino), []).append(path)
    result = {}
    base = prefix / 'share/symphony/carriers'
    for path in base.rglob('*'):
        if path.is_dir(): continue
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            c.require(stat.S_ISREG(before.st_mode) and before.st_size <= c.LIMIT and
                      before.st_nlink == len(links.get((before.st_dev, before.st_ino), [])),
                      'Installed carrier has an alias outside the private prefix')
            raw = stream.read(c.LIMIT + 1); after = os.fstat(stream.fileno())
            c.require(len(raw) == before.st_size and
                      (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink),
                      'Installed carrier changed during inspection')
        result[path.relative_to(prefix).as_posix()] = (raw, stat.S_IMODE(before.st_mode))
    return result


def exercise(pkg, row, cohort, expected, output):
    progress(output, 'inspect_native_pkg')
    audit_dir = output / 'inspection'; audit_dir.mkdir(mode=0o700)
    env = reuse.consumer.isolated_environment(output)
    env['CONDA_SUBDIR'] = 'osx-arm64'
    snapshot = reuse.snapshot_wrapper(pkg, row, output)
    execution = snapshot.with_suffix('.pkg'); snapshot.rename(execution)
    audited = construct.audit_pkg(execution, construct.archive_records(cohort), row['bootstrap_sha256'], [], work=audit_dir, env=env)
    c.require(audited['nested_archives_sha256'] == row['nested_archives_sha256'], 'Fresh native PKG inspection differs')
    layout = package_layout(audit_dir / 'expanded-pkg')
    progress(output, 'admit_current_home')
    home, prefix = current_home_prefix(layout['prefix_basename'])
    _, account_name = current_account()
    account_before, private_before = caller_files(home), gate.inventory(output / 'home')
    outside = output / 'outside-sentinel'; signing.write(outside, b'outside account state\n')
    install_env = {'HOME': str(home), 'USER': account_name, 'LOGNAME': account_name, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                   'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C'}
    progress(output, 'native_pkg_install')
    logs = [gate.invoke(['/usr/sbin/installer', '-verboseR', '-dumplog', '-pkg', execution, '-target', 'CurrentUserHomeDirectory'],
                        install_env, output / 'native-install.log', timeout=1200)]
    progress(output, 'verify_installed_carriers')
    c.require(prefix.is_dir() and not prefix.is_symlink(), 'Native installer did not create its selected home prefix')
    c.require(installed_carriers(prefix) == expected, 'Native installed carrier bytes or modes differ')
    names = reuse.consumer.installed_metadata(prefix, cohort['archives'])
    bootstrap = signing.regular(prefix / '_conda')
    c.require(signing.digest(bootstrap) == row['bootstrap_sha256'], 'Native installed bootstrap differs')
    auxiliary = gate.inventory(prefix / 'share/symphony/installer')
    c.require(caller_files(home) == account_before and gate.inventory(output / 'home') == private_before,
              'Native installation changed account configuration')
    signing.write(prefix / 'user-state.txt', b'preserve user state\n')
    progress(output, 'named_carrier_removal')
    logs.append(gate.invoke([bootstrap, 'remove', '--prefix', prefix, '--offline', '--yes', '--solver', 'classic', *names],
                            env, output / 'named-removal.log', timeout=600))
    progress(output, 'verify_removal')
    c.require(installed_carriers(prefix) == {} and not list((prefix / 'conda-meta').glob('*.json')),
              'Named carrier removal left package bytes or records')
    c.require((prefix / 'user-state.txt').read_bytes() == b'preserve user state\n' and
              outside.read_bytes() == b'outside account state\n' and caller_files(home) == account_before and
              gate.inventory(output / 'home') == private_before and
              gate.inventory(prefix / 'share/symphony/installer') == auxiliary and
              signing.digest(bootstrap) == row['bootstrap_sha256'] and signing.digest(execution) == row['sha256'],
              'Native package/removal changed selected bytes or caller state')
    return {'layout': layout, 'logs': logs, 'carrier_count': len(names), 'linked_file_count': len(expected),
            'native_pkg_executed': True, 'all_named_carriers_removed': True,
            'caller_configuration_preserved': True, 'user_and_outside_sentinels_preserved': True,
            'wrapper_support_files_preserved': True, 'apple_installer_receipts_retained_on_disposable_vm': True,
            'system_trust_changed': False, 'gatekeeper_bypassed': False, 'native_runtime_owner_invoked': False}


def private_input_snapshot(source, destination):
    """Create caller-owned copies; never transfer ownership of runner inputs."""
    source, destination = c.safe_root(source), c.safe_root(destination, exists=False)
    c.require(source != destination and source not in destination.parents and destination not in source.parents,
              'Private input snapshot overlaps original evidence')
    before = reuse.copy_tree(source, destination)
    verify_private_snapshot(destination, before)
    return before


def verify_private_snapshot(root, before):
    root = c.safe_root(root)
    c.require(root.stat().st_uid == os.geteuid() and stat.S_IMODE(root.stat().st_mode) == 0o700,
              'Input snapshot root must be private to the executing account')
    reuse.records_equal(root, before)
    for row in before:
        info = (root / row['path']).lstat()
        c.require(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022 and
                  not info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX),
                  'Input snapshot member ownership or mode differs')
        if row['kind'] == 'file':
            c.require(info.st_nlink == 1, 'Input snapshot must not share original inodes')


def retain_failure(output, error):
    output = gate.safe(output)
    if output.is_dir() and gate.OWNED_OUTPUTS.get(output) == (output.stat().st_dev, output.stat().st_ino):
        diagnostic = {'protocol': PROTOCOL, 'state': 'native_pkg_qualification_incomplete',
            'phase': PHASES.get(output, 'not_started'), 'error_type': type(error).__name__,
            'command_timeout_observed': isinstance(error, subprocess.TimeoutExpired),
            'installer_timeout_seconds': 1200, 'installer_command_attempted': output in INSTALL_STARTED,
            'hosted_current_user_account_required': True, 'root_execution_supported': False,
            'failure_cause_inferred': False, 'payloads_or_trust_modified_by_diagnostics': False,
            'logs': {name: sanitized_log_tail(output / name) for name in
                ('native-install.log', 'named-removal.log', 'inspection/expand-pkg.log')}}
        if not (output / 'diagnostics.json').exists():
            signing.write(output / 'diagnostics.json', signing.canonical(diagnostic), 0o644)
        if not (output / 'INCOMPLETE.json').exists():
            signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
                'error_type': type(error).__name__, 'phase': diagnostic['phase'],
                'diagnostics_sha256': signing.digest(output / 'diagnostics.json'),
                'private_logs_retained': True, 'publication_authorized': False}), 0o644)


def qualify_selected(args, custody, output):
    progress(output, 'admit_selected_inputs')
    original_cohort, original_wrappers = c.safe_root(args.cohort_root), c.safe_root(args.wrapper_root)
    c.require(signing.digest(original_cohort / 'cohort.json') == c.digest(args.cohort_sha256) and
              signing.digest(original_wrappers / 'result.json') == c.digest(args.wrapper_result_sha256),
              'Explicit native installer evidence selection differs')
    progress(output, 'copy_private_inputs')
    snapshots = output / 'input-snapshots'; snapshots.mkdir(mode=0o700)
    cohort_root, wrappers = snapshots / 'cohort', snapshots / 'wrappers'
    cohort_before = private_input_snapshot(original_cohort, cohort_root)
    wrapper_before = private_input_snapshot(original_wrappers, wrappers)
    # The existing archive reader deliberately admits only root/current-owner
    # files. Validate newly created private copies without changing original
    # artifact ownership or weakening the common reader.
    progress(output, 'audit_private_cohort')
    cohort = c.audit_cohort(cohort_root); audit = c.document(wrappers / 'result.json')
    row = select_pkg(cohort, audit, args.pkg_sha256)
    progress(output, 'verify_inspection_tools')
    tools = reuse.inspection_tools(args.inspection_tools, PROFILE); identity = helper_identity()
    expected = {}
    for entry in cohort['entries']:
        _, files = c.validate_recipe(cohort_root, entry)
        c.require(not expected.keys() & files.keys(), 'Carrier ownership overlaps'); expected.update(files)
    observations = exercise(wrappers / row['filename'], row, cohort, expected, output)
    progress(output, 'verify_original_inputs')
    reuse.records_equal(original_cohort, cohort_before); reuse.records_equal(original_wrappers, wrapper_before)
    verify_private_snapshot(cohort_root, cohort_before); verify_private_snapshot(wrappers, wrapper_before)
    c.require(signing.digest(original_cohort / 'cohort.json') == args.cohort_sha256 and
              signing.digest(original_wrappers / 'result.json') == args.wrapper_result_sha256 and
              signing.digest(original_wrappers / row['filename']) == args.pkg_sha256 and c.audit_cohort(cohort_root) == cohort and
              helper_identity() == identity and reuse.inspection_tools(args.inspection_tools, PROFILE) == tools,
              'Original inputs or executing helpers changed')
    snapshot_proof = {role: {'inventory_sha256': c.sha(c.canonical(rows)),
        'file_count': sum(row['kind'] == 'file' for row in rows), 'byte_and_mode_verified': True,
        'owned_by_executing_account': True, 'original_ownership_changed': False}
        for role, rows in (('cohort', cohort_before), ('wrappers', wrapper_before))}
    result = {'protocol': PROTOCOL, 'state': 'native_pkg_install_and_named_carrier_removal_passed', 'profile': PROFILE,
        'cohort_sha256': args.cohort_sha256, 'cohort_digest': cohort['cohort_digest'],
        'wrapper_result_sha256': args.wrapper_result_sha256, 'pkg_sha256': args.pkg_sha256,
        'hosted_custody': custody, 'executing_toolkit': identity, 'inspection_tools': tools, **observations,
        'input_snapshots': snapshot_proof,
        'scope': 'selected native PKG in the disposable hosted runner home; inert carrier install/removal only',
        'account_context': {'current_user_home': True, 'real_and_effective_uid_match': True, 'root_execution': False},
        'original_inputs_unchanged': True, 'apple_developer_id': False, 'notarized': False,
        'gatekeeper_acceptance_qualified': False, 'gui_install_qualified': False,
        'independent_physical_host_qualified': False, 'two_release_upgrade_qualified': False,
        'two_release_rollback_qualified': False, 'publication_authorized': False}
    progress(output, 'complete')
    signing.write(output / 'result.json', signing.canonical(result), 0o644)
    return result


def qualify(args):
    c.require(args.allow_ephemeral_install is True, 'Explicit disposable native installer opt-in required')
    # Host authority is checked before inspecting, creating or executing anything.
    custody = reuse.custody(PROFILE, args.output)
    current_account()
    # Reserve an owned attempt before pins, copies or archive admission so early
    # failures also leave bounded evidence for the workflow's always() upload.
    output = gate.fresh(args.output, (args.cohort_root, args.wrapper_root, args.inspection_tools, ROOT))
    try:
        return qualify_selected(args, custody, output)
    except BaseException as error:
        retain_failure(output, error)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort-root', 'wrapper-root', 'inspection-tools', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('cohort-sha256', 'wrapper-result-sha256', 'pkg-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--allow-ephemeral-install', action='store_true'); args = p.parse_args()
    try:
        result = qualify(args); print(json.dumps({'state': result['state'], 'carrier_count': result['carrier_count']}))
    except BaseException as error:
        retain_failure(args.output, error)
        raise


if __name__ == '__main__': main()
