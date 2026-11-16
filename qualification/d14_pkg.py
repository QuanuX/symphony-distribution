#!/usr/bin/env python3
"""Exercise an explicitly selected PKG only on a disposable hosted Apple runner.

Apple installer writes its normal receipt database on that disposable VM. This
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
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import native_rewrap as native
from qualification import d09_platform as gate

c, reuse, signing, construct = native.c, native.reuse, native.signing, native.construct
PROTOCOL = 'symphony.distribution.native-pkg-qualification.v1'
PROFILE = 'macos15-arm64'
HELPERS = tuple(sorted(set(native.HELPERS) | {'qualification/d14_pkg.py', '.github/workflows/d14-native-pkg.yml'}))


def helper_identity():
    commit = os.environ.get('GITHUB_SHA', '')
    c.require(re.fullmatch('[0-9a-f]{40}', commit), 'Exact hosted workflow revision required')
    # Only the explicitly selected checkout is readable under root; never alter
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


def root_prefix(basename):
    c.require(os.geteuid() == 0, 'Native PKG qualification requires the disposable VM root account')
    account = pwd.getpwuid(0)
    home = Path(account.pw_dir).resolve(strict=True)
    c.require(account.pw_name == 'root' and home == Path('/private/var/root') and
              home.is_dir() and not home.is_symlink(), 'Unexpected disposable root home')
    c.require(re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', basename), 'Unsafe native install prefix')
    prefix = home / basename
    c.require(not os.path.lexists(prefix), 'Native PKG qualification refuses an existing prefix')
    return home, prefix


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
    audit_dir = output / 'inspection'; audit_dir.mkdir(mode=0o700)
    env = reuse.consumer.isolated_environment(output)
    env['CONDA_SUBDIR'] = 'osx-arm64'
    snapshot = reuse.snapshot_wrapper(pkg, row, output)
    execution = snapshot.with_suffix('.pkg'); snapshot.rename(execution)
    audited = construct.audit_pkg(execution, construct.archive_records(cohort), row['bootstrap_sha256'], [], work=audit_dir, env=env)
    c.require(audited['nested_archives_sha256'] == row['nested_archives_sha256'], 'Fresh native PKG inspection differs')
    layout = package_layout(audit_dir / 'expanded-pkg')
    home, prefix = root_prefix(layout['prefix_basename'])
    account_before, private_before = caller_files(home), gate.inventory(output / 'home')
    outside = output / 'outside-sentinel'; signing.write(outside, b'outside account state\n')
    install_env = {'HOME': str(home), 'USER': 'root', 'LOGNAME': 'root', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                   'TMPDIR': str(output / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C'}
    logs = [gate.invoke(['/usr/sbin/installer', '-pkg', execution, '-target', 'CurrentUserHomeDirectory'],
                        install_env, output / 'native-install.log', timeout=1200)]
    c.require(prefix.is_dir() and not prefix.is_symlink(), 'Native installer did not create its selected home prefix')
    c.require(installed_carriers(prefix) == expected, 'Native installed carrier bytes or modes differ')
    names = reuse.consumer.installed_metadata(prefix, cohort['archives'])
    bootstrap = signing.regular(prefix / '_conda')
    c.require(signing.digest(bootstrap) == row['bootstrap_sha256'], 'Native installed bootstrap differs')
    auxiliary = gate.inventory(prefix / 'share/symphony/installer')
    c.require(caller_files(home) == account_before and gate.inventory(output / 'home') == private_before,
              'Native installation changed account configuration')
    signing.write(prefix / 'user-state.txt', b'preserve user state\n')
    logs.append(gate.invoke([bootstrap, 'remove', '--prefix', prefix, '--offline', '--yes', '--solver', 'classic', *names],
                            env, output / 'named-removal.log', timeout=600))
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


def qualify(args):
    c.require(args.allow_ephemeral_install is True, 'Explicit disposable native installer opt-in required')
    # Host authority is checked before inspecting, creating or executing anything.
    custody = reuse.custody(PROFILE, args.output)
    c.require(os.geteuid() == 0, 'Only the disposable hosted root account may execute this gate')
    cohort_root, wrappers = c.safe_root(args.cohort_root), c.safe_root(args.wrapper_root)
    c.require(signing.digest(cohort_root / 'cohort.json') == c.digest(args.cohort_sha256) and
              signing.digest(wrappers / 'result.json') == c.digest(args.wrapper_result_sha256),
              'Explicit native installer evidence selection differs')
    cohort = c.audit_cohort(cohort_root); audit = c.document(wrappers / 'result.json')
    row = select_pkg(cohort, audit, args.pkg_sha256)
    tools = reuse.inspection_tools(args.inspection_tools, PROFILE); identity = helper_identity()
    expected = {}
    for entry in cohort['entries']:
        _, files = c.validate_recipe(cohort_root, entry)
        c.require(not expected.keys() & files.keys(), 'Carrier ownership overlaps'); expected.update(files)
    output = gate.fresh(args.output, (cohort_root, wrappers, args.inspection_tools, ROOT))
    observations = exercise(wrappers / row['filename'], row, cohort, expected, output)
    c.require(signing.digest(cohort_root / 'cohort.json') == args.cohort_sha256 and
              signing.digest(wrappers / 'result.json') == args.wrapper_result_sha256 and
              signing.digest(wrappers / row['filename']) == args.pkg_sha256 and c.audit_cohort(cohort_root) == cohort and
              helper_identity() == identity and reuse.inspection_tools(args.inspection_tools, PROFILE) == tools,
              'Original inputs or executing helpers changed')
    result = {'protocol': PROTOCOL, 'state': 'native_pkg_install_and_named_carrier_removal_passed', 'profile': PROFILE,
        'cohort_sha256': args.cohort_sha256, 'cohort_digest': cohort['cohort_digest'],
        'wrapper_result_sha256': args.wrapper_result_sha256, 'pkg_sha256': args.pkg_sha256,
        'hosted_custody': custody, 'executing_toolkit': identity, 'inspection_tools': tools, **observations,
        'scope': 'selected native PKG on disposable hosted root home; inert carrier install/removal only',
        'original_inputs_unchanged': True, 'apple_developer_id': False, 'notarized': False,
        'gatekeeper_acceptance_qualified': False, 'gui_install_qualified': False,
        'independent_physical_host_qualified': False, 'two_release_upgrade_qualified': False,
        'two_release_rollback_qualified': False, 'publication_authorized': False}
    signing.write(output / 'result.json', signing.canonical(result), 0o644)
    return result


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
        output = gate.safe(args.output)
        if output.is_dir() and gate.OWNED_OUTPUTS.get(output) == (output.stat().st_dev, output.stat().st_ino):
            if not (output / 'INCOMPLETE.json').exists():
                signing.write(output / 'INCOMPLETE.json', signing.canonical({'protocol': PROTOCOL, 'state': 'incomplete',
                    'error_type': type(error).__name__, 'private_logs_retained': True, 'publication_authorized': False}), 0o644)
        raise


if __name__ == '__main__': main()
