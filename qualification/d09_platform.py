#!/usr/bin/env python3
"""Prepare primary review builds and qualify inert installers on disposable CI.

Exact reviewed source is mandatory. These E1 engineering checks neither grant
publisher trust nor complete the independent D10 fresh-host acceptance matrix.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ('macos15-arm64', 'ubuntu24.04-amd64', 'ubuntu24.04-arm64', 'ubuntu26.04-amd64')
REPOSITORY = 'QuanuX/symphony-distribution'
OWNED_OUTPUTS = {}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def read(path):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'Exact lowercase SHA256 required')
    return value


def safe(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked path refused')
    return path


def fresh(path, inputs):
    path = safe(path)
    require(not path.exists() and path.parent.is_dir(), 'Output must be new with an existing parent')
    for selected in inputs:
        selected = safe(selected)
        require(path != selected and path not in selected.parents and selected not in path.parents,
                'Output overlaps selected input')
    path.mkdir(mode=0o700)
    info = path.stat()
    OWNED_OUTPUTS[path] = (info.st_dev, info.st_ino)
    return path


def check_source(export, repository, policy, export_digest, manifest_sha256):
    digest(export_digest); digest(manifest_sha256)
    require(sha(export / 'SOURCE-EXPORT.json') == manifest_sha256, 'Independently selected source manifest differs')
    exporter = module('d09_export', 'source-export/export_source.py')
    exporter.configure_policy(policy)
    proof = exporter.verify(export, repository)
    require(proof['export_digest'] == export_digest and proof['verified'] is True,
            'Independently selected reviewed source differs')
    return proof


def prepare_source(repository, policy, output, export_digest, manifest_sha256):
    """Regenerate existing reviewed export; never approve a newly produced digest."""
    digest(export_digest); digest(manifest_sha256)
    repository, policy, output = safe(repository), safe(policy), safe(output)
    require(policy.is_file() and stat.S_IMODE(policy.stat().st_mode) == 0o600, 'Private policy must have mode 0600')
    require(not output.exists() and output.parent.is_dir(), 'Source output must be new')
    require(all(output != p and output not in p.parents and p not in output.parents for p in (repository, policy, ROOT)),
            'Source output overlaps input')
    exporter = module('d09_export_prepare', 'source-export/export_source.py')
    exporter.configure_policy(policy)
    exporter.build(repository, output)
    return check_source(output, repository, policy, export_digest, manifest_sha256)


def primary_build(aggregate, profile):
    require(profile in PROFILES, 'Only an explicitly selected primary profile is accepted')
    host = aggregate['host']
    require(host['scope'] == 'native_profile_build' and host['requested_profile'] == profile,
            'Supplemental or different native profile refused')
    require(aggregate['state'] == 'built_and_sdk_checked' and aggregate['repeated_payload_bytes_equal'] is True and
            len(aggregate['rounds']) == 2 and {r['directory'] for r in aggregate['rounds']} == {'round-1', 'round-2'},
            'Two completed identical native cohorts are required')
    require(aggregate['source_input']['kind'] == 'verified_reviewed_derived_export' and
            aggregate['source_input']['verified'] is True, 'Raw Git build cannot become a reviewed package')
    require(aggregate['publication_authorized'] is False and aggregate['acceptance_complete'] is False,
            'Unexpected release approval claim')


def acceptance_packet(repository, source_commit, profile, selected_cohort_digest):
    """Carry the original 36 cells forward; a carrier smoke test completes none."""
    plan_path = repository / 'tests/launch-acceptance/plan.json'
    plan = read(plan_path)
    require(tuple(plan['required_profiles']) == PROFILES and len(plan['required_scenarios']) == 9 and
            len(set(plan['required_scenarios'])) == 9, 'Source acceptance matrix changed')
    return {'protocol': 'symphony.distribution.d09-fresh-host-preparation.v1', 'source_commit': source_commit,
            'source_plan_sha256': sha(plan_path), 'selected_build_profile': profile,
            'selected_cohort_digest': selected_cohort_digest,
            'cells': [{'profile': p, 'scenario': scenario, 'state': 'pending',
                       'routes': {'cli': 'pending', 'standalone': 'pending'}}
                      for p in PROFILES for scenario in plan['required_scenarios']],
            'required_inputs': plan['required_inputs'], 'independent_reviewer': 'not_selected',
            'automated_scope': 'E1 inert carrier CLI and shell installer behavior on disposable hosted runners only',
            'release_acceptance_complete': False, 'publication_authorized': False}


def package(args):
    """Use unchanged D06 and D08 validators; no fabricated cohort/owner records."""
    inputs = [args.build_root, args.delivery, args.export, args.repository, args.privacy_policy, args.sdk_closure, ROOT]
    for name in ('build_root', 'delivery', 'export', 'repository', 'privacy_policy', 'sdk_closure'):
        setattr(args, name, safe(getattr(args, name)))
    proof = check_source(args.export, args.repository, args.privacy_policy, args.export_digest, args.manifest_sha256)
    aggregate = read(args.build_root / 'result.json')
    primary_build(aggregate, args.profile)
    require(aggregate['source_input']['export_digest'] == proof['export_digest'], 'Built source differs from selected export')
    sdk = read(args.sdk_closure / 'result.json')
    require(sdk['protocol'] == 'symphony.distribution.d06-sdk-closure.v1' and sdk['status'] == 'passed' and
            sdk['source_commit'] == aggregate['source_commit'] and sdk['source_tree'] == aggregate['source_tree'] and
            sdk['publication_authorized'] is False and sdk['release_acceptance_complete'] is False and
            sdk['cohort_result_sha256'] == sha(args.build_root / 'result.json') and
            sdk['round_result_sha256'] == sha(args.build_root / 'round-1/result.json'),
            'Supplementary final SDK closure incomplete or bound to different bytes')
    out = fresh(args.output, inputs)
    cohort = module('d09_input_cohort', 'installer_assembly/cohort.py')
    carriers = module('d09_carriers', 'installer_assembly/carriers.py')
    constructor = module('d09_constructor', 'installer_assembly/construct.py')
    identity = args.build_root / 'round-1/qxctl-identity'
    cohort.prepare_cohort(args.build_root, args.delivery / 'delivery-record.json', identity, args.export,
        out / 'input-cohort', expected_base_result_sha256=sha(args.build_root / 'result.json'),
        expected_round_result_sha256=sha(args.build_root / 'round-1/result.json'),
        expected_delivery_sha256=sha(args.delivery / 'delivery-record.json'),
        expected_qxctl_proof_sha256=sha(identity / 'result.json'))
    prepared = carriers.prepare(out / 'input-cohort', sha(out / 'input-cohort/cohort.json'), out / 'prepared',
                                profile=args.profile, privacy_policy=args.privacy_policy)
    archives = carriers.build_cohort(out / 'prepared', out / 'carriers', prepared['cohort_digest'])
    require(len(archives['archives']) == 58, 'Primary engineering cohort must contain exactly the baseline58 units')
    formats = ['pkg', 'sh'] if args.profile == 'macos15-arm64' else ['sh']
    wrapped = constructor.assemble(out / 'carriers', out / 'wrappers', interpreter=args.python,
        standalone=args.standalone, standalone_archive=args.standalone_archive, formats=formats,
        privacy_policy=args.privacy_policy)
    packet = acceptance_packet(args.repository, aggregate['source_commit'], args.profile, archives['cohort_digest'])
    write(out / 'fresh-host-requirements.json', packet)
    result = {'protocol': 'symphony.distribution.d09-primary-review.v1', 'state': 'primary_review_wrappers_audited',
        'profile': args.profile, 'source_commit': aggregate['source_commit'], 'source_tree': aggregate['source_tree'],
        'source_export_digest': proof['export_digest'], 'source_manifest_sha256': args.manifest_sha256,
        'build_result_sha256': sha(args.build_root / 'result.json'),
        'sdk_closure_sha256': sha(args.sdk_closure / 'result.json'), 'cohort_digest': archives['cohort_digest'],
        'wrapper_result_sha256': sha(out / 'wrappers/result.json'), 'wrapper_count': len(wrapped['wrappers']),
        'archive_count': 58, 'helper_sha256': sha(__file__),
        'fresh_host_requirements_sha256': sha(out / 'fresh-host-requirements.json'),
        'client_included': False, 'client_qualification': 'requires_matching_primary_client',
        'publication_authorized': False, 'publisher_trust_accepted': False,
        'independent_fresh_host_acceptance': False, 'release_acceptance_complete': False}
    write(out / 'result.json', result)
    return result


def hosted_custody(profile, output, environment):
    require(profile in PROFILES, 'Supplemental fixtures cannot claim primary qualification')
    require(environment.get('GITHUB_ACTIONS') == 'true' and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            environment.get('GITHUB_REPOSITORY') == REPOSITORY, 'Ephemeral hosted CI custody is required')
    require(re.fullmatch('[1-9][0-9]*', environment.get('GITHUB_RUN_ID', '')) and
            re.fullmatch('[1-9][0-9]*', environment.get('GITHUB_RUN_ATTEMPT', '')), 'Hosted run identity absent')
    root = safe(environment.get('RUNNER_TEMP', ''))
    require(root.is_dir() and root in safe(output).parents, 'Fresh-user output must be inside this runner temporary root')
    hosts = module('d09_host', 'qualification/host_platform.py')
    host = hosts.observe_host()
    require(hosts.profile_matches(profile, host), 'Actual native host differs from selected primary profile')
    return host


def inventory(root, *, allow_hardlinks=False):
    result = []
    for path in sorted(root.rglob('*')):
        info = path.lstat(); name = path.relative_to(root).as_posix()
        row = {'path': name, 'mode': stat.S_IMODE(info.st_mode)}
        if path.is_symlink():
            row['link'] = os.readlink(path)
        elif path.is_file():
            require(allow_hardlinks or info.st_nlink == 1, 'Unexpected shared user-state inode')
            row['sha256'] = sha(path)
        else:
            require(path.is_dir(), 'Unexpected user-state file type')
            row['directory'] = True
        result.append(row)
    return result


def invoke(command, env, log, *, expected=0, timeout=900):
    with log.open('xb') as stream:
        result = subprocess.run([str(p) for p in command], env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    require(result.returncode == expected, 'Isolated installer command returned an unexpected status; private log retained')
    return {'exit_code': result.returncode, 'log_sha256': sha(log)}


def failure_summary(output, error, policy=None):
    """Only known task logs, bounded and sanitized; no generic directory dump."""
    output = safe(output)
    if not output.is_dir() or (output / 'failure.json').exists():
        return
    info = output.stat()
    if OWNED_OUTPUTS.get(output) != (info.st_dev, info.st_ino):
        # A rejected existing/overlapping output must never acquire a failure
        # file. Only this process's newly admitted directory is writable here.
        return
    sanitizer = module('d09_failure_sanitizer', 'qualification/d06_failure_summary.py')
    aliases = [(output, 'task-output'), (ROOT, 'distribution-source')]
    for name in ('HOME', 'RUNNER_TEMP', 'GITHUB_WORKSPACE'):
        if os.environ.get(name): aliases.append((os.environ[name], name.lower()))
    identities = []
    if policy and Path(policy).is_file():
        identities = read(policy).get('markers', [])
    names = ['bootstrap.log', 'publisher.log', 'install.log', 'existing.log', 'force.log', 'upgrade.log',
             'dangling.log', 'cli/create.log', 'cli/remove.log', 'wrappers/work/constructor.log']
    candidates = [safe(output / name) for name in names if (output / name).is_file()]
    chosen = max(candidates, key=lambda p: p.stat().st_mtime_ns) if candidates else None
    details = None
    if chosen:
        with chosen.open('rb') as stream:
            stream.seek(max(0, chosen.stat().st_size - 32768))
            tail = stream.read(32768).decode(errors='replace')
        details = {'log': chosen.relative_to(output).as_posix(), 'sha256': sha(chosen),
                   'tail': sanitizer.sanitize(tail, aliases=aliases, identities=identities)}
    write(output / 'failure.json', {'protocol': 'symphony.distribution.d09-incomplete.v1',
          'state': 'incomplete', 'exception': type(error).__name__,
          'reason': sanitizer.sanitize(str(error), aliases=aliases, identities=identities),
          'selected_log': details, 'helper_sha256': sha(__file__), 'publication_authorized': False,
          'release_acceptance_complete': False})


def verify_wrapper_link(prefix, expected):
    """Check the complete carrier namespace without confusing wrapper files with carriers."""
    owned = Path('share/symphony/carriers')
    require(expected and all(Path(name).is_relative_to(owned) for name in expected), 'Carrier namespace differs')
    actual = {}
    for path in (prefix / owned).rglob('*'):
        require(not path.is_symlink(), 'Linked carrier file refused')
        if path.is_file():
            actual[path.relative_to(prefix).as_posix()] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
    require(actual == expected, 'Standalone installed carrier bytes or modes differ')
    require(not any((prefix / part).exists() for part in ('bin', 'sbin', 'etc', 'Library', 'Applications')),
            'Unexpected runtime activation/install namespace')
    return len(actual)


def fresh_user(args):
    require(args.allow_ephemeral_install is True, 'Explicit ephemeral installer opt-in required')
    host = hosted_custody(args.profile, args.output, os.environ)
    carriers = module('d09_fresh_carriers', 'installer_assembly/carriers.py')
    constructor = module('d09_fresh_construct', 'installer_assembly/construct.py')
    # link_qualification imports its sibling module by its ordinary name.
    sys.path.insert(0, str(ROOT / 'installer_assembly'))
    linking = module('d09_fresh_link', 'installer_assembly/link_qualification.py')
    root = safe(args.artifact)
    selected = read(root / 'result.json')
    require(sha(root / 'result.json') == digest(args.result_sha256), 'Explicit primary artifact selection differs')
    require(selected['state'] == 'primary_review_wrappers_audited' and selected['profile'] == args.profile and
            selected['archive_count'] == 58 and selected['publication_authorized'] is False,
            'Primary engineering artifact scope differs')
    require(sha(root / 'fresh-host-requirements.json') == selected['fresh_host_requirements_sha256'],
            'Independent acceptance requirements differ')
    cohort = carriers.audit_cohort(root / 'carriers')
    require(cohort['profile'] == args.profile and cohort['cohort_digest'] == selected['cohort_digest'], 'Carrier selection differs')
    wrapper = read(root / 'wrappers/result.json')
    require(sha(root / 'wrappers/result.json') == selected['wrapper_result_sha256'] and
            wrapper['state'] == 'unsigned_wrappers_audited', 'Wrapper evidence differs')
    shell = [r for r in wrapper['wrappers'] if r['filename'].endswith('.sh')]
    require(len(shell) == 1 and Path(shell[0]['filename']).name == shell[0]['filename'], 'Exact shell wrapper selection required')
    artifact = root / 'wrappers' / shell[0]['filename']
    require(sha(artifact) == shell[0]['sha256'] and artifact.stat().st_size == shell[0]['size'], 'Selected installer bytes differ')
    bootstrap_sha = digest(shell[0]['bootstrap_sha256'])
    constructor.audit_sh(artifact, constructor.archive_records(cohort), bootstrap_sha, [])
    out = fresh(args.output, (root, ROOT, Path(args.python).absolute().parent.parent))
    cli = linking.qualify(root / 'carriers', out / 'cli', expected_digest=cohort['cohort_digest'], python=args.python)
    home = out / 'home'; home.mkdir(mode=0o700)
    for name in ('.conda', '.config'):
        (home / name).mkdir(mode=0o700)
    for name in ('.condarc', '.bashrc', '.zshrc', '.conda/environments.txt', '.config/user-sentinel'):
        (home / name).write_bytes(b'# disposable-user-state-must-survive\n')
    before = inventory(home)
    temporary = out / 'tmp'; temporary.mkdir(mode=0o700)
    prefix = out / 'standalone-prefix'
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(temporary),
           'TMP': str(temporary), 'TEMP': str(temporary), 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
           'USER': 'builder', 'LOGNAME': 'builder', 'CONDA_REPORT_ERRORS': 'false',
           'CONDA_NO_PLUGINS': 'true', 'CONDA_OFFLINE': 'true', 'CONDA_REGISTER_ENVS': 'false'}
    installed = invoke(['/bin/bash', artifact, '-b', '-p', prefix], env, out / 'install.log')
    expected = {}
    for entry in cohort['entries']:
        _, files = carriers.validate_recipe(root / 'carriers', entry)
        require(not expected.keys() & files.keys(), 'Carrier overlap')
        expected.update(files)
    count = verify_wrapper_link(prefix, expected)
    metadata = [read(p) for p in (prefix / 'conda-meta').glob('*.json')]
    require(len(metadata) == len(cohort['archives']) and
            {(r['name'], r['version'], r['build']) for r in metadata} ==
            {(r['name'], r['version'], r['build']) for r in cohort['archives']}, 'Standalone package selection differs')
    require(inventory(home) == before, 'Installer changed ambient user state')
    prefix_before = inventory(prefix, allow_hardlinks=True)
    refusal = []
    for label, flags in (('existing', []), ('force', ['-f']), ('upgrade', ['-u'])):
        refusal.append(invoke(['/bin/bash', artifact, '-b', *flags, '-p', prefix], env, out / (label + '.log'), expected=1))
    dangling = out / 'dangling-prefix'; dangling.symlink_to(out / 'absent-target')
    refusal.append(invoke(['/bin/bash', artifact, '-b', '-p', dangling], env, out / 'dangling.log', expected=1))
    require(dangling.is_symlink() and not (out / 'absent-target').exists(), 'Dangling-prefix refusal mutated destination')
    require(inventory(prefix, allow_hardlinks=True) == prefix_before and inventory(home) == before,
            'Refusal changed installed or user state')
    require(carriers.audit_cohort(root / 'carriers') == cohort and sha(artifact) == shell[0]['sha256'], 'Selected inputs changed')
    result = {'protocol': 'symphony.distribution.d09-ephemeral-user.v1', 'state': 'passed',
        'profile': args.profile, 'observed_host': host, 'helper_sha256': sha(__file__),
        'github_run_id': os.environ['GITHUB_RUN_ID'], 'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
        'selected_primary_result_sha256': args.result_sha256, 'cohort_digest': cohort['cohort_digest'],
        'shell_wrapper_sha256': shell[0]['sha256'], 'installed_carrier_file_count': count,
        'cli_link_and_removal': cli['state'], 'shell_install': installed, 'fresh_prefix_refusals': refusal,
        'user_state_unchanged': True, 'native_runtime_owner_invoked': False, 'services_or_providers_started': False,
        'native_pkg_executed': False, 'physical_hardware_qualified': False,
        'publisher_trust_accepted': False, 'independent_fresh_host_acceptance': False,
        'release_acceptance_complete': False, 'publication_authorized': False,
        'remaining': ['D10 full36-cell independent campaign', 'primary client pair and actual Codex',
                      'native owner maintenance/rollback', 'Apple native PKG installation where applicable',
                      'publisher trust and final retrievable signed-byte acceptance']}
    write(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    source = commands.add_parser('source')
    for name in ('repository', 'policy', 'output'):
        source.add_argument('--' + name, required=True, type=Path)
    for name in ('export-digest', 'manifest-sha256'):
        source.add_argument('--' + name, required=True)
    pack = commands.add_parser('package')
    for name in ('build-root', 'delivery', 'sdk-closure', 'export', 'repository', 'privacy-policy', 'output',
                 'python', 'standalone', 'standalone-archive'):
        pack.add_argument('--' + name, required=True, type=Path)
    for name in ('export-digest', 'manifest-sha256'):
        pack.add_argument('--' + name, required=True)
    pack.add_argument('--profile', required=True, choices=PROFILES)
    fresh_parser = commands.add_parser('fresh-user')
    for name in ('artifact', 'output', 'python'):
        fresh_parser.add_argument('--' + name, required=True, type=Path)
    fresh_parser.add_argument('--result-sha256', required=True)
    fresh_parser.add_argument('--profile', required=True, choices=PROFILES)
    fresh_parser.add_argument('--allow-ephemeral-install', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'source':
            result = prepare_source(args.repository, args.policy, args.output, args.export_digest, args.manifest_sha256)
            print(json.dumps({'verified': result['verified'], 'export_digest': result['export_digest']}))
        else:
            result = package(args) if args.command == 'package' else fresh_user(args)
            print(json.dumps({'state': result['state'], 'publication_authorized': False}))
    except Exception as error:
        failure_summary(args.output, error, getattr(args, 'privacy_policy', getattr(args, 'policy', None)))
        raise


if __name__ == '__main__':
    main()
