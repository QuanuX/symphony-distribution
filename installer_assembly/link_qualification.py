#!/usr/bin/env python3
"""Qualify Conda's inert carrier linking in an isolated prefix, never native installation."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

import carriers as c


def invoke(command, env, log):
    with log.open('xb') as stream:
        process = subprocess.Popen(command, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=10)
            raise ValueError('Isolated Conda operation timed out; private evidence retained')
    c.require(code == 0, 'Isolated Conda operation failed; private log retained')
    return c.sha(log.read_bytes())


def verify_linked(prefix, expected):
    actual = {}
    for path in prefix.rglob('*'):
        rel = path.relative_to(prefix).as_posix()
        if rel == 'conda-meta' or rel.startswith('conda-meta/') or rel == 'user-state.txt':
            continue
        c.require(not path.is_symlink(), 'Unexpected linked prefix entry')
        if path.is_file():
            raw, mode = c.bounded(path)
            actual[rel] = (raw, mode)
    c.require(actual == expected, 'Linked Conda bytes or modes differ from audited carriers')
    return len(actual)


def qualify(root, output, *, expected_digest, python):
    root = c.safe_root(root); record = c.audit_cohort(root)
    c.require(record['cohort_digest'] == expected_digest, 'Selected archive cohort differs')
    interpreter = Path(python).resolve(strict=True)
    c.require(interpreter.is_file(), 'Selected publisher interpreter absent')
    output = c.safe_root(output, exists=False)
    c.require(not output.exists() and root not in output.parents and output not in root.parents, 'Qualification output must be new and separate')
    output.mkdir(mode=0o700)
    for name in ('home', 'tmp', 'pkgs', 'envs'):
        (output / name).mkdir(mode=0o700)
    config = output / 'home/condarc'
    config.write_text('channels: []\nreport_errors: false\nanaconda_upload: false\nregister_envs: false\n')
    env = {'HOME': str(output / 'home'), 'PATH': str(interpreter.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
        'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'USER': 'builder', 'LOGNAME': 'builder',
        'TMPDIR': str(output / 'tmp'), 'TEMP': str(output / 'tmp'), 'TMP': str(output / 'tmp'),
        'CONDARC': str(config), 'CONDA_OFFLINE': 'true', 'CONDA_SUBDIR': record['conda_subdir'],
        'CONDA_PKGS_DIRS': str(output / 'pkgs'), 'CONDA_ENVS_PATH': str(output / 'envs'),
        'CONDA_REPORT_ERRORS': 'false', 'CONDA_NO_PLUGINS': 'true', 'CONDA_SOLVER': 'classic',
        'CONDA_REGISTER_ENVS': 'false', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    tool = subprocess.run([str(interpreter), '-c', "import conda, importlib.metadata as m, conda_pycosat_solver.plugin as p, hashlib, json; print(json.dumps({'conda':conda.__version__,'solver':m.version('conda-pycosat-solver'),'solver_module_sha256':hashlib.sha256(open(p.__file__,'rb').read()).hexdigest()}))"], env=env,
                          capture_output=True, timeout=30)
    c.require(tool.returncode == 0, 'Selected publisher tool inspection failed')
    tool_identity = json.loads(tool.stdout)
    c.require(tool_identity['conda'] == '26.10.0' and tool_identity['solver'] == '26.10.0', 'Unqualified Conda or solver version')
    c.digest(tool_identity['solver_module_sha256'])
    prefix = output / 'prefix'; outside = output / 'outside-sentinel'; outside.write_bytes(b'outside-owned-state\n')
    explicit = output / 'explicit.txt'
    explicit.write_text('@EXPLICIT\n' + ''.join((root / 'channel' / r['subdir'] / r['filename']).as_uri() + '#' + r['md5'] + '\n' for r in record['archives']))
    command = [str(interpreter), '-m', 'conda', '--no-plugins', '--enable-plugins', 'conda-pycosat-solver']
    create_log = invoke(command + ['create', '--prefix', str(prefix), '--file', str(explicit), '--offline', '--yes',
                                    '--copy', '--solver', 'classic', '--no-default-packages'], env, output / 'create.log')
    expected = {}
    for entry in record['entries']:
        _, files = c.validate_recipe(root, entry)
        c.require(not expected.keys() & files.keys(), 'Carrier paths overlap'); expected.update(files)
    linked_count = verify_linked(prefix, expected)
    (prefix / 'user-state.txt').write_bytes(b'user-owned-state\n')
    metadata = list((prefix / 'conda-meta').glob('*.json'))
    names = {json.loads(path.read_text())['name'] for path in metadata}
    c.require(names == {r['name'] for r in record['archives']} and len(metadata) == len(names), 'Installed package selection differs')
    remove_log = invoke(command + ['remove', '--prefix', str(prefix), '--offline', '--yes', '--solver', 'classic',
                                    *sorted(names)], env, output / 'remove.log')
    c.require((prefix / 'user-state.txt').read_bytes() == b'user-owned-state\n' and outside.read_bytes() == b'outside-owned-state\n',
              'Removal changed user or outside state')
    c.require(not list((prefix / 'conda-meta').glob('*.json')), 'Carrier package metadata remains after removal')
    verify_linked(prefix, {})
    c.require(c.audit_cohort(root) == record, 'Original archives changed during linking/removal')
    result = {'protocol': 'symphony.distribution.d08-conda-inert-link-qualification.v1', 'state': 'passed',
        'cohort_digest': expected_digest, 'conda_version': '26.10.0', 'solver_tool_identity': tool_identity, 'helper_sha256': c.sha(Path(__file__).read_bytes()),
        'archive_count': len(names), 'linked_file_count': linked_count, 'copy_mode': True,
        'exact_linked_bytes_and_modes': True, 'all_selected_carriers_removed': True,
        'user_state_preserved': True, 'outside_state_preserved': True, 'original_archive_bytes_unchanged': True,
        'create_log_sha256': create_log, 'remove_log_sha256': remove_log,
        'native_runtime_owner_invoked': False, 'runtime_installation_accepted': False,
        'publisher_trust_accepted': False, 'fresh_host_accepted': False, 'publication_authorized': False}
    (output / 'result.json').write_bytes(c.canonical(result) + b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cohort-digest', required=True); parser.add_argument('--python', type=Path, default=Path(sys.executable))
    args = parser.parse_args()
    try:
        result = qualify(args.cohort, args.output, expected_digest=args.cohort_digest, python=args.python)
        print(json.dumps({'state': result['state'], 'archive_count': result['archive_count']}))
    except (ValueError, OSError, KeyError) as error:
        parser.exit(2, 'Inert Conda qualification refused: ' + str(error) + '\n')

if __name__ == '__main__': main()
