#!/usr/bin/env python3
"""Run the pinned constructor with explicit, audited wrapper metadata policy.

This is publisher tooling. It never executes the resulting installer. Its
bounded adapters change wrapper metadata and enforce inactive fresh-prefix
setup; they never change a supplied Conda archive.
"""
import hashlib
import json
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def normalized_tarinfo(member):
    member.uid = member.gid = 0
    member.uname = member.gname = ''
    member.mtime = 0
    # Constructor inputs have closed portable names. PAX path is retained only
    # when needed by tarfile; timestamps and publisher metadata are not retained.
    member.pax_headers = {key: value for key, value in member.pax_headers.items() if key in ('path', 'linkpath')}
    return member


def pkgbuild_command(command):
    result = list(command)
    if Path(result[0]).name == 'pkgbuild':
        require(result.count('--ownership') == 1, 'unexpected constructor pkgbuild command')
        index = result.index('--ownership') + 1
        require(result[index] == 'preserve', 'constructor ownership policy drift')
        result[index] = 'recommended'
        result[0] = '/usr/bin/pkgbuild'
    return result


def public_build_info(platform, versions):
    return {'protocol': 'symphony.distribution.constructor-public-metadata.v1',
            'target_subdir': platform, 'constructor': versions['constructor'],
            'conda': versions['conda'], 'python': versions['python'],
            'host_inventory_included': False, 'publication_authorized': False}


def inactive_script(data):
    require(data.startswith('#!/bin/bash\n'), 'constructor native script shebang drift')
    return data.replace('#!/bin/bash\n', '#!/bin/bash\nexport CONDA_REPORT_ERRORS=false\nexport CONDA_NO_PLUGINS=true\n'
                        'export CONDA_RESTRICT_RC_SEARCH_PATH=1\nexport CONDARC=/dev/null\n', 1)


# The pinned 26.9.4 standalone registers its embedded constructor command as an
# external plugin, and has no selective --enable-plugins option. Only extraction
# receives this command-local override. The assembly probe below proves that the
# selected frozen executable cannot discover caller Python distributions.
CONSTRUCTOR_COMMAND = ('CONDA_NO_PLUGINS=false CONDA_RESTRICT_RC_SEARCH_PATH=1 '
                       'CONDARC=/dev/null PYTHONNOUSERSITE=1 PYTHONPATH= "$CONDA_EXEC" constructor')


def scope_constructor_commands(data, expected):
    original = '"$CONDA_EXEC" constructor'
    require(data.count(original) == expected and 'CONDA_NO_PLUGINS=false' not in data,
            'constructor extraction command scope drift')
    return data.replace(original, CONSTRUCTOR_COMMAND)


FROZEN_CONSTRUCTOR_PROBE = '''import importlib.metadata as metadata, json, pathlib, sys
root = pathlib.Path(sys._MEIPASS).resolve()
assert getattr(sys, 'frozen', False) and sys.path
for entry in sys.path:
    assert pathlib.Path(entry).resolve().is_relative_to(root)
distributions = list(metadata.distributions())
assert distributions
for distribution in distributions:
    assert pathlib.Path(distribution.locate_file('')).resolve().is_relative_to(root)
    assert distribution.metadata.get('Name', '').lower() != 'symphony-unselected-host-plugin'
import conda, __main__
assert conda.__version__ == '26.9.4' and hasattr(__main__, '_conda_main')
print(json.dumps({'protocol': 'symphony.distribution.frozen-constructor-probe.v1',
    'conda_version': conda.__version__, 'frozen_paths_only': True, 'frozen_distributions_only': True,
    'sys_path_entries': len(sys.path), 'embedded_distributions': len(distributions)}), flush=True)
sys.argv = [sys.executable, 'constructor', '--no-rc', '--help']
raise SystemExit(__main__._conda_main())
'''


def probe_frozen_constructor(bootstrap, work):
    probe = Path(work) / 'constructor-isolation-probe'; probe.mkdir(mode=0o700)
    caller = probe / 'caller'; caller.mkdir(mode=0o700)
    marker = probe / 'HOST_PLUGIN_IMPORTED'
    body = 'from pathlib import Path\nPath(' + repr(str(marker.resolve())) + ').write_text("unexpected import")\n'
    (caller / 'rogue_plugin.py').write_text(body)
    (caller / 'sitecustomize.py').write_text(body)
    metadata = caller / 'symphony_unselected_host_plugin-1.0.dist-info'; metadata.mkdir()
    (metadata / 'METADATA').write_text('Metadata-Version: 2.1\nName: symphony-unselected-host-plugin\nVersion: 1.0\n')
    (metadata / 'entry_points.txt').write_text('[conda]\nrogue = rogue_plugin\n')
    env = dict(os.environ)
    env.update(CONDA_NO_PLUGINS='false', CONDA_RESTRICT_RC_SEARCH_PATH='1', CONDARC='/dev/null',
               PYTHONNOUSERSITE='1', PYTHONPATH=str(caller.resolve()), CONDA_REPORT_ERRORS='false')
    result = subprocess.run([str(Path(bootstrap).resolve()), 'python', '-c', FROZEN_CONSTRUCTOR_PROBE],
                            cwd=caller, env=env, capture_output=True, text=True, timeout=240)
    (probe / 'stdout.log').write_text(result.stdout); (probe / 'stderr.log').write_text(result.stderr)
    require(result.returncode == 0 and not marker.exists(), 'frozen constructor isolation/help probe failed')
    lines = result.stdout.splitlines()
    require(lines and any(line.startswith('usage: conda constructor ') for line in lines),
            'embedded constructor command was not observed')
    proof = json.loads(lines[0])
    require(set(proof) == {'protocol', 'conda_version', 'frozen_paths_only', 'frozen_distributions_only',
                          'sys_path_entries', 'embedded_distributions'} and
            proof['protocol'] == 'symphony.distribution.frozen-constructor-probe.v1' and
            proof['conda_version'] == '26.9.4' and proof['frozen_paths_only'] is True and
            proof['frozen_distributions_only'] is True and 0 < proof['sys_path_entries'] <= 16 and
            0 < proof['embedded_distributions'] <= 512, 'unqualified frozen constructor result')
    return {**proof, 'caller_plugin_fixture_ignored': True, 'constructor_help_exit_code': 0,
            'probe_sha256': hashlib.sha256(FROZEN_CONSTRUCTOR_PROBE.encode()).hexdigest(),
            'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr.encode()).hexdigest()}


AMBIENT_CONDA_OWNERSHIP = '''CONDA_DIR="${HOME}/.conda"
if [[ -d "${CONDA_DIR}" ]]; then
    if ! chown -R "${USER}" "${CONDA_DIR}"; then
        OWNER=$(stat -f "%Su" "${CONDA_DIR}")
        MSG="WARNING: Unable to change ownership of ${CONDA_DIR} (owned by ${OWNER})."
        logger -p "install.warning" "${MSG}" || echo "${MSG}"
    fi
fi
CONDARC="${HOME}/.condarc"
if [[ -f "${CONDARC}" ]]; then
    if ! chown "${USER}" "${CONDARC}"; then
        OWNER=$(stat -f "%Su" "${CONDARC}")
        MSG="WARNING: Unable to change ownership of ${CONDARC} (owned by ${OWNER})."
        logger -p "install.warning" "${MSG}" || echo "${MSG}"
    fi
fi
'''


def scope_native_script(name, data):
    if name == 'run_installation.sh':
        require(data.count(AMBIENT_CONDA_OWNERSHIP) == 1 and 'chown -R "${USER}" "$PREFIX"' in data,
                'constructor ownership block drift')
        data = data.replace(AMBIENT_CONDA_OWNERSHIP, '')
    elif name == 'checks_before_install.sh':
        guard = 'if [[ -e "$PREFIX" ]]; then'
        require(data.count(guard) == 1, 'constructor native prefix guard drift')
        data = data.replace(guard, 'if [[ -e "$PREFIX" || -L "$PREFIX" ]]; then')
    # The two native execution templates reset CONDARC after their shebang.
    # Keep the selected empty configuration in force at that exact location.
    expected_resets = 1 if name in ('prepare_installation.sh', 'run_installation.sh') else 0
    require(data.count('unset CONDARC\n') == expected_resets, 'constructor native RC reset drift')
    data = data.replace('unset CONDARC\n', 'export CONDARC=/dev/null\n')
    data = scope_constructor_commands(data, 1 if name == 'prepare_installation.sh' else 0)
    require('${HOME}/.conda' not in data and '${HOME}/.condarc' not in data,
            'ambient Conda-home mutation remains in generated script')
    return inactive_script(data)


def fresh_shell_header(header):
    for flag in ('f', 'u'):
        old = f'        {flag})\n            FORCE=1\n            ;;'
        require(header.count(old) == 1, 'constructor force/update option drift')
        new = f'        {flag})\n            printf "%s\\n" "Existing-prefix replacement is unavailable in this review installer." >&2\n            exit 1\n            ;;'
        header = header.replace(old, new)
    header = header.replace('-f           no error if install prefix already exists\n', '')
    header = header.replace('-u           update an existing installation\n', '')
    start = 'if [ "$FORCE" = "0" ] && [ -e "$PREFIX" ]; then\n'
    end = '    REINSTALL=1\nfi\n'
    require(header.count(start) == 1 and header.count(end) == 1, 'constructor shell prefix guard drift')
    first = header.index(start); last = header.index(end, first) + len(end)
    header = header[:first] + '''if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then
    printf "%s\\n" "Install location already exists; choose a new empty location." >&2
    exit 1
fi
''' + header[last:]
    require('FORCE=1' not in header and 'REINSTALL=1' not in header, 'existing-prefix overwrite path remains')
    return header


def scope_shell_header(header):
    require(header.count('unset CONDARC\n') == 1, 'constructor shell RC isolation drift')
    header = header.replace('unset CONDARC\n', 'export CONDARC=/dev/null\nexport CONDA_RESTRICT_RC_SEARCH_PATH=1\n')
    return scope_constructor_commands(fresh_shell_header(header), 4)


def run(request_path):
    import constructor
    import constructor.main as main
    import constructor.preconda as preconda
    import constructor.osxpkg as osxpkg
    import constructor.fcp as fcp
    import constructor.shar as shar
    import constructor.utils as utils
    import conda
    request = json.loads(Path(request_path).read_text())
    require(constructor.__version__ == '3.17.3' and conda.__version__ == '26.10.0',
            'unqualified constructor/Conda version')
    require(sys.version.split()[0] == request['tool_versions']['python'] and
            importlib.metadata.version('pillow') == '13.0.0', 'unqualified Python/Pillow version')
    root = Path(constructor.__file__).resolve().parent
    source_hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                     for name in request['constructor_source_sha256']}
    require(source_hashes == request['constructor_source_sha256'], 'constructor implementation differs from reviewed pin')
    require(Path.cwd().resolve() == Path(request['work']).resolve(), 'constructor work directory differs')
    probe = subprocess.run(['bootstrap/conda.exe', '--version'], capture_output=True, text=True, timeout=180)
    require(probe.returncode == 0 and probe.stdout.strip() == 'conda 26.9.4',
            'pinned standalone bootstrap could not be identified; assembly refused')
    bootstrap = Path('bootstrap/conda.exe').resolve()
    bootstrap_sha = hashlib.sha256(bootstrap.read_bytes()).hexdigest()
    require(bootstrap_sha == request['bootstrap_sha256'], 'selected bootstrap changed before construction')
    constructor_isolation = probe_frozen_constructor(bootstrap, Path.cwd())
    # A one-file standalone decompresses on every --version invocation. Reuse
    # this observed version only for these exact unchanged executable bytes.
    def verified_identity(executable=None):
        require(executable is not None and Path(executable).resolve() == bootstrap and
                hashlib.sha256(bootstrap.read_bytes()).hexdigest() == bootstrap_sha,
                'constructor requested an unselected or changed bootstrap')
        return utils.StandaloneExe.CONDA, '26.9.4'
    main.identify_conda_exe = utils.identify_conda_exe = verified_identity
    # Keep constructor's generated history independent of the publisher's paths.
    sys.argv = ['constructor', '--output-dir', 'out', '--cache-dir', 'cache',
                '--conda-exe', 'bootstrap/conda.exe', '--platform', request['subdir'], 'config']
    original_addfile = tarfile.TarFile.addfile
    def addfile(archive, tarinfo, fileobj=None):
        return original_addfile(archive, normalized_tarinfo(tarinfo), fileobj)
    tarfile.TarFile.addfile = addfile
    preconda.system_info = lambda: public_build_info(request['subdir'], request['tool_versions'])
    original_check_call = osxpkg.explained_check_call
    osxpkg.explained_check_call = lambda command, *args, **kwargs: original_check_call(pkgbuild_command(command), *args, **kwargs)
    original_move_script = osxpkg.move_script
    def move_script(src, dst, *args, **kwargs):
        require(Path(src).resolve().parent == root / 'osx' and Path(src).name in
                ('checks_before_install.sh', 'prepare_installation.sh', 'run_installation.sh'),
                'unapproved constructor native script')
        result = original_move_script(src, dst, *args, **kwargs)
        destination = Path(dst)
        destination.write_text(scope_native_script(Path(src).name, destination.read_text()))
        return result
    osxpkg.move_script = move_script
    original_get_header = shar.get_header
    shar.get_header = lambda *args, **kwargs: scope_shell_header(original_get_header(*args, **kwargs))
    # Solver results are checked before constructor copies or wraps any package.
    original_fetch = fcp._fetch_precs
    def fetch(precs, *args, **kwargs):
        observed = sorted((p.name, p.version, p.build, p.subdir, p.sha256, p.fn) for p in precs)
        expected = sorted(tuple(row) for row in request['expected_packages'])
        require(observed == expected, 'constructor solved package set differs from the reviewed cohort')
        return original_fetch(precs, *args, **kwargs)
    fcp._fetch_precs = fetch
    main.main(sys.argv[1:])
    Path('constructor-proof.json').write_text(json.dumps({
        'protocol': 'symphony.distribution.constructor-adapter.v1',
        'constructor_source_sha256': source_hashes,
        'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'target_subdir': request['subdir'], 'solved_packages': request['expected_packages'],
        'public_build_metadata_only': True, 'tar_owner_metadata_neutral': True,
        'pkgbuild_ownership': 'recommended', 'installer_executed': False,
        'bootstrap_version_observed': '26.9.4', 'bootstrap_sha256': bootstrap_sha,
        'bootstrap_external_plugins_disabled_by_default': True,
        'constructor_plugin_override': 'command_local_frozen_bundle_extraction_only',
        'constructor_isolation': constructor_isolation, 'caller_rc_configuration_ignored': True,
        'error_reporting_disabled': True,
        'ambient_conda_home_ownership_unchanged': True, 'fresh_prefix_only': True,
        'signing_requested': False, 'publication_authorized': False}, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'expected one private constructor request')
    run(sys.argv[1])
