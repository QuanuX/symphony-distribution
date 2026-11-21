#!/usr/bin/env python3
"""Assemble and inspect inert unsigned installers from one audited carrier set.

Never installs the resulting package, signs, publishes, changes shell startup,
or invokes a Symphony runtime owner. The complete carrier set is independently
audited before and after wrapping. Native-host checks deliberately exclude cross
platform acceptance claims.
"""
import argparse
import bz2
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
from urllib.parse import urlsplit
import zipfile

HERE = Path(__file__).resolve().parent
SCHEMA = 'symphony.distribution.d08-unsigned-wrapper.v1'
REVIEW_CHANNEL = 'https://symphony-review.invalid/unsigned'
REVIEW_IDS = {'0.2.0-beta.2': 'beta2', '0.2.0-beta.2.1': 'beta2-1'}
MAX_WRAPPER = 4 * 1024 ** 3
PROFILES = {'macos15-arm64': ('osx-arm64', 'Darwin', 'arm64'),
            'ubuntu24.04-amd64': ('linux-64', 'Linux', 'x86_64'),
            'ubuntu24.04-arm64': ('linux-aarch64', 'Linux', 'aarch64'),
            'ubuntu26.04-amd64': ('linux-64', 'Linux', 'x86_64'),
            'local-macos-amd64-fixture': ('osx-64', 'Darwin', 'x86_64')}
CONSTRUCTOR_COMMAND = ('CONDA_NO_PLUGINS=false CONDA_RESTRICT_RC_SEARCH_PATH=1 '
                       'CONDARC=/dev/null PYTHONNOUSERSITE=1 PYTHONPATH= "$CONDA_EXEC" constructor').encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 ** 2), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(name):
    require(isinstance(name, str) and name and '\\' not in name and
            not PurePosixPath(name).is_absolute() and
            all(part not in ('', '.', '..') for part in name.split('/')) and
            all(ord(c) >= 32 and ord(c) != 127 for c in name), 'unsafe wrapper member path')
    return name


def safe_absolute(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'linked installer input/output path refused')
    return path


def admit_output(output, inputs):
    output = safe_absolute(output)
    require(not output.exists() and output.parent.is_dir(), 'output must be new with an existing parent')
    require(all(output != p and output not in p.parents and p not in output.parents for p in inputs),
            'output overlaps selected input')
    return output


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def native_route(profile, subdir, formats, *, supplemental=False, system=None, machine=None):
    require(profile in PROFILES and PROFILES[profile][0] == subdir, 'unreviewed profile/subdir')
    expected_subdir, expected_system, expected_machine = PROFILES[profile]
    require((system or platform.system()) == expected_system and
            (machine or platform.machine()) == expected_machine, 'installer assembly requires the matching native host')
    require(profile != 'local-macos-amd64-fixture' or supplemental, 'supplemental profile requires explicit selection')
    require(formats and len(set(formats)) == len(formats) and set(formats) <= {'pkg', 'sh'}, 'unsupported installer format')
    require('pkg' not in formats or expected_system == 'Darwin', 'PKG requires a macOS cohort and host')
    return expected_subdir


def archive_records(cohort):
    require(cohort.get('state') == 'archives_audited' and cohort.get('archives'), 'cohort has no completed archive audit')
    rows = cohort['archives']
    names = set()
    for row in rows:
        require(set(('unit_id', 'filename', 'sha256', 'md5', 'size', 'name', 'version', 'build',
                     'build_number', 'subdir', 'depends')) <= set(row), 'archive binding is incomplete')
        require(re.fullmatch(r'[a-zA-Z0-9_.-]+\.conda', row['filename']) and row['filename'] not in names,
                'archive name is unsafe or repeated')
        names.add(row['filename'])
        require(row['filename'] == f"{row['name']}-{row['version']}-{row['build']}.conda" and
                row['depends'] == [] and row['subdir'] == cohort['conda_subdir'], 'archive identity or inert dependency policy differs')
        require(re.fullmatch('[0-9a-f]{64}', row['sha256']) and re.fullmatch('[0-9a-f]{32}', row['md5']) and
                isinstance(row['size'], int) and 0 < row['size'] < MAX_WRAPPER, 'invalid archive digest or size')
    return rows


def beta_authorization(path, expected_sha256, profile):
    """Bind published beta authority or review-only assembly, never promote either."""
    path = safe_absolute(path)
    require(re.fullmatch('[0-9a-f]{64}', expected_sha256 or '') and
            file_sha(path) == expected_sha256, 'Exact publisher decision digest required')
    decision = json.loads(path.read_bytes())
    published = decision['protocol'] == 'symphony.distribution.beta-publisher-decision.v1'
    review = decision['protocol'] == 'symphony.distribution.beta-candidate-authorization.v1'
    require((published or review) and profile in decision['profiles'] and
            decision['release_acceptance_complete'] is False and
            all(decision['trust'][key] is False for key in ('apple_developer_id', 'notarization', 'os_trust_store_change_authorized')) and
            all(decision['preserved_constraints'][key] is True for key in
                ('feature_freeze', 'main_unchanged', 'no_automatic_runtime_or_provider_activation', 'no_private_publisher_state_in_distribution')),
            'Publisher beta scope or trust boundary differs')
    if published:
        require(decision['release_class'] == 'public-beta' and decision['release_version'] in ('0.2.0-beta.1', '0.2.0-beta.2') and
                all(decision[key] is True for key in ('publication_authorized', 'legal_approval', 'publisher_acceptance')) and
                decision['trust']['mode'] == 'publisher-pinned-self-signed-detached-manifest',
                'Publisher beta scope or trust boundary differs')
        if decision['release_version'] == '0.2.0-beta.2':
            policy = load_module('beta_publication_policy', HERE / 'beta_signing.py').release_policy(decision['release_version'])
            require(expected_sha256 == policy['decision_sha256'] and
                decision['source_binding'] == {'core_commit': policy['core_commit'], 'client_commit': policy['client_commit']} and
                set(decision['profiles']) == set(PROFILES) - {'local-macos-amd64-fixture'} and len(decision['profiles']) == 4,
                'Exact approved beta.2 publication decision and source required')
    else:
        require(decision['release_class'] == 'beta-review-candidate' and decision['release_version'] in REVIEW_IDS and
                decision['candidate_assembly_authorized'] is True and decision['publication_authorized'] is False and
                decision['trust']['mode'] == 'unsigned-review' and
                set(decision['profiles']) == set(PROFILES) - {'local-macos-amd64-fixture'} and
                len(decision['profiles']) == 4 and
                set(decision['source_binding']) == {'core_commit', 'client_commit'} and
                all(re.fullmatch('[0-9a-f]{40}', value or '') for value in decision['source_binding'].values()) and
                all(key not in decision or decision[key] is False for key in ('legal_approval', 'publisher_acceptance')),
                'Review candidate cannot grant publication, acceptance or publisher trust')
    return {'decision': decision, 'sha256': expected_sha256}


def beta_delivery_scope(authorization):
    decision = authorization['decision']
    published = decision['publication_authorized']
    return {'release_version': decision['release_version'], 'publication_authorized': published,
        'assembly_state': 'beta_wrappers_and_shell_qualified' if published else 'beta_review_candidate_wrappers_and_shell_qualified',
        'wrapper_state': 'beta_wrappers_audited' if published else 'beta_review_candidate_wrappers_audited',
        'trust_status': 'native_wrapper_unsigned_detached_manifest_separate' if published else 'unsigned_review_candidate'}


def configuration(cohort, channel, formats, *, beta=None):
    rows = archive_records(cohort)
    digest = cohort['cohort_digest']
    require(re.fullmatch('sha256:[0-9a-f]{64}', digest), 'invalid cohort digest')
    result = {'name': 'SymphonyReview', 'version': '0.0.0.' + digest[7:19],
            'installer_type': formats, 'channels': [],
            'channels_remap': [{'src': Path(channel).resolve().as_uri(), 'dest': REVIEW_CHANNEL}],
            'specs': [f"{r['name']}={r['version']}={r['build']}" for r in rows],
            'initialize_conda': False, 'initialize_by_default': False, 'register_envs': False,
            'menu_packages': [], 'write_condarc': False, 'keep_pkgs': True,
            'script_env_variables': {'CONDA_REPORT_ERRORS': 'false', 'CONDA_NO_PLUGINS': 'true'},
            'ignore_duplicate_files': False, 'check_path_spaces': False,
            'pkg_domains': {'enable_anywhere': False, 'enable_currentUserHome': True, 'enable_localSystem': False},
            'reverse_domain_identifier': 'org.quanux.symphony.review',
            'default_prefix': '${HOME}/symphony-review',
            'conclusion_text': 'Unsigned review package prepared. This installer does not start Symphony services. '
                               'Explicit setup and release trust approval are separate steps.',
            'welcome_text': 'Symphony unsigned installer review',
            'welcome_image': '',
            'license_file': 'LICENSE.txt',
            'readme_text': 'This review installs immutable package carriers only. It does not enroll, '
                           'configure credentials, start services, or change application selections. '
                           'It is not approved for public beta distribution.',
            'extra_files': [{'COHORT.json': 'share/symphony/installer/COHORT.json'},
                            {'MAINTENANCE.txt': 'share/symphony/installer/MAINTENANCE.txt'},
                            {'BOOTSTRAP.json': 'share/symphony/installer/BOOTSTRAP.json'}]}
    if beta is not None:
        scope = beta_delivery_scope(beta)
        result.update(name='Symphony', version=scope['release_version'],
            channels_remap=[{'src': Path(channel).resolve().as_uri(), 'dest': 'https://conda.anaconda.org/QuanuX/label/beta'}],
            reverse_domain_identifier='org.quanux.symphony.beta', default_prefix='${HOME}/symphony',
            welcome_text='Symphony Public Beta ' + scope['release_version'],
            conclusion_text='Symphony package carriers are installed. This installer does not start Symphony services. '
                            'Use the published setup instructions to select and configure your modules.',
            readme_text='Symphony Public Beta installs immutable, independently maintainable package carriers. '
                        'It does not enroll, configure credentials, start services, or change application selections. '
                        'Verify the detached integrity manifest against the published publisher key pin. '
                        'Python 3.11 or later is required for explicit first-run retention using the included symphony-retain.py helper. '
                        'The macOS installer is unsigned and not notarized; a self-signed integrity manifest does not establish Apple trust.')
        if not scope['publication_authorized']:
            review_id = REVIEW_IDS[scope['release_version']]
            result.update(name='SymphonyReview',
                channels_remap=[{'src': Path(channel).resolve().as_uri(), 'dest': REVIEW_CHANNEL}],
                reverse_domain_identifier='org.quanux.symphony.' + review_id + '.review',
                default_prefix='${HOME}/symphony-' + review_id + '-review',
                welcome_text='Symphony beta review candidate ' + scope['release_version'],
                conclusion_text='Symphony review carriers are installed. No services have started. '
                                'This candidate is unsigned and is not approved for public distribution.',
                readme_text='Symphony beta review candidate installs immutable, independently maintainable package carriers. '
                            'It does not enroll, configure credentials, start services, or change application selections. '
                            'This candidate is unsigned and not approved for public distribution. '
                            'Python 3.11 or later is required for explicit first-run retention using the included symphony-retain.py helper. '
                            'The macOS installer is unsigned and not notarized. Qualification results and publisher approval remain separate.')
        result['extra_files'] += [
            {'BOOTSTRAP-INDEX.json': 'share/symphony/installer/BOOTSTRAP-INDEX.json'},
            {'symphony-retain.py': 'share/symphony/installer/symphony-retain.py'}]
    return result


def write_channel_index(channel, cohort):
    """Index only already audited bytes; no channel refresh or remote solve."""
    rows = archive_records(cohort)
    for subdir in (cohort['conda_subdir'], 'noarch'):
        directory = Path(channel) / subdir
        directory.mkdir(exist_ok=True)
        packages = {}
        if subdir == cohort['conda_subdir']:
            for row in rows:
                path = directory / row['filename']
                require(path.is_file() and not path.is_symlink() and path.stat().st_size == row['size'] and
                        file_sha(path) == row['sha256'], 'channel archive bytes differ')
                packages[row['filename']] = {key: row[key] for key in
                    ('name', 'version', 'build', 'build_number', 'subdir', 'depends', 'sha256', 'md5', 'size')}
        repodata = {'info': {'subdir': subdir}, 'packages': {}, 'packages.conda': packages,
                    'removed': [], 'repodata_version': 1}
        (directory / 'repodata.json').write_bytes(canonical(repodata))
        (directory / 'current_repodata.json').write_bytes(canonical(repodata))


def run(command, *, cwd, env, log, timeout=900):
    with Path(log).open('wb') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise ValueError('publisher command timed out; private evidence retained')
    require(code == 0, 'publisher command failed; private evidence retained')


def clean_env(work, interpreter, subdir):
    for name in ('home', 'tmp', 'pkgs', 'envs'):
        (work / name).mkdir(mode=0o700)
    config = work / 'home/condarc'
    config.write_text('channels: []\nreport_errors: false\nauto_activate_base: false\nanaconda_upload: false\n')
    return {'HOME': str(work / 'home'), 'PATH': str(interpreter.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
            'TMPDIR': str(work / 'tmp'), 'TMP': str(work / 'tmp'), 'TEMP': str(work / 'tmp'),
            'USER': 'builder', 'LOGNAME': 'builder', 'LANG': 'C.UTF-8', 'LC_ALL': 'C',
            'CONDARC': str(config), 'CONDA_OFFLINE': 'true', 'CONDA_NO_PLUGINS': 'true',
            'CONDA_SOLVER': 'classic', 'CONDA_SUBDIR': subdir, 'CONDA_REPORT_ERRORS': 'false',
            'CONDA_REGISTER_ENVS': 'false', 'CONDA_AUTO_ACTIVATE_BASE': 'false',
            'CONDA_PKGS_DIRS': str(work / 'pkgs'), 'CONDA_ENVS_PATH': str(work / 'envs'),
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'SOURCE_DATE_EPOCH': '0'}


def privacy_scan(data, markers):
    low = data.lower()
    require(not any(marker.lower() in low for marker in markers), 'private publisher marker in wrapper content')
    require(not re.search(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{32,}', data),
            'private key material in wrapper')


def markers_from_policy(path):
    markers = [b'SYMPHONY_PRIVATE_' + b'CANARY_']
    if path:
        policy = json.loads(Path(path).read_text())
        require(policy.get('schema') == 'symphony.source-privacy-policy.v1' and
                isinstance(policy.get('markers'), list) and policy['markers'], 'unsupported privacy policy')
        require(all(isinstance(item, str) and 3 <= len(item) <= 256 for item in policy['markers']), 'invalid privacy marker')
        markers += [item.encode() for item in policy['markers']]
    return markers


def bootstrap_components(zipped, pin):
    """Bind the stream reader's logical filename to the selected package identity."""
    require(all(isinstance(pin.get(key), str) and
                re.fullmatch(r'[A-Za-z0-9_.]{1,128}', pin[key]) for key in ('version', 'build')),
            'invalid standalone package identity')
    stem = f"conda-standalone-{pin['version']}-{pin['build']}"
    filename = stem + '.conda'
    url = urlsplit(pin.get('url', ''))
    require(url.scheme == 'https' and url.netloc == 'conda.anaconda.org' and
            not url.query and not url.fragment and url.path.split('/')[-1] == filename,
            'standalone URL differs from selected package identity')
    infos = zipped.infolist()
    expected = {'metadata.json', f'pkg-{stem}.tar.zst', f'info-{stem}.tar.zst'}
    require(len(infos) == len(expected) and {item.filename for item in infos} == expected,
            'standalone archive components differ from selected package identity')
    require(all(not item.is_dir() and not item.flag_bits & 1 and
                stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG) and
                item.compress_type == zipfile.ZIP_STORED and 0 < item.file_size <= MAX_WRAPPER
                for item in infos), 'unsupported standalone ZIP member')
    require(zipped.getinfo('metadata.json').file_size <= 4096, 'standalone metadata exceeds bound')
    # Preserve the selected upstream bytes; reject duplicate keys rather than letting
    # JSON parsing silently choose a competing archive-format declaration.
    pairs = json.loads(zipped.read('metadata.json'), object_pairs_hook=list)
    require(pairs == [('conda_pkg_format_version', 2)] and type(pairs[0][1]) is int,
            'unsupported standalone package metadata')
    return filename


def bootstrap_proof(archive, executable, pin):
    """Read the pinned public package without extracting archive-owned paths."""
    from conda_package_streaming.package_streaming import stream_conda_component
    require(file_sha(archive) == pin['sha256'], 'standalone archive differs from exact tool pin')
    expected_binary = None
    notices = {}
    with zipfile.ZipFile(archive) as zipped:
        filename = bootstrap_components(zipped, pin)
        for component in ('pkg', 'info'):
            # With an open ZIP, the library uses this name only to select pkg/info
            # members. The download's storage name (e.g. standalone.conda) is unrelated.
            for stream, member in stream_conda_component(filename, component=component, zf=zipped):
                safe_path(member.name.rstrip('/') if member.isdir() else member.name)
                wanted = member.name == 'standalone_conda/conda.exe' or member.name.startswith('info/licenses/')
                if not wanted or member.isdir():
                    continue
                require(member.isfile() and not member.linkname and member.size <= 256 * 1024 ** 2,
                        'unsupported standalone package member')
                data = stream.extractfile(member).read(member.size + 1)
                require(len(data) == member.size, 'truncated standalone package')
                if member.name == 'standalone_conda/conda.exe':
                    require(expected_binary is None, 'repeated standalone executable')
                    expected_binary = sha(data)
                else:
                    name = member.name.removeprefix('info/licenses/')
                    require(name not in notices, 'duplicate standalone notice')
                    notices[name] = data
    require(expected_binary is not None and expected_binary == file_sha(executable),
            'standalone executable differs from pinned package')
    require(notices, 'standalone package has no license notices')
    require(file_sha(archive) == pin['sha256'], 'standalone archive changed during inspection')
    return expected_binary, notices


def audit_nested_tar(raw, expected, markers, *, depth=0):
    require(depth <= 2 and len(raw) <= MAX_WRAPPER, 'nested wrapper archive exceeds bounds')
    if raw.startswith(b'BZh'):
        decoder = bz2.BZ2Decompressor()
        unpacked = decoder.decompress(raw, max_length=MAX_WRAPPER + 1)
        require(len(unpacked) <= MAX_WRAPPER and decoder.eof and not decoder.unused_data,
                'wrapper compression contains trailing data or exceeds bounds')
    else:
        unpacked = raw
    found = {}
    seen = set()
    boundary = 0
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
        require(not archive.pax_headers, 'global wrapper archive metadata is forbidden')
        for member in archive:
            name = safe_path(member.name.rstrip('/') if member.isdir() else member.name)
            require(name not in seen and len(seen) < 100000, 'duplicate or excessive wrapper members')
            seen.add(name)
            require(member.offset == boundary and unpacked[member.offset:member.offset_data] ==
                    member.tobuf(format=tarfile.PAX_FORMAT, encoding='utf-8', errors='strict'),
                    'noncanonical wrapper tar header or hidden metadata')
            end = member.offset_data + member.size
            boundary = (end + 511) // 512 * 512
            require(not any(unpacked[end:boundary]), 'nonzero wrapper tar member padding')
            require(member.uid == member.gid == 0 and member.uname == member.gname == '' and member.mtime == 0,
                    'wrapper archive exposes publisher owner/time metadata')
            require(set(member.pax_headers) <= {'path', 'linkpath'} and not member.mode & 0o7000,
                    'unexpected wrapper metadata or special mode')
            require(member.isdir() or member.isfile(), 'wrapper metadata tar contains a link or special file')
            if member.isdir():
                continue
            require(0 <= member.size <= MAX_WRAPPER, 'wrapper member exceeds limit')
            data = archive.extractfile(member).read(member.size + 1)
            require(len(data) == member.size, 'truncated wrapper member')
            if name.endswith('.conda'):
                filename = PurePosixPath(name).name
                require(filename in expected and filename not in found, 'unexpected nested Conda archive')
                row = expected[filename]
                require(len(data) == row['size'] and sha(data) == row['sha256'], 'nested Conda archive bytes differ')
                found[filename] = row['sha256']
            elif name.endswith(('.tar.bz2', '.tar')):
                nested = audit_nested_tar(data, expected, markers, depth=depth + 1)
                require(not set(nested) & set(found), 'repeated nested package')
                found.update(nested)
            else:
                privacy_scan(name.encode() + b'\n' + data, markers)
                require(not any(part in name for part in ('user_pre_install', 'user_post_install', 'pre_uninstall', 'run_conda_init')),
                        'unexpected activation hook in wrapper')
    require(len(unpacked) % tarfile.RECORDSIZE == 0 and len(unpacked) - boundary >= 1024 and
            not any(unpacked[boundary:]), 'wrapper tar has hidden trailing data or incomplete termination')
    return found


def audit_constructor_policy(data, expected):
    require(data.count(CONSTRUCTOR_COMMAND) == expected and
            data.count(b'CONDA_NO_PLUGINS=false') == expected and
            data.count(b'"$CONDA_EXEC" constructor') == expected and
            b"CONDA_NO_PLUGINS='false'" not in data and b'CONDA_NO_PLUGINS="false"' not in data,
            'constructor plugin override escapes its bounded extraction calls')
    require(b'export CONDARC=/dev/null\n' in data and b'export CONDA_RESTRICT_RC_SEARCH_PATH=1\n' in data and
            b'unset CONDARC\n' not in data, 'constructor caller configuration isolation differs')


def audit_sh(path, rows, bootstrap_sha, markers):
    require(Path(path).stat().st_size <= MAX_WRAPPER, 'wrapper exceeds size limit')
    raw = Path(path).read_bytes()
    marker = b'\n@@END_HEADER@@\n'
    offset = raw.find(marker)
    require(0 <= offset < 1024 ** 2, 'constructor shell header boundary is absent')
    boundary = offset + len(marker)
    header = raw[:boundary]
    privacy_scan(header, markers)
    lengths = []
    for index in (1, 2, 3):
        match = re.search(rb'boundary' + str(index).encode() + rb'=\$\(\( boundary' + str(index - 1).encode() + rb' \+ ([0-9]+) \)\)', header)
        require(match is not None, 'constructor shell payload offsets differ')
        lengths.append(int(match.group(1)))
    require(boundary + sum(lengths) == len(raw), 'constructor shell payload size differs')
    require(lengths[1] == 0, 'unqualified standalone onedir bootstrap')
    require(sha(raw[boundary:boundary + lengths[0]]) == bootstrap_sha, 'bootstrap bytes changed inside shell wrapper')
    require(b"CONDA_REGISTER_ENVS=\"false\"" in header and b'conda init' not in header,
            'shell wrapper initialization/registration policy differs')
    require(b"export CONDA_REPORT_ERRORS='false'" in header and b"export CONDA_NO_PLUGINS='true'" in header,
            'shell wrapper reporting/plugin policy differs')
    audit_constructor_policy(header, 4)
    require(b'if [ -e "$PREFIX" ] || [ -L "$PREFIX" ]; then' in header and
            b'FORCE=1' not in header and b'REINSTALL=1' not in header,
            'shell wrapper permits existing-prefix replacement')
    expected = {row['filename']: row for row in rows}
    found = audit_nested_tar(raw[boundary + lengths[0]:], expected, markers)
    require(found == {name: row['sha256'] for name, row in expected.items()}, 'shell wrapper does not contain exact cohort')
    return {'format': 'sh', 'archive_count': len(found), 'nested_archives_sha256': found,
            'bootstrap_sha256': bootstrap_sha, 'installer_executed': False, 'archive_metadata_neutral': True}


def audit_pkg(path, rows, bootstrap_sha, markers, *, work, env):
    require(platform.system() == 'Darwin', 'PKG inspection requires Apple tools')
    listing = subprocess.check_output(['/usr/bin/xar', '-tf', str(path)], env=env, timeout=30).decode().splitlines()
    for name in listing:
        safe_path(name.rstrip('/'))
    finalizer = load_module('d08_pkg_final_audit', HERE / 'pkg_finalize.py')
    toc_bytes, toc_root, _ = finalizer.toc(path, work / 'final-pkg-toc.xml', env)
    require(not any(node.tag in finalizer.FORBIDDEN_XAR for node in toc_root.iter()),
            'PKG XAR retains publisher ownership/device metadata')
    privacy_scan(toc_bytes, markers)
    destination = work / 'expanded-pkg'
    require(not destination.exists(), 'PKG inspection output already exists')
    run(['/usr/sbin/pkgutil', '--expand-full', str(path), str(destination)], cwd=work,
        env=env, log=work / 'expand-pkg.log', timeout=180)
    expected = {row['filename']: row for row in rows}
    found = {}
    bootstraps = []
    scripts = []
    constructor_calls = 0
    for entry in sorted(destination.rglob('*')):
        require(not entry.is_symlink(), 'unexpected link in expanded wrapper')
        require(entry.is_dir() or entry.is_file(), 'special file in expanded wrapper')
        if entry.is_dir():
            continue
        require(entry.stat().st_size <= MAX_WRAPPER, 'expanded wrapper member exceeds bound')
        if entry.suffix == '.conda':
            require(entry.name in expected and entry.name not in found, 'unexpected nested Conda archive in PKG')
            row = expected[entry.name]
            require(entry.stat().st_size == row['size'] and file_sha(entry) == row['sha256'], 'PKG nested archive differs')
            found[entry.name] = row['sha256']
        elif entry.name == '_conda':
            require(file_sha(entry) == bootstrap_sha, 'PKG standalone bytes differ')
            bootstraps.append(entry)
        else:
            data = entry.read_bytes()
            privacy_scan(str(entry.relative_to(destination)).encode() + b'\n' + data, markers)
            if 'Scripts' in entry.parts:
                scripts.append(str(entry.relative_to(destination)))
                require(b'export CONDA_REPORT_ERRORS=false\nexport CONDA_NO_PLUGINS=true\n' in data,
                        'PKG reporting/plugin policy differs')
                expected_calls = 1 if entry.name == 'postinstall' and 'prepare_installation.pkg' in entry.parts else 0
                audit_constructor_policy(data, expected_calls)
                constructor_calls += expected_calls
                require(b'${HOME}/.conda' not in data and b'${HOME}/.condarc' not in data and
                        b'"${CONDA_DIR}"' not in data, 'PKG mutates ambient Conda user state')
                if entry.name == 'preinstall':
                    require(b'if [[ -e "$PREFIX" || -L "$PREFIX" ]]; then' in data, 'PKG fresh-prefix guard differs')
                require(not any(token in data for token in (b'qxctl', b'symphony-ssiag', b'stav-append-authority', b'conda init')),
                        'unexpected runtime owner or activation call in PKG scripts')
    require(found == {name: row['sha256'] for name, row in expected.items()} and len(bootstraps) == 1 and constructor_calls == 1,
            'PKG does not contain exact cohort and bootstrap')
    distribution = (destination / 'Distribution').read_bytes()
    require(b'run_conda_init' not in distribution and b'user_pre_install' not in distribution and
            b'user_post_install' not in distribution, 'PKG contains unapproved installer choices')
    return {'format': 'pkg', 'archive_count': len(found), 'nested_archives_sha256': found,
            'bootstrap_sha256': bootstrap_sha, 'installer_executed': False,
            'scripts': scripts, 'signature_status': 'unsigned_review_only'}


def assemble(cohort_root, output, *, interpreter, standalone, standalone_archive, formats,
             privacy_policy=None, supplemental=False, beta_decision=None, beta_decision_sha256=None):
    cohort_root = safe_absolute(cohort_root)
    protected = [cohort_root, HERE.parent, Path(os.path.abspath(interpreter)).parent.parent,
                 Path(interpreter).resolve(), safe_absolute(standalone), safe_absolute(standalone_archive)]
    if privacy_policy:
        protected.append(safe_absolute(privacy_policy))
    require((beta_decision is None) == (beta_decision_sha256 is None), 'Complete publisher decision selection required')
    if beta_decision:
        protected.append(safe_absolute(beta_decision))
    output = admit_output(output, protected)
    carriers = load_module('symphony_d08_carriers', HERE / 'carriers.py')
    cohort = carriers.audit_cohort(cohort_root)
    beta = beta_authorization(beta_decision, beta_decision_sha256, cohort['profile']) if beta_decision else None
    rows = archive_records(cohort)
    subdir = native_route(cohort['profile'], cohort['conda_subdir'], formats, supplemental=supplemental)
    host_module = load_module('d08_host_profile', HERE.parent / 'qualification/host_platform.py')
    observed_host = host_module.observe_host()
    require(host_module.profile_matches(cohort['profile'], observed_host), 'actual OS release differs from selected installer profile')
    # Preserve a venv interpreter's invocation path; resolving its symlink would
    # silently select the base environment and a different publisher tool set.
    interpreter = Path(os.path.abspath(interpreter))
    standalone, standalone_archive = (Path(p).resolve() for p in (standalone, standalone_archive))
    require(all(p.is_file() for p in (interpreter, standalone, standalone_archive)), 'publisher tool input is absent')
    lock = json.loads((HERE / 'tool-lock.json').read_text())
    require(subdir in lock['standalone'], 'standalone target tool pin is pending')
    bootstrap = lock['standalone'][subdir]
    bootstrap_sha, bootstrap_notices = bootstrap_proof(standalone_archive, standalone, bootstrap)
    output.mkdir(mode=0o700, parents=True)
    work = output / 'work'; work.mkdir(mode=0o700)
    env = clean_env(work, interpreter, subdir)
    try:
        for directory in ('config', 'bootstrap', 'out', 'channel'):
            (work / directory).mkdir(mode=0o700)
        shutil.copyfile(standalone, work / 'bootstrap/conda.exe')
        (work / 'bootstrap/conda.exe').chmod(0o755)
        shutil.copytree(cohort_root / 'channel', work / 'channel', dirs_exist_ok=True)
        require(all(file_sha(work / 'channel' / subdir / r['filename']) == r['sha256'] for r in rows), 'copied cohort differs')
        write_channel_index(work / 'channel', cohort)
        config = configuration(cohort, work / 'channel', formats, beta=beta)
        for name, data in bootstrap_notices.items():
            local = work / 'config/bootstrap-notices' / name
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
            config['extra_files'].append({'bootstrap-notices/' + name: 'share/symphony/installer/bootstrap-notices/' + name})
        # JSON is a strict subset of YAML, avoiding implicit YAML scalar typing.
        (work / 'config/construct.yaml').write_bytes(canonical(config))
        shutil.copyfile(HERE.parent / 'LICENSE', work / 'config/LICENSE.txt')
        public_cohort = {'protocol': SCHEMA, 'cohort_digest': cohort['cohort_digest'], 'profile': cohort['profile'],
                         'archives': rows, 'publication_authorized': False, 'release_acceptance_complete': False,
                         'runtime_activated': False, 'trust_status': 'unsigned_review_only'}
        if beta:
            retention = load_module('symphony_beta_retention', HERE.parent / 'delivery/bootstrap.py')
            retention_index = canonical(retention.prepare_index(cohort_root, cohort)) + b'\n'
            (work / 'config/BOOTSTRAP-INDEX.json').write_bytes(retention_index)
            shutil.copyfile(HERE.parent / 'delivery/bootstrap.py', work / 'config/symphony-retain.py')
            scope = beta_delivery_scope(beta)
            public_cohort.update(protocol='symphony.distribution.beta-installer.v1', publication_authorized=scope['publication_authorized'],
                release_version=beta['decision']['release_version'], publisher_decision_sha256=beta['sha256'],
                trust_status=scope['trust_status'], apple_developer_id=False, notarization=False,
                retention_index_sha256=sha(retention_index), retention_helper_sha256=file_sha(HERE.parent / 'delivery/bootstrap.py'),
                retention_python_requirement='3.11 or later')
        (work / 'config/COHORT.json').write_bytes(canonical(public_cohort))
        (work / 'config/BOOTSTRAP.json').write_bytes(canonical({'package': bootstrap, 'subdir': subdir,
                                                            'executable_sha256': bootstrap_sha,
                                                            'notices': {n: sha(b) for n, b in bootstrap_notices.items()},
                                                            'role': 'installer_bootstrap_and_explicit_carrier_maintenance'}))
        (work / 'config/MAINTENANCE.txt').write_text(
            ('Symphony Public Beta contains immutable, independently maintainable package carriers.\n' if beta and beta['decision']['publication_authorized'] else
             'This unsigned review contains immutable Symphony package carriers.\n') +
            'No Symphony service, credential setup, enrollment, or application selection has run.\n'
            'Conda removes carriers only; runtime removal belongs to the existing native owner.\n'
            'Retain exact rollback material outside the mutable Conda cache before changing carriers.\n'
            'Use an independently trusted publisher policy before explicit runtime setup.\n'
            'Whole-profile apply must name its exact scope. Unsupported owner operations remain blocked.\n'
            'The embedded _conda tool can inspect this carrier prefix explicitly; no shell activation is required.\n')
        request = {'work': str(work), 'subdir': subdir, 'constructor_source_sha256': lock['constructor_source_sha256'],
                   'bootstrap_sha256': bootstrap_sha,
                   'tool_versions': {'constructor': lock['constructor_version'], 'conda': lock['conda_version'], 'python': '3.12.16'},
                   'expected_packages': [[r['name'], r['version'], r['build'], r['subdir'], r['sha256'], r['filename']] for r in rows]}
        (work / 'request.json').write_bytes(canonical(request))
        run([str(interpreter), '-I', '-B', str(HERE / 'constructor_runner.py'), 'request.json'],
            cwd=work, env=env, log=work / 'constructor.log')
        constructor_proof = json.loads((work / 'constructor-proof.json').read_text())
        isolation = constructor_proof['constructor_isolation']
        require(constructor_proof['adapter_sha256'] == file_sha(HERE / 'constructor_runner.py') and
                constructor_proof['bootstrap_sha256'] == bootstrap_sha and
                isolation['frozen_paths_only'] is True and isolation['frozen_distributions_only'] is True and
                isolation['caller_plugin_fixture_ignored'] is True and isolation['constructor_help_exit_code'] == 0,
                'selected bootstrap constructor isolation was not established')
        markers = markers_from_policy(privacy_policy) + [str(p).encode() for p in
                  (output, cohort_root, interpreter.parent.parent, standalone.parent, HERE.parent)]
        records = []
        for form in formats:
            candidates = list((work / 'out').glob('*.' + form))
            require(len(candidates) == 1, 'constructor output format count differs')
            artifact = candidates[0]
            finalization = None
            if form == 'pkg':
                finalizer = load_module('d08_pkg_finalizer', HERE / 'pkg_finalize.py')
                (work / 'final-pkg').mkdir(mode=0o700)
                finalized = work / 'final-pkg' / artifact.name
                finalization = finalizer.finalize(artifact, finalized, work / 'pkg-finalization', env)
                artifact = finalized
            result = (audit_sh(artifact, rows, bootstrap_sha, markers) if form == 'sh' else
                      audit_pkg(artifact, rows, bootstrap_sha, markers, work=work, env=env))
            result.update({'filename': artifact.name, 'sha256': file_sha(artifact), 'size': artifact.stat().st_size})
            if finalization:
                result['unsigned_wrapper_finalization'] = finalization
            records.append(result)
            shutil.copyfile(artifact, output / artifact.name)
        require(carriers.audit_cohort(cohort_root) == cohort, 'original cohort changed during assembly')
        report = {**public_cohort, 'state': 'unsigned_wrappers_audited', 'wrappers': records,
                  'constructor_adapter_sha256': file_sha(HERE / 'constructor_runner.py'),
                  'constructor_isolation': isolation,
                  'assembler_sha256': file_sha(Path(__file__)), 'tool_lock_sha256': file_sha(HERE / 'tool-lock.json'),
                  'private_policy_sha256': file_sha(privacy_policy) if privacy_policy else None,
                  'local_cli_cohort_identical': True, 'installer_executed': False,
                  'observed_host': observed_host,
                  'signature_verified': False, 'notarization_verified': False,
                  'release_blockers': ['publisher trust/signatures', 'final profile/fresh-host qualification',
                                       'explicit runtime owner lifecycle qualification', 'publication approval']}
        if beta:
            require(beta_authorization(beta_decision, beta_decision_sha256, cohort['profile']) == beta,
                    'Publisher decision changed during assembly')
            report.update(state=scope['wrapper_state'], release_blockers=['final installer qualification and detached integrity manifest'] +
                ([] if scope['publication_authorized'] else ['candidate publication approval']),
                known_limits=['native macOS package unsigned and not notarized', 'no automatic native runtime installation or activation'])
        (output / 'result.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        return report
    except Exception as exc:
        (output / 'INCOMPLETE.json').write_text(json.dumps({'protocol': SCHEMA, 'state': 'incomplete',
            'reason': str(exc), 'publication_authorized': False, 'installer_executed': False}, indent=2) + '\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--python', required=True)
    parser.add_argument('--standalone', required=True)
    parser.add_argument('--standalone-archive', required=True)
    parser.add_argument('--format', action='append', choices=['pkg', 'sh'], required=True)
    parser.add_argument('--privacy-policy')
    parser.add_argument('--supplemental', action='store_true')
    args = parser.parse_args()
    result = assemble(args.cohort, args.output, interpreter=args.python, standalone=args.standalone,
                      standalone_archive=args.standalone_archive, formats=args.format,
                      privacy_policy=args.privacy_policy, supplemental=args.supplemental)
    print(json.dumps({'state': result['state'], 'cohort_digest': result['cohort_digest'],
                      'formats': [r['format'] for r in result['wrappers']], 'publication_authorized': False}))


if __name__ == '__main__':
    main()
