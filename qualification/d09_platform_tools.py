#!/usr/bin/env python3
"""Prepare private, explicitly versioned review tools only on a hosted primary runner."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import d09_platform as gate

TARGETS = {
    'macos15-arm64': ('macos-15', 'osx-arm64', 'MacOSX-arm64', 'fb567612b76f4ef46de326f04425dbe381b6afc6a66c545f5043255a5ef34258'),
    'ubuntu24.04-amd64': ('ubuntu-24.04', 'linux-64', 'Linux-x86_64', 'bbaf16b3897da24c4be50315934ba74848f617b4495982841d6a0a60e0edbbdf'),
    'ubuntu24.04-arm64': ('ubuntu-24.04-arm', 'linux-aarch64', 'Linux-aarch64', '1adf18b530e4ffb00886ce6d5bd2eb1fa6311d2f14709b13bd154d8cd98d94c8'),
    'ubuntu26.04-amd64': ('ubuntu-26.04', 'linux-64', 'Linux-x86_64', 'bbaf16b3897da24c4be50315934ba74848f617b4495982841d6a0a60e0edbbdf'),
}


def download(url, destination, expected):
    gate.digest(expected)
    gate.require(url.startswith('https://') and not destination.exists(), 'Unsafe tool download selection')
    subprocess.run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
                    '--retry', '3', '--connect-timeout', '30', '--max-time', '600', url, '--output', str(destination)], check=True)
    gate.require(gate.sha(destination) == expected, 'Selected publisher tool archive differs')


def prepare(profile, output):
    gate.hosted_custody(profile, output, os.environ)
    root = gate.fresh(output, [gate.ROOT])
    _, subdir, asset, expected = TARGETS[profile]
    for name in ('home', 'tmp', 'downloads', 'pkgs', 'envs'):
        (root / name).mkdir(mode=0o700)
    condarc = root / 'home/condarc'
    condarc.write_text('channels: []\nreport_errors: false\nanaconda_upload: false\nauto_activate_base: false\nregister_envs: false\n')
    env = {'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
           'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'CONDARC': str(condarc), 'CONDA_REPORT_ERRORS': 'false',
           'CONDA_PKGS_DIRS': str(root / 'pkgs'), 'CONDA_ENVS_PATH': str(root / 'envs'),
           'CONDA_SUBDIR': subdir, 'CONDA_REGISTER_ENVS': 'false'}
    installer = root / 'downloads/miniforge.sh'
    download('https://github.com/conda-forge/miniforge/releases/download/26.9.4-2/Miniforge3-26.9.4-2-' + asset + '.sh', installer, expected)
    gate.invoke(['/bin/bash', installer, '-b', '-p', root / 'bootstrap'], env, root / 'bootstrap.log')
    conda = root / 'bootstrap/bin/conda'
    publisher = root / 'publisher'
    gate.invoke([conda, 'create', '--yes', '--override-channels', '--channel', 'conda-forge', '--prefix', publisher,
                 'python=3.12.16', 'conda=26.10.0', 'conda-build=26.9.1', 'conda-package-handling=2.6.0',
                 'constructor=3.17.3', 'pillow=13.0.0', 'conda-standalone=26.9.4.post1',
                 'conda-pycosat-solver=26.10.0'], env, root / 'publisher.log', timeout=1200)
    with (root / 'publisher.explicit.txt').open('xb') as stream:
        subprocess.run([str(conda), 'list', '--prefix', str(publisher), '--explicit', '--sha256'], env=env,
                       stdout=stream, stderr=subprocess.PIPE, check=True, timeout=90)
    pin = gate.read(gate.ROOT / 'installer_assembly/tool-lock.json')['standalone'][subdir]
    archive = root / 'downloads/standalone.conda'
    download(pin['url'], archive, pin['sha256'])
    record = {'protocol': 'symphony.distribution.d09-publisher-tools.v1', 'profile': profile,
              'bootstrap_archive_sha256': expected, 'standalone_archive_sha256': pin['sha256'],
              'resolved_tool_closure_sha256': gate.sha(root / 'publisher.explicit.txt'), 'helper_sha256': gate.sha(__file__),
              'resolved_transitive_closure_preapproved': False, 'publication_authorized': False}
    gate.write(root / 'result.json', record)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=gate.PROFILES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.profile, args.output)))
    except Exception as error:
        gate.failure_summary(args.output, error)
        raise
