#!/usr/bin/env python3
"""Read-only, identity-minimized S07 host inventory; never host acceptance."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


PROFILES = {
    'macos15-arm64': ('darwin', 'arm64', 'macos', '15'),
    'ubuntu24.04-amd64': ('linux', 'amd64', 'ubuntu', '24.04'),
    'ubuntu24.04-arm64': ('linux', 'arm64', 'ubuntu', '24.04'),
    'ubuntu26.04-amd64': ('linux', 'amd64', 'ubuntu', '26.04'),
    'local-macos-amd64-fixture': ('darwin', 'amd64', 'macos', None),
}


def os_release(path=Path('/etc/os-release')):
    """Read only distribution/version fields; never source shell content."""
    found = {}
    try:
        for line in path.read_text().splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ('ID', 'VERSION_ID'):
                found[key] = value.strip().strip('\"\'')
    except (OSError, UnicodeError):
        pass
    return found


def observe_host():
    host = os.uname()
    system = host.sysname.lower()
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(host.machine, 'unknown')
    distribution, version = 'unknown', 'unknown'
    if system == 'darwin':
        distribution = 'macos'
        try:
            result = subprocess.run(['/usr/bin/sw_vers', '-productVersion'], capture_output=True,
                                    text=True, timeout=5, check=False)
            candidate = result.stdout.strip()
            if result.returncode == 0 and candidate and all(c.isdigit() or c == '.' for c in candidate):
                version = candidate
        except (OSError, subprocess.TimeoutExpired):
            pass
    elif system == 'linux':
        release = os_release()
        distribution = release.get('ID', 'unknown')
        version = release.get('VERSION_ID', 'unknown')
    return {'system': system, 'architecture': architecture, 'distribution': distribution,
            'version': version, 'wsl': 'microsoft' in host.release.lower()}


def profile_matches(profile, host):
    system, architecture, distribution, version = PROFILES[profile]
    observed = (host['system'], host['architecture'], host['distribution'])
    version_match = version is None or host['version'] == version or (
        system == 'darwin' and host['version'].startswith(version + '.'))
    return observed == (system, architecture, distribution) and version_match and not host['wsl']


def probe(argv):
    """Discard raw manager output, which can contain unrelated user identities."""
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5, check=False)
        return {'state': 'accessible' if result.returncode == 0 else 'inaccessible',
                'exit_code': result.returncode}
    except subprocess.TimeoutExpired:
        return {'state': 'timeout', 'exit_code': None}
    except OSError:
        return {'state': 'inaccessible', 'exit_code': None}


def manager_inventory(host):
    system = host['system']
    if system == 'darwin':
        executable = shutil.which('launchctl')
        scopes = [('user', 'user/' + str(os.getuid())), ('gui', 'gui/' + str(os.getuid())), ('system', 'system')]
        commands = [(scope, [executable, 'print', domain]) for scope, domain in scopes]
        manager = 'launchd'
    elif system == 'linux':
        executable = shutil.which('systemctl')
        commands = [('user', [executable, '--user', 'show', '--property=Version', '--value']),
                    ('system', [executable, 'show', '--property=Version', '--value'])]
        manager = 'systemd'
    else:
        return {'manager': 'unsupported', 'scopes': [], 'availability': 'incomplete',
                'acceptance': 'not_run', 'activation_performed': False}
    results = [{'scope': scope, **(probe(argv) if executable else {'state': 'missing', 'exit_code': None})}
               for scope, argv in commands]
    return {'manager': manager, 'scopes': results,
            'availability': 'observed' if all(row['state'] == 'accessible' for row in results) else 'incomplete',
            'acceptance': 'not_run', 'activation_performed': False}


def profile_inventory(profile):
    host = observe_host()
    return {'protocol': 'symphony.distribution.platform-inventory.v1',
            'requested_profile': profile, 'observed_host': host,
            'profile_matches': profile_matches(profile, host),
            'evidence_level': 'E1_host_inventory_only',
            'supplemental': profile == 'local-macos-amd64-fixture',
            'service_manager': manager_inventory(host),
            'fresh_host_acceptance': 'incomplete', 'publisher_acceptance': 'not_run',
            'host_activation_performed': False, 'system_provisioning_performed': False,
            'physical_hardware_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, choices=sorted(PROFILES))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = profile_inventory(args.profile)
    # Exclusive creation prevents a prior host's evidence being silently replaced.
    with args.output.open('x') as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write('\n')
    print(json.dumps({'profile_matches': report['profile_matches'],
                      'manager_availability': report['service_manager']['availability'],
                      'fresh_host_acceptance': report['fresh_host_acceptance']}))
    return 0 if report['profile_matches'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
