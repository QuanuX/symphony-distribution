#!/usr/bin/env python3
"""Run the real three local native installers without claiming source attestation.

This gate accepts explicitly selected local binaries for functional qualification.
It never fabricates artifact-build-identity metadata or approves distribution.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess

import go_delivery as d


def run(binaries, output):
    d.require(os.geteuid() != 0 and platform.system() == 'Darwin' and platform.machine() == 'x86_64',
              'this bounded local fixture requires the current macOS Intel user host')
    selected = {}
    for component in sorted(d.owners.SERVICE_IDS):
        unit = d.owners.OWNERS[component]
        data, mode = d.regular(Path(binaries) / unit['binary_name'], executable=True, limit=d.MAX_BINARY)
        d.require(mode == 0o755, 'local owner executable mode differs')
        selected[component] = data
    out = d.Output(output, [binaries])
    rows = []
    try:
        for component, data in selected.items():
            unit = d.owners.OWNERS[component]
            out.write(component + '/retained/' + unit['binary_name'], data, 0o755)
            component_root = out.path / component
            prefix = component_root / 'installation'
            home = component_root / 'private-home'
            prefix.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            sentinel = prefix / 'unowned-user-data'
            sentinel.write_text('preserve\n')
            executable = component_root / 'retained' / unit['binary_name']
            argv = d.owners.install_argv(component, executable, prefix)
            out.document(component + '/intent.json', {'argv': argv, 'automatic_retry': False, 'source_attestation': False})
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home), 'TMPDIR': str(home),
                   'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_STATE_HOME': str(home / 'state'), 'XDG_RUNTIME_DIR': str(home / 'runtime')}
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    cwd=component_root, env=env, timeout=120, check=False)
            out.write(component + '/owner.log', result.stdout or b'(empty output)\n')
            d.require(result.returncode == 0, 'local native owner failed; preserve evidence without retry')
            manifest = {'profile': d.owners.FIXTURE_PROFILE, 'files': [d.file_record(unit['binary_name'], data, 0o755)]}
            evidence = d.verify_receipt(prefix, manifest, unit)
            d.require(sentinel.read_text() == 'preserve\n', 'native install changed unrelated user data')
            # Explicit portable export has exactly these two paths. This is
            # never a copy of the installed tree with its inode-bound guards.
            for field in ('binary_relative', 'receipt_relative'):
                relative = evidence[field]
                payload, mode = d.regular(prefix / relative, limit=d.MAX_BINARY)
                out.write(component + '/portable-payload/' + relative, payload, mode)
            d.verify_receipt(component_root / 'portable-payload', manifest, unit)
            files = [str(p.relative_to(component_root / 'portable-payload')) for p in (component_root / 'portable-payload').rglob('*') if p.is_file()]
            d.require(set(files) == {evidence['binary_relative'], evidence['receipt_relative']}, 'unexpected portable export')
            rows.append({'component_id': component, 'binary_sha256': d.sha(data), **evidence,
                         'native_owner_exit_code': result.returncode, 'independent_receipt_verified': True,
                         'unrelated_data_preserved': True, 'portable_export_file_count': len(files), 'local_guard_exported': False})
        record = {'protocol': 'symphony.distribution.native-owner-local-fixture.v1', 'profile': d.owners.FIXTURE_PROFILE,
                  'owners': rows, 'source_attestation_verified': False, 'carrier_identity_fixture': False,
                  'runtime_activation_changed': False, 'host_services_changed': False,
                  'physical_beta_platform_accepted': False, 'publication_authorized': False}
        out.document('result.json', record)
        return record
    finally:
        out.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binaries', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        print(json.dumps(run(a.binaries, a.output), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        p.exit(2, 'REFUSED: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
