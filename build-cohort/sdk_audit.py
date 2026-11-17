#!/usr/bin/env python3
"""Detached consumers of finalized native SDKs; no publisher or live-host claim.

The repository supplies only consumer examples, the dependency map, and the
existing import proof. All are copied before the first compiler invocation.
Every imported first-party header/library must then resolve under the selected
relocated payload. No build command is given a repository source path.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk_bounded', ROOT / 'qualification/native_campaign.py')
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def under(path, root):
    return path == root or root in path.parents


def cmake_quote(value):
    value = str(value)
    require(not any(c in value for c in ('\n', '\r', ';', '"', '$')), 'Unsupported CMake path metacharacter')
    return '"' + value.replace('\\', '/') + '"'


def safe_copy(source, destination, hashes):
    require(source.is_dir() and not source.is_symlink(), 'Consumer source must be a regular directory')
    for path in sorted(source.rglob('*')):
        require(not path.is_symlink(), 'Consumer source symlink refused')
        if path.is_file():
            relative = path.relative_to(source)
            require(not any(part in ('build', 'CMakeFiles', '.git') for part in relative.parts), 'Consumer contains build artifacts')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            hashes[str(relative)] = sha(target)
        else:
            require(path.is_dir(), 'Consumer special file refused')


def selected_components(mapping, components):
    selected = [c for c in mapping['native_components'] if c.get('exported_packages') and
                (components is None or c['component_id'] in components)]
    require(selected, 'No native SDK producers selected')
    if components is not None:
        known = {c['component_id'] for c in mapping['native_components']}
        require(not set(components) - known, 'Unknown native component selection')
    return selected


def consumer_metadata(selected, targets):
    return {'project_version': None, 'artifact_targets': targets,
            'first_party_sdk_dependencies': [
                {'target': target, 'scope': 'runtime'} for component in selected
                for export in component['exported_packages'] for target in export['targets']]}


def import_project(selected, prefix):
    lines = ['cmake_minimum_required(VERSION 3.30)', 'project(DetachedSdkImports LANGUAGES C CXX)']
    for component in selected:
        for package in component['exported_packages']:
            name = package['package']
            if package['cmake_version_file']:
                lines.append(f'find_package({name} {package["version"]} EXACT REQUIRED CONFIG PATHS {cmake_quote(prefix)} NO_DEFAULT_PATH)')
            else:
                exact = prefix / 'lib/cmake' / name / package['receipt_release']
                lines.append(f'find_package({name} REQUIRED CONFIG PATHS {cmake_quote(exact)} NO_DEFAULT_PATH)')
    # The complete imported-target proof runs even for interface-only SDKs.
    lines.extend(['add_executable(consumer main.cpp)', 'set_target_properties(consumer PROPERTIES CXX_STANDARD 26 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)'])
    return '\n'.join(lines) + '\n'


SNV_IDS = {'sniv-engine', 'snrv-engine', 'sciv-engine', 'scnv-engine', 'snv-engine', 'snv-local-observer'}
SNV_SMOKE = '''#include <stdexcept>
#include <symphony/snv/sniv.hpp>
#include <symphony/snv/snrv.hpp>
#include <symphony/snv/sciv.hpp>
#include <symphony/snv/scnv.hpp>
#include <symphony/snv/snv.hpp>
#include <symphony/snv/local_observer.hpp>
int main() {
  namespace s = symphony::snv;
  if (s::sniv::operations().empty() || s::snrv::operations().empty() ||
      s::sciv::operations().empty() || s::scnv::operations().empty() ||
      s::snv::operations().empty() || s::local_observer::operations().empty())
    throw std::runtime_error("installed SDK operation contract is empty");
  const auto observer = s::local_observer::descriptor();
  if (observer.at("engine_id") != "symphony-snv-local-observer")
    throw std::runtime_error("installed observer identity differs");
}
'''


def selected_tool(tool):
    # Compiler dispatch depends on argv[0]: resolving clang++ to clang silently
    # drops the C++ runtime from the final link on Linux.
    path = Path(os.path.abspath(shutil.which(str(tool)) or str(tool)))
    require(path.is_file() and os.access(path, os.X_OK), 'Selected tool must be executable')
    return str(path)


def run_audit(source, prefix, work, cmake='cmake', cxx='c++', components=None,
              external_prefix=None, timeout=300, developer_dir=None):
    source, prefix, work = (Path(p).resolve() for p in (source, prefix, work))
    require(source.is_dir() and prefix.is_dir(), 'Source and finalized prefix must exist')
    require(not work.exists() and not under(work, source) and not under(work, prefix), 'Audit work must be new and outside source/payload')
    for path in (source, prefix, work):
        cmake_quote(path)
    mapping = json.loads((source / 'cmake/mvp-dependencies.json').read_text())
    selected = selected_components(mapping, components)
    ids = {c['component_id'] for c in selected}
    work.mkdir(mode=0o700, parents=True)
    for name in ('home', 'tmp', 'logs', 'metadata', 'harness', 'consumers'):
        (work / name).mkdir(mode=0o700)
    harness = work / 'harness'
    for name in ('common.cmake', 'prove-imports.cmake'):
        shutil.copyfile(source / 'tests/mvp-dependencies' / name, harness / name)
    shutil.copyfile(source / 'cmake/mvp-dependencies.json', harness / 'mvp-dependencies.json')
    evidence = {'protocol': 'symphony.distribution.detached-sdk-audit.v1',
                'status': 'incomplete', 'scope': 'relocated installed SDK import, compile, link and API smoke',
                'source_map_sha256': sha(harness / 'mvp-dependencies.json'),
                'harness_sha256': {name: sha(harness / name) for name in ('common.cmake', 'prove-imports.cmake')},
                'selected_sdk_producers': sorted(ids), 'checks': [],
                'runtime_provider_qualification': False, 'fresh_host_acceptance': False,
                'publisher_trust_acceptance': False}
    evidence_path = work / 'sdk-audit.json'
    def save():
        evidence_path.write_text(json.dumps(evidence, indent=2) + '\n')
    save()
    cmake, cxx = (selected_tool(tool) for tool in (cmake, cxx))
    require(Path(cmake).is_file() and Path(cxx).is_file(), 'Explicit selected compiler and CMake must exist')
    env = {'PATH': os.pathsep.join(dict.fromkeys([str(Path(cmake).parent), str(Path(cxx).parent),
                                                '/usr/bin', '/bin', '/usr/sbin', '/sbin']))}
    if developer_dir:
        require(Path(developer_dir).is_dir(), 'Selected Apple developer directory is absent')
        env['DEVELOPER_DIR'] = str(Path(developer_dir).resolve())
    env.update(HOME=str(work / 'home'), TMPDIR=str(work / 'tmp'))
    if external_prefix is not None:
        external_prefix = Path(external_prefix).resolve()
        require(external_prefix.is_dir(), 'External SDK prefix is absent')
        cmake_quote(external_prefix)
        env['CMAKE_PREFIX_PATH'] = str(external_prefix)
    common = [str(cmake), '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
              f'-DCMAKE_CXX_COMPILER={cxx}', f'-DCMAKE_PREFIX_PATH={prefix}',
              '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
              '-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON', '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON',
              f'-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={harness}/prove-imports.cmake',
              f'-DMVP_REPOSITORY={harness}', f'-DMVP_MAP={harness}/mvp-dependencies.json',
              f'-DMVP_SELECTED_PREFIX={prefix}']
    if external_prefix is not None:
        common += [f'-DMVP_EXTERNAL_PREFIX={external_prefix}']
    def run(label, argv):
        log = work / 'logs' / (label + '.log')
        with log.open('wb') as stream:
            code = bounded.bounded_run([str(x) for x in argv], cwd=work / 'tmp', env=env,
                                       stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        evidence['checks'].append({'name': label, 'exit_code': code, 'log_sha256': sha(log)})
        save()
        require(code == 0, f'Detached SDK {label} failed; retained log: {log}')
    def consumer(label, selected_for_proof, copied_from=None, text=None, main='int main() {}\n',
                 targets=None, extra=(), execute=None):
        directory = work / 'consumers' / label
        hashes = {}
        if copied_from:
            safe_copy(copied_from, directory, hashes)
        else:
            directory.mkdir()
            (directory / 'CMakeLists.txt').write_text(text)
            (directory / 'main.cpp').write_text(main)
            hashes = {p.name: sha(p) for p in directory.iterdir()}
        evidence.setdefault('consumer_sources', {})[label] = hashes
        metadata = work / 'metadata' / (label + '.json')
        metadata.write_text(json.dumps(consumer_metadata(selected_for_proof, targets or ['consumer'])) + '\n')
        run(label + '-configure', common + ['-S', directory, '-B', directory / 'build',
            f'-DMVP_COMPONENT_FILE={metadata}', f'-DMVP_PROOF_LOG={work}/logs/{label}-imports.log', *extra])
        run(label + '-build', [cmake, '--build', directory / 'build', '--parallel', '2'])
        if execute:
            execute(directory)
        else:
            run(label + '-run', [directory / 'build/consumer'])
    try:
        consumer('all-imports', selected, text=import_project(selected, prefix))
        for component in selected:
            for entry in component.get('installed_sdk_consumer_checks', []):
                if entry['path'].endswith('/tests/sdk-consumer/CMakeLists.txt'):
                    consumer(component['component_id'], [component], copied_from=(source / entry['path']).parent)
        if 'knowledge-vector-engine-cpp' in ids:
            owners = [c for c in selected if c['component_id'] in {'knowledge-vector-engine-cpp', 'snv-common-cpp'}]
            consumer('mechanics', owners, copied_from=source / 'tests/native-sdk-distribution/mechanics',
                     extra=['-DSDK_INCLUDE_SNV_COMMON=' + ('ON' if 'snv-common-cpp' in ids else 'OFF')])
        if SNV_IDS <= ids:
            owners = [c for c in selected if c['component_id'] in SNV_IDS]
            text = import_project(owners, prefix) + 'target_link_libraries(consumer PRIVATE ' + ' '.join(
                target for c in owners for p in c['exported_packages'] for target in p['targets']) + ')\n'
            consumer('snv-api-smoke', owners, text=text, main=SNV_SMOKE)
        if 'sbv-engine' in ids:
            owners = [c for c in selected if c['component_id'] == 'sbv-engine']
            targets = ['sbv-installed-c-consumer', 'sbv-installed-cpp-consumer', 'sbv-installed-provider-abi', 'sbv-installed-interop']
            ctest = str(Path(cmake).parent / 'ctest') if Path(cmake).is_absolute() else 'ctest'
            consumer('sbv-abi', owners, copied_from=source / 'tests/mvp-dependencies/sbv-consumer',
                     targets=targets, extra=[f'-DSBV_PREFIX={prefix}', '-DBUILD_TESTING=ON'],
                     execute=lambda d: run('sbv-abi-ctest', [ctest, '--test-dir', d / 'build', '--output-on-failure', '--no-tests=error']))
        evidence['status'] = 'passed'
        save()
        return evidence
    except BaseException:
        save()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--cmake', default='cmake')
    parser.add_argument('--cxx', default='c++')
    parser.add_argument('--component', action='append')
    parser.add_argument('--external-prefix')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--developer-dir')
    args = parser.parse_args()
    require(0 < args.timeout <= 3600, 'Timeout must be bounded between 1 and 3600 seconds')
    result = run_audit(args.source, args.prefix, args.work, args.cmake, args.cxx,
                       args.component, args.external_prefix, args.timeout, args.developer_dir)
    print(json.dumps({'status': result['status'], 'sdk_producers': len(result['selected_sdk_producers'])}))


if __name__ == '__main__':
    main()
