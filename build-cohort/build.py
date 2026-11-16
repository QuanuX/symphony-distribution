#!/usr/bin/env python3
"""Build the frozen native/Go cohort into private, relocated qualification stages.

Never installs into an existing prefix, changes source, activates a service, or
publishes. A completed build is not supported-host or distribution acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile

import plan as cohort_plan
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification.native_campaign import bounded_run


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def safe_path(path):
    path = Path(os.path.abspath(path))
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink path refused')
    return path


def fresh(path, inputs):
    path = safe_path(path)
    require(not path.exists(), 'output must be a new private directory')
    for value in inputs:
        value = Path(value).resolve()
        require(path != value and value not in path.parents and path not in value.parents,
                'output must be disjoint from all inputs')
    path.mkdir(mode=0o700)
    return path


def load_exporter():
    sys.path.insert(0, str(ROOT / 'source-export'))
    import export_source
    return export_source


def source_tree(repository, output, export=None, policy=None):
    source = output / 'source'
    if export:
        require(policy is not None, 'reviewed export requires its private policy')
        exporter = load_exporter()
        exporter.configure_policy(policy)
        proof = exporter.verify(export, repository)
        shutil.copytree(export / 'source', source, symlinks=False)
        return source, {'kind': 'verified_reviewed_derived_export', **proof}
    require(policy is None, 'private policy requires an explicit reviewed export')
    archive = output / 'committed-source.tar'
    with archive.open('xb') as stream:
        subprocess.run(['git', '--no-replace-objects', '-C', str(repository), 'archive',
                        '--format=tar', cohort_plan.read_json((ROOT/'source-binding.json').read_bytes())['source_commit']],
                       check=True, stdout=stream)
    source.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and
                    (member.isfile() or member.isdir()), 'nonregular or unsafe source archive entry')
        tar.extractall(source, filter='data')
    return source, {'kind': 'exact_committed_source_archive', 'archive_sha256': sha(archive),
                    'reviewed_source_export_privacy_approved': False}


def selected_host(profile, contract, supplemental):
    system = platform.system()
    arch = {'x86_64':'amd64', 'aarch64':'arm64', 'arm64':'arm64'}.get(platform.machine())
    require(system in ('Darwin', 'Linux') and arch is not None, 'native Unix target required')
    os_name = 'macos' if system == 'Darwin' else 'linux'
    release = platform.mac_ver()[0] if system == 'Darwin' else platform.freedesktop_os_release().get('VERSION_ID')
    if not supplemental:
        require(os_name == contract['os'] and arch == contract['architecture'] and
                (release.split('.')[0] == contract['os_release'] if system == 'Darwin'
                 else release == contract['os_release']), 'actual host differs from selected primary profile')
    else:
        require(os_name == contract['os'], 'supplemental host must use the same operating-system family')
    return {'requested_profile': profile, 'os': os_name, 'architecture': arch,
            'os_release': release, 'kernel': platform.release(),
            'scope': 'supplemental_local_build' if supplemental else 'native_profile_build',
            'primary_profile_accepted': False, 'fresh_host_accepted': False}


def clean_environment(work, go, gomodcache, cc, cxx):
    for name in ('home', 'tmp'):
        (work/name).mkdir(mode=0o700)
    paths = [str(go.parent), str(cc.parent), str(cxx.parent), '/usr/bin', '/bin', '/usr/sbin', '/sbin']
    env = {'PATH': ':'.join(dict.fromkeys(paths)), 'HOME':str(work/'home'), 'TMPDIR':str(work/'tmp'),
           'LANG':'C', 'LC_ALL':'C', 'ZERO_AR_DATE':'1', 'SOURCE_DATE_EPOCH':'0', 'GOTOOLCHAIN':'local', 'GOWORK':'off', 'GOENV':'off',
           'GOTELEMETRY':'off', 'GOPROXY':'off', 'GOSUMDB':'off', 'GOAUTH':'off',
           'GOVCS':'*:off', 'GOPRIVATE':'', 'GONOPROXY':'', 'GONOSUMDB':'', 'GOINSECURE':'',
           'GOMODCACHE':str(gomodcache), 'GOCACHE':str(work/'go-cache'), 'GOPATH':str(work/'go-path'),
           'CGO_ENABLED':'0', 'CC':str(cc), 'CXX':str(cxx), 'SYMPHONY_CODESIGN_IDENTITY':'-',
           'XDG_CONFIG_HOME':str(work/'home/config'), 'XDG_STATE_HOME':str(work/'home/state')}
    return env


class Runner:
    def __init__(self, work, env, timeout):
        self.work, self.env, self.timeout = work, env, timeout
        (work/'logs').mkdir()
        self.logs = []
    def run(self, name, command, cwd=None):
        path = self.work/'logs'/(name+'.log')
        with path.open('x') as stream:
            status = bounded_run([str(x) for x in command], cwd=cwd or self.work, env=self.env,
                                 stdout=stream, stderr=subprocess.STDOUT, timeout=self.timeout)
        self.logs.append({'name':path.name, 'sha256':sha(path), 'exit_code':status})
        require(status == 0, 'step failed: ' + name + '; private log retained')
        return path


def verify_archive_metadata(data):
    require(not data.startswith(b'!<thin>\n'), 'thin SDK archive retains external build objects')
    if not data.startswith(b'!<arch>\n'):
        return
    offset=8
    while offset<len(data):
        header=data[offset:offset+60]
        require(len(header)==60 and header[58:60]==b'`\n', 'invalid static archive member')
        for value in (header[16:28],header[28:34],header[34:40]):
            require(value.strip() in (b'',b'0'), 'static SDK archive retains builder identity or timestamp')
        size=header[48:58].strip()
        require(size.isdigit(), 'invalid static archive size')
        size=int(size);offset+=60+size+(size%2)
        require(offset<=len(data), 'truncated static archive')


def snapshot(prefix, privacy=None, forbidden=()):
    result = []
    for path in sorted(prefix.rglob('*')):
        relative = path.relative_to(prefix).as_posix()
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(prefix), 'payload symlink escapes candidate')
            result.append({'path':relative, 'link':os.readlink(path)})
        elif path.is_file():
            data = path.read_bytes()
            verify_archive_metadata(data)
            require(not any(str(p).encode() in data for p in forbidden),
                    'private build path retained in final file: '+relative)
            require(b'/Users/' not in data and b'/home/runner/' not in data and b'/opt/homebrew/' not in data,
                    'developer/runner path retained in final file: '+relative)
            if privacy:
                privacy.scan(relative, data)
            result.append({'path':relative, 'sha256':hashlib.sha256(data).hexdigest(),
                           'size':len(data), 'mode':path.stat().st_mode & 0o777})
    return result


def verify_receipts(prefix, units):
    rows, owned = [], set()
    for unit in units:
        path = prefix/'share/symphony/receipts'/unit['component_id']/unit['version']/'install-receipt.json'
        safe_path(path)
        data = cohort_plan.read_json(path.read_bytes())
        claimed = data.pop('receipt_digest')
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        require(claimed == 'sha256:'+hashlib.sha256(canonical).hexdigest(), 'receipt canonical hash differs')
        require(data['component_id'] == unit['component_id'] and data['version'] == unit['version'],
                'receipt identity differs')
        for item in data['files']:
            relative = cohort_plan.relative(item['path'])
            file = safe_path(prefix/relative)
            require(file.is_file() and not file.is_symlink() and relative not in owned,
                    'receipt path missing, aliased or multiply owned')
            require(item['digest'] == 'sha256:'+sha(file) and item['size'] == file.stat().st_size,
                    'receipt bytes differ')
            owned.add(relative)
        rows.append({'component_id':unit['component_id'], 'version':unit['version'],
                     'receipt_sha256':sha(path), 'owned_file_count':len(data['files'])})
    return rows


def build_round(args, source, plan, root, external):
    work = root
    work.mkdir(mode=0o700)
    env = clean_environment(work, args.go, args.gomodcache, args.cc, args.cxx)
    if args.developer_dir:env['DEVELOPER_DIR']=str(args.developer_dir)
    runner = Runner(work, env, args.timeout)
    stage = work/'stage'; stage.mkdir()
    shutil.copytree(external, stage/'third-party', symlinks=True)
    env.update(SYMPHONY_D06_EXTERNAL_PREFIX=str(external), SYMPHONY_D06_STAGE_EXTERNAL=str(stage/'third-party'),
               SYMPHONY_D06_PYTHON=sys.executable)
    # All build executables are caller-selected. No CMake user/package registry.
    env['PATH'] = str(args.cmake.parent) + ':' + env['PATH']
    system = platform.system()
    flags = f'"-ffile-prefix-map={source}=/symphony-source" "-fdebug-prefix-map={work}=/symphony-build"'
    base = [f'-DCMAKE_INSTALL_PREFIX={stage}', f'-DCMAKE_PREFIX_PATH={stage};{stage}/third-party',
            '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
            '-DCMAKE_INSTALL_LIBDIR=lib', '-DBUILD_TESTING=OFF', '-DSYMPHONY_KVE_BUILD_TESTING=OFF',
            '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
            '-DCMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY=ON', '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON',
            '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF',
            '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
            '-DCMAKE_INSTALL_RPATH_USE_LINK_PATH=OFF', '-DCMAKE_INSTALL_RPATH=',
            '-DCMAKE_INSTALL_NAME_DIR=@rpath', f'-DCMAKE_C_COMPILER={args.cc}', f'-DCMAKE_CXX_COMPILER={args.cxx}',
            f'-DCMAKE_C_FLAGS={flags}', f'-DCMAKE_CXX_FLAGS={flags}',
            f'-DSYMPHONY_PACKAGE_FINALIZER={Path(__file__).with_name("FinalizeNative.cmake")}',
            f'-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={source}/tests/mvp-dependencies/prove-imports.cmake',
            f'-DMVP_SELECTED_PREFIX={stage}', f'-DMVP_EXTERNAL_PREFIX={stage}/third-party',
            f'-DMVP_REPOSITORY={source}']
    if system == 'Darwin':
        base += ['-DCMAKE_EXE_LINKER_FLAGS=-Wl,-headerpad_max_install_names', '-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-headerpad_max_install_names']
        if not args.supplemental:base += ['-DCMAKE_OSX_DEPLOYMENT_TARGET=15.0']
    units = plan['profiles'][args.profile]['native_build_order']
    source_map = json.loads((source/'cmake/mvp-dependencies.json').read_text())
    originals = {r['component_id']:r for r in source_map['native_components']}
    metadata = work/'metadata';metadata.mkdir()
    built = []
    for index, unit in enumerate(units):
        cid = unit['component_id']; build = work/'build'/cid
        record = metadata/(cid+'.json');dump(record, originals[cid])
        options = [f'-D{k}={v}' for k,v in unit['installed_options'].items()]
        print(f'Native {index+1}/{len(units)}: {cid}', flush=True)
        runner.run(cid+'-configure', [args.cmake, '-S', source/unit['source_root'], '-B', build,
                   *base, *options, f'-DMVP_COMPONENT_FILE={record}',
                   f'-DMVP_PROOF_LOG={work}/logs/{cid}-imports.txt'])
        runner.run(cid+'-build', [args.cmake, '--build', build, '--parallel', str(args.jobs)])
        runner.run(cid+'-install', [args.cmake, f'-DSYMPHONY_PACKAGE_STAGE_ROOT={stage}', '-P', build/'cmake_install.cmake'])
        runner.run(cid+'-receipt', [args.cmake, f'-DMVP_REPOSITORY={source}', f'-DMVP_COMPONENT_FILE={record}',
                   f'-DMVP_SELECTED_PREFIX={stage}', '-P', source/'tests/mvp-dependencies/verify-receipt.cmake'])
        for item in json.loads((stage/'share/symphony/receipts'/cid/unit['version']/'install-receipt.json').read_text())['files']:
            if item['path'].endswith('.a'):verify_archive_metadata((stage/item['path']).read_bytes())
        built.append(cid)
        dump(work/'progress.json', {'completed_native':built, 'expected_native':len(units), 'acceptance':False})
        if args.prune_builds:
            # Only this fresh invocation's completed build subtree, after receipt proof.
            require(build.parent == work/'build' and not build.is_symlink(), 'build cleanup custody differs')
            shutil.rmtree(build)
    go_results = []
    for unit in plan['profiles'][args.profile]['go_commands']:
        cid=unit['component_id']; module=source/unit['source_root']
        path=stage/'go'/cid/'bin'/unit['binary_name'];path.parent.mkdir(parents=True)
        flags='-buildid='
        if unit['version_symbol']:flags+=' -X '+unit['version_symbol']+'='+unit['package_version']
        listing=runner.run(cid+'-go-closure',[args.go,'list','-mod=readonly','-m','-f','{{if .Replace}}{{.Path}}{{end}}','all'],module)
        require(not listing.read_text().strip(), 'workspace/replacement module refused')
        runner.run(cid+'-go-verify',[args.go,'mod','verify'],module)
        runner.run(cid+'-go-build',[args.go,'build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags='+flags,
                                   '-o',path,unit['main_package']],module)
        version=runner.run(cid+'-go-version',[path,'--version']).read_text().strip()
        require(version == unit['version_output_prefix']+unit['package_version'], 'Go compiled version differs')
        go_results.append({'component_id':cid,'version':unit['package_version'],'sha256':sha(path)})
    runner.run('external-finalization',[sys.executable,Path(__file__).with_name('finalize_native.py'),
                '--root',stage,'--external','--evidence',work/'external-finalization.json'])
    from loader_audit import audit as loader_audit
    loader_proof=loader_audit(stage)
    dump(work/'loader-audit.json',loader_proof)
    receipt_proof=verify_receipts(stage,units)
    # Relocation, not a duplicate prefix with the original still usable.
    relocated=work/'relocated-prefix';stage.rename(relocated)
    from sdk_audit import run_audit
    sdk=run_audit(source,relocated,work/'sdk-audit',cmake=str(args.cmake),cxx=str(args.cxx),
                  components=[u['component_id'] for u in units],external_prefix=relocated/'third-party',timeout=args.timeout,
                  developer_dir=args.developer_dir)
    from owner_audit import run_owner_audit
    owner=run_owner_audit(source,relocated,work/'owner-audit',go=args.go,
                          gomodcache=args.gomodcache,timeout=args.timeout,env=env)
    require(verify_receipts(relocated,units)==receipt_proof,'SDK/owner audit changed sealed payload')
    exporter=load_exporter() if args.export else None
    inventory=snapshot(relocated,exporter,forbidden=(source,work,args.repository,external))
    result={'state':'built_and_sdk_checked','native_count':len(built),'native_receipts':receipt_proof,
            'go_commands':go_results,'sdk_audit':sdk,'installed_owner_audit':owner,'loader_audit':loader_proof,'payload_inventory':inventory,
            'logs':runner.logs,'build_cache_fresh':True,'private_home':True,
            'installed_stage_relocated':True,'external_payload_ownership':'separate_distribution_build_inventory_not_native_receipt',
            'native_live_owner_acceptance':False,'publication_authorized':False}
    dump(work/'result.json',result)
    return result


def run(args):
    for name in ('repository','gomodcache','external_prefix'):
        setattr(args,name,Path(getattr(args,name)).resolve(strict=True))
    for name in ('cmake','cc','cxx','go'):
        value=Path(os.path.abspath(getattr(args,name)))
        require(value.is_file() and os.access(value,os.X_OK),'selected tool absent or not executable')
        setattr(args,name,value)
    from external import inventory as external_inventory
    external_report=cohort_plan.read_json((args.external_prefix.parent/'external-build.json').read_bytes())
    require(external_report['status']=='built_and_scanned' and
            external_report['inventory']==external_inventory(args.external_prefix,()),
            'external dependency evidence or exact bytes differ')
    if args.developer_dir:
        args.developer_dir=Path(args.developer_dir).resolve(strict=True)
        require(platform.system()=='Darwin' and args.developer_dir.is_dir(),'explicit Apple developer directory required')
    if args.export:args.export=Path(args.export).resolve(strict=True)
    if args.privacy_policy:args.privacy_policy=Path(args.privacy_policy).resolve(strict=True)
    binding=cohort_plan.read_json((ROOT/'source-binding.json').read_bytes())
    plan=cohort_plan.read_json(Path(__file__).with_name('cohort.json').read_bytes())
    cohort_plan.validate(plan,args.repository,binding)
    host=selected_host(args.profile,plan['profiles'][args.profile]['platform_contract'],args.supplemental)
    observed=subprocess.check_output([args.go,'env','GOVERSION','GOHOSTOS','GOHOSTARCH'],
                                    env={'PATH':'/usr/bin:/bin','GOTOOLCHAIN':'local','GOENV':'off','GOWORK':'off'},text=True).splitlines()
    require(observed==['go1.26.5','darwin' if host['os']=='macos' else 'linux',host['architecture']],
            'exact native Go1.26.5 toolchain required')
    protected=[args.repository,args.external_prefix,args.gomodcache,args.go,ROOT]
    if args.export:protected.append(args.export)
    if args.privacy_policy:protected.append(args.privacy_policy)
    out=fresh(args.output,protected)
    args.owned_output=out;args.output_identity=(out.stat().st_dev,out.stat().st_ino)
    source,provenance=source_tree(args.repository,out,args.export,args.privacy_policy)
    result={'protocol':'symphony.distribution.clean-cohort.v1','source_commit':plan['source_commit'],
            'source_tree':plan['source_tree'],'plan_sha256':sha(Path(__file__).with_name('cohort.json')),
            'builder_sha256':sha(__file__),'build_helpers':{p.name:sha(p) for p in sorted(Path(__file__).parent.iterdir()) if p.suffix in ('.py','.cmake') and not p.name.startswith('test_')},'imported_helpers':{str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'qualification/native_campaign.py',ROOT/'source-export/export_source.py')},'external_evidence_sha256':sha(args.external_prefix.parent/'external-build.json'),'host':host,'source_input':provenance,'state':'building',
            'acceptance_complete':False,'publication_authorized':False,'rounds':[]}
    dump(out/'result.json',result)
    for index in range(2 if args.repeat else 1):
        round_result=build_round(args,source,plan,out/f'round-{index+1}',args.external_prefix)
        result['rounds'].append({'directory':f'round-{index+1}','result_sha256':sha(out/f'round-{index+1}/result.json'),
                                 'native_count':round_result['native_count'],'go_count':len(round_result['go_commands'])})
        if index == 0:first=round_result
        else:
            require(first['payload_inventory']==round_result['payload_inventory'],'repeated final payload bytes differ')
        dump(out/'result.json',result)
    result.update(state='built_and_sdk_checked',repeated_payload_bytes_equal=args.repeat,
                  blockers=['native supported-profile/fresh-host acceptance remains separate',
                            'external runtime ownership must be integrated into distribution carrier closure',
                            'live owner removal and whole-profile gates remain in the dossier',
                            'publisher signing, final delivery and independent review remain open'])
    cohort_plan.validate(plan,args.repository,binding)
    require(result['build_helpers']=={p.name:sha(p) for p in sorted(Path(__file__).parent.iterdir()) if p.suffix in ('.py','.cmake') and not p.name.startswith('test_')},'build helper changed during run')
    require(all(sha(ROOT/p)==h for p,h in result['imported_helpers'].items()),'imported helper changed during run')
    dump(out/'result.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('repository','output','cmake','cc','cxx','go','gomodcache','external-prefix'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',choices=cohort_plan.PROFILES,required=True)
    p.add_argument('--developer-dir',type=Path);p.add_argument('--export',type=Path);p.add_argument('--privacy-policy',type=Path)
    p.add_argument('--supplemental',action='store_true');p.add_argument('--repeat',action='store_true')
    p.add_argument('--prune-builds',action='store_true',help='remove only this run completed build dirs after receipt checks')
    p.add_argument('--jobs',type=int,default=2);p.add_argument('--timeout',type=int,default=900)
    a=p.parse_args()
    try:
        require(a.jobs in range(1,17) and 1<=a.timeout<=7200,'invalid bounded build controls')
        result=run(a);print(json.dumps({'state':result['state'],'rounds':result['rounds'],'publication_authorized':False}))
    except BaseException as e:
        if hasattr(a,'owned_output'):
            out=a.owned_output
            if not out.is_symlink() and (out.stat().st_dev,out.stat().st_ino)==a.output_identity:
                dump(out/'INCOMPLETE.json',{'state':'incomplete','reason':str(e),'acceptance_complete':False})
        print(str(e),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
