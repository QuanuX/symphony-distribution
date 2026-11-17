#!/usr/bin/env python3
"""Build six non-qxctl commands from verified derived source, outside Git.

This is selected corresponding-source evidence, not a new candidate identity or
the qxctl two-build recipe. No service or application is activated.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import export_source as exporter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from qualification.native_campaign import bounded_run


def new_output(args):
    output=Path(os.path.abspath(args.output))
    exporter.require(not any(p.is_symlink() for p in (output,*output.parents)),
                     'output path must not contain symlinks')
    exporter.require(not output.exists(),'output must be new')
    protected=[args.export.resolve(),args.repository.resolve(),args.candidates.resolve(),
               args.gomodcache.resolve(),args.go.resolve().parent,args.privacy_policy.resolve()]
    exporter.require(all(output!=p and output not in p.parents and p not in output.parents for p in protected),
                     'output must be disjoint from source, candidates, tools and private inputs')
    output.mkdir(mode=0o700,exist_ok=False)
    held=output.stat()
    args.output=output
    args.owned_output_identity=(held.st_dev,held.st_ino)


def mark_incomplete(args):
    identity=getattr(args,'owned_output_identity',None)
    if identity is None:return
    try:
        path=args.output
        if any(p.is_symlink() for p in (path,*path.parents)):return
        held=path.stat()
        if (held.st_dev,held.st_ino)!=identity or held.st_uid!=os.geteuid() or held.st_mode&0o077:return
        fd=os.open(path/'INCOMPLETE',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:stream.write('Source build incomplete; not accepted.\n')
    except OSError:
        pass


def run(args):
    exporter.configure_policy(args.privacy_policy)
    verification=exporter.verify(args.export,args.repository)
    source=args.export.resolve()/'source'
    new_output(args)
    home=args.output/'home';home.mkdir(mode=0o700)
    env={key:os.environ[key] for key in ('PATH','TMPDIR','LANG') if key in os.environ}
    env.update(HOME=str(home),XDG_CONFIG_HOME=str(home/'config'),XDG_STATE_HOME=str(home/'state'),
               GOTOOLCHAIN='local',GOENV='off',GOWORK='off',GOPROXY='off',GOSUMDB='off',
               CGO_ENABLED='0',GOMODCACHE=str(args.gomodcache.resolve()),
               GOCACHE=str(args.output/'cache'),GOPATH=str(args.output/'gopath'),GOTELEMETRY='off')
    go=str(args.go.resolve())
    host=subprocess.check_output([go,'env','GOVERSION','GOHOSTOS','GOHOSTARCH'],env=env,text=True).splitlines()
    exporter.require(len(host)==3 and host[0]=='go1.26.5','exact source-build toolchain required')
    catalog=json.loads((source/'cmake/mvp-release-identities.json').read_text())
    selected=[row for row in catalog['go_artifacts'] if row['recipe']=='go-candidate']
    exporter.require(len(selected)==6,'six-command source contract differs')
    results=[]
    for row in selected:
        component=row['component_id'];work=args.output/component;work.mkdir(mode=0o700)
        module=source/row['path']
        identity_path=args.candidates/'identities'/(component+'.json')
        identity=json.loads(identity_path.read_text())
        expected=args.candidates/component/'bin'/row['binary_name']
        exporter.require(identity['source_commit']==exporter.EXPECTED_COMMIT and
                         identity['source_tree']==exporter.EXPECTED_TREE and
                         identity['goos']==host[1] and identity['goarch']==host[2] and
                         identity['version']==row['package_version'] and
                         identity['executable_sha256']==exporter.digest(expected.read_bytes()),
                         'comparison candidate source/host/bytes differ')
        flags='-buildid='
        if row['version_symbol']:flags+=' -X '+row['version_symbol']+'='+row['package_version']
        binary=work/row['binary_name']
        commands=[['list','-mod=readonly','-m','-f','{{if .Replace}}{{.Path}}{{end}}','all'],
                  ['mod','verify'],['build','-mod=readonly','-trimpath','-buildvcs=false',
                                   '-ldflags='+flags,'-o',str(binary),row['main_package']]]
        for index,command in enumerate(commands):
            with (work/(str(index)+'.log')).open('x') as log:
                code=bounded_run([go,*command],cwd=module,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
            exporter.require(code==0,'selected source build failed; private log retained')
        exporter.require(not (work/'0.log').read_text().strip(),'source build used module replacements')
        version=subprocess.check_output([str(binary),'--version'],env=env,text=True,timeout=10).strip()
        exporter.require(version==row['version_output_prefix']+row['package_version'],'compiled version differs')
        data=binary.read_bytes();exporter.scan(row['binary_name'],data)
        exporter.require(all(str(p).encode() not in data for p in (source,args.output,args.repository)),
                         'private build path leaked into binary')
        observed=exporter.digest(data)
        exporter.require(observed==identity['executable_sha256'],'derived-source binary differs from reviewed candidate')
        results.append({'component_id':component,'native_version':row['package_version'],
                        'executable_sha256':observed,'candidate_identity_sha256':exporter.digest(identity_path.read_bytes()),
                        'candidate_bytes_equal':True,'module_cache_verified':True,
                        'private_path_scan_passed':True,'version_output':version,
                        'logs':[{'name':p.name,'sha256':exporter.digest(p.read_bytes())} for p in sorted(work.glob('*.log'))]})
        print(component+': source build matches reviewed bytes',flush=True)
    exporter.verify(args.export,args.repository)
    result={'protocol':'symphony.distribution.derived-go-source-build.v1','status':'passed',
            'source_commit':exporter.EXPECTED_COMMIT,'source_tree':exporter.EXPECTED_TREE,
            'derived_export_digest':verification['export_digest'],
            'source_archive_sha256':verification['archive_sha256'],
            'recipe_sha256':exporter.digest(Path(__file__).read_bytes()),'toolchain':host[0],
            'os':host[1],'architecture':host[2],'fresh_build_cache':True,'private_build_home':True,
            'core_checkout_used_as_build_input':False,'source_replacements':False,
            'go_commands':results,'qxctl_rebuilt':False,'all_source_roots_build_tested':False,
            'host_acceptance':False,'release_acceptance_complete':False,'publication_authorized':False}
    (args.output/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('export','repository','privacy-policy','candidates','go','gomodcache','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:
        run(args)
    except BaseException:
        mark_incomplete(args)
        raise


if __name__=='__main__':main()
