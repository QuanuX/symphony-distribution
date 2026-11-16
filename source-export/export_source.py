#!/usr/bin/env python3
"""Export immutable Git blobs, sanitize documented metadata, refuse unknown contamination.

This is an external distribution preparation tool, not a product installer.
It does not modify the repository, generate user state, or authorize release.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parents[1]
BINDING=json.loads((ROOT/'source-binding.json').read_text())
EXPECTED_COMMIT=BINDING['source_commit']
EXPECTED_TREE=BINDING['source_tree']
SOURCE_MAP='cmake/mvp-dependencies.json'
PRIVATE_MARKERS=[b'SYMPHONY_PRIVATE_CANARY_']
ATTRIBUTIONS={}
POLICY_DIGEST=None
FIXTURES={
 'modules/shv-engine/tests/fixtures/interface-history.v1.json',
 'modules/shv-graph-adapter/tests/fixtures/interface-history.v1.json',
 'modules/shv-graph-duckdb-connector/tests/fixtures/interface-history.v1.json',
 'modules/shv-partition-engine/tests/fixtures/interface-history.v1.json',
 'modules/shv-pdf-adapter/tests/fixtures/interface-history.v1.json',
 'tools/qxctl/internal/knowledgeengine/testdata/shv-store/native-results.json',
}
KEEP_EXECUTION_DOCS={'tests/public-beta/execution/CAMPAIGN-HANDOFF.md','tests/public-beta/execution/W12-REVIEW.md'}

def digest(b): return hashlib.sha256(b).hexdigest()
def canonical(o): return json.dumps(o,sort_keys=True,separators=(',',':')).encode()
def git(repo,*args): return subprocess.check_output(['git','--no-replace-objects','-C',str(repo),*args])
def require(test,reason):
    if not test: raise ValueError(reason)

def configure_policy(path):
    """Keep publisher-specific scan terms in private input, never source/payload."""
    global PRIVATE_MARKERS, ATTRIBUTIONS, POLICY_DIGEST
    raw=Path(path).read_bytes();policy=json.loads(raw)
    require(set(policy)=={'schema','markers','document_attributions'} and
            policy['schema']=='symphony.source-privacy-policy.v1','unsupported privacy policy')
    markers=policy['markers'];attributions=policy['document_attributions']
    require(isinstance(markers,list) and markers and len(set(markers))==len(markers) and
            all(isinstance(m,str) and 3<=len(m)<=256 and all(32<=ord(c)<127 for c in m) for m in markers),
            'invalid private scan markers')
    require(isinstance(attributions,dict) and all(k.lstrip('@') in markers and
            v in ('the project owner','release owner','the release owner') for k,v in attributions.items()),
            'unreviewed attribution replacement')
    PRIVATE_MARKERS=[b'SYMPHONY_PRIVATE_CANARY_']+[m.encode() for m in markers]
    ATTRIBUTIONS=attributions
    POLICY_DIGEST=digest(canonical(policy))

def safe_path(path):
    p=PurePosixPath(path)
    require(path and not p.is_absolute() and not any(part in ('','.','..') for part in path.split('/')) and '\\' not in path,'unsafe archive path')
    require(all(part not in ('.git','.DS_Store','__pycache__') for part in p.parts),'forbidden metadata path')
    require(not any(ord(c)<32 or ord(c)==127 for c in path),'control character in path')
    return p

def exclusion(path):
    if path.startswith('tests/public-beta/') and not path.endswith('.md'):
        return 'historical publisher dossier, assignments and dossier-only tests; retained privately in source-bound distribution inventory'
    if path.startswith('tests/public-beta/execution/') and path not in KEEP_EXECUTION_DOCS:
        return 'historical private qualification evidence, not public source build input'
    if path=='knowledge/sclv/CHANGELOG.md':
        return 'historical development ledger with workstation references'
    if path.startswith('.github/workflows/') or path.startswith('.github/codeql/'):
        return 'publisher CI and historical security evidence; not end-user build material'
    if path=='.github/launch-tasks.json':
        return 'private operational assignment record'
    return None

def walk_strings(value, transform):
    if isinstance(value,str): return transform(value)
    if isinstance(value,list): return [walk_strings(x,transform) for x in value]
    if isinstance(value,dict): return {k:walk_strings(v,transform) for k,v in value.items()}
    return value

def fixture_string(value):
    # Frozen interface descriptors and result values are preserved. Only captured
    # workstation locations become synthetic absolute paths. Path hashes make
    # references deterministic without revealing personal path segments.
    if any(m.lower() in value.encode().lower() for m in PRIVATE_MARKERS):
        marker='/libexec/symphony/'
        if marker in value:
            return '/__symphony_fixture__'+value[value.index(marker):]
        return '/__symphony_fixture__/path-'+digest(value.encode())[:16]
    return value

def sanitize(path,data):
    transforms=[]
    require(b'SYMPHONY_PRIVATE_CANARY_' not in data,'private marker contamination canary')
    if path=='modules/scnv-engine/tests/scnv_test.cpp':
        matches=list(re.finditer(re.escape(b'{"source", {{"kind", "user"}, {"id", "')+rb'([^"\\]+)'+re.escape(b'"}}}'),data))
        require(len(matches)==1 and any(matches[0].group(1).lower()==m.lower() for m in PRIVATE_MARKERS),'SCNV synthetic fixture shape drift')
        data=data[:matches[0].start(1)]+b'synthetic-user'+data[matches[0].end(1):]
        transforms.append('scnv_test_user_fixture_v1')
    if path in FIXTURES:
        parsed=json.loads(data)
        normalized=walk_strings(parsed,fixture_string)
        if normalized!=parsed:
            data=(json.dumps(normalized,indent=2)+'\n').encode()
            transforms.append('synthetic_workstation_fixture_paths_v1')
    # Preserve functional source. Personal narrative attribution in public docs
    # becomes role-based wording. Copyright/license material is never rewritten.
    if path.endswith('.md') and not any(x in PurePosixPath(path).name.upper() for x in ('LICENSE','COPYRIGHT','NOTICE')):
        text=data.decode('utf-8')
        updated=text
        for original, replacement in sorted(ATTRIBUTIONS.items(),key=lambda row:len(row[0]),reverse=True):
            for paragraph in re.split(r'\n\s*\n',updated):
                require(not (original in paragraph and re.search(
                    r'copyright|all rights reserved|spdx-license-identifier|licensed under|license notice|©',paragraph,re.I)),
                    'legal attribution requires independent review; cannot rewrite')
            updated=updated.replace(original,replacement)
        if updated!=text:
            data=updated.encode();transforms.append('public_document_role_attribution_v1')
    scan(path,data)
    return data,transforms

def scan(path,data):
    safe_path(path)
    require(not any(m.lower() in path.encode().lower() for m in PRIVATE_MARKERS),'private marker in file name')
    require(not any(m.lower() in data.lower() for m in PRIVATE_MARKERS),'private marker in '+path)
    # Detect complete private-key blocks, not a source parser's isolated header.
    key=re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=\r\n]{32,}-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----')
    require(not key.search(data),'private key block in '+path)
    require(not re.search(rb'AKIA[A-Z0-9]{16}',data),'credential-shaped AWS access key in '+path)

def git_blobs(repo,commit):
    raw=git(repo,'ls-tree','-rlz',commit)
    rows=[]
    for item in raw.split(b'\0'):
        if not item: continue
        header,name=item.split(b'\t',1);mode,kind,oid,size=header.split()
        path=name.decode('utf-8');safe_path(path)
        require(kind==b'blob' and mode in (b'100644',b'100755'),'unsupported source object type: '+path)
        rows.append({'path':path,'mode':mode.decode(),'blob':oid.decode(),'size':int(size)})
    require(len(rows)==len({r['path'] for r in rows}),'duplicate source path')
    # Communicate reads concurrently with input writing; no pipe-buffer deadlock.
    proc=subprocess.run(['git','--no-replace-objects','-C',str(repo),'cat-file','--batch'],input=b''.join((r['blob']+'\n').encode() for r in rows),capture_output=True,check=True)
    stream=io.BytesIO(proc.stdout)
    for row in rows:
        header=stream.readline().split()
        require(len(header)==3 and header[0].decode()==row['blob'] and header[1]==b'blob','unexpected Git object response')
        size=int(header[2]);data=stream.read(size)
        require(size==row['size'] and len(data)==size and stream.read(1)==b'\n','incomplete Git blob')
        yield row,data
    require(not stream.read(),'trailing Git object data')

def write_archive(stream,entries,files,manifest_bytes):
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as tar:
        for entry in entries:
            info=tarfile.TarInfo('symphony-source/'+entry['path'])
            info.size=entry['export_size'];info.mode=0o755 if entry['mode']=='100755' else 0o644
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
            tar.addfile(info,io.BytesIO(files[entry['path']]))
        info=tarfile.TarInfo('symphony-source/SOURCE-EXPORT.json');info.size=len(manifest_bytes);info.mode=0o644;info.mtime=0
        tar.addfile(info,io.BytesIO(manifest_bytes))

def build(repo,output,commit=EXPECTED_COMMIT):
    repo=repo.resolve();output=output.resolve()
    require(POLICY_DIGEST is not None,'explicit private privacy policy required')
    require(commit==EXPECTED_COMMIT,'unreviewed source commit')
    require(git(repo,'rev-parse','HEAD').decode().strip()==commit,'source checkout is not exact reviewed commit')
    require(not git(repo,'status','--porcelain','--untracked-files=all').strip(),'dirty source checkout')
    require(not output.exists(),'output must be new')
    require(repo not in output.parents and output!=repo,'export must be outside repository')
    tree=git(repo,'rev-parse',f'{commit}^{{tree}}').decode().strip()
    require(tree==EXPECTED_TREE,'unreviewed source tree')
    files={};entries=[];excluded=[]
    for row,original in git_blobs(repo,commit):
        path=row['path'];reason=exclusion(path)
        entry={'path':path,'source_blob':row['blob'],'source_sha256':digest(original),'source_size':len(original),'mode':row['mode']}
        if reason:
            excluded.append(dict(entry,reason=reason));continue
        exported,transforms=sanitize(path,original)
        files[path]=exported
        entries.append(dict(entry,export_sha256=digest(exported),export_size=len(exported),transformations=transforms))
    # Rebind only this derived export's source-input hashes. Preserve the source
    # map schema, owner versions/operations and original upstream metadata.
    map_doc=json.loads(files[SOURCE_MAP]);rebound=[];removed_inputs=[]
    original_hashes={entry['path']:entry['source_sha256'] for entry in entries}
    excluded_hashes={entry['path']:entry['source_sha256'] for entry in excluded}
    retained_inputs=[]
    for row in map_doc['source_inputs']:
        if row['path'] not in files:
            require(row['path'].startswith('tests/public-beta/') and row['path'] in excluded_hashes,
                    'excluded file is required by product source map: '+row['path'])
            require(row['sha256']==excluded_hashes[row['path']],'original excluded source-map input drift')
            removed_inputs.append(dict(row,reason='private publisher dossier/test artifact omitted from derived public source'))
            continue
        require(row['sha256']==original_hashes[row['path']],'original source-map input drift: '+row['path'])
        h=digest(files[row['path']])
        if h!=row['sha256']:
            rebound.append({'path':row['path'],'original_sha256':row['sha256'],'export_sha256':h})
            row['sha256']=h
        retained_inputs.append(row)
    map_doc['source_inputs']=retained_inputs
    if rebound or removed_inputs:
        files[SOURCE_MAP]=(json.dumps(map_doc,indent=2)+'\n').encode()
        for entry in entries:
            if entry['path']==SOURCE_MAP:
                entry.update(export_sha256=digest(files[SOURCE_MAP]),export_size=len(files[SOURCE_MAP]))
                entry['transformations'].append('derived_export_source_input_rebinding_v1')
    entries.sort(key=lambda r:r['path']);excluded.sort(key=lambda r:r['path'])
    for path,data in files.items():scan(path,data)
    export_digest=digest(canonical([{'path':e['path'],'mode':e['mode'],'sha256':e['export_sha256']} for e in entries]))
    manifest={'protocol':'symphony.public-source-export.v2','source_repository':'https://github.com/QuanuX/Symphony',
              'origin_commit':commit,'origin_tree':tree,'derived_export_digest':export_digest,
              'privacy_policy_digest':POLICY_DIGEST,'source_binding_digest':BINDING['binding_digest'],
              'is_original_git_tree':False,'state':'sanitized_source_preparation_not_release',
              'transformation_implementation_sha256':digest(Path(__file__).read_bytes()),
              'source_files':entries,'excluded_files':excluded,'source_map_rebindings':rebound,
              'source_map_omitted_private_publisher_test_inputs':removed_inputs,
              'privacy_scan':{'known_private_markers':'passed','complete_private_keys':'passed','credential_shaped_access_keys':'passed',
                 'scope':'Tracked source text/bytes only; independent review and final binary/archive privacy qualification remain required.'},
              'public_source_build_tested':False,'source_test_suite_qualified':False,
              'release_acceptance_complete':False,'publication_authorized':False,
              'limitations':['Historical CI/evidence intentionally omitted; tests requiring Git history are not public-source acceptance.',
                 'Normalized historical fixtures are synthetic, never recipient hardware/user state.',
                 'Corresponding-source and notices review remains required for final selected dependencies.']}
    manifest_bytes=(json.dumps(manifest,indent=2)+'\n').encode();scan('SOURCE-EXPORT.json',manifest_bytes)
    output.mkdir(parents=True,mode=0o700)
    source=output/'source';source.mkdir(mode=0o700)
    try:
        for entry in entries:
            path=source/entry['path'];path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(files[entry['path']]);path.chmod(0o755 if entry['mode']=='100755' else 0o644)
        (output/'SOURCE-EXPORT.json').write_bytes(manifest_bytes)
        archive=output/'symphony-source.tar'
        with archive.open('xb') as stream:write_archive(stream,entries,files,manifest_bytes)
        verify(output)
        return manifest
    except Exception:
        # Keep partial work clearly invalid for inspection; never claim success.
        (output/'INCOMPLETE').write_text('Export failed; do not distribute.\n')
        raise

def verify_origin(manifest, repository):
    require(POLICY_DIGEST is not None and manifest.get('privacy_policy_digest')==POLICY_DIGEST,'private privacy policy differs')
    require(manifest.get('source_binding_digest')==BINDING['binding_digest'],'distribution source binding differs')
    require(manifest.get('origin_commit')==EXPECTED_COMMIT,'unreviewed origin commit')
    require(manifest.get('origin_tree')==EXPECTED_TREE,'unreviewed origin tree')
    if repository is None:
        return 'pinned_commit_tree_only_original_blobs_not_rechecked'
    repository=Path(repository).resolve()
    require(git(repository,'rev-parse',f'{EXPECTED_COMMIT}^{{tree}}').decode().strip()==EXPECTED_TREE,'repository tree mismatch')
    exported={r['path']:r for r in manifest['source_files']}
    excluded={r['path']:r for r in manifest['excluded_files']}
    require(not set(exported)&set(excluded),'source both included and excluded')
    require(len(excluded)==len(manifest['excluded_files']),'duplicate excluded path')
    actual=set()
    for row,original in git_blobs(repository,EXPECTED_COMMIT):
        path=row['path'];actual.add(path)
        observed=exported.get(path,excluded.get(path))
        require(observed is not None,'unaccounted original source path: '+path)
        for key,value in [('source_blob',row['blob']),('source_sha256',digest(original)),('source_size',len(original)),('mode',row['mode'])]:
            require(observed.get(key)==value,'forged original source binding: '+path)
        reason=exclusion(path)
        if reason:
            require(path in excluded and observed.get('reason')==reason,'unreviewed exclusion: '+path)
        else:
            require(path in exported,'unreviewed omitted source: '+path)
            expected,transforms=sanitize(path,original)
            if path!=SOURCE_MAP:
                require(observed['export_sha256']==digest(expected) and observed['transformations']==transforms,'unreviewed source transformation: '+path)
            else:
                doc=json.loads(expected)
                retained=[];rebindings=[];omitted=[]
                for source_input in doc['source_inputs']:
                    p=source_input['path']
                    if p in exported:
                        require(source_input['sha256']==exported[p]['source_sha256'],'original source-map drift')
                        h=exported[p]['export_sha256']
                        if h!=source_input['sha256']:
                            rebindings.append({'path':p,'original_sha256':source_input['sha256'],'export_sha256':h})
                            source_input['sha256']=h
                        retained.append(source_input)
                    else:
                        require(p.startswith('tests/public-beta/') and p in excluded,'unreviewed omitted map input')
                        omitted.append(dict(source_input,reason='private publisher dossier/test artifact omitted from derived public source'))
                doc['source_inputs']=retained
                rebound=(json.dumps(doc,indent=2)+'\n').encode() if rebindings or omitted else expected
                require(observed['export_sha256']==digest(rebound),'unreviewed derived source map')
                require(manifest.get('source_map_rebindings')==rebindings and manifest.get('source_map_omitted_private_publisher_test_inputs')==omitted,'source-map transformation record drift')
    require(actual==set(exported)|set(excluded),'extra invented original source binding')
    return 'all_original_git_blobs_and_export_transformations_verified'

def verify(output, repository=None):
    output=Path(output);require(not (output/'INCOMPLETE').exists(),'incomplete export')
    manifest=json.loads((output/'SOURCE-EXPORT.json').read_bytes())
    require(set(manifest)=={'protocol','source_repository','origin_commit','origin_tree','derived_export_digest',
            'privacy_policy_digest','source_binding_digest','is_original_git_tree','state',
            'transformation_implementation_sha256','source_files','excluded_files','source_map_rebindings',
            'source_map_omitted_private_publisher_test_inputs','privacy_scan','public_source_build_tested',
            'source_test_suite_qualified','release_acceptance_complete','publication_authorized','limitations'},
            'unrecognized manifest fields')
    require(manifest.get('protocol')=='symphony.public-source-export.v2' and
            manifest.get('state')=='sanitized_source_preparation_not_release' and
            manifest.get('source_repository')=='https://github.com/QuanuX/Symphony',
            'unsupported source-export manifest')
    require(all(manifest.get(k) is False for k in ('is_original_git_tree','public_source_build_tested',
            'source_test_suite_qualified','release_acceptance_complete','publication_authorized')),
            'source export cannot grant build or release acceptance')
    require(manifest.get('transformation_implementation_sha256')==digest(Path(__file__).read_bytes()),
            'export transformer differs')
    origin_binding=verify_origin(manifest,repository)
    entries=manifest['source_files'];require(len(entries)==len({e['path'] for e in entries}),'duplicate manifest path')
    require(entries==sorted(entries,key=lambda e:e['path']),'source entries are not canonical')
    expected={e['path']:e for e in entries}
    require(not any(p.is_symlink() for p in (output/'source').rglob('*')),'symlink in exported source')
    observed={p.relative_to(output/'source').as_posix() for p in (output/'source').rglob('*') if p.is_file()}
    require(observed==set(expected),'missing/extra source files')
    for path,entry in expected.items():
        p=output/'source'/path;data=p.read_bytes();scan(path,data)
        require(digest(data)==entry['export_sha256'] and len(data)==entry['export_size'],'export byte drift: '+path)
        require((p.stat().st_mode & 0o777)==(0o755 if entry['mode']=='100755' else 0o644),'export mode drift: '+path)
    recomputed=digest(canonical([{'path':e['path'],'mode':e['mode'],'sha256':e['export_sha256']} for e in entries]))
    require(recomputed==manifest['derived_export_digest'],'export manifest digest mismatch')
    archive=output/'symphony-source.tar'
    with tarfile.open(archive,'r:') as tar:
        members=tar.getmembers();names=[m.name for m in members]
        require(len(names)==len(set(names)),'duplicate archive member')
        require(set(names)=={'symphony-source/'+p for p in expected}|{'symphony-source/SOURCE-EXPORT.json'},'archive membership mismatch')
        for m in members:
            require(m.isfile() and m.uid==m.gid==0 and m.uname==m.gname=='' and m.mtime==0,'unsafe or personal archive metadata')
            data=tar.extractfile(m).read();path=m.name.removeprefix('symphony-source/');scan(path,data)
            expected_mode=0o644 if path=='SOURCE-EXPORT.json' else (0o755 if expected[path]['mode']=='100755' else 0o644)
            require(m.mode==expected_mode,'archive mode drift')
            require(all(key=='path' and value==m.name for key,value in m.pax_headers.items()),'unreviewed archive extended metadata')
            target=(output/'SOURCE-EXPORT.json').read_bytes() if path=='SOURCE-EXPORT.json' else (output/'source'/path).read_bytes()
            require(data==target,'archive bytes differ from exported source')
    # Parsers may ignore post-EOF bytes, padding and extra PAX/global records.
    # Reconstruct the entire canonical stream instead of trusting membership.
    canonical_tar=io.BytesIO()
    write_archive(canonical_tar,entries,{p:(output/'source'/p).read_bytes() for p in expected},
                  (output/'SOURCE-EXPORT.json').read_bytes())
    require(archive.read_bytes()==canonical_tar.getvalue(),'noncanonical archive bytes or hidden trailer')
    return {'files':len(entries),'excluded':len(manifest['excluded_files']),
            'transformed':sum(bool(e['transformations']) for e in entries),
            'archive_sha256':digest(archive.read_bytes()),'export_digest':recomputed,'origin_binding':origin_binding,'verified':True}

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    make=sub.add_parser('build');make.add_argument('--repository',type=Path,required=True);make.add_argument('--output',type=Path,required=True)
    check=sub.add_parser('verify');check.add_argument('--output',type=Path,required=True);check.add_argument('--repository',type=Path,required=True)
    for command in (make,check):command.add_argument('--privacy-policy',type=Path,required=True,help='private local scan/attribution policy; never bundled')
    a=p.parse_args()
    configure_policy(a.privacy_policy)
    if a.command=='build':build(a.repository,a.output)
    print(json.dumps(verify(a.output,a.repository),sort_keys=True))
if __name__=='__main__':main()
