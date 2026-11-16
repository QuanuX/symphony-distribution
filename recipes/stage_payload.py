#!/usr/bin/env python3
"""Conda build-time exact-copy gate; never copies generated build/debug files."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for b in iter(lambda:stream.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()

def safe_file(root, name):
    rel=PurePosixPath(name)
    require(str(rel)==name and not rel.is_absolute() and '..' not in rel.parts and '\\' not in name,
            'Unsafe payload name')
    path=root/name
    for piece in [path, *path.parents]:
        require(not piece.is_symlink(), 'Symlink in payload path')
        if piece==root:
            break
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1, 'Non-regular payload file')
    return path, stat.S_IMODE(info.st_mode)

def stage(source, prefix, expected_digest, relative_destination):
    source=Path(source).absolute();prefix=Path(prefix).absolute()
    for root in (source,prefix):
        for p in (root,*root.parents):
            require(not p.is_symlink(), 'Symlinked source or prefix')
    rel=PurePosixPath(relative_destination)
    require(not rel.is_absolute() and '..' not in rel.parts and str(rel)==relative_destination,
            'Unsafe carrier destination')
    destination=prefix/relative_destination
    for p in (destination,*destination.parents):
        require(not p.is_symlink(), 'Symlinked carrier destination')
        if p==prefix:
            break
    require(not destination.exists(), 'Carrier destination already exists')
    manifest_path,mode=safe_file(source,'carrier-manifest.json')
    require(digest(manifest_path)==expected_digest,'Manifest changed before Conda build')
    manifest=json.loads(manifest_path.read_bytes())
    files=manifest['files']
    names=set()
    for row in files:
        require(row['path'] not in names and row['path']!='carrier-manifest.json','Duplicate payload file')
        names.add(row['path'])
        path,mode=safe_file(source,row['path'])
        require(mode==row['mode'] and mode in (0o444,0o555,0o644,0o755),'Payload mode changed')
        require(path.stat().st_size==row['size'] and digest(path)==row['sha256'],'Payload changed before Conda build')
    destination.mkdir(parents=True)
    for row in files:
        path,mode=safe_file(source,row['path'])
        output=destination/row['path'];output.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,output);output.chmod(mode)
        require(digest(output)==row['sha256'],'Payload changed during Conda build')
    shutil.copyfile(manifest_path,destination/'carrier-manifest.json')
    require(digest(destination/'carrier-manifest.json')==expected_digest,'Manifest changed during copy')

if __name__=='__main__':
    try:
        require(len(sys.argv)==5,'source, prefix, manifest digest and destination required')
        stage(*sys.argv[1:])
    except (OSError,ValueError,KeyError) as exc:
        print('Carrier build refused: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
