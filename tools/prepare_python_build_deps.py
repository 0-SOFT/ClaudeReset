"""Stage pinned CPython build inputs without running upstream fetch/clean scripts."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import urllib.request
import zipfile
import argparse
import shutil

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'work/dependencies/Python-3.12.16'


def safe(name):
    parts=PurePosixPath(name).parts
    if (not parts or PurePosixPath(name).is_absolute() or '\\' in name
            or any(p in ('.','..') or ':' in p or p.endswith((' ','.')) for p in parts)):
        raise RuntimeError('Unsafe dependency member')
    return Path(*parts)


def main(openssl_lts=False):
    base=ROOT/'work/dependencies/Python-3.12.16-openssl359' if openssl_lts else BASE
    output=base/'source/externals'
    if output.exists(): raise RuntimeError('Preserve existing dependency staging')
    rows=json.loads((ROOT/'third_party/sources/python-security-build-binaries-lock.json').read_text('utf-8'))['archives']
    if openssl_lts:
        replacement=json.loads((ROOT/'third_party/sources/openssl-lts-lock.json').read_text('utf-8'))['binary']
        rows=[r for r in rows if not r['tag'].startswith('openssl-bin-')]+[replacement]
    source_rows=json.loads((ROOT/'third_party/sources/cpython-native-source-lock.json').read_text('utf-8'))['source_archives']
    inputs=[]
    for name in ('bzip2','sqlite','xz','zlib'):
        row=next(r for r in source_rows if r['name']==name)
        archive=ROOT/'work/dependencies/cpython-native-sources'/(row['sha256']+'.tar.gz')
        inputs.append((name+'-'+row['version'],archive,row['sha256'],False))
    for row in rows:
        archive=base/'build-dependency-archives'/row['file']
        cached=(ROOT/'work/dependencies/openssl-3.5.9'/row['file'] if row['tag']=='openssl-bin-3.5.9'
                else BASE/'build-dependency-archives'/row['file'])
        if openssl_lts and not archive.exists() and cached.exists():
            archive.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(cached,archive)
        if not archive.exists():
            archive.parent.mkdir(parents=True,exist_ok=True)
            with urllib.request.urlopen(row['archive_url'],timeout=60) as response,archive.open('xb') as stream:
                total=0
                while chunk:=response.read(1048576):
                    total+=len(chunk)
                    if total>row['bytes']: raise RuntimeError('Oversized build dependency')
                    stream.write(chunk)
        inputs.append((row['tag'],archive,row['sha256'],True))
    for _,archive,digest,_ in inputs:
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=digest: raise RuntimeError('Build dependency archive changed')
    output.mkdir()
    manifest={}; total=0
    for label,archive,digest,is_zip in inputs:
        seen=set()
        def write(name,data):
            nonlocal total
            relative=safe(name)
            if str(relative).casefold() in seen: raise RuntimeError('Case-colliding dependency member')
            seen.add(str(relative).casefold());total+=len(data)
            if total>1024*1024*1024: raise RuntimeError('Oversized dependency tree')
            target=output/label/relative;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(data)
            manifest[target.relative_to(output).as_posix()]=hashlib.sha256(data).hexdigest()
        if is_zip:
            with zipfile.ZipFile(archive) as source:
                for member in source.infolist():
                    if member.is_dir():continue
                    if stat.S_ISLNK(member.external_attr>>16) or member.file_size>64*1024*1024: raise RuntimeError('Nonregular dependency member')
                    name='/'.join(PurePosixPath(member.filename).parts[1:])
                    # Keep all upstream architecture folders; no source rewrite.
                    write(name,source.read(member))
        else:
            with tarfile.open(archive,'r:gz') as source:
                for member in source:
                    if member.isdir():continue
                    if not member.isfile() or member.size>64*1024*1024: raise RuntimeError('Nonregular dependency member')
                    write('/'.join(PurePosixPath(member.name).parts[1:]),source.extractfile(member).read())
    (base/'build-dependency-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'files':len(manifest),'bytes':total,'executed':False,'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-lts',action='store_true')
    main(parser.parse_args().openssl_lts)
