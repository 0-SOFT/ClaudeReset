"""Extract the pinned CPython security candidate as regular files only."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import argparse
import shutil

ROOT=Path(__file__).resolve().parents[1]


def main(openssl_lts=False):
    lock=json.loads((ROOT/'third_party/sources/python-security-candidate-lock.json').read_text('utf-8'))
    original=ROOT/'work/dependencies'/lock['version']
    base=ROOT/'work/dependencies'/(lock['version']+'-openssl359') if openssl_lts else original
    if openssl_lts:
        base.mkdir(exist_ok=False)
        shutil.copyfile(original/lock['filename'],base/lock['filename'])
    archive=base/lock['filename']; output=base/'source'
    if output.exists(): raise RuntimeError('Preserve existing security candidate source')
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['sha256']: raise RuntimeError('CPython source archive changed')
    reserved={'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
    with tarfile.open(archive,'r:xz') as source:
        members=source.getmembers(); selected=[]; seen=set(); total=0
        if len(members)>30000: raise RuntimeError('Oversized source tree')
        for member in members:
            path=PurePosixPath(member.name)
            if not path.parts or path.parts[0]!=lock['version'] or path.is_absolute(): raise RuntimeError('Unexpected archive prefix')
            relative=PurePosixPath(*path.parts[1:])
            if member.isdir(): continue
            if (not member.isfile() or not relative.parts or '\\' in member.name
                    or any(p in ('.','..') or ':' in p or p.endswith((' ','.'))
                           or p.split('.')[0].upper() in reserved for p in relative.parts)
                    or relative.as_posix().casefold() in seen or not 0<=member.size<=64*1024*1024):
                raise RuntimeError('Unsafe or ambiguous source member')
            seen.add(relative.as_posix().casefold()); total+=member.size
            if total>1024*1024*1024: raise RuntimeError('Oversized source contents')
            selected.append((member,relative))
        output.mkdir()
        hashes={}
        for member,relative in selected:
            path=output/str(relative);path.parent.mkdir(parents=True,exist_ok=True)
            data=source.extractfile(member).read()
            if len(data)!=member.size: raise RuntimeError('Truncated source member')
            with path.open('xb') as stream: stream.write(data)
            hashes[relative.as_posix()]=hashlib.sha256(data).hexdigest()
    (base/'source-manifest.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
    print(json.dumps({'source_files':len(hashes),'bytes':total,'executed':False,'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-lts',action='store_true')
    main(parser.parse_args().openssl_lts)
