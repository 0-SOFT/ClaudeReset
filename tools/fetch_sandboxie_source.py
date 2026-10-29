"""Acquire the pinned full upstream tree and validate every reviewed patch input."""
import hashlib
import argparse
import json
from pathlib import Path, PurePosixPath
import stat
import urllib.request
import zipfile
from prepare_sandboxie_hardening import HASHES as SERVICE
from prepare_sandboxie_helper_hardening import HASHES as DRIVER

ROOT=Path(__file__).resolve().parents[1]
LOCK=json.loads((ROOT/'third_party/sources/sandboxie-lock.json').read_text('utf-8'))
COMMIT=LOCK['commit']
URL=LOCK['archive_url']
DEST=ROOT/'work/dependencies/sandboxie-v1.18.8'


def main():
    DEST.mkdir(parents=True,exist_ok=True)
    archive=DEST/'upstream.zip'
    if not archive.exists():
        with urllib.request.urlopen(URL,timeout=40) as response, archive.with_suffix('.partial').open('xb') as out:
            size=0
            while block:=response.read(1024**2):
                size+=len(block)
                if size>300*1024**2: raise RuntimeError('Unexpected source archive size')
                out.write(block)
        archive.with_suffix('.partial').rename(archive)
    prefix='Sandboxie-'+COMMIT
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=LOCK['archive_sha256']:
        raise RuntimeError('Upstream archive differs from the reviewed source lock')
    source=DEST/'source'
    if source.exists(): raise RuntimeError('Preserve existing source tree')
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None: raise RuntimeError('Invalid source archive')
        total=0
        for entry in z.infolist():
            path=PurePosixPath(entry.filename)
            if path.parts[0]!=prefix or '..' in path.parts or path.is_absolute() or stat.S_ISLNK(entry.external_attr>>16):
                raise RuntimeError('Unsafe source archive entry')
            total+=entry.file_size
            if total>1024**3: raise RuntimeError('Oversized source tree')
        for name,digest in SERVICE.items():
            assert hashlib.sha256(z.read(prefix+'/Sandboxie/core/svc/'+name)).hexdigest()==digest, name
        for name,digest in DRIVER.items():
            assert hashlib.sha256(z.read(prefix+'/Sandboxie/core/drv/'+name)).hexdigest()==digest, name
        for entry in z.infolist():
            relative=PurePosixPath(entry.filename).parts[1:]
            if not relative: continue
            destination=source.joinpath(*relative)
            if entry.is_dir(): destination.mkdir(parents=True,exist_ok=True)
            else:
                destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(z.read(entry))
    receipt={'schema':1,'tag':'v1.18.8','commit':COMMIT,'url':URL,'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
             'reviewed_service_files':SERVICE,'reviewed_driver_files':DRIVER,'all_patch_inputs_match':True,'executed':False}
    (DEST/'source-receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'source':str(source),'all_patch_inputs_match':True,'files':len(list(source.rglob('*')))}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-root',type=Path,default=DEST)
    DEST=parser.parse_args().output_root.resolve()
    main()
