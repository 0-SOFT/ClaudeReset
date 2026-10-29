"""Extract the complete official UDF image into the workspace; never mount or install."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'work/toolchains/ewdk-26100.6584'
sys.path.insert(0,str(ROOT/'work/toolchains/iso-reader'))
import pycdlib


def main():
    destination=BASE/'extracted'
    if destination.exists(): raise RuntimeError('Existing extraction preserved')
    receipt=json.loads((BASE/'download-receipt.json').read_text())
    with (BASE/'ewdk.iso').open('rb') as f:
        if hashlib.file_digest(f,'sha256').hexdigest()!=receipt['sha256']: raise RuntimeError('Downloaded image changed')
    iso=pycdlib.PyCdlib();iso.open(str(BASE/'ewdk.iso'))
    entries=[];total=0
    for directory,_,files in iso.walk(udf_path='/'):
        for name in files:
            path=PurePosixPath(directory)/name
            if '..' in path.parts or any(':' in p or p.endswith((' ','.')) for p in path.parts[1:]): raise RuntimeError('Unsafe image path')
            size=iso.get_record(udf_path=str(path)).get_data_length()
            entries.append((str(path),size));total+=size
    if shutil.disk_usage(BASE).free < total+8*1024**3: raise RuntimeError('Insufficient extraction space with 8 GiB reserve')
    print(json.dumps({'files':len(entries),'expanded_bytes':total,'space_verified':True}),flush=True)
    destination.mkdir();manifest={}
    for count,(name,size) in enumerate(entries,1):
        target=destination.joinpath(*PurePosixPath(name).parts[1:]);target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as f:iso.get_file_from_iso_fp(f,udf_path=name)
        if target.stat().st_size!=size:raise RuntimeError('Extracted size mismatch')
        with target.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        manifest[name.lstrip('/')]={'bytes':size,'sha256':digest}
        if count%5000==0: print(json.dumps({'extracted':count,'total':len(entries)}),flush=True)
    iso.close()
    (BASE/'extraction-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'extracted':len(entries),'complete':True,'executed':False,'installed':False}),flush=True)


if __name__=='__main__':main()
