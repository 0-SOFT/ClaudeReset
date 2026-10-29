"""Download hash-pinned archives from the upstream CPython installer SBOM."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request

ROOT=Path(__file__).resolve().parents[1]


def main(output):
    output=output.resolve()
    if output.exists(): raise RuntimeError('Choose a fresh source directory')
    lock= json.loads((ROOT/'third_party/sources/cpython-native-source-lock.json').read_text('utf-8'))
    output.mkdir(parents=True)
    def fetch(row):
        parsed=urllib.parse.urlparse(row['url'])
        if (parsed.scheme!='https' or parsed.hostname not in ('github.com','files.pythonhosted.org','www.bytereef.org')
                or not re.fullmatch(r'[a-f0-9]{64}',row['sha256'])):
            raise RuntimeError('Unexpected locked source location')
        suffix='.zip' if parsed.path.endswith('.zip') else '.tar.gz'
        target=output/(row['sha256']+suffix)
        digest=hashlib.sha256(); total=0
        with urllib.request.urlopen(row['url'],timeout=60) as response,target.open('xb') as stream:
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>128*1024*1024: raise RuntimeError('Oversized source dependency')
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=row['sha256']: raise RuntimeError('CPython dependency archive checksum differs: '+row['name'])
        return {**row,'file':target.name,'bytes':total,'verified':True}
    with ThreadPoolExecutor(max_workers=4) as workers: rows=list(workers.map(fetch,lock['source_archives']))
    (output/'source-inventory.json').write_text(json.dumps({'schema':1,'sources':rows,'executed':False},indent=2),encoding='utf-8')
    print(json.dumps({'verified_source_archives':len(rows),'executed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args().output)
