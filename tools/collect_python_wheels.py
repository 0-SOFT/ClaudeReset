"""Download only compatible pinned wheels; no source builds or install hooks."""
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
    if output.exists():raise RuntimeError('Preserve existing wheel cache')
    output.mkdir(parents=True)
    specifications=[line.split('==') for line in (ROOT/'requirements-lock.txt').read_text('utf-8').splitlines()
                    if line and not line.startswith('#')]
    def fetch(spec):
        name,version=spec
        if not all(re.fullmatch(r'[A-Za-z0-9._-]+',p) for p in spec):raise RuntimeError('Invalid dependency')
        url='https://pypi.org/pypi/'+name+'/'+version+'/json'
        with urllib.request.urlopen(url,timeout=30) as response:info=json.load(response)
        wheels=[r for r in info['urls'] if r['packagetype']=='bdist_wheel'
                and r['filename'].endswith(('-py3-none-any.whl','-py2.py3-none-any.whl','-py3-none-win_amd64.whl'))]
        if len(wheels)!=1:raise RuntimeError('Expected one reviewed compatible wheel: '+name)
        row=wheels[0];location=urllib.parse.urlparse(row['url'])
        if (location.scheme!='https' or location.hostname!='files.pythonhosted.org'
                or not re.fullmatch(r'[A-Za-z0-9._-]+',row['filename'])
                or not re.fullmatch(r'[a-f0-9]{64}',row['digests']['sha256'])):
            raise RuntimeError('Unexpected wheel identity')
        digest=hashlib.sha256();total=0
        with urllib.request.urlopen(row['url'],timeout=60) as response,(output/row['filename']).open('xb') as stream:
            while chunk:=response.read(1048576):
                total+=len(chunk)
                if total>min(row['size'],64*1024*1024):raise RuntimeError('Oversized wheel')
                digest.update(chunk);stream.write(chunk)
        if total!=row['size'] or digest.hexdigest()!=row['digests']['sha256']:raise RuntimeError('Wheel hash differs')
        return {'name':name,'version':version,'file':row['filename'],'url':row['url'],
                'sha256':digest.hexdigest(),'bytes':total}
    with ThreadPoolExecutor(max_workers=4) as workers:rows=list(workers.map(fetch,specifications))
    result={'schema':1,'platform':'Windows x64','requirements_sha256':hashlib.sha256((ROOT/'requirements-lock.txt').read_bytes()).hexdigest(),
            'wheels':rows,'installed':False,'source_builds_executed':False}
    (output/'wheel-inventory.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    (output/'requirements-wheels.lock').write_text(''.join(r['name']+'=='+r['version']+' --hash=sha256:'+r['sha256']+'\n' for r in rows),encoding='utf-8')
    print(json.dumps({'wheels':len(rows),'installed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args().output)
