"""Download exact Python dependency source distributions without running build hooks."""
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
    if output.exists(): raise RuntimeError('Preserve previous dependency sources')
    output.mkdir(parents=True)
    specs=[]
    for line in (ROOT/'requirements-lock.txt').read_text('utf-8').splitlines():
        if line and not line.startswith('#'): specs.append(line.split('=='))

    def fetch(spec):
        name, version=spec
        if not all(re.fullmatch(r'[A-Za-z0-9._-]+',p) for p in spec): raise RuntimeError('Invalid locked dependency')
        metadata_url='https://pypi.org/pypi/'+name+'/'+version+'/json'
        with urllib.request.urlopen(metadata_url,timeout=30) as response: data=response.read(4*1024*1024+1)
        if len(data)>4*1024*1024: raise RuntimeError('Oversized package metadata')
        info=json.loads(data)
        sources=[row for row in info['urls'] if row['packagetype']=='sdist']
        if len(sources)!=1: raise RuntimeError('Expected one exact source distribution: '+name)
        row=sources[0]; parsed=urllib.parse.urlparse(row['url'])
        if (parsed.scheme!='https' or parsed.hostname!='files.pythonhosted.org'
                or parsed.username or parsed.password or parsed.port
                or not re.fullmatch(r'[A-Za-z0-9._-]+',row['filename'])
                or not re.fullmatch(r'[a-f0-9]{64}',row['digests']['sha256'])
                or type(row['size']) is not int or not 0<row['size']<=64*1024*1024):
            raise RuntimeError('Unexpected source distribution location or identity')
        target=output/row['filename']; digest=hashlib.sha256(); total=0
        with urllib.request.urlopen(row['url'],timeout=60) as response, target.open('xb') as stream:
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>row['size']: raise RuntimeError('Source exceeds published size')
                stream.write(chunk);digest.update(chunk)
        if total!=row['size'] or digest.hexdigest()!=row['digests']['sha256']:
            raise RuntimeError('Source distribution checksum differs: '+name)
        return {'name':name,'version':version,'file':row['filename'],'sha256':digest.hexdigest(),
                'bytes':total,'metadata_url':metadata_url,'url':row['url'],'source_code_executed':False}

    with ThreadPoolExecutor(max_workers=4) as workers: results=list(workers.map(fetch,specs))
    receipt={'schema':1,'requirements_sha256':hashlib.sha256((ROOT/'requirements-lock.txt').read_bytes()).hexdigest(),
             'sources':results,'source_code_executed':False,'installed':False,
             'limits':['CPython and its bundled native dependencies are separate.',
                       'Sources match public PyPI release digests; installed wheel provenance needs separate verification.']}
    (output/'source-inventory.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps({'source_distributions':len(results),'source_code_executed':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args().output)
