"""Download the pinned Go source archive only; no extraction or execution."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def fetch(lock_name):
    if lock_name not in ('go-source-lock.json','python-source-lock.json','python-security-candidate-lock.json'):
        raise RuntimeError('Unknown source lock')
    lock = json.loads((ROOT/'third_party/sources'/lock_name).read_text('utf-8'))
    destination = ROOT/'work/dependencies'/lock['version']
    if destination.exists(): raise RuntimeError('Preserve existing source download')
    destination.mkdir()
    partial = destination/(lock['filename']+'.part')
    digest = hashlib.sha256(); total = 0
    with urllib.request.urlopen(lock['url'], timeout=60) as response, partial.open('xb') as stream:
        while chunk := response.read(1024*1024):
            total += len(chunk)
            if total > lock.get('bytes',64*1024*1024): raise RuntimeError('Source exceeds bounded size')
            digest.update(chunk); stream.write(chunk)
    if ('bytes' in lock and total != lock['bytes']) or digest.hexdigest() != lock['sha256']:
        raise RuntimeError('Source archive does not match the official pinned digest')
    partial.rename(destination/lock['filename'])
    receipt = {'schema':1, 'version':lock['version'], 'sha256':digest.hexdigest(),
               'bytes':total, 'extracted':False, 'executed':False}
    (destination/'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__': fetch('go-source-lock.json')
