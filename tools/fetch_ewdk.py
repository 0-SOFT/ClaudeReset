"""Download the selected official EWDK as data. No mount, install or execution."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://download.microsoft.com/download/be985897-caaa-4497-9ea4-17fa7065cd8a/EWDK_ge_release_svc_prod1_26100_250904-1728.iso'
SIZE = 20002537472
DEST = ROOT / 'work/toolchains/ewdk-26100.6584'


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    partial, final = DEST / 'ewdk.iso.partial', DEST / 'ewdk.iso'
    if final.exists():
        raise RuntimeError('Existing image is preserved; verify its receipt instead')
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > SIZE or shutil.disk_usage(DEST).free < (SIZE-offset) + SIZE + 8 * 1024**3:
        raise RuntimeError('Insufficient space for image, extraction allowance and 8 GiB reserve')
    request = urllib.request.Request(URL, headers={'Range': 'bytes=%d-' % offset} if offset else {})
    with urllib.request.urlopen(request, timeout=40) as response:
        if response.url != URL:
            raise RuntimeError('Unexpected download redirect')
        if offset and (response.status != 206 or not response.headers.get('Content-Range', '').startswith('bytes %d-' % offset)):
            raise RuntimeError('Server did not accept exact resume; partial image preserved')
        if not offset and (response.status != 200 or int(response.headers.get('Content-Length', '-1')) != SIZE):
            raise RuntimeError('Official image size changed; review required')
        digest = hashlib.sha256()
        if offset:
            with partial.open('rb') as old:
                for block in iter(lambda: old.read(4*1024**2), b''):
                    digest.update(block)
        total, announced = offset, offset
        with partial.open('ab' if offset else 'xb') as target:
            while block := response.read(4*1024**2):
                total += len(block)
                if total > SIZE:
                    raise RuntimeError('Oversized image')
                target.write(block); digest.update(block)
                if total-announced >= 512*1024**2:
                    print(json.dumps({'downloaded':total, 'total':SIZE}), flush=True); announced=total
        if total != SIZE:
            raise RuntimeError('Incomplete image retained for exact range resume')
    partial.rename(final)
    receipt = dict(schema=1, utc=datetime.now(timezone.utc).isoformat(), url=URL, bytes=SIZE,
                   sha256=digest.hexdigest(), source='Microsoft HTTPS; official WDK table -> EWDK VS2022 license link 2335681',
                   publisher_checksum_verified=False, component_authenticode_verified=False,
                   executable_components_run=False, installed=False)
    (DEST / 'download-receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    main()
