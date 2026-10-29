"""Fetch a pinned official engine into a fresh build directory; never execute it."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / 'third_party/sources/sing-box-lock.json').read_text())
    directory = ROOT / 'work/dependencies' / ('sing-box-' + lock['version'])
    if directory.exists(): raise RuntimeError('Existing dependency preserved')
    request = urllib.request.Request('https://api.github.com/repos/SagerNet/sing-box/releases/tags/v' + lock['version'],
                                    headers={'User-Agent': 'ClaudeReset-build-review'})
    with urllib.request.urlopen(request, timeout=30) as response: release = json.load(response)
    if release['tag_name'] != 'v' + lock['version'] or release.get('immutable') is not True:
        raise RuntimeError('The selected release is not immutable')
    asset = next(a for a in release['assets'] if a['name'] == lock['asset'])
    if (asset['size'] != lock['bytes'] or asset['digest'] != 'sha256:' + lock['sha256']
            or asset['browser_download_url'] != lock['url']):
        raise RuntimeError('Official release asset metadata changed')
    directory.mkdir(parents=True)
    archive = directory / lock['asset']
    digest = hashlib.sha256(); size = 0
    with urllib.request.urlopen(lock['url'], timeout=60) as source, archive.open('xb') as destination:
        while data := source.read(1024 * 1024):
            size += len(data)
            if size > lock['bytes']: raise RuntimeError('Download exceeds pinned length')
            digest.update(data); destination.write(data)
    if size != lock['bytes'] or digest.hexdigest() != lock['sha256']:
        raise RuntimeError('Downloaded engine archive differs')
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if len(names) != len(set(names)) or sum(i.file_size for i in bundle.infolist()) > 200_000_000:
            raise RuntimeError('Unexpected ZIP structure')
        for info in bundle.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or '..' in name.parts or ':' in info.filename or '\\' in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError('Unsafe ZIP entry')
        executable = 'sing-box-' + lock['version'] + '-windows-amd64/sing-box.exe'
        data = bundle.read(executable)
        if hashlib.sha256(data).hexdigest() != lock['executable_sha256']:
            raise RuntimeError('Executable differs from the reviewed engine')
        bundle.extractall(directory / 'extracted')
    receipt = dict(lock, downloaded_archive_verified=True, official_immutable_asset_digest_verified=True,
                   executable_verified=True, executed=False, installed=False, client_network_opened=False)
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps({'version': lock['version'], 'archive_verified': True, 'executable_verified': True, 'executed': False}))


if __name__ == '__main__': main()
