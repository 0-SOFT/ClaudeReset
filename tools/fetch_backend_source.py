"""Recover the exact official engine source archive into a fresh review tree."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from claude_reset.safeio import guarded


def main():
    lock = json.loads((ROOT/'third_party/sources/sing-box-lock.json').read_text())
    directory = ROOT/'work/dependencies'/('sing-box-'+lock['version'])
    source = directory/'source'
    if source.exists(): raise RuntimeError('Existing source tree preserved')
    directory.mkdir(parents=True,exist_ok=True)
    archive = guarded(directory/lock['source_archive'],directory)
    if not archive.exists():
        with urllib.request.urlopen(lock['source_url'],timeout=45) as remote, archive.open('xb') as output:
            size = 0
            while data := remote.read(1048576):
                size += len(data)
                if size > lock['source_bytes']: raise RuntimeError('Source download exceeded pinned length')
                output.write(data)
    if archive.stat().st_size != lock['source_bytes'] or hashlib.sha256(archive.read_bytes()).hexdigest() != lock['source_sha256']:
        raise RuntimeError('Pinned engine source archive differs')
    manifest = {}
    with zipfile.ZipFile(archive) as bundle:
        prefix = 'sing-box-'+lock['source_commit']+'/'
        seen = set(); entries = []
        if sum(info.file_size for info in bundle.infolist()) > 100_000_000:
            raise RuntimeError('Unexpected source expansion')
        for info in bundle.infolist():
            if not info.filename.startswith(prefix): raise RuntimeError('Source archive root differs')
            name = info.filename[len(prefix):]
            if not name: continue
            relative = PurePosixPath(name)
            if (relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name
                    or (info.external_attr >> 16) & 0o170000 == 0o120000
                    or name.casefold() in seen):
                raise RuntimeError('Unsafe source archive entry')
            seen.add(name.casefold())
            target = guarded(source/Path(relative),source)
            entries.append((info,target))
        source.mkdir()
        for info,target in entries:
            if info.is_dir(): target.mkdir(parents=True,exist_ok=True); continue
            target.parent.mkdir(parents=True,exist_ok=True)
            data = bundle.read(info)
            with target.open('xb') as output: output.write(data)
            manifest[target.relative_to(source).as_posix()] = hashlib.sha256(data).hexdigest()
    (directory/'source-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'source_commit':lock['source_commit'],'files':len(manifest),'archive_verified':True,'executed':False}))


if __name__ == '__main__': main()
