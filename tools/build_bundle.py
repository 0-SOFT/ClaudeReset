"""Build the portable ClaudeReset folder and ZIP: bundled Python, the program, a prebuilt controller.

Run with the project environment from the repository root:
    .venv\\Scripts\\python.exe tools\\build_bundle.py --out D:\\ClaudeReset-bundle
The output folder must not exist yet (or be empty). Downloads are cached in <out>\\..\\bundle-cache and
checked against packaging/bundle/python-lock.json. Nothing outside --out and the cache is written.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from claude_reset import __version__, brand, l1_install  # noqa: E402

LOCK = ROOT / 'packaging/bundle/python-lock.json'
CSC = Path(r'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe')
# Files the program reads while it runs (relative to the repository root).
RUNTIME = ['LICENSE', 'src/launcher.py', 'src/launcher_run.py', 'src/claude_reset', 'packaging/identity', 'packaging/backend',
           'third_party/NOTICES.md', 'third_party/licenses', 'third_party/sources/sing-box-lock.json',
           'tools/vscode_claude_proxy.py', 'docs/USER-GUIDE.md', 'docs/GUI-ACCEPTANCE.md',
           'docs/LICENSE-REVIEW-G6.md', 'docs/GUIDE-FRESH-START.md']
READ_ME = """ClaudeReset {version}

Как запустить: дважды щёлкните ClaudeReset.exe в этой папке.
Дальше всё в окне: «Шаг 1 · Сброс», затем «Шаг 2 · Прокси и защита».
Руководство открывается в окне на странице «Помощь».

Не перемещайте и не удаляйте эту папку, пока защита включена:
защита запускает отсюда свои части. Перед удалением папки выключите защиту.
"""


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fetch_python(cache):
    lock = json.loads(LOCK.read_text('utf-8'))
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / Path(lock['url'].split('/')[-1].replace('%2B', '+')).name
    if not archive.is_file() or sha256(archive) != lock['sha256']:
        partial = archive.with_suffix('.part')
        with urllib.request.urlopen(lock['url'], timeout=120) as response, open(partial, 'wb') as target:
            shutil.copyfileobj(response, target)
        if sha256(partial) != lock['sha256']:
            partial.unlink()
            raise SystemExit('Python archive hash does not match the lock')
        partial.replace(archive)
    return archive, lock


def copy_runtime(stage):
    for relative in RUNTIME:
        source = ROOT / relative
        if not source.exists():
            raise SystemExit('Missing runtime file: ' + relative)
        target = stage / relative
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns(*('__pycache__', '*.pyc', '.pytest_cache')))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def build_controller(stage, work):
    """The controller kit from the same sources that were copied into the bundle."""
    if l1_install.source_digest(stage) != l1_install.source_digest(ROOT):
        raise SystemExit('Copied sources differ from the repository')
    dist = l1_install.build_executables(work / 'controller-build')
    kit = stage / 'controller'
    kit.mkdir()
    files = {}
    for name, _, _ in l1_install.BUILDS:
        shutil.copy2(dist / (name + '.exe'), kit / (name + '.exe'))
        files[name + '.exe'] = sha256(kit / (name + '.exe'))
    manifest = {'schema': 1, 'version': __version__, 'source_sha256': l1_install.source_digest(stage), 'files': files}
    (kit / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    if l1_install.controller_kit(root=stage) != kit:
        raise SystemExit('The built controller kit does not verify')


def build_launcher(stage, work):
    icon = stage / 'ClaudeReset.ico'
    icon.write_bytes(brand.ico())
    result = subprocess.run([str(CSC), '/nologo', '/target:winexe', '/optimize+', '/codepage:65001',
                             '/r:System.Windows.Forms.dll', '/win32icon:' + str(icon),
                             '/out:' + str(stage / 'ClaudeReset.exe'), str(ROOT / 'packaging/bundle/ClaudeResetLauncher.cs')],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('Launcher build failed: ' + result.stdout[-500:])


def build_setup(stage, payload, target, work):
    """Setup.exe: the ZIP, icon, mark and fonts embedded; installs per user without administrator rights."""
    fonts = ROOT / 'src/claude_reset/assets/fonts'
    mark = work / 'mark.png'
    mark.write_bytes(brand.mark(68, background=brand.LIGHT['paper']))
    resources = [(payload, 'payload.zip'), (stage / 'ClaudeReset.ico', 'icon.ico'), (mark, 'mark.png'),
                 (fonts / 'CormorantGaramondMedium.ttf', 'display.ttf'), (fonts / 'Onest.ttf', 'body.ttf'),
                 (fonts / 'OnestMedium.ttf', 'medium.ttf')]
    result = subprocess.run([str(CSC), '/nologo', '/target:winexe', '/optimize+', '/codepage:65001',
                             '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.IO.Compression.dll',
                             '/r:System.IO.Compression.FileSystem.dll', '/win32icon:' + str(stage / 'ClaudeReset.ico')]
                            + [f'/resource:{path},{name}' for path, name in resources]
                            + ['/out:' + str(target), str(ROOT / 'packaging/bundle/ClaudeResetSetup.cs')],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('Setup build failed: ' + result.stdout[-800:])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--no-zip', action='store_true')
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit('Output folder is not empty: ' + str(out))
    name = f'ClaudeReset-{__version__}'
    stage, work = out / name, out / 'work'
    work.mkdir(parents=True)
    archive, lock = fetch_python(out.parent / 'bundle-cache')
    with tarfile.open(archive) as source:
        source.extractall(stage, filter='data')  # the archive's top folder is python/
    python = stage / 'python' / 'python.exe'
    if not python.is_file() or not (stage / 'python' / 'pythonw.exe').is_file():
        raise SystemExit('Unexpected Python archive layout')
    subprocess.run([str(python), '-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--no-warn-script-location',
                    '--no-cache-dir', '-r', str(ROOT / 'requirements-runtime.txt')], check=True)
    check = subprocess.run([str(python), '-I', '-c', 'import tkinter, dissect.hypervisor; print(tkinter.TkVersion)'],
                           capture_output=True, text=True)
    if check.returncode:
        raise SystemExit('Bundled Python cannot import Tk or dependencies')
    copy_runtime(stage)
    build_controller(stage, work)
    build_launcher(stage, work)
    (stage / 'Как запустить.txt').write_text(READ_ME.format(version=__version__), encoding='utf-8-sig')
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    packages = subprocess.run([str(python), '-I', '-m', 'pip', 'freeze', '--disable-pip-version-check'],
                              capture_output=True, text=True).stdout.split()
    files = {p.relative_to(stage).as_posix(): sha256(p) for p in sorted(stage.rglob('*')) if p.is_file()}
    manifest = {'schema': 1, 'product': 'ClaudeReset', 'version': __version__, 'commit': commit,
                'built_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'python': {k: lock[k] for k in ('python', 'source', 'sha256')}, 'packages': packages,
                'controller_source_sha256': l1_install.source_digest(stage), 'files': files}
    (stage / 'bundle-manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'{stage}  files {len(files)}')
    if not args.no_zip:
        target = out / f'{name}-windows-x64.zip'
        with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in sorted(stage.rglob('*')):
                if path.is_file():
                    bundle.write(path, Path(name) / path.relative_to(stage))
        print(f'{target}  {target.stat().st_size // (1024 * 1024)} MB  sha256 {sha256(target)}')
        setup = out / f'{name}-setup.exe'
        build_setup(stage, target, setup, work)
        print(f'{setup}  {setup.stat().st_size // (1024 * 1024)} MB  sha256 {sha256(setup)}')
    shutil.rmtree(work)


if __name__ == '__main__':
    main()
