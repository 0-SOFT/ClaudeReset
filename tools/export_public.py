"""Export the public copy of ClaudeReset: code, tests, packaging, licences and user documentation only.

    .venv\\Scripts\\python.exe tools\\export_public.py --out D:\\claudereset-public

No git history, no internal notes (agent instructions, plans, reports, evidence), nothing machine-specific.
The copy is scanned before it is accepted: a secret, a personal detail or an internal note stops the export.
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = ['LICENSE', 'ClaudeReset.cmd', 'requirements-runtime.txt', 'requirements-lock.txt', 'requirements-dev.txt',
           'src/launcher.py', 'src/launcher_run.py', 'src/pyproject.toml', 'src/claude_reset', 'src/tests', 'src/native',
           'packaging/identity', 'packaging/backend', 'packaging/bundle', 'third_party', 'examples',
           'tools',
           'docs/USER-GUIDE.md', 'docs/GUIDE-FRESH-START.md', 'docs/GUI-ACCEPTANCE.md', 'docs/LICENSE-REVIEW-G6.md',
           'docs/USER-GUIDE.en.md', 'docs/GUI-ACCEPTANCE.en.md', 'docs/LICENSE-REVIEW-G6.en.md']  # NOTICES.en.md comes with third_party
# Internal release-process tools of the private repository (they read its plans) and their tests.
SKIP_TOOLS = {'release_checkpoint.py', 'release_acceptance.py', 'package_release.py', 'package_service_bundle.py',
              # one-off maintenance scripts of the development stand (they name its folders)
              'desktop_policy_set.py', 'l1_gate_test.py', 'l1_legacy_cleanup.py', 'l1_sublayer_cleanup.py'}
SKIP_TESTS = {'test_release_contract.py', 'test_package_release_gate.py', 'test_source_supplement.py'}
# Words and addresses of the development stand are listed only in the private repository, so the public copy
# does not name them; without that file (in the public copy) only the general checks run.
PRIVATE_PATTERNS = ROOT / 'packaging/private/forbidden-patterns.json'
GITIGNORE = '.venv/\n__pycache__/\n.pytest_cache/\n*.py[cod]\nbuild/\n*.dpapi\n/controller/\n'
FORBIDDEN = {
    'private key': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    'token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}|\bsk-(?:ant-)?[A-Za-z0-9_\-]{24,}|\bAKIA[0-9A-Z]{16}\b'),
    'vless link': re.compile(r'vless://[0-9a-fA-F-]{36}@'),
    'personal e-mail': re.compile(r'[A-Za-z0-9._%+-]+@(?:hotmail|gmail|outlook|yandex|mail|icloud)\.[a-z]{2,}', re.I),
    'user folder': re.compile(r'(?i)[A-Z]:[\\/]+Users[\\/]+(?!<|\{|%|Public|Default|Private|someone|alice|bob|user[\\/])[A-Za-z0-9._-]+'),
}


def forbidden():
    patterns = dict(FORBIDDEN)
    if PRIVATE_PATTERNS.is_file():
        for label, pattern in json.loads(PRIVATE_PATTERNS.read_text(encoding='utf-8')).items():
            patterns[label] = re.compile(pattern)
    return patterns


def copy(out):
    for relative in INCLUDE:
        source = ROOT / relative
        target = out / relative
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.pytest_cache'))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    for name in SKIP_TESTS:
        (out / 'src/tests' / name).unlink()
    for name in SKIP_TOOLS:
        (out / 'tools' / name).unlink()
    shutil.copy2(ROOT / 'packaging/public/README.md', out / 'README.md')
    shutil.copy2(ROOT / 'packaging/public/README.ru.md', out / 'README.ru.md')
    shutil.copy2(ROOT / 'packaging/public/DEVELOPMENT.md', out / 'docs/DEVELOPMENT.md')
    for notes in (ROOT / 'packaging/public').glob('RELEASE-NOTES-*.md'):
        shutil.copy2(notes, out / 'docs' / notes.name)
    (out / '.gitignore').write_text(GITIGNORE, encoding='utf-8')


def scan(out):
    findings = []
    patterns = forbidden()
    for path in sorted(out.rglob('*')):
        if not path.is_file() or path.suffix in ('.gz', '.ttf', '.msix', '.exe', '.png'):
            continue
        data = path.read_bytes().decode('utf-8', 'ignore')
        for label, pattern in patterns.items():
            if pattern.search(data):
                findings.append((label, path.relative_to(out).as_posix()))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit('Output folder is not empty: ' + str(out))
    copy(out)
    findings = scan(out)
    for label, path in findings:
        print(f'{label}: {path}')
    if findings:
        raise SystemExit(f'{len(findings)} findings; nothing is ready to publish')
    files = sum(1 for p in out.rglob('*') if p.is_file())
    print(f'{out}  files {files}  scan clean')


if __name__ == '__main__':
    sys.exit(main())
