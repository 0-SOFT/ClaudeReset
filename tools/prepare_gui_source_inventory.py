"""Подготовить исходный комплект окна и SPDX без запуска клиентов и выпуска."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claude_reset.help_docs import DOCUMENTS, LICENSE_DOCUMENTS


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(root, names, output):
    """names — явный список исходников; окружение и пользовательские данные не читаются."""
    required = {'ClaudeReset.cmd', 'src/launcher.py', 'src/pyproject.toml',
                'requirements-lock.txt', 'requirements-dev.txt', 'docs/DEVELOPMENT.md'}
    required.update(path for _, path in DOCUMENTS.values())
    required.update(LICENSE_DOCUMENTS)
    selected = required | {n for n in names if n.startswith(('src/', 'tools/'))
                           and Path(n).suffix in ('.py', '.ps1', '.in', '.cs', '.c', '.h', '.cpp', '.toml')}
    blobs = {}
    for name in sorted(selected):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Исходный комплект неполон или содержит ссылку.')
        blobs[name] = path.read_bytes()
    lock = blobs['requirements-lock.txt'].decode('utf-8')
    dependencies = [line.strip().split('==') for line in lock.splitlines()
                    if line.strip() and not line.startswith('#')]
    if any(len(pair) != 2 or not all(pair) for pair in dependencies):
        raise ValueError('Требуется закреплённый список зависимостей.')
    rows = [{'path': n, 'sha256': sha(b), 'bytes': len(b)} for n, b in blobs.items()]
    fingerprint = sha(json.dumps(rows, sort_keys=True).encode())
    scope = ('Исходный комплект окна для проверки, не выпуск и не автономный дистрибутив. '
             'Python/Tcl/Tk, установленные зависимости, движок, драйвер и внешние исходные '
             'архивы не включены. Lock описывает требования разработки, не установку. '
             'Лицензия проекта и право распространения не определены.')
    root_id = 'SPDXRef-GuiSource'
    packages = [dict(SPDXID=root_id, name='ClaudeReset-GUI-source-review',
                     downloadLocation='NOASSERTION', filesAnalyzed=False,
                     licenseConcluded='NOASSERTION', licenseDeclared='NOASSERTION',
                     copyrightText='NOASSERTION', sourceInfo=scope)]
    relations = [dict(spdxElementId='SPDXRef-DOCUMENT', relationshipType='DESCRIBES',
                      relatedSpdxElement=root_id)]
    for i, (name, version) in enumerate(dependencies):
        key = f'SPDXRef-Lock-{i}'
        packages.append(dict(SPDXID=key, name=name, versionInfo=version,
                             downloadLocation='NOASSERTION', filesAnalyzed=False,
                             licenseConcluded='NOASSERTION', licenseDeclared='NOASSERTION',
                             copyrightText='NOASSERTION',
                             sourceInfo='Только requirements-lock.txt; байты зависимости не включены.'))
        relations.append(dict(spdxElementId=root_id, relationshipType='OTHER',
                              relatedSpdxElement=key, comment='Закреплённое требование окружения разработки.'))
    files = []
    for i, row in enumerate(rows):
        key = f'SPDXRef-File-{i}'
        files.append(dict(SPDXID=key, fileName='./' + row['path'],
                          checksums=[dict(algorithm='SHA256', checksumValue=row['sha256'])],
                          licenseConcluded='NOASSERTION', licenseInfoInFiles=['NOASSERTION'],
                          copyrightText='NOASSERTION'))
        relations.append(dict(spdxElementId=root_id, relationshipType='CONTAINS', relatedSpdxElement=key))
    sbom = dict(spdxVersion='SPDX-2.3', dataLicense='CC0-1.0', SPDXID='SPDXRef-DOCUMENT',
                name='ClaudeReset-GUI-source-review',
                documentNamespace='https://spdx.org/spdxdocs/claudereset-gui-' + fingerprint,
                creationInfo=dict(creators=['Tool: prepare_gui_source_inventory.py'],
                                  created=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')),
                documentComment=scope, packages=packages, files=files, relationships=relations)
    output.mkdir(parents=True, exist_ok=False)
    archive = output / 'gui-source-review.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as target:
        for name, data in blobs.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(info, data)
    manifest = dict(schema_version=1, release_ready=False, scope=scope,
                    source_fingerprint=fingerprint, files=rows)
    for name, value in [('source-files.json', manifest), ('source.spdx.json', sbom)]:
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    hashes = {p.name: sha(p.read_bytes()) for p in sorted(output.iterdir())}
    (output / 'SHA256SUMS').write_text(''.join(f'{h}  {n}\n' for n, h in hashes.items()), encoding='utf-8')
    return dict(files=len(rows), declared_dependencies=len(dependencies), release_ready=False, sha256=hashes)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0')
    print(json.dumps(prepare(ROOT, names, args.output), ensure_ascii=False))
