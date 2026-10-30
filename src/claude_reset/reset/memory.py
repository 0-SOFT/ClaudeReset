"""The memory a reset keeps: Claude Code's CLAUDE.md files, gathered into one bundle before the wipe and put back after."""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path, PurePosixPath

from ..errors import SafetyError
from ..safeio import atomic_bytes, guarded, walk_files

__all__ = ['MEMORY_LIMIT', 'SUPPORTED', 'restore_memory', 'snapshot_memory', 'validate_memory_bundle']


SUPPORTED = ('code', 'vscode', 'chrome')


MEMORY_LIMIT = 64 * 1024 * 1024


SECRET_PATTERNS = (r'sk-ant-[A-Za-z0-9_-]+', r'(?i)(accessToken|refreshToken|api[_-]?key)\s*[=:]')


GEO_PATTERNS = (r'(?i)Europe/Moscow|Russian Standard Time|Москва|Россия|\bRussia\b',)


def memory_files(config: Path):
    files = []
    guarded(config, config, allow_root=True)
    if not config.exists():
        return files
    direct = guarded(config / 'CLAUDE.md', config)
    if direct.is_file():
        files.append(direct)
    roots = [config / 'memory', config / 'agent-memory']
    projects = guarded(config / 'projects', config)
    if projects.exists():
        for project in projects.iterdir():
            guarded(project, config)
            if project.is_dir():
                roots.append(project / 'memory')
    for root in roots:
        for file in walk_files(root, config):
            if file.suffix.lower() == '.md':
                files.append(file)
    return sorted(files)


def snapshot_memory(config: Path):
    result = []
    total = 0
    risks = {'files_with_possible_secrets': 0, 'files_with_geo_markers': 0}
    for path in memory_files(config):
        content = path.read_bytes()
        total += len(content)
        if total > MEMORY_LIMIT:
            raise SafetyError('Memory archive size limit exceeded')
        text = content.decode('utf-8', errors='replace')
        risks['files_with_possible_secrets'] += int(any(re.search(x, text) for x in SECRET_PATTERNS))
        risks['files_with_geo_markers'] += int(any(re.search(x, text) for x in GEO_PATTERNS))
        result.append({'path': path.relative_to(config).as_posix(), 'data': base64.b64encode(content).decode(),
                       'sha256': hashlib.sha256(content).hexdigest()})
    return {'schema': 1, 'files': result}, risks


def validate_memory_bundle(bundle):
    if not isinstance(bundle, dict) or bundle.get('schema') != 1 or not isinstance(bundle.get('files'), list):
        raise SafetyError('Unknown memory archive schema')
    total, seen, validated = 0, set(), []
    for record in bundle['files']:
        if not isinstance(record, dict) or not all(isinstance(record.get(k), str) for k in ('path', 'data', 'sha256')):
            raise SafetyError('Invalid memory archive record')
        name = record['path']
        p = PurePosixPath(name)
        if not name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or p.suffix.lower() != '.md' or name.casefold() in seen or str(p) != name:
            raise SafetyError('Unsafe memory archive path')
        allowed = name == 'CLAUDE.md' or p.parts[0] in ('memory', 'agent-memory') or (len(p.parts) >= 4 and p.parts[0] == 'projects' and p.parts[2] == 'memory')
        if not allowed:
            raise SafetyError('Archive entry is not an approved memory file')
        try:
            data = base64.b64decode(record['data'], validate=True)
        except Exception:
            raise SafetyError('Invalid memory data') from None
        total += len(data)
        if total > MEMORY_LIMIT or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise SafetyError('Memory archive integrity check failed')
        seen.add(name.casefold())
        validated.append((name, data))
    return validated


def restore_memory(bundle, config: Path):
    entries = validate_memory_bundle(bundle)
    # Validate every target before any write.
    for name, _ in entries:
        guarded(config / name, config)
    for name, data in entries:
        atomic_bytes(config / name, data, config)
