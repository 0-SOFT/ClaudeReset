from __future__ import annotations
import base64
import hashlib
from pathlib import Path, PurePosixPath
import re
import sqlite3
from contextlib import closing
from ..errors import SafetyError
from ..safeio import guarded, walk_files, atomic_bytes

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


def db_keys(path: Path, root: Path):
    guarded(path, root)
    for suffix in ('-wal', '-journal'):
        journal = guarded(Path(str(path) + suffix), root)
        if journal.exists() and journal.stat().st_size:
            raise SafetyError('Database has a pending journal; close and recover the client before planning', code='database_journal_pending')
    try:
        # No WAL exists: immutable read avoids creating or modifying shared memory
        # and acquires no write locks during inventory. A pending WAL is blocked.
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)) as connection:
            columns = {row[1] for row in connection.execute('PRAGMA table_info(ItemTable)')}
            if not {'key', 'value'} <= columns:
                raise SafetyError('Unknown VS Code database schema')
            return [row[0] for row in connection.execute('SELECT key FROM ItemTable')]
    except sqlite3.Error:
        raise SafetyError('VS Code database is unavailable') from None


def owned_vscode_key(key: str):
    return key.lower() == 'anthropic.claude-code'


def reset_vscode_db(path: Path, root: Path):
    keys = [k for k in db_keys(path, root) if owned_vscode_key(k)]
    try:
        with closing(sqlite3.connect(path, timeout=2)) as connection, connection:
            connection.execute('PRAGMA secure_delete=ON')
            connection.execute('BEGIN IMMEDIATE')
            connection.executemany('DELETE FROM ItemTable WHERE key=?', [(k,) for k in keys])
            if connection.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise SafetyError('VS Code database validation failed')
    except sqlite3.Error:
        raise SafetyError('VS Code database transaction failed') from None
    if any(owned_vscode_key(k) for k in db_keys(path, root)):
        raise SafetyError('VS Code record was not cleared')


def vscode_databases(code_user: Path):
    guarded(code_user, code_user, allow_root=True)
    if not code_user.exists():
        return []
    profiles = [code_user]
    named = guarded(code_user / 'profiles', code_user)
    if named.exists():
        profiles.extend(guarded(p, code_user) for p in named.iterdir() if p.is_dir())
    directories = []
    for profile in profiles:
        directories.append(profile / 'globalStorage')
        workspaces = guarded(profile / 'workspaceStorage', code_user)
        if workspaces.exists():
            directories.extend(guarded(p, code_user) for p in workspaces.iterdir() if p.is_dir())
    result = []
    for directory in directories:
        for name in ('state.vscdb', 'state.vscdb.backup'):
            path = guarded(directory / name, code_user)
            if path.is_file():
                result.append(path)
    return result

