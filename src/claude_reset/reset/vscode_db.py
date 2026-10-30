"""Claude's own keys in VS Code's state database: which ones there are, and removing exactly those."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from ..errors import SafetyError
from ..safeio import guarded

__all__ = ['db_keys', 'owned_vscode_key', 'reset_vscode_db', 'vscode_databases']


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
