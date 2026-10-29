from __future__ import annotations
import base64
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import uuid
from contextlib import closing
from .safeio import SafetyError, guarded, walk_files, fingerprint, remove_owned, atomic_json, atomic_bytes
from .windows import DPAPI, inspect_windows
from . import __version__
from .compatibility import CLIENTS

SUPPORTED = ('code', 'vscode', 'chrome')
AUTH_VARS = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
             'ANTHROPIC_PROFILE', 'ANTHROPIC_FEDERATION_RULE_ID', 'ANTHROPIC_ORGANIZATION_ID',
             'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY')
MEMORY_LIMIT = 64 * 1024 * 1024
KNOWN_CLI_VERSIONS = CLIENTS['code']['reset_versions']
KNOWN_EXTENSION_VERSIONS = CLIENTS['vscode']['reset_versions']
SECRET_PATTERNS = (r'sk-ant-[A-Za-z0-9_-]+', r'(?i)(accessToken|refreshToken|api[_-]?key)\s*[=:]')
GEO_PATTERNS = (r'(?i)Europe/Moscow|Russian Standard Time|Москва|Россия|\bRussia\b',)


@dataclass
class Paths:
    home: Path
    roaming: Path
    local: Path
    state: Path

    @classmethod
    def current(cls, state_root=None):
        if os.name != 'nt':
            raise SafetyError('This build targets Windows')
        from .state_location import resolve, physical_local_appdata
        home, local = Path.home(), Path(os.environ['LOCALAPPDATA'])
        state = resolve(home, physical_local_appdata(), local, explicit=state_root)
        result = cls(home, Path(os.environ['APPDATA']), local, state)
        result.validate()
        return result

    def validate(self):
        for p in (self.home, self.roaming, self.local, self.state):
            guarded(p, p, allow_root=True)
        if self.state == self.home or self.state.is_relative_to(self.home / '.claude'):
            raise SafetyError('Invalid application-state location')


@dataclass
class Action:
    kind: str
    target: str
    root: str
    component: str
    description: str
    before: str


def _report_versions(value):
    # Version resources and extension manifests are client-controlled input.
    # Keep exact values in the local plan for compatibility checks, but never
    # copy arbitrary manifest text or objects into the diagnostic export.
    def version(item):
        if item is None:return None
        if isinstance(item,str) and re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){2,3}',item):return item
        return 'unknown'
    def versions(items):
        return [version(item) for item in items] if isinstance(items,list) else ['unknown']
    if not isinstance(value,dict):value={}
    return {'cli':version(value.get('cli')),'extension':versions(value.get('extension',[])),
            'desktop':versions(value.get('desktop',[]))}


@dataclass
class Plan:
    id: str
    created_utc: str
    components: list[str]
    actions: list[Action] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    memory_count: int = 0
    memory_risks: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    complete_reset_supported: bool = False
    server_status: str = 'not_verified'
    network_status: str = 'not_verified'
    selection: object = None
    inventory: object = None
    data_size: dict = field(default_factory=lambda: {'files': 0, 'bytes': 0, 'complete': True})

    def redacted(self):
        # No user paths, old identifiers, account names, tokens or stable hashes.
        return {'version': __version__, 'run': self.id, 'created_utc': self.created_utc,
                'components': self.components, 'action_counts': {c: sum(a.component == c for a in self.actions) for c in self.components},
                'blockers': self.blockers, 'observations': self.observations,
                'memory_count': self.memory_count, 'memory_risks': self.memory_risks,
                'versions': _report_versions(self.versions),
                'complete_reset_supported': False, 'server_status': self.server_status,
                'network_status': self.network_status,
                'data_size': self.data_size,
                'inventory': self.inventory.redacted() if self.inventory else {},
                'coverage': {'local_reset': 'planned' if not self.blockers else 'blocked',
                             'authorization': 'not_verified', 'desktop_keys': 'preserved_not_verified',
                             'environment': 'residual_fields_available', 'network': 'not_verified',
                             'ready_for_new_account': False}}


def read_json(path: Path, root: Path):
    path = guarded(path, root)
    if not path.exists():
        return {}
    if path.stat().st_size > 20_000_000:
        raise SafetyError('Configuration file is too large')
    try:
        obj = json.loads(path.read_text('utf-8-sig'))
    except (ValueError, UnicodeError, OSError):
        raise SafetyError('Configuration cannot be parsed safely') from None
    if not isinstance(obj, dict):
        raise SafetyError('Unknown configuration format')
    return obj


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
            raise SafetyError('Database has a pending journal; close and recover the client before planning')
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


def new_id():
    return uuid.uuid4().hex


def build_plan(*args, **kwargs):
    from .planner import build_plan as create
    return create(*args, **kwargs)


class Executor:
    def __new__(cls, *args, **kwargs):
        from .execution import Executor as Implementation
        return Implementation(*args, **kwargs)


def recover_memory(paths: Paths, run_id: str, crypto=None):
    from .execution import archive_profiles, operation_lock
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid recovery run ID')
    source = guarded(paths.state / 'runs' / run_id / 'memory.dpapi', paths.state)
    if source.stat().st_size > MEMORY_LIMIT * 2:
        raise SafetyError('Archive too large')
    bundle = json.loads((crypto or DPAPI()).decrypt(source.read_bytes()))
    profiles = archive_profiles(bundle)
    # Recovery exports into its OWN directory, never overwrites a live Claude profile.
    destination = paths.state / 'recovered-memory' / new_id()
    with operation_lock(paths):
        guarded(destination, paths.state)
        destination.mkdir(parents=True)
        for i, profile in enumerate(profiles):
            root = destination if len(profiles) == 1 else destination / ('profile-' + str(i + 1))
            root.mkdir(parents=True, exist_ok=True)
            restore_memory(profile, root)
    return destination
