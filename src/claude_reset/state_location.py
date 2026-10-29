"""One explicit archive location shared by packaged and ordinary launchers.

The selection contains a path only, never service instructions or credentials.
Discovery reads directory metadata, never decrypts or migrates old archives.
"""
from __future__ import annotations
import ctypes
import json
import os
from pathlib import Path
import uuid
from .safeio import SafetyError, atomic_json, guarded, local_volume
from .jsonc import unique

MARKERS = ('runs', 'key-runs', 'cowork-runs', 'customization-runs', 'ChromeProfiles',
           'ClaudeOnlyVSCode', 'connection.dpapi', 'strict-guard', 'operation.lock')


def physical_local_appdata():
    if os.name != 'nt':
        raise SafetyError('This build targets Windows')
    # NO_PACKAGE_REDIRECTION: same known folder for packaged and ordinary hosts.
    folder = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091').bytes_le)
    shell, ole = ctypes.WinDLL('shell32'), ctypes.WinDLL('ole32')
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    result = ctypes.c_void_p()
    try:
        if shell.SHGetKnownFolderPath(ctypes.byref(folder), 0x10000, None, ctypes.byref(result)) != 0:
            raise SafetyError('Unredirected LocalAppData is unavailable')
        return Path(ctypes.wstring_at(result))
    finally:
        if result.value: ole.CoTaskMemFree(result)


def selection_file(home):
    # Outside AppData redirection. This belongs to ClaudeReset, not Claude/Codex.
    return local_volume(Path(home)) / '.claude-reset' / 'state-root.json'


def validate_root(path, home):
    path = local_volume(Path(path))
    if not path.is_absolute() or str(path).startswith(('\\\\', '//')):
        raise SafetyError('State root must be an absolute local path')
    path = guarded(path, path, allow_root=True)
    home = Path(home)
    if path == Path(path.anchor) or path == home or path.is_relative_to(home / '.claude'):
        raise SafetyError('Invalid application-state location')
    if path.exists() and not path.is_dir():
        raise SafetyError('State root is not a directory')
    return path


def discover(home, physical_local, environment_local):
    home, local = Path(home), Path(physical_local)
    candidates = [local / 'ClaudeReset', Path(environment_local) / 'ClaudeReset']
    packages = guarded(local / 'Packages', local)
    if packages.exists():
        for package in sorted(packages.glob('OpenAI.Codex_*')):
            guarded(package, packages)
            candidates.append(package / 'LocalCache/Local/ClaudeReset')
    found, seen = [], set()
    for candidate in candidates:
        path = validate_root(candidate, home)
        key = os.path.normcase(str(path))
        if key in seen: continue
        seen.add(key)
        markers = [name for name in MARKERS if guarded(path / name, path).exists()] if path.exists() else []
        # Any existing entry can represent unrecognized state. Never hide it by
        # silently choosing a new empty directory on schema drift.
        nonempty = path.exists() and next(path.iterdir(), None) is not None
        found.append({'path':str(path), 'exists':path.exists(), 'nonempty':nonempty, 'markers':markers})
    return found


def read_selection(home):
    file = selection_file(home)
    guarded(file, file.parent)
    if not file.exists(): return None
    # Bound the actual read, including growth after a metadata snapshot.
    with file.open('rb') as stream: raw = stream.read(8193)
    if len(raw) > 8192: raise SafetyError('State selection exceeds size limit')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError): raise SafetyError('Invalid state selection') from None
    if (not isinstance(data, dict) or set(data) != {'schema','state_root'}
            or type(data['schema']) is not int or data['schema'] != 1
            or not isinstance(data['state_root'], str)):
        raise SafetyError('Unknown state selection schema')
    path = validate_root(data['state_root'], home)
    if not path.is_dir():
        raise SafetyError('Selected state root is missing; refusing to create a replacement')
    return path


def resolve(home, physical_local, environment_local, explicit=None):
    if explicit is not None: return validate_root(explicit, home)
    selected = read_selection(home)
    if selected is not None: return selected
    candidates = discover(home, physical_local, environment_local)
    existing = [row for row in candidates if row['nonempty']]
    if existing:
        raise SafetyError('Existing application state requires an explicit selection. Use --state-inspect, then --state-select PATH; archives will not be moved.')
    # New installations use a nonredirected per-user location outside AppData.
    # Persisting the first selection is a separate explicit operation.
    return validate_root(Path(home) / '.claude-reset/state', home)


def select(home, path):
    selected = validate_root(path, home)
    # Selection is not migration. Require an existing directory so a typo cannot
    # switch the user to a fresh empty archive store.
    if not selected.is_dir(): raise SafetyError('Choose an existing state directory; no data is moved')
    file = selection_file(home)
    guarded(file, file.parent)
    atomic_json(file, {'schema':1,'state_root':str(selected)}, file.parent)
    return {'selected':True, 'state_root':str(selected), 'archives_moved':False, 'network_authorized':False}


def inspect(home, physical_local, environment_local):
    selected = read_selection(home)
    candidates = discover(home, physical_local, environment_local)
    return {'schema':1,'read_only':True,'selection_file':str(selection_file(home)),
            'selected':str(selected) if selected else None,'candidates':candidates,
            'default_new_state':str(Path(home) / '.claude-reset/state'),
            'selection_required':selected is None and any(row['nonempty'] for row in candidates),
            'archives_moved':False,'network_authorized':False}
