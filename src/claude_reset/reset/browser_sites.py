"""Narrow offline cleanup; shared browser stores are explicitly unverified."""
import os
import re
import sqlite3
from pathlib import Path
from types import MappingProxyType

from ..errors import BrowsersOpenError, SafetyError
from ..model.confirmation import Confirmation
from ..model.notes import Note
from ..model.status import Reset
from ..safeio import guarded, remove_owned, tree_entries
from ..windows import process
from ..windows.powershell import ps_json

__all__ = ['ORIGIN_DIRS', 'ROOTS', 'external_scope_report', 'manual_cleanup_profiles', 'open_site_settings',
           'site_data']

ROOTS = MappingProxyType({'Chrome': 'Google/Chrome/User Data', 'Edge': 'Microsoft/Edge/User Data'})
ORIGIN_DIRS = ('IndexedDB/https_claude.ai_0.indexeddb.leveldb',
               'IndexedDB/https_claude.ai_0.indexeddb.blob')
COOKIE_MATCH = "host_key IN ('claude.ai', '.claude.ai') OR host_key LIKE '%.claude.ai'"


def manual_cleanup_profiles(paths):
    """Public ordinal list; never expose profile names or stored content."""
    return [{'browser': browser, 'profile_number': number}
            for number, (browser, _) in enumerate(profiles(paths), 1)]


def open_site_settings(paths, profile_number, *, launch=process.start_quietly, environ=os.environ):
    """Open a selected standard profile; deletion stays with the person."""
    selected = profiles(paths)
    if type(profile_number) is not int or not 1 <= profile_number <= len(selected):
        raise SafetyError('Choose an existing profile number from the new list', code='profile_number')
    browser, profile = selected[profile_number - 1]
    relative = ('Google/Chrome/Application/chrome.exe' if browser == 'Chrome'
                else 'Microsoft/Edge/Application/msedge.exe')
    roots = [paths.local] + [Path(environ[key]) for key in ('ProgramFiles', 'ProgramFiles(x86)') if environ.get(key)]
    executable = next((root / relative for root in roots if (root / relative).is_file()), None)
    if executable is None:
        raise SafetyError('The standard browser installation was not found; open the settings of the profile by hand', code='browser_not_found')
    try:
        launch([str(executable), '--profile-directory=' + profile.name,
                ('chrome' if browser == 'Chrome' else 'edge') + '://settings/'])
    except Exception:
        raise SafetyError('The browser settings did not open; do the manual step in the profile', code='browser_settings_failed') from None
    return {'status': Reset.MANUAL_ACTION_REQUIRED, 'browser': browser,
            'profile_number': profile_number, 'all_site_data_verified_absent': False,
            'ready_for_new_account': False,
            'steps': [
                Note('sites.step.check_profile'),
                Note('sites.step.close_tabs'),
                Note('sites.step.open_settings'),
                Note('sites.step.remove'),
                Note('sites.step.recheck'),
                Note('sites.step.close_browser'),
            ],
            'unsupported': [
                Note('sites.unsupported.storage'),
                Note('sites.unsupported.cache'),
                Note('sites.unsupported.profiles'),
            ]}


def browsers_running():
    return ps_json("@(Get-Process -Name chrome,msedge -ErrorAction SilentlyContinue).Count | ConvertTo-Json") != 0


def profiles(paths):
    result = []
    for browser, relative in ROOTS.items():
        root = guarded(paths.local / relative, paths.local)
        if root.exists():
            for child in sorted(root.iterdir()):
                if re.fullmatch(r'Default|Profile [0-9]+', child.name):
                    guarded(child, paths.local)
                    if child.is_dir():
                        result.append((browser, child))
    return result


def _database(path, root):
    guarded(path, root)
    for suffix in ('-wal', '-shm', '-journal'):
        guarded(path.with_name(path.name + suffix), root)
    return sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=0)


def site_data(paths, *, erase=False, confirmation=None, inspect=browsers_running):
    if erase and confirmation is not Confirmation.ERASE:
        raise SafetyError('Erasing site data requires an explicit confirmation')
    try:
        if inspect():
            raise BrowsersOpenError('Close Chrome and Edge yourself and check again')
        rows = []
        for browser, profile in profiles(paths):
            cookies = removed = 0
            directories = [guarded(profile / name, paths.local) for name in ORIGIN_DIRS]
            for directory in directories:
                list(tree_entries(directory, paths.local))
            for relative in ('Network/Cookies', 'Cookies'):
                database = guarded(profile / relative, paths.local)
                if not database.exists():
                    continue
                connection = _database(database, paths.local)
                try:
                    with connection:
                        connection.execute('BEGIN IMMEDIATE' if erase else 'BEGIN')
                        count = connection.execute('SELECT count(*) FROM cookies WHERE ' + COOKIE_MATCH).fetchone()[0]
                        cookies += count
                        if erase:
                            connection.execute('DELETE FROM cookies WHERE ' + COOKIE_MATCH)
                            if connection.execute('SELECT count(*) FROM cookies WHERE ' + COOKIE_MATCH).fetchone()[0]:
                                raise SafetyError('Cookie removal could not be verified', code='cookies_unverified')
                            removed += count
                finally:
                    connection.close()
            found = sum(directory.exists() for directory in directories)
            if erase:
                for directory in directories:
                    remove_owned(directory, paths.local)
            rows.append({'browser': browser, 'profile_number': len(rows) + 1,
                         'cookies_found': cookies, 'cookies_removed': removed,
                         'origin_directories_found': found,
                         'origin_directories_remaining': sum(p.exists() for p in directories)})
        return {'status': Reset.SUPPORTED_DATA_REMOVED if erase else Reset.PREVIEW, 'profiles': rows,
                'profiles_preserved': True, 'all_site_data_verified_absent': False,
                'remaining': [Note('sites.remaining.shared'),
                              Note('sites.remaining.profiles')],
                'ready_for_new_account': False}
    except SafetyError:
        raise
    except Exception:
        raise SafetyError('Site data is unavailable or its schema is not supported; the result may be partial, preview again', code='site_data_unavailable') from None


def external_scope_report():
    """Do not traverse projects or invoke remote runtimes for cleanup."""
    return {'mode': 'report_only', 'changed': False,
            'areas': [{'area': name, 'status': Reset.NOT_INSPECTED, 'action': Note('scope.check_by_hand')}
                      for name in (Note('scope.projects'), Note('scope.environment'), Note('scope.wsl'), Note('scope.docker'), Note('scope.ssh'))]}
