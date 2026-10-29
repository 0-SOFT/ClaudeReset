"""The installed program: where it lives and how it removes itself. No Tk.

The installer puts a per-user copy in %LOCALAPPDATA%\\Programs\\ClaudeReset:
  ClaudeReset.exe, ClaudeReset.ico  the launcher and its icon
  current.txt                       the version folder to start, e.g. app-1.0.0
  app-<version>\\                    python, src, controller, docs
and records shortcuts and the uninstall entry for the current user only (no administrator rights).
A source checkout or the portable ZIP is not an installation: it is removed by deleting its folder.
"""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNINSTALL_KEY = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeReset'
VERSION_DIR = re.compile(r'app-[0-9A-Za-z.\-]+')
DETACHED, NO_WINDOW = 0x00000008, 0x08000000


def installation(root=ROOT):
    """The install folder when this copy runs from it, else None."""
    home, pointer = root.parent, root.parent / 'current.txt'
    if not VERSION_DIR.fullmatch(root.name) or not pointer.is_file():
        return None
    try:
        current = pointer.read_text('utf-8-sig').strip()
    except OSError:
        return None
    return home if current == root.name else None


class Registry:
    """The current user's uninstall entry (HKCU)."""

    def values(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
                result, index = {}, 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        return result
                    result[name], index = value, index + 1
        except FileNotFoundError:
            return {}

    def delete(self):
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY)
        except FileNotFoundError:
            pass


def remove_shortcuts(values, home):
    """Only the shortcuts the installer recorded, only named ClaudeReset.lnk."""
    removed = 0
    for key in ('ShortcutStartMenu', 'ShortcutDesktop'):
        path = values.get(key)
        if isinstance(path, str) and path and Path(path).name == 'ClaudeReset.lnk' and Path(path).is_file():
            Path(path).unlink()
            removed += 1
    return removed


def schedule_folder_removal(home, *, spawn=subprocess.Popen):
    """The running program holds its own files: a detached cmd deletes the folder a few seconds after it exits."""
    if not (home / 'current.txt').is_file() or home.name != 'ClaudeReset':
        raise ValueError('Not an installation folder')
    spawn(['cmd.exe', '/d', '/c', f'ping -n 6 127.0.0.1 >nul & rmdir /s /q "{home}"'],
          cwd=os.environ.get('SystemRoot', 'C:\\Windows'), creationflags=DETACHED | NO_WINDOW, close_fds=True)


def plan(paths, *, root=ROOT, summary=None):
    """What uninstalling will do, in plain words, before anything changes."""
    from . import proxy_flow
    home = installation(root)
    state = (summary or proxy_flow.summary)(paths)
    protection = state['state'] not in ('off', 'unknown') or bool(state.get('proxy_saved'))
    archives = paths.state.is_dir() and any(paths.state.iterdir())
    return {'installed': home is not None, 'protection': protection, 'archives': archives,
            'archives_folder': str(paths.state)}


def uninstall(paths, *, root=ROOT, step=lambda label, fn, uac=False: fn(), summary=None, remove_protection=None,
              registry=None, spawn=subprocess.Popen):
    """Switch the protection off first (UAC), then remove shortcuts, the uninstall entry and the program folder.

    Saved archives (memory copies) stay where they are; the result names their folder."""
    from . import l1_remove
    home = installation(root)
    if home is None:
        return {'status': 'not_installed'}
    if plan(paths, root=root, summary=summary)['protection']:
        report = step('remove', lambda: (remove_protection or l1_remove.run)(paths), uac=True)
        if report.get('status') != 'removed':
            return {'status': 'protection_not_removed'}
    registry = registry or Registry()
    values = registry.values()
    shortcuts = remove_shortcuts(values, home)
    registry.delete()
    schedule_folder_removal(home, spawn=spawn)
    return {'status': 'removed', 'shortcuts_removed': shortcuts, 'archives_folder': str(paths.state)}
