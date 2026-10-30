"""The installed program: where it lives and how it removes itself. No Tk.

The installer puts a per-user copy in %LOCALAPPDATA%\\Programs\\ClaudeReset:
  ClaudeReset.exe, ClaudeReset.ico  the launcher and its icon
  current.txt                       the version folder to start, e.g. app-1.0.0
  app-<version>\\                    python, src, controller, docs
and records shortcuts and the uninstall entry for the current user only (no administrator rights).
A source checkout or the portable ZIP is not an installation: it is removed by deleting its folder.
"""
import re
from pathlib import Path
from .. import layout
from ..windows import process
from ..windows.registry import UserKey
from ..model.status import Protection, Uninstall
from . import protection

__all__ = ['installation', 'plan', 'schedule_folder_removal', 'uninstall']

ROOT = layout.PROGRAM_DIR
UNINSTALL_KEY = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeReset'
VERSION_DIR = re.compile(r'app-[0-9A-Za-z.\-]+')


def installation(root: Path = ROOT) -> Path | None:
    """The install folder when this copy runs from it, else None."""
    home, pointer = root.parent, root.parent / 'current.txt'
    if not VERSION_DIR.fullmatch(root.name) or not pointer.is_file():
        return None
    try:
        current = pointer.read_text('utf-8-sig').strip()
    except OSError:
        return None
    return home if current == root.name else None


def remove_shortcuts(values: dict, home: Path) -> int:
    """Only the shortcuts the installer recorded, only named ClaudeReset.lnk."""
    removed = 0
    for key in ('ShortcutStartMenu', 'ShortcutDesktop'):
        path = values.get(key)
        if isinstance(path, str) and path and Path(path).name == 'ClaudeReset.lnk' and Path(path).is_file():
            Path(path).unlink()
            removed += 1
    return removed


def schedule_folder_removal(home: Path, *, spawn=None) -> None:
    """The running program holds its own files: the folder is deleted a few seconds after it exits."""
    if not (home / 'current.txt').is_file() or home.name != layout.PRODUCT:
        raise ValueError('Not an installation folder')
    process.remove_folder_later(home, spawn=spawn)


def plan(paths, *, root: Path = ROOT, summary=None) -> dict:
    """What uninstalling will do, in plain words, before anything changes."""
    home = installation(root)
    state = (summary or protection.state)(paths)
    protection = state['state'] not in ('off', 'unknown') or bool(state.get('proxy_saved'))
    archives = paths.state.is_dir() and any(paths.state.iterdir())
    return {'installed': home is not None, 'protection': protection, 'archives': archives,
            'archives_folder': str(paths.state)}


def uninstall(paths, *, root: Path = ROOT, step=lambda label, fn, uac=False: fn(), summary=None,
              remove_protection=None, registry=None, spawn=None) -> dict:
    """Switch the protection off first (UAC), then remove shortcuts, the uninstall entry and the program folder.

    Saved archives (memory copies) stay where they are; the result names their folder."""
    from ..network import l1_remove
    home = installation(root)
    if home is None:
        return {'status': Uninstall.NOT_INSTALLED}
    if plan(paths, root=root, summary=summary)['protection']:
        report = step('remove', lambda: (remove_protection or l1_remove.run)(paths), uac=True)
        if report.get('status') != Protection.REMOVED:
            return {'status': Uninstall.PROTECTION_NOT_REMOVED}
    registry = registry or UserKey(UNINSTALL_KEY)
    values = registry.values()
    shortcuts = remove_shortcuts(values, home)
    registry.delete()
    schedule_folder_removal(home, spawn=spawn)
    return {'status': Uninstall.REMOVED, 'shortcuts_removed': shortcuts, 'archives_folder': str(paths.state)}
