"""The installed program: where it lives and how it removes itself. No Tk.

The installer puts a per-user copy in %LOCALAPPDATA%\\Programs\\ClaudeReset:
  ClaudeReset.exe, ClaudeReset.ico  the launcher and its icon
  current.txt                       the version folder to start, e.g. app-1.0.0
  app-<version>\\                    python, src, controller, docs
and records shortcuts and the uninstall entry for the current user only (no administrator rights).
A source checkout or the portable ZIP is not an installation: it is removed by deleting its folder.
"""
import re
from dataclasses import dataclass
from pathlib import Path

from .. import layout
from ..model.records import present
from ..model.status import Protection, ProtectionState, Uninstall
from ..network import l1_remove
from ..windows import process
from ..windows.registry import UserKey
from . import protection

__all__ = ['UninstallPlan', 'UninstallResult', 'installation', 'plan', 'schedule_folder_removal', 'uninstall']

ROOT = layout.PROGRAM_DIR
UNINSTALL_KEY = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeReset'
VERSION_DIR = re.compile(r'app-[0-9A-Za-z.\-]+')


@dataclass(frozen=True)
class UninstallPlan:
    """What uninstalling will do: whether this copy is installed, the protection goes first, archives stay."""
    installed: bool
    protection: bool
    archives: bool
    archives_folder: str

    def to_json(self) -> dict:
        return {'installed': self.installed, 'protection': self.protection, 'archives': self.archives,
                'archives_folder': self.archives_folder}


@dataclass(frozen=True)
class UninstallResult:
    """How uninstalling ended; a removal names the shortcuts it removed and the folder the archives stay in."""
    status: Uninstall
    shortcuts_removed: int | None = None
    archives_folder: str | None = None

    def to_json(self) -> dict:
        return present(status=self.status, shortcuts_removed=self.shortcuts_removed,
                       archives_folder=self.archives_folder)


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


def schedule_folder_removal(home: Path, *, remove_later=process.remove_folder_later) -> None:
    """The running program holds its own files: the folder is deleted a few seconds after it exits."""
    if not (home / 'current.txt').is_file() or home.name != layout.PRODUCT:
        raise ValueError('Not an installation folder')
    remove_later(home)


def plan(paths, *, root: Path = ROOT, summary=protection.state) -> UninstallPlan:
    """What uninstalling will do, in plain words, before anything changes."""
    home = installation(root)
    state = summary(paths)
    protected = state.state not in (ProtectionState.OFF, ProtectionState.UNKNOWN) or bool(state.proxy_saved)
    archives = paths.state.is_dir() and any(paths.state.iterdir())
    return UninstallPlan(installed=home is not None, protection=protected, archives=archives,
                         archives_folder=str(paths.state))


def uninstall(paths, *, root: Path = ROOT, step=lambda label, fn, uac=False: fn(), summary=protection.state,
              remove_protection=l1_remove.run, registry=UserKey(UNINSTALL_KEY),
              remove_later=process.remove_folder_later) -> UninstallResult:
    """Switch the protection off first (UAC), then remove shortcuts, the uninstall entry and the program folder.

    Saved archives (memory copies) stay where they are; the result names their folder."""
    home = installation(root)
    if home is None:
        return UninstallResult(Uninstall.NOT_INSTALLED)
    if plan(paths, root=root, summary=summary).protection:
        report = step('remove', lambda: remove_protection(paths), uac=True)
        if report.get('status') != Protection.REMOVED:
            return UninstallResult(Uninstall.PROTECTION_NOT_REMOVED)
    values = registry.values()
    shortcuts = remove_shortcuts(values, home)
    registry.delete()
    schedule_folder_removal(home, remove_later=remove_later)
    return UninstallResult(Uninstall.REMOVED, shortcuts_removed=shortcuts, archives_folder=str(paths.state))
