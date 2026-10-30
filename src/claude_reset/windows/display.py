"""What the windows need from Windows: private fonts, DPI awareness, the apps theme, a dark title bar, starting
the program again. Each call affects this process or its own windows only."""
from __future__ import annotations

import ctypes
import subprocess
import winreg
from collections.abc import Callable, Sequence
from pathlib import Path

__all__ = ['add_private_font', 'apps_use_dark_theme', 'set_dark_title_bar', 'set_dpi_awareness', 'start_program']

FR_PRIVATE = 0x10
THEME_KEY = r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
# SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED: repaint the frame where it is.
REPAINT_FRAME = 0x1 | 0x2 | 0x4 | 0x20


def add_private_font(path: Path) -> int:
    """Load a font for this process only; the number of fonts added (0 when it failed)."""
    return ctypes.windll.gdi32.AddFontResourceExW(str(path), FR_PRIVATE, 0)


def set_dpi_awareness() -> None:
    """Crisp text on scaled displays (system DPI aware); raises when Windows refuses."""
    ctypes.windll.shcore.SetProcessDpiAwareness(1)


def apps_use_dark_theme() -> bool:
    """Windows apps theme: AppsUseLightTheme = 0 means dark. Raises OSError when the value is missing."""
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, THEME_KEY) as key:
        return winreg.QueryValueEx(key, 'AppsUseLightTheme')[0] == 0


def set_dark_title_bar(window_id: int, on: bool, *, api: Callable = ctypes.windll.dwmapi.DwmSetWindowAttribute,
                       parent: Callable = ctypes.windll.user32.GetParent,
                       redraw: Callable | bool = ctypes.windll.user32.SetWindowPos) -> bool:
    """The title bar of this program's window in dark or light colours (Windows 10 20H1 and later).

    redraw=False leaves the frame to repaint on its own."""
    handle = parent(window_id) or window_id   # Tk's frame lives inside the top-level window
    value = ctypes.c_int(1 if on else 0)
    done = api(handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value)) == 0
    if done and redraw is not False:
        # The frame repaints only when told.
        redraw(handle, 0, 0, 0, 0, 0, REPAINT_FRAME)
    return done


def start_program(command: Sequence[str], cwd: Path) -> None:
    """Start another process of the program and do not wait for it."""
    subprocess.Popen(list(command), cwd=str(cwd))
