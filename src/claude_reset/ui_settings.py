"""Window preferences of this user (the theme) and the Windows look that follows it.

Not program state: losing the file only resets the choice to "as in Windows"."""
import json

from .safeio import atomic_json

CHOICES = ('system', 'light', 'dark')


def location(paths):
    return paths.home / '.claude-reset' / 'ui.json'


def theme(paths):
    try:
        value = json.loads(location(paths).read_text('utf-8')).get('theme')
    except (OSError, ValueError, AttributeError):
        return 'system'
    return value if value in CHOICES else 'system'


def save_theme(paths, value):
    if value not in CHOICES:
        raise ValueError('Unknown theme')
    path = location(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, {'schema': 1, 'theme': value}, path.parent)


def system_dark(*, read=None):
    """Windows apps theme: AppsUseLightTheme = 0 means dark. Unknown means light."""
    try:
        if read is None:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as key:
                return winreg.QueryValueEx(key, 'AppsUseLightTheme')[0] == 0
        return read() == 0
    except (OSError, ImportError):
        return False


def resolve(choice, *, system=system_dark):
    if choice == 'system':
        return 'dark' if system() else 'light'
    return choice if choice in ('light', 'dark') else 'light'


def dark_title_bar(window, on, *, api=None, parent=None, redraw=None):
    """Title bar of this program's own window in the theme's colours (Windows 10 20H1 and later); best effort."""
    try:
        import ctypes
        api = api or ctypes.windll.dwmapi.DwmSetWindowAttribute
        parent = parent or ctypes.windll.user32.GetParent
        handle = parent(window.winfo_id()) or window.winfo_id()  # Tk's frame lives inside the top-level window
        value = ctypes.c_int(1 if on else 0)
        done = api(handle, 20, ctypes.byref(value), ctypes.sizeof(value)) == 0
        if done and redraw is not False:
            # The frame repaints only when told: SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED.
            (redraw or ctypes.windll.user32.SetWindowPos)(handle, 0, 0, 0, 0, 0, 0x1 | 0x2 | 0x4 | 0x20)
        return done
    except Exception:
        return False
