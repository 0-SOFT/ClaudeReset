"""Window preferences of this user (theme and language) and the Windows look that follows them.

Not program state: losing the file only resets the theme to "as in Windows" and the language to Russian."""
import json

from ..safeio import atomic_json
from .. import layout
from ..windows import display

CHOICES = ('system', 'light', 'dark')
LANGUAGES = ('ru', 'en')  # Russian by default; English is one click away


def location(paths):
    return layout.tool_home(paths) / 'ui.json'


def _read(paths):
    try:
        data = json.loads(location(paths).read_text('utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(paths, key, value):
    path = location(paths)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in _read(paths).items() if k in ('theme', 'language')}
    atomic_json(path, dict(data, schema=1, **{key: value}), path.parent)


def theme(paths):
    value = _read(paths).get('theme')
    return value if value in CHOICES else 'system'


def save_theme(paths, value):
    if value not in CHOICES:
        raise ValueError('Unknown theme')
    _write(paths, 'theme', value)


def language(paths):
    value = _read(paths).get('language')
    return value if value in LANGUAGES else 'ru'


def save_language(paths, value):
    if value not in LANGUAGES:
        raise ValueError('Unknown language')
    _write(paths, 'language', value)


def system_dark(*, read=None):
    """Windows apps theme: AppsUseLightTheme = 0 means dark. Unknown means light."""
    try:
        if read is None:
            return display.apps_use_dark_theme()
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
        return display.set_dark_title_bar(window.winfo_id(), on, api=api, parent=parent, redraw=redraw)
    except Exception:
        return False
