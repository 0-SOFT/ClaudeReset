"""Theme preference and the Windows title bar."""
from types import SimpleNamespace

import pytest

from claude_reset.ui import settings as ui_settings
from claude_reset.windows import display


def test_theme_round_trip_and_defaults(tmp_path):
    paths = SimpleNamespace(home=tmp_path)
    assert ui_settings.theme(paths) == 'system'
    ui_settings.save_theme(paths, 'dark')
    assert ui_settings.theme(paths) == 'dark'
    ui_settings.location(paths).write_text('{"theme": "neon"}', encoding='utf-8')
    assert ui_settings.theme(paths) == 'system'
    ui_settings.location(paths).write_text('not json', encoding='utf-8')
    assert ui_settings.theme(paths) == 'system'
    with pytest.raises(ValueError):
        ui_settings.save_theme(paths, 'neon')


def test_resolve_follows_windows_only_for_system():
    assert ui_settings.resolve('system', system=lambda: True) == 'dark'
    assert ui_settings.resolve('system', system=lambda: False) == 'light'
    assert ui_settings.resolve('light', system=lambda: True) == 'light'
    assert ui_settings.resolve('dark', system=lambda: False) == 'dark'


def test_system_dark_reads_apps_theme():
    assert ui_settings.system_dark(read=lambda: True) is True
    assert ui_settings.system_dark(read=lambda: False) is False

    def missing():
        raise OSError('no value')
    assert ui_settings.system_dark(read=missing) is False


def test_title_bar_uses_the_top_level_window_and_repaints_its_frame():
    calls = []
    api = lambda handle, attribute, value, size: calls.append(('set', handle, attribute)) or 0
    redraw = lambda handle, *args: calls.append(('frame', handle, args[-1]))
    assert display.set_dark_title_bar(11, True, api=api, parent=lambda child: 99, redraw=redraw) is True
    assert calls == [('set', 99, 20), ('frame', 99, 0x27)]
    failing = lambda *args: 1
    assert display.set_dark_title_bar(11, True, api=failing, parent=lambda child: 99, redraw=redraw) is False


def test_title_bar_is_best_effort():
    def gone():
        raise RuntimeError('window destroyed')
    assert ui_settings.dark_title_bar(SimpleNamespace(winfo_id=gone), True) is False


def test_language_is_russian_by_default_and_remembered(tmp_path):
    paths = SimpleNamespace(home=tmp_path)
    assert ui_settings.language(paths) == 'ru'
    ui_settings.save_theme(paths, 'dark')
    ui_settings.save_language(paths, 'en')
    assert ui_settings.language(paths) == 'en' and ui_settings.theme(paths) == 'dark'
    with pytest.raises(ValueError):
        ui_settings.save_language(paths, 'system')
