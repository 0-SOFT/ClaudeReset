"""Theme preference and the Windows title bar."""
from types import SimpleNamespace

import pytest

from claude_reset import ui_settings


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
    assert ui_settings.system_dark(read=lambda: 0) is True
    assert ui_settings.system_dark(read=lambda: 1) is False

    def missing():
        raise OSError('no value')
    assert ui_settings.system_dark(read=missing) is False


def test_title_bar_uses_the_top_level_window_and_repaints_its_frame():
    calls = []
    window = SimpleNamespace(winfo_id=lambda: 11)
    api = lambda handle, attribute, value, size: calls.append(('set', handle, attribute)) or 0
    redraw = lambda handle, *args: calls.append(('frame', handle, args[-1]))
    assert ui_settings.dark_title_bar(window, True, api=api, parent=lambda child: 99, redraw=redraw) is True
    assert calls == [('set', 99, 20), ('frame', 99, 0x27)]
    failing = lambda *args: 1
    assert ui_settings.dark_title_bar(window, True, api=failing, parent=lambda child: 99, redraw=redraw) is False
