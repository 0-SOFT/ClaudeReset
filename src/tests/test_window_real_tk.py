"""Real (hidden) Tk window on an isolated profile: every plan-table capability has a wired button,
and the read-only buttons run to completion without an error dialog."""
import gc
import os
import time
import tkinter as tk

import pytest

from claude_reset.ui import expert_window as app
from claude_reset.windows import system as windows
from claude_reset.layout import Paths
from dialog_fakes import Dialogs

# Plan v4 section 2: capability -> visible button text (substring).
CAPABILITIES = {
    'proxy form: check': 'Проверить прокси',
    'proxy form: save with confirmed exit': 'Сохранить прокси и выход',
    'VLESS import': 'Импортировать VLESS+Reality',
    'VLESS engine install': 'Установить движок VLESS',
    'proxy / engine removal': 'Снять прокси или движок',
    'controller reinstall': 'Переустановить контроллер',
    'wizard progress': 'Обновить ход',
    'wizard next step': 'Следующий шаг',
    'L1 install': 'Включить защиту L1',
    'L1 status': 'Обновить состояние L1',
    'L1 restart': 'Перезапустить L1',
    'L1 remove': 'Снять защиту L1',
    'change proxy': 'Применить проверенный прокси',
    'exit mismatch: accept new exit': 'Подтвердить новый выход и перезапустить',
    'exit unreachable: retry': 'Повторить проверку',
    'login refused: re-enter': 'Ввести реквизиты',
    'VS Code extension switch': 'Применить выбор расширения',
    'cleanup preview': 'Предпросмотр и размеры',
    'cleanup execute': 'Выполнить выбранную очистку',
    'zero-remainder audit': 'Проверить остатки файлов',
    'resolve: close processes': 'Закрыть процессы Claude',
    'resolve: stop Cowork service': 'Остановить службу Cowork',
    'resolve: export Cowork': 'Устранить: экспорт Cowork',
    'resolve: extra entries': 'Устранить: дополнительные записи',
    'resolve: unlisted version': 'Устранить: неизвестная версия',
    'browser site data': 'Удалить cookies и IndexedDB Claude',
    'device keys plan': 'План ключей Desktop',
    'server checklist': 'Я выполнил нужный отзыв на сервере',
    'diagnostics report': 'Проверить и показать отчёт без секретов',
    'time zone / language advice': 'Совет по языку и поясу',
    'open time settings': 'Открыть настройки времени',
    'open language settings': 'Открыть настройки языка',
}
READ_ONLY = ['Проверить комплект справки', 'Анализ без изменений', 'Предпросмотр и размеры', 'Проверить остатки файлов',
             'Обновить состояние L1', 'Проверить и показать отчёт без секретов',
             'Журнал сброса и стирания без секретов', 'Совет по языку и поясу', 'Обновить ход']


@pytest.fixture(scope='module')
def host_state():
    # Platform inspection needs the real environment; take it before the profile is redirected.
    return windows.inspect_windows()


@pytest.fixture
def window(tmp_path, monkeypatch, host_state, tk_root):
    home = tmp_path / 'user'
    for sub in ('AppData/Roaming', 'AppData/Local'):
        (home / sub).mkdir(parents=True)
    (tmp_path / 'pd').mkdir()
    monkeypatch.setenv('USERPROFILE', str(home))
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('APPDATA', str(home / 'AppData/Roaming'))
    monkeypatch.setenv('LOCALAPPDATA', str(home / 'AppData/Local'))
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'pd'))
    shown = []
    dialogs = Dialogs(**{name: (lambda *a, _n=name, **k: shown.append((_n, a)) or False)
                         for name in ('showinfo', 'showwarning', 'showerror', 'askyesno')})
    root = tk.Toplevel(tk_root)
    root.withdraw()
    ui = app.App(root=root, paths=Paths.current(tmp_path / 'state'), dialogs=dialogs)
    ui.inspect = lambda: host_state
    yield ui, root, shown
    root.destroy()
    # Tk variables of this window must be finalized here, on the main thread: a collection that happens
    # to run in the next test's worker thread would block in Variable.__del__ waiting for Tcl.
    gc.collect()


def buttons(widget):
    for child in widget.winfo_children():
        if child.winfo_class() == 'TButton':
            yield child
        yield from buttons(child)


def all_controls(widget):
    for child in widget.winfo_children():
        if child.winfo_class() in ('TButton', 'TCheckbutton', 'TRadiobutton'):
            yield child
        yield from all_controls(child)


def pump(root, ui, limit=30):
    end = time.time() + limit
    while time.time() < end:
        root.update()
        time.sleep(0.02)
        if not ui.busy:
            root.update()
            return
    raise AssertionError('operation did not finish')


def test_every_command_button_is_wired_and_every_capability_has_a_control(window):
    ui, root, _ = window
    texts, unwired = [], []
    for tab in ui.tabs.tabs():
        for control in all_controls(root.nametowidget(tab)):
            texts.append(str(control.cget('text')))
            if control.winfo_class() == 'TButton' and not control.cget('command'):
                unwired.append(texts[-1])
    assert not unwired
    missing = [name for name, text in CAPABILITIES.items() if not any(text in t for t in texts)]
    assert not missing


@pytest.mark.parametrize('text', READ_ONLY)
def test_read_only_button_runs_without_error_dialog(window, text):
    ui, root, shown = window
    matches = [b for tab in ui.tabs.tabs() for b in buttons(root.nametowidget(tab)) if b.cget('text') == text]
    assert len(matches) == 1
    matches[0].invoke()
    pump(root, ui)
    assert not [d for d in shown if d[0] in ('showerror',)]


def test_wizard_progress_marks_every_step_on_an_empty_profile(window):
    ui, root, shown = window
    states = {k: v.get() for k, v in ui.wizard_states.items()}
    assert set(states.values()) == {'ещё не проверено'}
    [b for b in buttons(root.nametowidget(ui.tabs.tabs()[0])) if b.cget('text') == 'Обновить ход'][0].invoke()
    pump(root, ui)
    states = {k: v.get() for k, v in ui.wizard_states.items()}
    assert states['server'] == states['cleanup'] == '○ не сделано'
    assert states['checks'] == '… после остальных шагов'
    assert ui.wizard_next == 'server'
    next_button = [b for b in buttons(root.nametowidget(ui.tabs.tabs()[0])) if b.cget('text') == 'Следующий шаг'][0]
    next_button.invoke()
    assert root.nametowidget(ui.tabs.select()) is ui.wizard_pages['server']


def test_empty_proxy_form_explains_what_to_fix(window):
    ui, root, shown = window
    check = [b for tab in ui.tabs.tabs() for b in buttons(root.nametowidget(tab)) if b.cget('text') == 'Проверить прокси'][0]
    check.invoke()
    pump(root, ui)
    assert shown and shown[-1][0] == 'showwarning'
    assert 'IPv4' in shown[-1][1][1]
