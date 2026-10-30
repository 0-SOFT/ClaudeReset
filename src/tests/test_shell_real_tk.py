"""The main window on a real (hidden) Tk: navigation, the one-button reset and the proxy path.

Every system call is replaced; questions are answered by the test."""
import gc
import time
import tkinter as tk
from pathlib import Path

import pytest
from claude_reset.model.confirmation import Confirmation

from claude_reset.network import remote_backend
from claude_reset.ui import protection_panel, reset_flow, shell
from claude_reset.layout import Paths
from proxy_fakes import Probe, working
from scripted import Strict

SUMMARY = {'state': 'paused', 'title': 'Защита на паузе', 'text': 'Claude сейчас выходит в интернет напрямую, без прокси.',
           'fix': 'resume', 'proxy': 'VLESS', 'proxy_saved': True, 'clients': [{'name': 'Claude Desktop', 'present': True}]}


def program(summaries=(SUMMARY,), rows=()):
    """The window's program with scripted reads; it has no network or L1: a check it was not given fails the test."""
    value = shell.Program()
    value.protection = lambda paths: summaries[-1]
    value.history = lambda paths: {'rows': list(rows)}
    value.probe, value.l1 = Probe(), Strict()
    return value


class Answers:
    def __init__(self):
        self.asked, self.replies = [], []

    def __call__(self, title, text, buttons=(), lines=(), typed=None):
        self.asked.append({'title': title, 'text': text, 'lines': list(lines), 'typed': typed})
        return self.replies.pop(0) if self.replies else None


@pytest.fixture
def ui(tmp_path, monkeypatch, tk_root):
    home = tmp_path / 'user'
    for sub in ('AppData/Roaming', 'AppData/Local'):
        (home / sub).mkdir(parents=True)
    for name, value in (('USERPROFILE', home), ('HOME', home), ('APPDATA', home / 'AppData/Roaming'),
                        ('LOCALAPPDATA', home / 'AppData/Local')):
        monkeypatch.setenv(name, str(value))
    summaries = [dict(SUMMARY)]
    top = tk.Toplevel(tk_root)
    top.withdraw()
    window = shell.Shell(Paths.current(tmp_path / 'state'), top, theme='light', language='ru',
                         program=program(summaries, [{'status': 'fixed_locations_wiped'}]))
    window.ask = Answers()
    window.summaries = summaries
    pump(window)
    yield window
    top.destroy()
    gc.collect()  # finalize Tk variables on the main thread, never in a later worker thread


def pump(window, limit=20):
    end = time.time() + limit
    while time.time() < end:
        window.root.update()
        time.sleep(.01)
        if not window.worker.busy and window.operation is None:
            window.root.update()
            return
    raise AssertionError('background work did not finish')


def texts(widget):
    for child in widget.winfo_children():
        try:
            yield str(child.cget('text'))
        except tk.TclError:
            pass
        yield from texts(child)


def button(window, page, text):
    def walk(widget):
        for child in widget.winfo_children():
            if child.winfo_class() == 'TButton' and child.cget('text') == text:
                yield child
            yield from walk(child)
    found = list(walk(window.pages[page].inner))
    assert found, text
    return found[0]


def test_home_shows_both_steps_and_real_states(ui):
    shown = list(texts(ui.pages['home'].inner))
    assert 'Начнём с нуля' in shown and 'Перейти к сбросу →' in shown and 'Настроить прокси →' in shown
    assert 'Защита на паузе' in shown and 'Сброс уже выполнялся на этом компьютере' in shown
    for key in ('reset', 'proxy', 'help', 'home'):
        ui.show(key)
        pump(ui)
        assert str(ui.nav[key].cget('style')) == 'NavOn.TButton'
        assert sum(str(b.cget('style')) == 'NavOn.TButton' for b in ui.nav.values()) == 1


def test_every_button_does_something(ui):
    def walk(widget):
        for child in widget.winfo_children():
            if child.winfo_class() == 'TButton':
                yield child
            yield from walk(child)
    assert all(b.cget('command') for page in ui.pages.values() for b in walk(page.inner))
    assert shell.expert_command()[-1] == '--expert'
    assert Path(shell.expert_command()[-2]).name in ('launcher.py', 'ClaudeReset.exe') or len(shell.expert_command()) == 2


class FakeSession:
    instances = []

    def __init__(self, paths, keep_memory=True, **_):
        self.keep_memory, self.accept_unlisted, self.calls = keep_memory, False, []
        self.checks = list(FakeSession.checks)
        FakeSession.instances.append(self)

    def check(self, step):
        self.calls.append('check')
        return step('check', lambda: self.checks.pop(0))

    def resolve(self, step):
        self.calls.append('resolve')
        return step('close_claude', lambda: self.checks.pop(0))

    def wipe(self, word, *, browsers, step):
        self.calls.append(('wipe', word, browsers))
        return step('wipe', lambda: {'status': 'done', 'memory': 'restored_verbatim', 'desktop_keys': 'not_supported',
                                     'browsers': 'browsers_open', 'passwords_removed': 2, 'no_files_left': True})


def found(blockers=()):
    return {'rows': [{'label': 'Desktop', 'bytes': 12 * 1024 ** 3 // 10, 'status': 'present'}],
            'total_bytes': 12 * 1024 ** 3 // 10, 'credentials': 2, 'blockers': list(blockers), 'ready': not blockers, 'nothing_found': False}


AUTO = {'key': 'processes', 'kind': 'auto'}
VSCODE = {'key': 'vscode', 'kind': 'user'}


def test_reset_waits_for_the_site_step(ui):
    ui.program.reset = lambda *a, **k: pytest.fail('started')
    ui.reset_start()
    assert ui.ask.asked[-1]['title'] == 'Сначала сайт Claude'


def test_one_button_reset_resolves_confirms_and_wipes(ui):
    FakeSession.checks, FakeSession.instances = [found([AUTO]), found()], []
    ui.program.reset = FakeSession
    ui.server_done.set(True)
    ui.ask.replies = [True]
    ui.reset_start()
    pump(ui)
    pump(ui)
    session = FakeSession.instances[-1]
    assert session.calls == ['check', 'resolve', ('wipe', Confirmation.ERASE, True)]
    confirm = ui.ask.asked[0]
    assert confirm['typed'] == 'СТЕРЕТЬ' and 'Claude Desktop: вход, история, настройки — 1,2 ГБ' in confirm['lines']
    shown = list(texts(ui.reset_result))
    assert 'Готово ✓' in shown and 'Память Claude Code возвращена на место.' in shown
    assert any('не сброшен' in t for t in shown) and 'Выйти из claude.ai в браузерах' in shown


def test_reset_stops_and_explains_what_the_person_must_do(ui):
    FakeSession.checks, FakeSession.instances = [found([VSCODE])], []
    ui.program.reset = FakeSession
    ui.server_done.set(True)
    ui.reset_start()
    pump(ui)
    assert FakeSession.instances[-1].calls == ['check'] and not ui.ask.asked
    shown = list(texts(ui.reset_result))
    assert 'Нужно сделать вам' in shown and 'Проверить снова' in shown


def test_cancelled_confirmation_deletes_nothing(ui):
    FakeSession.checks, FakeSession.instances = [found()], []
    ui.program.reset = FakeSession
    ui.server_done.set(True)
    ui.ask.replies = [None]
    ui.reset_start()
    pump(ui)
    assert FakeSession.instances[-1].calls == ['check']


def test_wrong_proxy_fields_are_explained_inline(ui):
    ui.show('proxy')
    pump(ui)
    ui.fields['host'].set('proxy.example')
    ui.proxy_go()
    assert 'IPv4' in ui.proxy_error.cget('text')


def test_proxy_check_confirm_and_switch_on(ui):
    ui.summaries.append(dict(SUMMARY, state='off', fix=None, title='Защита выключена'))
    ui.show('proxy')
    pump(ui)
    assert ui.proxy_button.cget('text') == 'Проверить и включить защиту'

    ui.program.probe = working('9.9.9.9')
    boundary = next(iter(protection_panel.LIMITS))
    ui.program.l1 = Strict(boundaries=[boundary], install={'status': 'installed'})
    for key, value in (('host', '9.9.9.9'), ('port', '1080'), ('username', 'u'), ('password', 'secret-pass')):
        ui.fields[key].set(value)
    ui.protect_extension.set(True)
    ui.ask.replies = [True, True, True]
    ui.proxy_go()
    for _ in range(4):
        pump(ui)
    titles = [a['title'] for a in ui.ask.asked]
    assert titles[:2] == ['Прокси работает ✓', 'Перед включением'] and ui.ask.asked[0]['lines'] == ['9.9.9.9']
    assert ui.ask.asked[1]['lines'] == [protection_panel.LIMITS[boundary]]
    assert [(name, kw['protect_extension']) for name, _, kw in ui.program.l1.calls if name != 'boundaries'] == [
        ('install', True)]
    assert remote_backend.load(ui.paths)['password'] == 'secret-pass'   # the checked proxy was saved before the install
    assert all('secret-pass' not in str(a) for a in ui.ask.asked) and 'secret-pass' not in ui.status.get()


@pytest.mark.parametrize('state,fix,expected', [
    ('on', None, ['Проверить сейчас', 'Перезапустить', 'Выключить защиту', 'Обновить защиту после обновления программы']),
    ('problem', 'accept_exit', ['Проверить и принять новый адрес', 'Выключить защиту']),
    ('paused', 'resume', ['Снять с паузы и включить', 'Выключить защиту']),
    ('off', None, ['Удалить сохранённый прокси'])])
def test_protection_card_offers_the_right_actions(ui, state, fix, expected):
    ui.paint_proxy(dict(SUMMARY, state=state, fix=fix, title='T'))
    shown = list(texts(ui.proxy_state))
    assert all(label in shown for label in expected)


def test_typed_dialog_unlocks_only_on_the_exact_word(ui):
    dialog = shell.Dialog(ui, 'Стереть?', 'Текст', buttons=(('Primary', 'Стереть', True), ('Ghost', 'Отмена', None)), typed='СТЕРЕТЬ')
    primary = [w for w in dialog.winfo_children()[0].winfo_children() if w.winfo_class() == 'TFrame'][-1].winfo_children()[0]
    assert primary.instate(['disabled'])
    dialog.word.set('стереть')
    assert primary.instate(['disabled'])
    dialog.word.set('СТЕРЕТЬ')
    assert not primary.instate(['disabled'])
    dialog.destroy()


def test_theme_switch_rebuilds_in_place_and_is_remembered(ui):
    from claude_reset.ui import brand, settings as ui_settings
    ui.show('reset')
    ui.set_theme('dark')
    assert ui.theme.mode == 'dark' and ui.theme.colors['paper'] == brand.DARK['paper']
    assert ui.current == 'reset' and str(ui.nav['reset'].cget('style')) == 'NavOn.TButton'
    assert ui_settings.theme(ui.paths) == 'dark'
    for mode in ('dark', 'light'):
        ui.set_theme(mode)
        # Text on turquoise stays ink in both themes.
        assert ui.theme.style.lookup('Accent.h3.TLabel', 'foreground') == '#0e0e0e'
    assert ui.theme.mode == 'light' and ui.theme.colors['paper'] == brand.LIGHT['paper']


def test_keyboard_reaches_every_step(ui):
    ui.root.event_generate('<Alt-Key-2>')
    assert ui.current == 'reset'
    frame = [f for value, f, _, _ in ui.choices if value == 'none'][0]
    assert str(frame.cget('takefocus')) in ('1', 'True', 'true')
    # Key events go to the focused window: show it off screen so it can take focus.
    ui.root.geometry('+-4000+-4000')
    ui.root.deiconify()
    ui.root.update()
    try:
        frame.focus_force()
        ui.root.update()
        assert str(frame.cget('style')) == 'ChoiceFocus.TFrame'
        frame.event_generate('<space>')
        ui.root.update()
        assert ui.keep_memory.get() == 'none' and str(frame.cget('style')) == 'ChoiceOnFocus.TFrame'
        ui.nav['help'].focus_force()
        ui.root.update()
        ui.nav['help'].event_generate('<Return>')
        ui.root.update()
        assert ui.current == 'help'
    finally:
        ui.root.withdraw()


def test_window_fits_a_small_screen(tk_root, tmp_path):
    top = tk.Toplevel(tk_root)
    top.withdraw()
    top.winfo_screenwidth, top.winfo_screenheight = (lambda: 1000), (lambda: 700)
    window = shell.Shell(Paths.current(tmp_path / 'state'), top, theme='light', language='ru', program=program())
    pump(window)
    size = top.geometry().split('+')[0].split('x')
    assert int(size[0]) <= 920 and int(size[1]) <= 616
    top.destroy()


def test_help_is_rendered_not_raw_markdown(ui):
    before = set(ui.root.winfo_children())
    ui.open_doc('guide')
    window = [w for w in ui.root.winfo_children() if w not in before][0]
    text = [w for w in window.winfo_children() if isinstance(w, tk.Text)][0]
    content = text.get('1.0', 'end')
    assert content.startswith('Руководство ClaudeReset') and '\n## ' not in content and '**' not in content
    assert text.tag_ranges('h1') and text.tag_ranges('h2') and text.tag_ranges('item0')
    window.destroy()


def test_closing_during_a_read_only_check_does_not_ask(ui, monkeypatch):
    import threading
    gate = threading.Event()
    monkeypatch.setattr(ui.root, 'destroy', lambda: setattr(ui, 'closed', True))
    ui.run(lambda step: step('summary', gate.wait), lambda result: None)
    ui.close()
    assert getattr(ui, 'closed', False) and not ui.ask.asked
    gate.set()
    pump(ui)
    ui.closed = False
    hold = threading.Event()
    ui.run(lambda step: step('wipe', hold.wait), lambda result: None)
    end = time.time() + 5
    while not ui.changing and time.time() < end:
        ui.root.update()
    ui.close()
    assert ui.ask.asked[-1]['title'] == 'Закрыть окно?' and not ui.closed
    hold.set()
    pump(ui)


def test_reset_continues_by_itself_once_the_person_closes_vs_code(ui):
    # two checks while VS Code is open, one that sees it closed, and the fresh check before the wipe
    FakeSession.checks, FakeSession.instances = [found([VSCODE]), found([VSCODE]), found(), found()], []
    ui.program.reset = FakeSession
    ui.WATCH_MS = 20
    ui.server_done.set(True)
    ui.ask.replies = [True]
    ui.show('reset')
    pump(ui)
    ui.reset_start()
    end = time.time() + 15
    while time.time() < end and not any(isinstance(c, tuple) for c in FakeSession.instances[-1].calls):
        ui.root.update()
        time.sleep(.01)
    pump(ui)
    assert FakeSession.instances[-1].calls == ['check', 'check', 'check', 'check', ('wipe', Confirmation.ERASE, True)]
    assert ui.ask.asked[0]['typed'] == 'СТЕРЕТЬ'


def test_leaving_the_page_stops_waiting(ui):
    FakeSession.checks, FakeSession.instances = [found([VSCODE])] * 3, []
    ui.program.reset = FakeSession
    ui.WATCH_MS = 400
    ui.server_done.set(True)
    ui.show('reset')
    pump(ui)
    ui.reset_start()
    pump(ui)
    ui.show('home')
    pump(ui)
    end = time.time() + 1
    while time.time() < end:
        ui.root.update()
    assert FakeSession.instances[-1].calls == ['check']


def test_english_window_has_no_russian_anywhere(tk_root, tmp_path):
    import re
    cyrillic = re.compile('[А-Яа-яЁё]')
    top = tk.Toplevel(tk_root)
    top.withdraw()
    try:
        window = shell.Shell(Paths.current(tmp_path / 'state'), top, theme='light', language='en', program=program())
        window.ask = Answers()
        pump(window)

        def russian():
            found = []
            for page in window.pages.values():
                found += [t for t in texts(page.inner) if cyrillic.search(t) and t not in ('Русский', 'РУССКИЙ')]
            found += [t for t in texts(window.root) if cyrillic.search(t) and t not in ('Русский', 'РУССКИЙ')]
            return sorted(set(found))
        for key in ('home', 'reset', 'proxy', 'help'):
            window.show(key)
            pump(window)
        assert russian() == []
        for state, fix in (('on', None), ('problem', 'accept_exit'), ('paused', 'resume'), ('partial', 'install'),
                           ('off', None), ('unknown', None)):
            window.paint_proxy({'state': state, 'fix': fix, 'proxy': 'SOCKS5', 'proxy_saved': True,
                                'title': {'on': 'Защита включена', 'paused': 'Защита на паузе'}.get(state, 'Claude сейчас без сети'),
                                'text': 'Прокси не отвечает. Напрямую Claude не выйдет — так задумано.',
                                'clients': [{'name': 'Claude Code в терминале', 'present': True}]})
            assert russian() == [], state
        window.session = type('S', (), {'keep_memory': True, 'accept_unlisted': False})()
        window.reset_checked({'rows': [{'label': 'Claude Code: история, проекты, память', 'size': '40,3 МБ', 'status': 'present'}],
                              'total': '40,3 МБ', 'credentials': 2, 'nothing_found': False, 'ready': False,
                              'blockers': [{'key': 'vscode', 'kind': 'user', 'text': reset_flow.BLOCKERS['vscode']},
                                           {'key': 'processes', 'kind': 'auto', 'text': reset_flow.BLOCKERS['processes']}]}, False)
        window.stop_watch()
        assert russian() == [] and '40.3 MB' in list(texts(window.reset_result))
        window.reset_done({'stage': 'wiped', 'result': {'status': 'done', 'memory': 'restored_verbatim', 'desktop_keys': 'not_supported',
                                                        'browsers': 'browsers_open', 'passwords_removed': 2, 'no_files_left': True}})
        assert russian() == []
        assert window.ask.asked == []
    finally:
        top.destroy()


def test_russian_by_default_and_english_one_click_away(tk_root, tmp_path):
    from claude_reset.ui import settings as ui_settings
    top = tk.Toplevel(tk_root)
    top.withdraw()
    try:
        window = shell.Shell(Paths.current(tmp_path / 'state'), top, theme='light', program=program())
        pump(window)
        assert window.language.code == 'ru' and str(window.language_button.cget('text')) == 'ENGLISH'
        window.show('reset')
        pump(window)
        window.language_button.invoke()
        pump(window)
        assert window.language.code == 'en' and window.current == 'reset'
        assert str(window.language_button.cget('text')) == 'РУССКИЙ' and 'Reset Claude' in list(texts(window.pages['reset'].inner))
        assert ui_settings.language(window.paths) == 'en'
        window.language_button.invoke()
        pump(window)
        assert window.language.code == 'ru' and ui_settings.language(window.paths) == 'ru'
    finally:
        top.destroy()


def test_english_dialogs_have_english_default_buttons(ui):
    # The default buttons were once worded when the module loaded, so an English window showed Russian ones.
    ui.set_language_choice('en')
    pump(ui)
    dialog = shell.Dialog(ui, 'Title', 'Text')
    try:
        assert 'OK' in list(texts(dialog))
    finally:
        dialog.destroy()
    asked = []
    ui.ask = lambda title, text, buttons=(), lines=(), typed=None: asked.append(buttons)
    ui.confirm('Title', 'Text', 'Yes')
    assert [label for _, label, _ in asked[0]] == ['Yes', 'Cancel']
