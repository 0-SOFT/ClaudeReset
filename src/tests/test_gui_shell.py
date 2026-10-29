"""Build every actual tab using a display-free Tk substitute; never use live paths."""
from types import SimpleNamespace
import json
import pytest

from claude_reset import app


class Widget:
    all = []

    def __init__(self, parent=None, **options):
        self.parent, self.options = parent, options
        self.value = options.get('value', '')
        self.pages, self.scheduled = [], []
        self.selected = None
        self.content, self.protocols = [], {}
        self.destroyed = False
        self.all.append(self)

    def pack(self, **kwargs): pass
    def title(self, *args): pass
    def geometry(self, *args): pass
    def minsize(self, *args): pass
    def protocol(self, name, callback): self.protocols[name] = callback
    def bind(self, *args): pass
    def insert(self, *args): self.content.append(args[-1])
    def delete(self, *args): self.content.clear()
    def destroy(self): self.destroyed = True
    def transient(self, *_): pass
    def winfo_screenwidth(self): return 1200
    def winfo_screenheight(self): return 900
    def selection_set(self, *_): pass
    def curselection(self): return (1,)
    def configure(self, **kwargs): self.options.update(kwargs)
    def set(self, value): self.value = value
    def get(self): return self.value
    def after(self, *args): self.scheduled.append(args)
    def add(self, page, **kwargs): self.pages.append((page, kwargs['text']))
    def select(self, page): self.selected = page
    def yview(self, *args): pass
    def create_window(self, *args, **kwargs): return 1


def test_build_all_tabs_and_navigate_without_actions(monkeypatch, tmp_path):
    Widget.all = []
    for name in ('BooleanVar', 'StringVar', 'Canvas', 'Text'):
        monkeypatch.setattr(app.tk, name, Widget)
    for name in ('Frame', 'Label', 'Checkbutton', 'Radiobutton', 'Notebook', 'Scrollbar', 'Button', 'Entry'):
        monkeypatch.setattr(app.ttk, name, Widget)
    monkeypatch.setattr(app.Worker, 'start', lambda *_: (_ for _ in ()).throw(AssertionError('unexpected startup action')))
    root = Widget()
    ui = app.App(root=root, paths=SimpleNamespace(state=tmp_path))
    assert [label for _, label in ui.tabs.pages] == [
        'Мастер', 'Анализ и операции', 'Очистка', 'Серверные действия', 'Пояс, сеть и память',
        'Сетевая защита Claude', 'Соединение', 'Windows-защита', 'Профили и автоматизация', 'Диагностика']
    wizard = ui.tabs.pages[0][0]
    # Step buttons sit in per-step rows; "Следующий шаг" also only navigates ("Обновить ход" starts a check).
    navigation = [w for w in Widget.all if 'command' in w.options and getattr(w.parent, 'parent', None) is wizard
                  and (w.options.get('text', '')[:1].isdigit() or w.options.get('text') == 'Следующий шаг')]
    assert len(navigation) == 6
    for button in navigation:
        button.options['command']()
        assert ui.tabs.selected in [page for page, _ in ui.tabs.pages[1:]]
    assert not ui.busy and ui.events.empty()
    assert root.scheduled and ui.cancel_button.options['state'] == 'disabled'
    assert all(callable(w.options['command']) for w in Widget.all if 'command' in w.options)


@pytest.fixture
def ui(monkeypatch, tmp_path):
    Widget.all = []
    for name in ('BooleanVar', 'StringVar', 'Canvas', 'Text', 'Toplevel', 'Listbox'):
        monkeypatch.setattr(app.tk, name, Widget)
    for name in ('Frame', 'Label', 'Checkbutton', 'Radiobutton', 'Notebook', 'Scrollbar', 'Button', 'Entry'):
        monkeypatch.setattr(app.ttk, name, Widget)
    monkeypatch.setattr(app.scrolledtext, 'ScrolledText', Widget)
    window = app.App(root=Widget(), paths=SimpleNamespace(state=tmp_path, home=tmp_path, local=tmp_path))
    window.messages = []
    monkeypatch.setattr(app.messagebox, 'showerror', lambda *args: window.messages.append(args))
    monkeypatch.setattr(app.messagebox, 'showinfo', lambda *args: window.messages.append(args))
    return window


def button(label):
    return next(w for w in reversed(Widget.all) if w.options.get('text') == label)


def test_diagnostics_buttons_and_export(ui, monkeypatch, tmp_path):
    from claude_reset import diagnostics
    calls = []
    monkeypatch.setattr(ui, 'run', lambda action, callback: callback(action()))
    monkeypatch.setattr(diagnostics, 'collect', lambda paths: calls.append('collect') or {'schema': 1})
    monkeypatch.setattr(diagnostics, 'operation_history', lambda paths: calls.append('history') or {'rows': []})
    monkeypatch.setattr(diagnostics, 'advise', lambda country: calls.append(country) or {'status': 'unsupported'})
    monkeypatch.setattr(diagnostics, 'open_settings', lambda kind: calls.append(kind))
    path = tmp_path / 'diagnostic.json'
    monkeypatch.setattr(app.filedialog, 'asksaveasfilename', lambda **kw: str(path))
    button('Проверить и показать отчёт без секретов').options['command']()
    button('Сохранить JSON').options['command']()
    assert json.loads(path.read_text(encoding='utf-8')) == {'schema': 1}
    ui.advisor_country.set('DE')
    button('Совет по языку и поясу').options['command']()
    button('Открыть настройки времени').options['command']()
    button('Открыть настройки языка').options['command']()
    assert calls == ['collect', 'DE', 'timezone', 'language']
    monkeypatch.setattr(app.filedialog, 'asksaveasfilename', lambda **kw: '')
    button('Сохранить JSON').options['command']()
    assert json.loads(path.read_text(encoding='utf-8')) == {'schema': 1}
    button('Журнал сброса и стирания без секретов').options['command']()
    assert calls[-1] == 'history'


def test_cleanup_buttons_and_modes(ui, monkeypatch):
    from claude_reset import cleanup
    calls = []
    result = {'rows': [], 'bytes': 0, 'zero_file_remainder': True}
    monkeypatch.setattr(cleanup, 'preview', lambda paths, mode: calls.append(mode) or result)
    monkeypatch.setattr(cleanup, 'prepare_wipe', lambda paths, mode, **kw: SimpleNamespace(blockers=(), mode=mode, credentials=()))
    monkeypatch.setattr(cleanup, 'audit', lambda paths: calls.append('audit') or result)
    monkeypatch.setattr(ui, 'run', lambda action, callback: callback(action()))
    monkeypatch.setattr(ui, 'analyze', lambda: calls.append('reset'))
    for mode in cleanup.MODES:
        ui.cleanup_mode.set(mode)
        button('Предпросмотр и размеры').options['command']()
    button('Проверить остатки файлов').options['command']()
    assert calls == ['reset', 'wipe', 'wipe_memory', 'audit']
    assert 'Полный нулевой остаток не подтверждён' in ui.cleanup_text.content[0]


@pytest.mark.parametrize('answer', ['СТЕРЕТЬ', 'cancel', 'changed'])
def test_cleanup_typed_confirmation(ui, monkeypatch, answer):
    from claude_reset import cleanup
    calls = []
    plan = SimpleNamespace(id='reviewed', mode='wipe', blockers=())
    ui.cleanup_mode.set('wipe')
    ui.wipe_plan = plan
    ui.server_done.set(True)
    def confirm(*args, **kwargs):
        if answer == 'changed':
            ui.cleanup_mode.set('wipe_memory')
            return 'СТЕРЕТЬ'
        return answer
    monkeypatch.setattr(app.simpledialog, 'askstring', confirm)
    monkeypatch.setattr(cleanup, 'WipeExecutor', lambda paths: SimpleNamespace(
        apply=lambda reviewed, **kw: calls.append((reviewed, kw))))
    ui.run = lambda work, callback: work()
    button('Выполнить выбранную очистку').options['command']()
    assert bool(calls) == (answer == 'СТЕРЕТЬ')
    if calls:
        assert calls[0][0] is plan and calls[0][1]['consent_id'] == 'reviewed'


def test_cleanup_version_choice_requires_explicit_yes(ui, monkeypatch):
    calls = []
    ui.cleanup_preview = lambda: calls.append('preview')
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: False)
    button('Устранить: неизвестная версия').options['command']()
    assert not ui.cleanup_accept_unlisted and not calls
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: True)
    button('Устранить: неизвестная версия').options['command']()
    assert ui.cleanup_accept_unlisted and calls == ['preview']


def test_json_export_matches_display_after_source_changes(ui, monkeypatch, tmp_path):
    result = {'items': ['reviewed']}
    ui.show_json(result)
    displayed = next(w.content[0] for w in Widget.all if w.content and 'reviewed' in w.content[0])
    result['items'].append('later')
    destination = tmp_path / 'report.json'
    monkeypatch.setattr(app.filedialog, 'asksaveasfilename', lambda **_: str(destination))
    button('Сохранить JSON').options['command']()
    assert json.loads(destination.read_text('utf-8')) == json.loads(displayed) == {'items': ['reviewed']}


def test_report_snapshot_survives_modal_plan_replacement(ui, monkeypatch, tmp_path):
    payload = {'items': ['reviewed']}
    ui.plan = SimpleNamespace(redacted=lambda: payload)
    destination = tmp_path / 'report.json'
    def choose(**_):
        payload['items'].append('later')
        ui.invalidate()
        return str(destination)
    monkeypatch.setattr(app.filedialog, 'asksaveasfilename', choose)
    ui.save_report()
    assert json.loads(destination.read_text('utf-8')) == {'items': ['reviewed']}


@pytest.mark.parametrize('change', ['replace', 'edit', 'invalidate_restore', 'busy', 'none'])
def test_profile_window_rejects_stale_selection(ui, change):
    profiles = [SimpleNamespace(component='code', path=str(i), selected=True) for i in range(2)]
    original = SimpleNamespace(inventory=SimpleNamespace(profiles=profiles))
    ui.plan = original
    ui.choose_profiles()
    child = button('Применить выбор и пересчитать план').parent
    analyzed = []
    ui.analyze = lambda: analyzed.append(True)
    if change == 'replace': ui.plan = SimpleNamespace(inventory=None)
    elif change == 'edit': profiles[1].path = 'changed'
    elif change == 'invalidate_restore':
        ui.invalidate()
        ui.plan = original
    elif change == 'busy': ui.worker = SimpleNamespace(busy=True)
    button('Применить выбор и пересчитать план').options['command']()
    if change == 'none':
        assert ui.selection.profiles == ['1'] and analyzed and child.destroyed
    else:
        assert not analyzed and not child.destroyed and ui.messages


def test_customization_window_preserves_selection_while_busy(ui, monkeypatch):
    from claude_reset import customizations
    monkeypatch.setattr(customizations, 'extra_entries', lambda _: ['first', 'second'])
    calls = []
    monkeypatch.setattr(customizations, 'create_plan', lambda paths, selected: calls.append(selected))
    ui.plan_customizations()
    prepare = button('Создать архив и план без удаления')
    ui.worker = SimpleNamespace(busy=True)
    prepare.options['command']()
    assert not calls and not prepare.parent.destroyed and ui.messages
    ui.worker = SimpleNamespace(busy=False)
    ui.run = lambda action, callback: action()
    prepare.options['command']()
    assert calls == [['second']] and prepare.parent.destroyed


def test_close_protocol_refuses_busy_worker(ui):
    ui.worker = SimpleNamespace(busy=True)
    ui.root.protocols['WM_DELETE_WINDOW']()
    assert not ui.root.destroyed and ui.messages
    ui.worker = SimpleNamespace(busy=False)
    ui.root.protocols['WM_DELETE_WINDOW']()
    assert ui.root.destroyed


@pytest.mark.parametrize('label,method', [('Закрыть процессы Claude', 'resolve_processes'),
                                        ('Остановить службу Cowork', 'resolve_service')])
def test_cleanup_resolve_buttons(ui, monkeypatch, label, method):
    from claude_reset import cleanup_actions
    calls = []
    monkeypatch.setattr(cleanup_actions, method, lambda: calls.append(method) or {'status': 'checked'})
    ui.cleanup_preview = lambda: calls.append('preview')
    ui.show_json = lambda result: calls.append(result['status'])
    ui.run = lambda work, callback: callback(work())
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: False)
    button(label).options['command']()
    assert not calls
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: True)
    button(label).options['command']()
    assert calls == [method, 'checked', 'preview']


@pytest.mark.parametrize('word', ['СБРОСИТЬ', None, 'wrong'])
def test_reset_word(ui, monkeypatch, word):
    ui.plan = SimpleNamespace(id='plan', blockers=[])
    ui.server_done.set(True)
    calls = []
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: True)
    monkeypatch.setattr(app.simpledialog, 'askstring', lambda *args, **kw: word)
    monkeypatch.setattr(app, 'Executor', lambda paths: SimpleNamespace(apply=lambda *a, **kw: calls.append(kw)))
    ui.run = lambda work, callback: work()
    button('Выполнить выбранную очистку').options['command']()
    assert bool(calls) == (word == 'СБРОСИТЬ')


@pytest.mark.parametrize('status', ['encrypted_export_verified', 'inventory_complete'])
def test_export_cowork_binding(ui, monkeypatch, status):
    from claude_reset import cowork
    monkeypatch.setattr(cowork, 'export_all', lambda *a, **kw: {'status': status, 'runs': ['a' * 32]})
    ui.run = lambda work, callback: callback(work())
    ui.show_json = lambda _: None
    button('Устранить: экспорт Cowork').options['command']()
    assert ui.cleanup_cowork_export == (('a' * 32,) if status == 'encrypted_export_verified' else None)


def test_reset_word_cannot_authorize_replaced_plan(ui, monkeypatch):
    ui.plan = SimpleNamespace(id='plan', blockers=[])
    ui.server_done.set(True)
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *args: True)
    def word(*args, **kw):
        ui.invalidate()
        return 'СБРОСИТЬ'
    monkeypatch.setattr(app.simpledialog, 'askstring', word)
    ui.run = lambda *args: pytest.fail('stale plan must not execute')
    ui.apply()
    assert ui.messages
