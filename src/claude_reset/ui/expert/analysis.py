"""The analysis tab of the specialist window: the reset plan — analysis, its report and the local operations."""
import copy
import json
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from ... import layout
from ...errors import SafetyError
from ...reset.new_account import managed_chrome_profiles
from ...reset.planner import build_plan
from ...safeio import atomic_json
from ..text import JSON_FILES, render, say

__all__ = ['AnalysisTab']


class AnalysisTab:
    """Analyses the chosen components into a plan, shows it, saves its report and runs it after two confirmations."""

    def __init__(self, app):
        self.app = app

    def build(self, page):
        """The reset plan: analysis, report and the local operations."""
        self.page = page
        self.text = tk.Text(page, wrap='word', font=('Segoe UI', 10), height=25)
        self.text.pack(fill='both', expand=True)
        self.text.insert('1.0', 'Анализ читает локальные данные без запуска Claude и без обращения к его API.\n\n'
                         'Для ключей Desktop и Cowork есть отдельные планы и экспорт. Обычный файловый сброс сохраняет '
                         'ключи и регистрацию вместе.\n'
                         'Старые профили Chrome остаются на диске. Новый профиль нужно выбирать для входа и мостов.\n'
                         'Память сохраняется без изменения текста в защищённом DPAPI-архиве. Содержимое памяти в '
                         'журнал не попадает.')
        self.text.configure(state='disabled')
        buttons = ttk.Frame(page)
        buttons.pack(fill='x', pady=(10, 0))
        ttk.Button(buttons, text='Анализ без изменений', command=self.analyze).pack(side='left')
        ttk.Button(buttons, text='Сохранить отчёт', command=self.save_report).pack(side='left', padx=8)
        ttk.Button(buttons, text='Выполнить локальные операции', command=self.apply).pack(side='left')
        ttk.Button(buttons, text='Проверить возможность открытия Chrome', command=self.open_chrome).pack(side='right')

    def display(self, content):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.insert('1.0', content)
        self.text.configure(state='disabled')

    def analyze(self):
        app = self.app
        components = [k for k, v in app.components.items() if v.get()]
        if not components:
            return app.dialogs.showinfo('Выбор', 'Выберите хотя бы один компонент.')
        selection = copy.deepcopy(app.selection)
        app.run(lambda: build_plan(app.paths, components, selection=selection, platform_state=app.inspect()),
                self.show_plan)

    def show_plan(self, plan):
        app = self.app
        app.plan_revision = getattr(app, 'plan_revision', 0) + 1
        app.plan = plan
        lines = ['ПЛАН ЛОКАЛЬНЫХ ОПЕРАЦИЙ', '', f'Найдено файлов памяти: {plan.memory_count}',
                 (f'Объём выбранных объектов: {plan.data_size["files"]} файлов, {plan.data_size["bytes"]:,} байт'
                  if plan.data_size.get('complete', True) else
                  'Объём не подсчитан полностью: сначала нужно устранить блокирующие условия'),
                 'Ключи Desktop: сохраняются; Cowork VM: отдельная непроверенная среда', '', 'Найденные профили:']
        if plan.inventory:
            lines += [f'• [{p.component}] {"выбран" if p.selected else "исключён"}: {p.path}'
                      for p in plan.inventory.profiles]
        lines += ['', 'Операции:']
        lines += [f'• [{a.component}] {say(a.description, 'ru')}\n  {a.target}' for a in plan.actions]
        lines += ['', 'Блокирующие условия:'] + (
            ['• ' + say(b, 'ru') for b in plan.blockers]
            or ['Нет обнаруженных блокировок для перечисленных локальных операций.'])
        lines += ['', 'Ограничения и наблюдения:'] + ['• ' + say(n, 'ru') for n in plan.observations]
        if any(plan.memory_risks.values()):
            lines += ['', 'В памяти обнаружены возможные секреты/географические маркеры. Текст не изменяется и не '
                      'выводится.']
        self.display('\n'.join(lines))

    def apply(self):
        app = self.app
        if app.busy:
            return
        if not app.plan:
            return app.dialogs.showinfo('Нужен план', 'Сначала выполните анализ.')
        if app.plan.blockers:
            return app.dialogs.showerror('Есть блокировки',
                                         'Устраните перечисленные блокировки и повторите анализ. Ничего не изменено.')
        if not app.server_done.get():
            return app.dialogs.showinfo('Серверный этап',
                                        'Сначала выполните нужные действия на вкладке «Серверные действия».')
        plan = app.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(app, 'plan_revision', 0)
        if not app.dialogs.askyesno('Выполнить показанные операции?',
                                    'Будут удалены выбранные локальные данные входа и история Claude Code, сброшено '
                                    'выбранное состояние расширения. Память сохранится без изменения текста и будет '
                                    'возвращена. Если выбран Desktop, будут сброшены перечисленные хранилища; ключи '
                                    'сохранятся. Продолжить?'):
            return
        if not app.confirmed_plan_current(plan, snapshot, revision) or not app.server_done.get():
            return
        word = app.dialogs.askstring('Подтверждение сброса', 'Введите СБРОСИТЬ:', parent=app.root)
        if word != 'СБРОСИТЬ':
            return
        if not app.confirmed_plan_current(plan, snapshot, revision) or not app.server_done.get():
            return
        app.plan = None
        app.run(lambda: app.executor(app.paths).apply(snapshot, consent_id=snapshot.id, server_step_complete=True),
                self.applied)

    def applied(self, result):
        self.app.last_run = result['run']
        self.display(json.dumps(render(result, 'ru'), ensure_ascii=False, indent=2))

    def save_report(self):
        app = self.app
        if not app.plan:
            return app.dialogs.showinfo('Отчёт', 'Сначала выполните анализ.')
        from ..public_view import redact
        snapshot = redact(render(app.plan.redacted(), 'en'))
        file = app.dialogs.asksaveasfilename(defaultextension='.json', initialfile='claude-reset-audit.json',
                                             filetypes=JSON_FILES)
        if file:
            app.safe(lambda: atomic_json(Path(file), snapshot, Path(file).parent))

    def open_chrome(self):
        app = self.app
        if not app.last_run:
            try:
                profiles = managed_chrome_profiles(app.paths)
            except (OSError, SafetyError):
                return app.dialogs.showerror('Профиль Chrome',
                                             'Не удалось проверить сохранённые профили Chrome. Данные не изменены.')
            if len(profiles) == 1:
                app.last_run = profiles[0]
        if not app.last_run:
            file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.CHROME_PROFILES),
                                               filetypes=[('Профиль', layout.PROFILE_MARKER)])
            if not file:
                return
            app.last_run = Path(file).parent.name
        app.safe(lambda: app.launch_chrome(app.paths, app.last_run))
