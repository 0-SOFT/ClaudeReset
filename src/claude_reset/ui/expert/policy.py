"""The "profiles and automation" tab of the specialist window: the profiles of the next analysis, projects to check,
saved policies for unattended resets and the extra Code files."""
import copy
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from ... import layout
from ...errors import SafetyError
from ...reset.policy import policy_plan

__all__ = ['PolicyTab']


class PolicyTab:
    """What the next analysis covers, and a reviewed plan saved as a policy; the extra Code files are planned here."""

    def __init__(self, app):
        self.app = app

    def build(self, policy):
        """Chosen profiles, saved policies and the extra Code files."""
        ttk.Label(policy, text='Сначала выполните анализ, затем выберите найденные профили. Новые пути и версии '
                  'требуют нового просмотра.', wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(policy, text='Выбрать найденные профили', command=self.choose_profiles).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Добавить проект для проверки настроек',
                   command=self.add_project).pack(anchor='w', pady=5)
        self.strict = tk.BooleanVar(value=False)
        ttk.Checkbutton(policy, text='Отключить необязательную телеметрию CLI (может повлиять на Remote Control)',
                        variable=self.strict, command=self.set_privacy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Сохранить политику показанного плана',
                   command=self.save_policy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Открыть сохранённую политику', command=self.load_policy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Разобрать дополнительные файлы Code',
                   command=self.plan_customizations).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Применить план дополнительных файлов',
                   command=self.apply_customizations).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Извлечь архив исходников Code',
                   command=self.recover_customizations).pack(anchor='w', pady=5)
        ttk.Label(policy, text='Политика зашифрована DPAPI. Автоматический CLI-запуск: --apply --policy <файл> '
                  '--server-step-complete.\n'
                  'Серверный этап подтверждается для каждого запуска; сохранённая политика не подтверждает отзыв '
                  'новых сессий.', wraplength=930).pack(anchor='w', pady=12)

    def choose_profiles(self):
        app = self.app
        if not app.plan or not app.plan.inventory:
            return app.dialogs.showinfo('Профили', 'Сначала выполните анализ.')
        plan = app.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(app, 'plan_revision', 0)
        profiles = [p for p in snapshot.inventory.profiles if p.component in ('code', 'vscode', 'desktop')]
        window = tk.Toplevel(app.root)
        window.title('Область следующего анализа')
        window.geometry('900x360')
        listing = tk.Listbox(window, selectmode='multiple', exportselection=False)
        listing.pack(fill='both', expand=True, padx=12, pady=12)
        for i, p in enumerate(profiles):
            listing.insert('end', f'[{p.component}] {p.path}')
            if p.selected:
                listing.selection_set(i)

        def selected():
            if not app.confirmed_plan_current(plan, snapshot, revision):
                return
            app.selection.profiles = [profiles[i].path for i in listing.curselection()]
            app.invalidate()
            window.destroy()
            app.analysis_tab.analyze()
        ttk.Button(window, text='Применить выбор и пересчитать план', command=selected).pack(pady=12)

    def add_project(self):
        app = self.app
        directory = app.dialogs.askdirectory(title='Проект: только проверка, файлы не удаляются')
        if directory and directory not in app.selection.projects:
            app.selection.projects.append(directory)
            app.invalidate()

    def set_privacy(self):
        self.app.selection.privacy = 'strict' if self.strict.get() else 'compatible'
        self.app.invalidate()

    def save_policy(self):
        app = self.app
        if app.busy:
            return
        if not app.plan or app.plan.blockers:
            return app.dialogs.showinfo('Политика', 'Нужен проверенный план без блокирующих условий.')
        plan = app.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(app, 'plan_revision', 0)
        file = app.dialogs.asksaveasfilename(defaultextension='.dpapi', initialfile='policy.dpapi')
        if file:
            if not app.confirmed_plan_current(plan, snapshot, revision):
                return
            if not app.dialogs.askyesno('Автоматическое выполнение',
                                        'Разрешить будущие локальные сбросы в показанной области без повторного '
                                        'просмотра? Новые профили и версии будут блокироваться.'):
                return
            if not app.confirmed_plan_current(plan, snapshot, revision):
                return
            app.safe(lambda: app.policy.save_policy(Path(file), snapshot, consent_id=snapshot.id))

    def load_policy(self):
        app = self.app
        file = app.dialogs.askopenfilename(filetypes=[('Политика DPAPI', '*.dpapi')])
        if file:
            def loaded(plan):
                app.selection = plan.selection
                self.strict.set(plan.selection.privacy == 'strict')
                for key, variable in app.components.items():
                    variable.set(key in plan.components)
                app.analysis_tab.show_plan(plan)
            app.run(lambda: policy_plan(app.paths, Path(file)), loaded)

    def plan_customizations(self):
        app = self.app
        try:
            entries = app.customizations.extra_entries(layout.code_home(app.paths))
        except (OSError, SafetyError):
            return app.dialogs.showerror('Дополнительные файлы', 'Не удалось безопасно прочитать профиль Code.')
        window = tk.Toplevel(app.root)
        window.title('Экспорт пользовательских исходников')
        window.geometry('740x460')
        ttk.Label(window, text='Выберите исходники для отдельного зашифрованного архива. При применении плана все '
                  'перечисленные объекты будут удалены из активного Code, включая невыбранные. Учётные данные '
                  'экспортировать нельзя. Память здесь не затрагивается.', wraplength=700).pack(padx=12, pady=12)
        listing = tk.Listbox(window, selectmode='multiple', exportselection=False)
        listing.pack(fill='both', expand=True, padx=12)
        for entry in entries:
            listing.insert('end', entry)
        listing.selection_set(0, 'end')

        def prepare():
            if app.busy:
                app.show_operation_error('operation_busy')
                return
            selected = [entries[i] for i in listing.curselection()]
            window.destroy()
            app.run(lambda: app.customizations.create_plan(app.paths, selected), app.show_json)
        ttk.Button(window, text='Создать архив и план без удаления', command=prepare).pack(pady=12)

    def apply_customizations(self):
        from ...reset.customizations import apply_plan
        self.app.apply_after_server(layout.CUSTOMIZATION_RUNS, 'План DPAPI', 'Удаление дополнительных файлов',
                                    'Применить выбранный план? Исходники сохранятся в отдельном архиве; невыбранные '
                                    'объекты будут удалены без экспорта. Старые настройки автоматически не '
                                    'возвращаются.', apply_plan)

    def recover_customizations(self):
        from ...reset.customizations import recover
        self.app.recover_from_plan(layout.CUSTOMIZATION_RUNS, 'План DPAPI', 'Экспорт исходников Code', recover)
