"""The "time zone, network and memory" tab of the specialist window: the state folder, the time zone and network
checks, the clean Chrome profile, memory recovery, the acceptance form, the Desktop keys and the Cowork reset."""
from pathlib import Path
from tkinter import ttk

from ... import layout
from ...errors import SafetyError
from ...privacy.browser_probe import browser_measurement
from ...reset.execution import recover_memory, verify_run
from ...reset.new_account import network_probe
from ...reset.verification import template_for_run
from ...safeio import atomic_json
from ...windows.inventory import inspect_windows
from ...windows.timezone import set_istanbul_same_offset
from ..text.ru import PROBE_PAGE

__all__ = ['SettingsTab']


class SettingsTab:
    """Tools around a reset run: nothing here changes settings during an analysis."""

    def __init__(self, app):
        self.app = app

    def build(self, settings):
        """State folder, time zone and network checks, memory and key recovery tools."""
        app = self.app
        ttk.Label(settings, text='Настройки не меняются автоматически при анализе',
                  font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(settings, text='Хранилище архивов этого запуска: ' + str(app.paths.state),
                  wraplength=930).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Выбрать хранилище для следующих запусков',
                   command=self.choose_state_location).pack(anchor='w', pady=5)
        ttk.Label(settings, text='Стамбул применяется только при совпадении текущего UTC-смещения. Меняется системный '
                  'пояс, а не UTC-время.\n'
                  'Проверка сети обращается к ipify.org и показывает IP только для этого процесса; настройки сети '
                  'остаются прежними.', wraplength=930).pack(anchor='w', pady=12)
        ttk.Button(settings, text='Проверить текущий пояс',
                   command=lambda: app.run(lambda: inspect_windows()['timezone'], app.show_json)).pack(anchor='w',
                                                                                                     pady=5)
        ttk.Button(settings, text='Применить Стамбул с тем же временем',
                   command=self.change_timezone).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить выход IPv4 / IPv6',
                   command=lambda: app.run(network_probe, app.show_json)).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Измерить пояс и языки нового Chrome',
                   command=self.probe_browser).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Открыть ссылку OAuth в новом Chrome',
                   command=self.open_oauth).pack(anchor='w', pady=5)
        ttk.Label(settings, text='Восстановление из memory.dpapi экспортирует память в отдельную папку и не '
                  'перезаписывает активный Claude.', wraplength=930).pack(anchor='w', pady=(20, 8))
        ttk.Button(settings, text='Экспортировать сохранённую память', command=self.recover).pack(anchor='w')
        ttk.Button(settings, text='Продолжить после сбоя', command=self.resume).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сохранить бланк приёмки T-01–T-13',
                   command=self.acceptance_template).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сравнить ID после нового запуска',
                   command=self.verify_identifiers).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить настройки приватности без изменений',
                   command=self.audit_privacy).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Составить план сброса ключей Desktop (MSIX)',
                   command=self.plan_desktop_keys).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Применить / продолжить план ключей Desktop',
                   command=self.apply_desktop_keys).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить новый ключ Desktop после входа',
                   command=self.verify_desktop_key).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Экспортировать память и результаты Cowork',
                   command=app.cleanup_tab.export_cowork).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сбросить Cowork после проверенного экспорта',
                   command=self.reset_cowork).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Извлечь архив Cowork в отдельную папку',
                   command=self.recover_cowork).pack(anchor='w', pady=5)

    def choose_state_location(self):
        app = self.app
        if app.busy:
            return
        directory = app.dialogs.askdirectory(parent=app.root, initialdir=str(app.paths.state),
                                             title='Выберите существующее хранилище ClaudeReset — файлы не '
                                                   'перемещаются', mustexist=True)
        if not directory:
            return
        from ...layout import select
        try:
            select(app.paths.home, Path(directory))
        except (SafetyError, OSError):
            return app.show_operation_error('operation_failed')
        app.dialogs.showinfo('Хранилище выбрано', 'Архивы не перемещались. Новый путь будет использоваться после '
                             'перезапуска ClaudeReset. Текущий запуск продолжает использовать прежний путь.')

    def change_timezone(self):
        app = self.app
        if app.dialogs.askyesno('Системный часовой пояс',
                                'Изменить пояс всей Windows на Стамбул, только если время на часах сохранится?'):
            app.plan = None
            app.run(set_istanbul_same_offset, app.show_json)

    def open_oauth(self):
        app = self.app
        if not app.last_run:
            return app.dialogs.showinfo('Профиль', 'Сначала создайте или откройте управляемый профиль Chrome.')
        url = app.dialogs.askstring('OAuth', 'Вставьте ссылку HTTPS на claude.ai, claude.com или platform.claude.com. '
                                    'Ссылка не записывается в отчёт.')
        if url:
            app.safe(lambda: app.launch_chrome(app.paths, app.last_run, url))

    def probe_browser(self):
        app = self.app
        if not app.last_run:
            return app.dialogs.showinfo('Профиль', 'Сначала создайте или откройте управляемый профиль Chrome.')
        run_id = app.last_run
        app.run(lambda: browser_measurement(lambda url: app.launch_chrome(app.paths, run_id, url, loopback_probe=True),
                                            PROBE_PAGE), app.show_json)

    def recover(self):
        app = self.app
        file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.RUNS),
                                           filetypes=[('Memory DPAPI', 'memory.dpapi')])
        if file:
            run_id = Path(file).parent.name
            app.run(lambda: str(recover_memory(app.paths, run_id)),
                    lambda value: app.dialogs.showinfo('Память экспортирована', value))

    def resume(self):
        app = self.app
        file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.RUNS),
                                           filetypes=[('Журнал', 'journal.dpapi')])
        if file:
            run_id = Path(file).parent.name
            app.run(lambda: app.executor(app.paths).resume(run_id), app.analysis_tab.applied)

    def acceptance_template(self):
        app = self.app
        if not app.last_run:
            return app.dialogs.showinfo('Приёмка', 'Сначала выполните локальные операции. Бланк привязывается к '
                                        'конкретному запуску.')
        file = app.dialogs.asksaveasfilename(defaultextension='.json', initialfile='acceptance.json')
        if file:
            app.safe(lambda: atomic_json(Path(file), template_for_run(app.paths, app.last_run), Path(file).parent))

    def verify_identifiers(self):
        app = self.app
        if not app.last_run:
            file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.RUNS),
                                               filetypes=[('Журнал', 'journal.dpapi')])
            if not file:
                return
            app.last_run = Path(file).parent.name
        run_id = app.last_run
        app.run(lambda: verify_run(app.paths, run_id), app.show_json)

    def audit_privacy(self):
        from ...privacy.inventory import audit
        app = self.app
        profiles = None
        if app.plan and app.plan.inventory:
            profiles = [(p.component, Path(p.path)) for p in app.plan.inventory.profiles if p.selected]
        app.run(lambda: audit(app.paths, profiles), app.show_json)

    def plan_desktop_keys(self):
        from ...reset.desktop_keys import create_plan
        app = self.app
        profile = layout.desktop_data(app.paths)
        app.run(lambda: create_plan(app.paths, profile, desktop=app.desktop), app.show_json)

    def apply_desktop_keys(self):
        from ...reset.desktop_keys import apply_plan, review_plan
        app = self.app
        if not app.server_done.get():
            return app.dialogs.showinfo('Серверный этап', 'Сначала выполните отзыв устройств и сессий на сервере и '
                                        'отметьте этот этап.')
        file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.KEY_RUNS),
                                           filetypes=[('План ключей DPAPI', layout.PLAN_FILE)])
        if not file:
            return
        run_id = Path(file).parent.name

        def reviewed(report):
            if app.dialogs.askyesno('Удаление ключей приложения',
                                    f'План {run_id}: аккаунтов {report["accounts"]}, ключей {report["keys"]}. Удалить '
                                    'эти ключи и регистрацию? Действие необратимо. Desktop и служба Cowork должны быть '
                                    'остановлены.'):
                app.run(lambda: apply_plan(app.paths, run_id, server_step_complete=True, desktop=app.desktop),
                        app.show_json)
        app.run(lambda: review_plan(app.paths, run_id), reviewed)

    def verify_desktop_key(self):
        from ...reset.desktop_keys import verify_after_reset
        app = self.app
        file = app.dialogs.askopenfilename(initialdir=str(app.paths.state / layout.KEY_RUNS),
                                           filetypes=[('План ключей DPAPI', layout.PLAN_FILE)])
        if file:
            app.run(lambda: verify_after_reset(app.paths, Path(file).parent.name, desktop=app.desktop), app.show_json)

    def reset_cowork(self):
        from ...reset.cowork import reset_exported
        self.app.apply_after_server(layout.COWORK_RUNS, 'План экспорта DPAPI', 'Сброс Cowork',
                                    'Удалить локальные сессии и sessiondata.vhdx после проверки этого экспорта? Память '
                                    'и выбранные результаты останутся в отдельном DPAPI-архиве; импорт в новый аккаунт '
                                    'выполняется отдельно. Остальная история будет удалена.', reset_exported)

    def recover_cowork(self):
        from ...reset.cowork import recover_export
        self.app.recover_from_plan(layout.COWORK_RUNS, 'План экспорта DPAPI', 'Экспорт Cowork', recover_export)
