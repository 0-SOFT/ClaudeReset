"""The protection tabs of the specialist window: the local backend check ("network protection of Claude") and the L1
protection itself ("Windows protection") — its state, install, restart, removal, the VS Code choice and a new proxy."""
import tkinter as tk
from tkinter import ttk

from .. import protection_panel

__all__ = ['GuardTab', 'ProtectionTab']


class GuardTab:
    """The local backend the L1 controller relies on, checked without network requests."""

    def __init__(self, app):
        self.app = app

    def build(self, guard):
        """The local backend the L1 controller relies on."""
        ttk.Label(guard, text='Локальная защита только для Claude', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(guard, text='Здесь проверяется установленный локальный backend. '
                  'Постоянный запрет прямых соединений включается на вкладке «Windows-защита». '
                  'Обычные Chrome, VS Code, Discord и сайты не входят в область.',
                  wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(guard, text='Проверить защиту без сетевых запросов',
                   command=self.guard_status).pack(anchor='w', pady=5)

    def guard_status(self):
        from ...backend.location import status
        app = self.app
        app.run(lambda: status(app.paths), app.show_json)


class ProtectionTab:
    """L1: every operation is confirmed in a dialog that says what it changes; its text shows the last result.

    The VS Code choice is kept until it is applied; a new proxy comes checked from the connection tab or from the saved
    profile checked again here."""

    def __init__(self, app):
        self.app = app
        self.protection_extension_choice = None
        self.protection_proxy_draft = None

    def build(self, page, connection):
        self.protection_text = tk.StringVar(value='Состояние ещё не проверялось. Открытие окна ничего не меняет.')
        self.protect_extension = tk.BooleanVar(value=False)
        tabs = self.app.tabs
        ttk.Label(page, text='Защита L1', font=('Segoe UI', 13, 'bold')).pack(anchor='w', pady=8)
        ttk.Label(page, textvariable=self.protection_text, wraplength=930).pack(anchor='w', pady=8)
        row = ttk.Frame(page)
        row.pack(anchor='w', pady=8)
        for label, action in [('Обновить состояние L1', 'status'), ('Включить защиту L1', 'install'),
                              ('Перезапустить L1', 'restart'), ('Снять защиту L1', 'remove')]:
            ttk.Button(row, text=label, command=lambda a=action: self.protection_action(a)).pack(side='left', padx=3)
        ttk.Button(page, text='Переустановить контроллер (после обновления программы)',
                   command=lambda: self.protection_action('reinstall')).pack(anchor='w', pady=5)
        ttk.Checkbutton(page, text='Защищать Claude Code в общем VS Code',
                        variable=self.protect_extension, command=self.protection_extension_changed).pack(anchor='w',
                                                                                                         pady=8)
        ttk.Label(page, text='Без выбора сохраняется прежняя область; при первой установке расширение исключено. '
                  'Примените выбор отдельной кнопкой. Сеансы Claude Code могут потерять сеть. '
                  'После применения выполните Developer: Reload Window в VS Code и /resume в Claude Code.',
                  wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(page, text='Применить выбор расширения',
                   command=lambda: self.protection_action('extension')).pack(anchor='w', pady=5)
        ttk.Button(page, text='Применить проверенный прокси',
                   command=self.protection_change_proxy).pack(anchor='w', pady=5)
        ttk.Button(page, text='Повторить проверку / проверить новый выход',
                   command=self.protection_retry).pack(anchor='w', pady=5)
        ttk.Button(page, text='Подтвердить новый выход и перезапустить',
                   command=lambda: self.protection_change_proxy(saved=True)).pack(anchor='w', pady=5)
        ttk.Button(page, text='Ввести реквизиты / выбрать другой прокси',
                   command=lambda: tabs.select(connection)).pack(anchor='w', pady=5)
        ttk.Button(page, text='Настроить соединение', command=lambda: tabs.select(connection)).pack(anchor='w', pady=5)
        ttk.Label(page, text='L1 имеет открытые границы DNS, посредников и Cowork. Полный доступ к файлам сохраняется.',
                  wraplength=930).pack(anchor='w', pady=8)

    def protection_retry(self):
        from ...services.proxy import check_saved
        app = self.app
        if app.busy:
            return
        self.protection_proxy_draft = None

        def checked(pair):
            self.protection_proxy_draft, outcome = pair
            app.connection_tab.proxy_result(outcome)
            self.protection_text.set(app.status.get())
        app.run(lambda: check_saved(app.paths, probe=app.probe), checked)

    def protection_change_proxy(self, saved=False):
        app = self.app
        if app.busy:
            return
        connection = app.connection_tab
        draft = self.protection_proxy_draft if saved else connection.proxy_draft
        if draft is None or draft.expected is None or (not saved and not connection.draft_matches_form(draft)):
            self.protection_result({'text': protection_panel.RESULTS['proxy_confirmation_required']})
            return
        if app.dialogs.askyesno('Смена прокси / ожидаемого выхода',
                                'Подтвердить измеренный выход: ' + draft.expected['expected_exit_ips'][0] +
                                '\nСохранить профиль DPAPI и перезапустить установленный контроллер без '
                                'переустановки? Клиенты временно потеряют сеть. При частичном исходе нужна проверка '
                                'состояния.'):
            self.protection_text.set('Применение профиля; прежнее состояние не актуально.')
            app.run(lambda: protection_panel.perform(app.paths, 'change_proxy', confirmed=True,
                                                     proxy_draft=draft, l1=app.l1), self.protection_result)

    def protection_extension_changed(self):
        self.protection_extension_choice = bool(self.protect_extension.get())

    def protection_result(self, result):
        self.protection_text.set(result['text'])

    def protection_action(self, action):
        app = self.app
        if app.busy:
            return
        if action == 'status':
            self.protection_text.set('Идёт новая проверка состояния…')
            app.run(lambda: protection_panel.status(app.paths, l1=app.l1), self.protection_result)
            return
        extension = self.protection_extension_choice

        def confirm(limits=None):
            if app.busy:
                return
            if action in ('install', 'reinstall'):
                if not limits['known']:
                    self.protection_result({'text': 'Новая граница L1: установка из окна недоступна.'})
                    return
                text = 'Вы принимаете следующие открытые границы L1?\n\n' + '\n'.join(limits['lines'])
                text += '\n\nУстановка запросит UAC. Защищённые клиенты могут временно потерять сеть.'
                if action == 'reinstall':
                    text += ('\nКонтроллер будет остановлен и заменён текущей сборкой программы; прокси и выход '
                             'сохраняются.')
                if extension is not None:
                    text += ('\nБудет изменена область Claude Code в VS Code; сохраните работу и затем перезагрузите '
                             'окно VS Code.')
            elif action == 'extension':
                text = ('Применить выбор к установленному контроллеру и перезапустить его? Сохраните работу Claude '
                        'Code; затем выполните Developer: Reload Window и /resume. При исключении потребуется UAC для '
                        'удаления только фильтров установленных бинарников расширения; будут сняты только точные '
                        'настройки проекта. Расширение останется без защиты L1. Фильтры удалённых версий требуют '
                        'отдельной проверки.')
            elif action == 'restart':
                text = ('Перезапустить контроллер? Клиенты временно останутся без сети; время будет показано в '
                        'результате.')
            else:
                text = ('Снять защиту L1? Будут удалены её фильтры, автозапуск, backend, профиль соединения и '
                        'согласие. Потребуется UAC. До завершения клиенты могут быть без сети.')
            if app.dialogs.askyesno('Подтверждение операции L1', text):
                self.protection_text.set('Операция выполняется; прежнее состояние больше не актуально.')
                app.run(lambda: protection_panel.perform(app.paths, action, confirmed=True,
                                                         protect_extension=extension, l1=app.l1),
                        self.protection_result,
                        waiting_uac=action in ('install', 'reinstall', 'remove') or (action == 'extension'
                                                                                     and extension is False))
        if action in ('install', 'reinstall'):
            app.run(lambda: protection_panel.limits(app.paths, l1=app.l1), confirm)
        else:
            confirm()
