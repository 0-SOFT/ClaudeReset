"""The connection tab of the specialist window: the remote proxy form, the local tunnel profile and its engine, and a
separate diagnosis of a local proxy path."""
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from types import MappingProxyType

from ... import config
from ...errors import SafetyError
from ...model.status import Backend, Proxy
from ..text import JSON_FILES, error_text

__all__ = ['ConnectionTab', 'PROXY_MESSAGES']

# What the specialist window says after each proxy step.
PROXY_MESSAGES = MappingProxyType({
    Proxy.PROXY_CHECKED: 'Прокси проверен. При сохранении подтвердите измеренный выход.',
    Proxy.PROXY_UNREACHABLE: 'Прокси не отвечает. Проверьте адрес и порт.',
    Proxy.PROXY_LOGIN_OR_CONNECT_REFUSED: 'Прокси отказал во входе или CONNECT. Проверьте реквизиты.',
    Proxy.PROXY_EXIT_UNAVAILABLE: 'Вход выполнен, но выход не измерен. Повторите проверку.',
    Proxy.VLESS_IMPORTED: 'VLESS+Reality сохранён DPAPI как неактивный профиль. Откройте список импортированных.',
    Proxy.VLESS_IMPORT_REFUSED: 'Импорт не выполнен. Нужен локальный JSON VLESS+Reality с версией и SHA-256 движка; '
                                'проверьте файл.',
    Proxy.PROXY_SAVED: 'Прокси и ожидаемый выход сохранены DPAPI. Клиенты не изменены.',
    Proxy.PROXY_CONFIRMATION_REQUIRED: 'Сначала проверьте прокси и подтвердите выход.',
    Proxy.ENGINE_INSTALLED: 'Движок VLESS установлен и запущен. Идёт измерение выхода.',
    Proxy.ENGINE_NEEDS_ATTENTION: 'Движок установлен, но проверка или измерение выхода не прошли. Повторите проверку.',
    Proxy.ENGINE_NOT_STARTED: 'Движок не установлен: задача уже есть, порт занят или папка движка не пуста. Снимите '
                              'прежний движок.',
    Proxy.ENGINE_REMOTE_PROFILE_SAVED: 'Сохранён удалённый прокси SOCKS5/HTTP. Сначала «Снять прокси или движок».',
    Proxy.ENGINE_INSTALL_FAILED: 'Установка движка не выполнена. Проверьте профиль, архив и сеть; затем повторите.',
    Proxy.BACKEND_REMOVED: 'Движок и сохранённый удалённый прокси сняты. Ожидаемый выход сохранён.',
    Proxy.BACKEND_REMOVE_REFUSED: 'Снятие отклонено или не завершено. Если защита L1 работает, сначала снимите её.',
})


class ConnectionTab:
    """A proxy is checked into a draft and saved only with the measured exit the person confirms.

    The draft lives here; the protection tab applies it to the installed controller."""

    def __init__(self, app):
        self.app = app
        self.proxy_draft = None

    def build(self, connection):
        """Remote proxy, local tunnel profile and connection diagnostics."""
        self.connection_local = tk.StringVar(value=config.BACKEND_URL)
        self.connection_router = tk.StringVar()
        self.connection_ips = tk.StringVar()
        self.proxy_fields = {key: tk.StringVar(value='1080' if key == 'port' else '')
                             for key in ('host', 'port', 'username', 'password')}
        ttk.Label(connection, text='Удалённый прокси', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        self.proxy_type = tk.StringVar(value='socks5')
        type_row = ttk.Frame(connection)
        type_row.pack(anchor='w')
        for value, label in [('socks5', 'SOCKS5'), ('http', 'HTTP CONNECT')]:
            ttk.Radiobutton(type_row, text=label, variable=self.proxy_type, value=value).pack(side='left')
        proxy_row = ttk.Frame(connection)
        proxy_row.pack(fill='x')
        for key, label in [('host', 'Публичный IPv4'), ('port', 'Порт'), ('username', 'Логин'), ('password', 'Пароль')]:
            cell = ttk.Frame(proxy_row)
            cell.pack(side='left', padx=4)
            ttk.Label(cell, text=label).pack(anchor='w')
            ttk.Entry(cell, textvariable=self.proxy_fields[key], width=8 if key == 'port' else 20,
                      show='*' if key == 'password' else '').pack(anchor='w')
        ttk.Label(connection, text='Сервер: публичный IPv4; выход: IPv4 или IPv6. Логин и пароль — оба или пустые.',
                  wraplength=760).pack(anchor='w', pady=4)
        ttk.Label(connection, text='SOCKS5 и HTTP Basic не шифруют логин и пароль до прокси. '
                  'Для HTTP логин не должен содержать двоеточие. HTTPS-прокси не поддержан.',
                  wraplength=760).pack(anchor='w')
        proxy_buttons = ttk.Frame(connection)
        proxy_buttons.pack(anchor='w', pady=6)
        ttk.Button(proxy_buttons, text='Проверить прокси', command=self.proxy_check).pack(side='left')
        ttk.Button(proxy_buttons, text='Сохранить прокси и выход', command=self.proxy_save).pack(side='left', padx=8)
        ttk.Label(connection, text='Профиль локального туннеля', font=('Segoe UI', 13, 'bold')).pack(anchor='w', pady=8)
        row = ttk.Frame(connection)
        row.pack(anchor='w', pady=4)
        ttk.Button(row, text='Импортировать VLESS+Reality (JSON)',
                   command=self.backend_import).pack(side='left', padx=(0, 8))
        ttk.Button(row, text='Показать импортированные', command=self.backend_catalog).pack(side='left')
        row = ttk.Frame(connection)
        row.pack(anchor='w', pady=4)
        ttk.Button(row, text='Установить движок VLESS', command=self.engine_install).pack(side='left', padx=(0, 8))
        ttk.Button(row, text='Снять прокси или движок', command=self.backend_remove).pack(side='left')
        ttk.Label(connection, text='Импорт сохраняет профиль зашифрованным. Он остаётся неактивным до установки и '
                  'приёмки защиты. Импорт и просмотр не запускают туннель и не открывают Claude.',
                  wraplength=760).pack(anchor='w', pady=6)
        ttk.Label(connection, text='Отдельная диагностика соединения',
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=6)
        for label, variable in [('Локальный proxy (HTTP CONNECT или SOCKS5)', self.connection_local),
                                ('Ожидаемые публичные IP выхода, через запятую', self.connection_ips)]:
            ttk.Label(connection, text=label).pack(anchor='w', pady=(8, 2))
            ttk.Entry(connection, textvariable=variable, width=75).pack(anchor='w', fill='x')
        ttk.Label(connection, text=f'Формат: {config.BACKEND_URL} или socks5://127.0.0.1:1080. '
                  'IP выхода возьмите из доверенной настройки провайдера. Диагностика использует только указанный '
                  'локальный proxy.', wraplength=760).pack(anchor='w', pady=8)
        row = ttk.Frame(connection)
        row.pack(anchor='w', pady=6)
        ttk.Button(row, text='Сохранить профиль', command=self.connection_save).pack(side='left', padx=(0, 8))
        ttk.Button(row, text='Загрузить сохранённый', command=self.connection_load).pack(side='left')
        ttk.Button(connection, text='Проверить сохранённый локальный путь',
                   command=lambda: self.connection_check(False)).pack(anchor='w', pady=4)
        ttk.Label(connection, text='Проверка измеряет выход одного HTTPS-запроса, не весь трафик Claude. Текущие '
                  'сеансы и настройки сети не меняются. Успешное измерение не разрешает запуск рабочих клиентов. '
                  'Прозрачный путь роутера не поддержан.', wraplength=760).pack(anchor='w', pady=8)

    def proxy_check(self):
        from ...services.proxy import ProxyDraft
        app = self.app

        def start():
            try:
                draft = ProxyDraft(proxy_type=self.proxy_type.get(), probe=app.probe,
                                   **{key: value.get() for key, value in self.proxy_fields.items()})
            except SafetyError as exc:
                # The draft raises only a fixed input hint, never the entered values.
                app.status.set(error_text(exc, 'ru'))
                app.dialogs.showwarning('Проверьте поля прокси', error_text(exc, 'ru'))
                return
            self.proxy_draft = draft
            app.run(draft.check, self.proxy_result)
        app.safe(start)

    def proxy_result(self, result):
        self.app.status.set(PROXY_MESSAGES.get(result.status, 'Проверка прокси не завершена. Повторите проверку.'))

    def draft_matches_form(self, draft):
        """The checked draft is for the type and the fields the form shows now."""
        return draft.proxy_type == self.proxy_type.get() and not any(
            str(draft.profile[key]) != value.get().strip() if key in ('host', 'port')
            else draft.profile[key] != value.get() for key, value in self.proxy_fields.items())

    def proxy_save(self):
        from ...services.proxy import ProxyResult
        app = self.app
        if app.busy:
            return
        draft = self.proxy_draft
        if draft is None or draft.expected is None or not self.draft_matches_form(draft):
            self.proxy_result(ProxyResult(Proxy.PROXY_CONFIRMATION_REQUIRED))
            return
        if app.dialogs.askyesno('Подтвердить ожидаемый выход',
                                'Измеренный адрес: ' + draft.expected['expected_exit_ips'][0] +
                                '\nСохранить его как ожидаемый? Адрес хранится только в профиле DPAPI.'):
            app.run(lambda: draft.save(app.paths, confirmed=True), self.proxy_result)

    def connection_save(self):
        from ...network.connections import save
        app = self.app
        profile = {'schema': 1, 'local_proxy': self.connection_local.get().strip(),
                   'router_proxy': None,
                   'expected_exit_ips': [s.strip() for s in self.connection_ips.get().split(',') if s.strip()]}
        app.run(lambda: save(app.paths, profile), app.show_json)

    def backend_import(self):
        from ...services.proxy import import_vless
        app = self.app
        if app.busy:
            return
        file = app.dialogs.askopenfilename(title='Профиль VLESS+Reality с параметрами движка (JSON)',
                                           filetypes=JSON_FILES)
        if file:
            app.run(lambda: import_vless(app.paths, Path(file)), self.proxy_result)

    def engine_install(self):
        from ...services.proxy import install_engine
        app = self.app
        if app.busy:
            return
        profile = app.dialogs.askopenfilename(title='Профиль VLESS+Reality с параметрами движка (JSON)',
                                              filetypes=JSON_FILES)
        if not profile:
            return
        archive = None
        if app.dialogs.askyesno('Архив движка', 'Есть локальный архив движка закреплённой версии?\n'
                                '«Нет» — скачать закреплённую версию с официальной страницы выпусков; хеш '
                                'проверяется.'):
            archive = app.dialogs.askopenfilename(title='Архив движка', filetypes=[('ZIP', '*.zip')]) or None
            if archive is None:
                return
        if not app.dialogs.askyesno('Установка движка VLESS',
                                    'Установить локальный туннель как задачу текущего пользователя? '
                                    'Клиенты Claude не меняются; после установки выход будет измерен и предложен для '
                                    'подтверждения.'):
            return
        app.run(lambda: install_engine(app.paths, Path(profile), Path(archive) if archive else None),
                self.engine_installed)

    def engine_installed(self, result):
        from ...services.proxy import LocalBackendDraft
        app = self.app
        self.proxy_result(result)
        if result.status not in (Proxy.ENGINE_INSTALLED, Proxy.ENGINE_NEEDS_ATTENTION):
            return
        draft = LocalBackendDraft(app.paths, first=True, probe=app.probe)

        def checked(outcome):
            self.proxy_result(outcome)
            if outcome.status == Proxy.PROXY_CHECKED and app.dialogs.askyesno(
                    'Подтвердить ожидаемый выход', 'Измеренный адрес: ' + draft.expected['expected_exit_ips'][0] +
                    '\nСохранить его как ожидаемый? Адрес хранится только в профиле DPAPI.'):
                app.run(lambda: draft.save(app.paths, confirmed=True), self.proxy_result)
        app.run(draft.check, checked)

    def backend_remove(self):
        from ...services.proxy import remove_backend
        app = self.app
        if app.busy or not app.dialogs.askyesno('Снять прокси или движок',
                                                'Удалить задачу движка VLESS и сохранённый удалённый прокси? Защита L1 '
                                                'при этом должна быть снята или остановлена: пока реле открыто, '
                                                'удаление будет отклонено. Ожидаемый выход сохраняется.'):
            return
        app.run(lambda: remove_backend(app.paths), self.proxy_result)

    def backend_catalog(self):
        from ...backend.profiles import catalog
        app = self.app
        app.run(lambda: catalog(app.paths), self.show_backend_catalog)

    def show_backend_catalog(self, result):
        app = self.app
        app.status.set('Список профилей прочитан. Туннель и Claude не запускались.')
        dialog = tk.Toplevel(app.root)
        dialog.title('Профили локального туннеля')
        dialog.geometry('880x410')
        dialog.minsize(740, 320)
        dialog.transient(app.root)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Импортированные профили', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Все профили неактивны. Для запуска требуется установленная и проверенная защита.',
                  wraplength=810).pack(anchor='w', pady=(8, 12))
        if not result['profiles']:
            ttk.Label(frame, text='Профили ещё не импортированы. Вернитесь на вкладку «Соединение» и выберите '
                      'JSON-файл.').pack(anchor='w', pady=15)
        else:
            table = ttk.Treeview(frame, columns=('id', 'version', 'state'), show='headings', height=7)
            for key, label, width in [('id', 'Идентификатор', 290), ('version', 'Заявленная версия', 150),
                                      ('state', 'Состояние', 240)]:
                table.heading(key, text=label)
                table.column(key, width=width, minwidth=100)
            for profile in result['profiles']:
                state = 'Неактивен' if profile['status'] == Backend.IMPORTED_INACTIVE else 'Не удалось прочитать'
                table.insert('', 'end', values=(profile['profile_id'], profile.get('declared_engine_version', '—'),
                                                state))
            table.pack(fill='both', expand=True)
        buttons = ttk.Frame(frame)
        buttons.pack(side='bottom', fill='x', pady=(12, 0))
        ttk.Button(buttons, text='Диагностический отчёт', command=lambda: app.show_json(result)).pack(side='left')
        ttk.Button(buttons, text='Закрыть', command=dialog.destroy).pack(side='right')

    def connection_load(self):
        from ...network.connections import load
        app = self.app

        def loaded(profile):
            if profile is None:
                app.status.set('Профиль соединения пока не сохранён.')
                return
            self.connection_local.set(profile['local_proxy'])
            self.connection_router.set(profile['router_proxy'] or '')
            self.connection_ips.set(', '.join(profile['expected_exit_ips']))
            app.status.set('Профиль соединения загружен. Сетевых запросов не было.')
        app.run(lambda: load(app.paths), loaded)

    def connection_check(self, include_router):
        from ...network.remote_backend import check_saved
        app = self.app
        app.run(lambda: check_saved(app.paths, include_router=include_router), app.show_json)
