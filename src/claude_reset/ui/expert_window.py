from __future__ import annotations
import copy
import json
from pathlib import Path
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext
from types import MappingProxyType
from .. import __version__
from ..layout import Paths
from ..reset.core import SUPPORTED
from ..reset.planner import build_plan
from ..reset.execution import Executor, recover_memory, verify_run
from ..errors import SafetyError
from ..safeio import atomic_json
from ..reset.new_account import open_server_page, network_probe, launch_clean_chrome, managed_chrome_profiles
from ..windows.system import inspect_windows, set_istanbul_same_offset
from .text import error_text, gui_message, render, say
from .text.ru import PROBE_PAGE
from ..model.reset import Selection
from ..reset import policy as reset_policy
from ..reset.policy import policy_plan
from ..reset.verification import template_for_run
from ..privacy.browser_probe import browser_measurement
from .worker import FINISHED, Phase, Worker
from .. import config
from .. import layout
from ..model import clients
from ..model.confirmation import Confirmation
from ..model.status import Backend, Export, Proxy, Reset
from ..network.probe import Probe
from ..reset.desktop_keys import Desktop
from ..services.protection import L1
from ..reset import browser_sites, cleanup, cowork, customizations
from ..services import diagnostics
from ..windows import cleanup_actions


# The server steps the person does in the old account.
SERVER_STEPS = (
    'В старом аккаунте открыть Settings → Account и завершить нужные сессии. Выход со всех устройств затронет также другие ПК и телефоны.',
    'Отдельно открыть Settings → Claude Code и отозвать нужные токены. Выход из веб-сессий не засчитывается как этот шаг.',
    'Проверить доступные в аккаунте устройства Cowork/Remote Control и сопряжения. Неподдерживаемый интерфейс не считать автоматически очищенным.',
    'Повторить для каждого прежнего аккаунта, для которого нужен отзыв. Без доступа к аккаунту серверный отзыв здесь не выполняется.',
    'Сохранить/экспортировать нужную облачную память до выхода. Программа сохраняет только найденную локальную память.',
)

# What the specialist window says about each cleanup blocker and mode.
WIPE_BLOCKERS = MappingProxyType({
    'processes': 'Закройте Claude и сеанс расширения; общий редактор автоматически не закрывается.',
    'extra_entries': 'Архивируйте и удалите дополнительные записи Code.',
    'unlisted_version': 'Версия не проверена: требуется явное согласие на фиксированную область.',
    'inventory': 'Не удалось проверить расположения: устраните ссылки или ошибку доступа.',
    'restore_sources': 'Отключите восстановление старого состояния перед очисткой.',
    'cowork_service': 'Служба Cowork должна быть остановлена перед стиранием.',
    'cowork_export': 'Нужен проверенный экспорт работы Cowork; затем повторите предпросмотр.',
    'cowork_location': 'Работа Cowork найдена вне поддержанного профиля экспорта. Стирание заблокировано; нужен адаптер этого расположения.',
})
WIPE_MODES = MappingProxyType({
    'reset_memory': 'Сброс, сохранив память',
    'wipe': 'Стереть всё',
    'wipe_memory': 'Стереть всё, сохранив память',
})

# What the specialist window says after each proxy step.
PROXY_MESSAGES = MappingProxyType({
    Proxy.PROXY_CHECKED: 'Прокси проверен. При сохранении подтвердите измеренный выход.',
    Proxy.PROXY_UNREACHABLE: 'Прокси не отвечает. Проверьте адрес и порт.',
    Proxy.PROXY_LOGIN_OR_CONNECT_REFUSED: 'Прокси отказал во входе или CONNECT. Проверьте реквизиты.',
    Proxy.PROXY_EXIT_UNAVAILABLE: 'Вход выполнен, но выход не измерен. Повторите проверку.',
    Proxy.VLESS_IMPORTED: 'VLESS+Reality сохранён DPAPI как неактивный профиль. Откройте список импортированных.',
    Proxy.VLESS_IMPORT_REFUSED: 'Импорт не выполнен. Нужен локальный JSON VLESS+Reality с версией и SHA-256 движка; проверьте файл.',
    Proxy.PROXY_SAVED: 'Прокси и ожидаемый выход сохранены DPAPI. Клиенты не изменены.',
    Proxy.PROXY_CONFIRMATION_REQUIRED: 'Сначала проверьте прокси и подтвердите выход.',
    Proxy.ENGINE_INSTALLED: 'Движок VLESS установлен и запущен. Идёт измерение выхода.',
    Proxy.ENGINE_NEEDS_ATTENTION: 'Движок установлен, но проверка или измерение выхода не прошли. Повторите проверку.',
    Proxy.ENGINE_NOT_STARTED: 'Движок не установлен: задача уже есть, порт занят или папка движка не пуста. Снимите прежний движок.',
    Proxy.ENGINE_REMOTE_PROFILE_SAVED: 'Сохранён удалённый прокси SOCKS5/HTTP. Сначала «Снять прокси или движок».',
    Proxy.ENGINE_INSTALL_FAILED: 'Установка движка не выполнена. Проверьте профиль, архив и сеть; затем повторите.',
    Proxy.BACKEND_REMOVED: 'Движок и сохранённый удалённый прокси сняты. Ожидаемый выход сохранён.',
    Proxy.BACKEND_REMOVE_REFUSED: 'Снятие отклонено или не завершено. Если защита L1 работает, сначала снимите её.',
})


class Dialogs:
    """The Tk dialogs the specialist window asks with; a test gives the window scripted ones instead."""

    def askyesno(self, *args: object, **kwargs: object) -> bool:
        return messagebox.askyesno(*args, **kwargs)

    def showinfo(self, *args: object, **kwargs: object) -> str:
        return messagebox.showinfo(*args, **kwargs)

    def showerror(self, *args: object, **kwargs: object) -> str:
        return messagebox.showerror(*args, **kwargs)

    def showwarning(self, *args: object, **kwargs: object) -> str:
        return messagebox.showwarning(*args, **kwargs)

    def askopenfilename(self, **kwargs: object) -> str:
        return filedialog.askopenfilename(**kwargs)

    def asksaveasfilename(self, **kwargs: object) -> str:
        return filedialog.asksaveasfilename(**kwargs)

    def askdirectory(self, **kwargs: object) -> str:
        return filedialog.askdirectory(**kwargs)

    def askstring(self, *args: object, **kwargs: object) -> str | None:
        return simpledialog.askstring(*args, **kwargs)

    def askinteger(self, *args: object, **kwargs: object) -> int | None:
        return simpledialog.askinteger(*args, **kwargs)


class App:
    dialogs = Dialogs()
    probe = Probe()   # the network checks of proxy drafts; tests give the window scripted ones
    desktop = Desktop()   # the PC-facing steps of the Desktop key reset
    l1 = L1()   # the L1 checks and operations behind the protection tab
    # The areas behind the tabs, reached through the window so that a test gives it scripted ones.
    diagnostics = diagnostics
    cleanup = cleanup
    cleanup_actions = cleanup_actions
    cowork = cowork
    browser_sites = browser_sites
    customizations = customizations
    executor = Executor   # runs a reviewed reset plan
    policy = reset_policy   # saves a reviewed plan as a policy file
    help_root = layout.PROGRAM_DIR   # the program folder the help sections are read from
    inspect = staticmethod(inspect_windows)   # reads processes, time zone and restore points of this PC
    launch_chrome = staticmethod(launch_clean_chrome)   # opens the clean Chrome profile of a reset run

    def __init__(self, root=None, paths=None, dialogs=None):
        if dialogs is not None:
            self.dialogs = dialogs
        self.root = root or tk.Tk()
        self.root.title('Claude Reset ' + __version__)
        self.root.geometry('1040x760')
        self.root.minsize(860, 600)
        self.paths, self.plan, self.last_run = paths or Paths.current(), None, None
        self.selection = Selection()
        self.policy_file = None
        self.worker = Worker()
        self.events = self.worker.events
        self.operation = None
        self.result_callback = None
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.report_callback_exception = self.callback_exception
        self.components = {c: tk.BooleanVar(value=c != 'desktop') for c in (*SUPPORTED, 'desktop')}
        self.server_done = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value='Ничего не изменено. Начните с анализа.')
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Claude Reset', font=('Segoe UI', 22, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Сброс выбранных локальных данных с сохранением памяти. Ключи Desktop, Cowork и сетевые проверки имеют отдельные статусы.',
                  wraplength=970).pack(anchor='w', pady=(4, 12))
        options = ttk.Frame(frame)
        options.pack(fill='x')
        for key, label in [('code', 'Claude Code'), ('vscode', 'VS Code'), ('chrome', 'Новый Chrome'), ('desktop', 'Состояние Desktop')]:
            ttk.Checkbutton(options, text=label, variable=self.components[key], command=self.invalidate).pack(side='left', padx=(0, 16))
        tabs = ttk.Notebook(frame)
        self.tabs = tabs
        tabs.pack(fill='both', expand=True, pady=12)
        wizard = ttk.Frame(tabs, padding=10)
        tabs.add(wizard, text=gui_message('wizard'))
        self.analysis = ttk.Frame(tabs, padding=10)
        server = ttk.Frame(tabs, padding=10)
        settings_page, settings = self.scrollable(tabs)
        policy = ttk.Frame(tabs, padding=10)
        guard = ttk.Frame(tabs, padding=10)
        connection = ttk.Frame(tabs, padding=10)
        strict_page = ttk.Frame(tabs, padding=10)
        tabs.add(self.analysis, text='Анализ и операции')
        cleanup_page = ttk.Frame(tabs, padding=10)
        tabs.add(cleanup_page, text='Очистка')
        self.build_cleanup_panel(cleanup_page)
        tabs.add(server, text='Серверные действия')
        tabs.add(settings_page, text='Пояс, сеть и память')
        tabs.add(guard, text='Сетевая защита Claude')
        tabs.add(connection, text='Соединение')
        tabs.add(strict_page, text='Windows-защита')
        self.build_protection_panel(strict_page, connection)
        tabs.add(policy, text='Профили и автоматизация')
        diagnostics_page = ttk.Frame(tabs, padding=10)
        tabs.add(diagnostics_page, text='Диагностика')
        self.build_diagnostics_tab(diagnostics_page)
        self.build_wizard_tab(wizard, {'server': server, 'cleanup': cleanup_page, 'connection': connection,
                                       'protection': strict_page, 'checks': diagnostics_page})
        self.build_analysis_tab()
        self.build_server_tab(server)
        self.build_settings_tab(settings)
        self.build_guard_tab(guard)
        self.build_connection_tab(connection)
        self.build_policy_tab(policy)
        ttk.Label(frame, textvariable=self.status, wraplength=970).pack(anchor='w', pady=(4, 0))
        self.cancel_button = ttk.Button(frame, text=gui_message('cancel'), command=self.cancel, state='disabled')
        self.cancel_button.pack(anchor='w', pady=4)
        self.root.after(100, self.poll)

    def scrollable(self, tabs):
        """A tab page whose content scrolls vertically: (page, content frame)."""
        settings_page = ttk.Frame(tabs)
        settings_canvas = tk.Canvas(settings_page, highlightthickness=0)
        settings_scroll = ttk.Scrollbar(settings_page, orient='vertical', command=settings_canvas.yview)
        settings_canvas.configure(yscrollcommand=settings_scroll.set)
        settings_scroll.pack(side='right', fill='y')
        settings_canvas.pack(side='left', fill='both', expand=True)
        settings = ttk.Frame(settings_canvas, padding=10)
        settings_item = settings_canvas.create_window((0, 0), window=settings, anchor='nw')
        settings.bind('<Configure>', lambda _: settings_canvas.configure(scrollregion=settings_canvas.bbox('all')))
        settings_canvas.bind('<Configure>', lambda event: settings_canvas.itemconfigure(settings_item, width=event.width))
        return settings_page, settings

    def build_diagnostics_tab(self, diagnostics_page):
        """Local checks and reports without secrets; time zone and language advice."""
        ttk.Label(diagnostics_page, text='Локальная проверка компонентов L1 и остатков файлов. '
                  'Без сетевых проб и изменений. Отчёт перечисляет непроверенные области.',
                  wraplength=900).pack(anchor='w', pady=8)
        ttk.Button(diagnostics_page, text='Проверить и показать отчёт без секретов',
                   command=self.run_diagnostics).pack(anchor='w', pady=8)
        ttk.Button(diagnostics_page, text='Журнал сброса и стирания без секретов',
                   command=self.show_operation_history).pack(anchor='w', pady=8)
        ttk.Button(diagnostics_page, text='Сводка сохранённого журнала назначений',
                   command=self.show_privacy_observations).pack(anchor='w', pady=8)
        ttk.Label(diagnostics_page, text='В окне результата нажмите «Сохранить JSON». '
                  'Отчёт содержит только статусы и количества, без адресов, имён и текста ошибок.',
                  wraplength=900).pack(anchor='w')
        ttk.Label(diagnostics_page, text='Страна выхода по вашей проверке (DE, TR, GB). '
                  'Другие страны и несколько поясов требуют ручного сравнения.').pack(anchor='w', pady=8)
        self.advisor_country = tk.StringVar(value='')
        ttk.Entry(diagnostics_page, textvariable=self.advisor_country).pack(anchor='w')
        ttk.Button(diagnostics_page, text='Совет по языку и поясу', command=self.run_advisor).pack(anchor='w', pady=8)
        for kind, label in [('timezone', 'Открыть настройки времени'), ('language', 'Открыть настройки языка')]:
            ttk.Button(diagnostics_page, text=label,
                       command=lambda k=kind: self.open_advisor_settings(k)).pack(anchor='w', pady=4)

    def build_wizard_tab(self, wizard, pages):
        """The steps in the order the program requires, each opening its tab."""
        ttk.Label(wizard, text=gui_message('wizard_intro'), wraplength=930).pack(anchor='w', pady=12)
        self.wizard_pages = pages
        self.wizard_states, self.wizard_next = {}, 'server'
        for key, page in self.wizard_pages.items():
            row = ttk.Frame(wizard)
            row.pack(anchor='w', fill='x', pady=4)
            ttk.Button(row, text=gui_message('wizard_' + key), command=lambda p=page: self.tabs.select(p)).pack(side='left')
            self.wizard_states[key] = tk.StringVar(value=gui_message('wizard_state_unchecked'))
            ttk.Label(row, textvariable=self.wizard_states[key]).pack(side='left', padx=12)
        row = ttk.Frame(wizard)
        row.pack(anchor='w', pady=8)
        ttk.Button(row, text='Обновить ход', command=self.wizard_refresh).pack(side='left')
        ttk.Button(row, text='Следующий шаг', command=lambda: self.tabs.select(self.wizard_pages[self.wizard_next])).pack(side='left', padx=8)
        ttk.Label(wizard, text=gui_message('wizard_unverified'), wraplength=930).pack(anchor='w', pady=12)
        from .help_docs import DOCUMENTS
        for kind, (label, _) in DOCUMENTS.items():
            ttk.Button(wizard, text=label, command=lambda k=kind: self.open_help(k)).pack(anchor='w', pady=4)
        ttk.Button(wizard, text='Проверить комплект справки', command=lambda: self.open_help('bundle')).pack(anchor='w', pady=4)

    def build_analysis_tab(self):
        """The reset plan: analysis, report and the local operations."""
        self.text = tk.Text(self.analysis, wrap='word', font=('Segoe UI', 10), height=25)
        self.text.pack(fill='both', expand=True)
        self.text.insert('1.0', 'Анализ читает локальные данные без запуска Claude и без обращения к его API.\n\n'
                         'Для ключей Desktop и Cowork есть отдельные планы и экспорт. Обычный файловый сброс сохраняет ключи и регистрацию вместе.\n'
                         'Старые профили Chrome остаются на диске. Новый профиль нужно выбирать для входа и мостов.\n'
                         'Память сохраняется без изменения текста в защищённом DPAPI-архиве. Содержимое памяти в журнал не попадает.')
        self.text.configure(state='disabled')
        buttons = ttk.Frame(self.analysis)
        buttons.pack(fill='x', pady=(10, 0))
        ttk.Button(buttons, text='Анализ без изменений', command=self.analyze).pack(side='left')
        ttk.Button(buttons, text='Сохранить отчёт', command=self.save_report).pack(side='left', padx=8)
        ttk.Button(buttons, text='Выполнить локальные операции', command=self.apply).pack(side='left')
        ttk.Button(buttons, text='Проверить возможность открытия Chrome', command=self.open_chrome).pack(side='right')

    def build_server_tab(self, server):
        """What the person does in the old account before the reset."""
        ttk.Label(server, text='Выполните до удаления старого входа', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        for i, text in enumerate(SERVER_STEPS, 1):
            ttk.Label(server, text=f'{i}. {text}', wraplength=930).pack(anchor='w', pady=8)
        links = ttk.Frame(server)
        links.pack(anchor='w', pady=12)
        for kind, label in [('sessions', 'Сессии аккаунта'), ('code_tokens', 'Токены Claude Code'), ('help', 'Официальная инструкция')]:
            ttk.Button(links, text=label, command=lambda k=kind: self.safe(lambda: open_server_page(k))).pack(side='left', padx=(0, 10))
        ttk.Checkbutton(server, text='Я выполнил нужный отзыв на сервере и сохранил облачную память, если она нужна', variable=self.server_done).pack(anchor='w')
        ttk.Label(server, text='Эта отметка — подтверждение пользователя. Программа не проверяет сервер. '
                  'Автоматическое открытие ссылок в общем браузере отключено до готовности защищённого запуска.', wraplength=930).pack(anchor='w', pady=8)

    def build_settings_tab(self, settings):
        """State folder, time zone and network checks, memory and key recovery tools."""
        ttk.Label(settings, text='Настройки не меняются автоматически при анализе', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(settings, text='Хранилище архивов этого запуска: ' + str(self.paths.state), wraplength=930).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Выбрать хранилище для следующих запусков', command=self.choose_state_location).pack(anchor='w', pady=5)
        ttk.Label(settings, text='Стамбул применяется только при совпадении текущего UTC-смещения. Меняется системный пояс, а не UTC-время.\n'
                  'Проверка сети обращается к ipify.org и показывает IP только для этого процесса; настройки сети остаются прежними.', wraplength=930).pack(anchor='w', pady=12)
        ttk.Button(settings, text='Проверить текущий пояс', command=lambda: self.run(lambda: inspect_windows()['timezone'], self.show_json)).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Применить Стамбул с тем же временем', command=self.change_timezone).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить выход IPv4 / IPv6', command=lambda: self.run(network_probe, self.show_json)).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Измерить пояс и языки нового Chrome', command=self.probe_browser).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Открыть ссылку OAuth в новом Chrome', command=self.open_oauth).pack(anchor='w', pady=5)
        ttk.Label(settings, text='Восстановление из memory.dpapi экспортирует память в отдельную папку и не перезаписывает активный Claude.', wraplength=930).pack(anchor='w', pady=(20, 8))
        ttk.Button(settings, text='Экспортировать сохранённую память', command=self.recover).pack(anchor='w')
        ttk.Button(settings, text='Продолжить после сбоя', command=self.resume).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сохранить бланк приёмки T-01–T-13', command=self.acceptance_template).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сравнить ID после нового запуска', command=self.verify_identifiers).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить настройки приватности без изменений', command=self.audit_privacy).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Составить план сброса ключей Desktop (MSIX)', command=self.plan_desktop_keys).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Применить / продолжить план ключей Desktop', command=self.apply_desktop_keys).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Проверить новый ключ Desktop после входа', command=self.verify_desktop_key).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Экспортировать память и результаты Cowork', command=self.export_cowork).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Сбросить Cowork после проверенного экспорта', command=self.reset_cowork).pack(anchor='w', pady=5)
        ttk.Button(settings, text='Извлечь архив Cowork в отдельную папку', command=self.recover_cowork).pack(anchor='w', pady=5)

    def build_guard_tab(self, guard):
        """The legacy local guard checks."""
        ttk.Label(guard, text='Локальная защита только для Claude', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(guard, text='Здесь проверяется существующая локальная конфигурация. '
                  'Постоянный запрет прямых соединений включается на вкладке «Windows-защита». '
                  'Запуск клиентов недоступен до полной приёмки установленной защиты. '
                  'Обычные Chrome, VS Code, Discord и сайты не входят в область.', wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(guard, text='Проверить защиту без сетевых запросов', command=self.guard_status).pack(anchor='w', pady=5)
        ttk.Button(guard, text='Проверить соединения защищённых пакетов', command=self.guard_probe).pack(anchor='w', pady=5)
        ttk.Button(guard, text='Проверить WFP-фильтры (потребуется UAC)', command=self.guard_filters).pack(anchor='w', pady=5)
        ttk.Button(guard, text='Запустить защищённый Chrome Claude', state='disabled', command=lambda: self.guard_launch('chrome')).pack(anchor='w', pady=(15, 5))
        ttk.Button(guard, text='Запустить защищённый редактор Claude', state='disabled', command=lambda: self.guard_launch('vscode')).pack(anchor='w', pady=5)
        ttk.Label(guard, text='Диагностические проверки не разрешают запуск рабочих клиентов. '
                  'До полной приёмки установленной защиты запуск заблокирован.', wraplength=930).pack(anchor='w', pady=8)

    def build_connection_tab(self, connection):
        """Remote proxy, local tunnel profile and connection diagnostics."""
        self.connection_local = tk.StringVar(value=config.BACKEND_URL)
        self.connection_router = tk.StringVar()
        self.connection_ips = tk.StringVar()
        self.proxy_fields = {key: tk.StringVar(value='1080' if key == 'port' else '')
                             for key in ('host', 'port', 'username', 'password')}
        self.proxy_draft = None
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
        ttk.Button(row, text='Импортировать VLESS+Reality (JSON)', command=self.backend_import).pack(side='left', padx=(0,8))
        ttk.Button(row, text='Показать импортированные', command=self.backend_catalog).pack(side='left')
        row = ttk.Frame(connection)
        row.pack(anchor='w', pady=4)
        ttk.Button(row, text='Установить движок VLESS', command=self.engine_install).pack(side='left', padx=(0, 8))
        ttk.Button(row, text='Снять прокси или движок', command=self.backend_remove).pack(side='left')
        ttk.Label(connection, text='Импорт сохраняет профиль зашифрованным. Он остаётся неактивным до установки и приёмки защиты. '
                  'Импорт и просмотр не запускают туннель и не открывают Claude.', wraplength=760).pack(anchor='w', pady=6)
        ttk.Label(connection, text='Отдельная диагностика соединения', font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=6)
        for label, variable in [('Локальный proxy (HTTP CONNECT или SOCKS5)', self.connection_local),
                                ('Ожидаемые публичные IP выхода, через запятую', self.connection_ips)]:
            ttk.Label(connection, text=label).pack(anchor='w', pady=(8, 2))
            ttk.Entry(connection, textvariable=variable, width=75).pack(anchor='w', fill='x')
        ttk.Label(connection, text=f'Формат: {config.BACKEND_URL} или socks5://127.0.0.1:1080. '
                  'IP выхода возьмите из доверенной настройки провайдера. Диагностика использует только указанный локальный proxy.', wraplength=760).pack(anchor='w', pady=8)
        row = ttk.Frame(connection)
        row.pack(anchor='w', pady=6)
        ttk.Button(row, text='Сохранить профиль', command=self.connection_save).pack(side='left', padx=(0, 8))
        ttk.Button(row, text='Загрузить сохранённый', command=self.connection_load).pack(side='left')
        ttk.Button(connection, text='Проверить сохранённый локальный путь', command=lambda: self.connection_check(False)).pack(anchor='w', pady=4)
        ttk.Label(connection, text='Проверка измеряет выход одного HTTPS-запроса, не весь трафик Claude. Текущие сеансы и настройки сети не меняются. '
                  'Успешное измерение не разрешает запуск рабочих клиентов. Прозрачный путь роутера не поддержан.', wraplength=760).pack(anchor='w', pady=8)

    def build_policy_tab(self, policy):
        """Chosen profiles, saved policies and the extra Code files."""
        ttk.Label(policy, text='Сначала выполните анализ, затем выберите найденные профили. Новые пути и версии требуют нового просмотра.', wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(policy, text='Выбрать найденные профили', command=self.choose_profiles).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Добавить проект для проверки настроек', command=self.add_project).pack(anchor='w', pady=5)
        self.strict = tk.BooleanVar(value=False)
        ttk.Checkbutton(policy, text='Отключить необязательную телеметрию CLI (может повлиять на Remote Control)', variable=self.strict, command=self.set_privacy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Сохранить политику показанного плана', command=self.save_policy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Открыть сохранённую политику', command=self.load_policy).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Разобрать дополнительные файлы Code', command=self.plan_customizations).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Применить план дополнительных файлов', command=self.apply_customizations).pack(anchor='w', pady=5)
        ttk.Button(policy, text='Извлечь архив исходников Code', command=self.recover_customizations).pack(anchor='w', pady=5)
        ttk.Label(policy, text='Политика зашифрована DPAPI. Автоматический CLI-запуск: --apply --policy <файл> --server-step-complete.\n'
                  'Серверный этап подтверждается для каждого запуска; сохранённая политика не подтверждает отзыв новых сессий.', wraplength=930).pack(anchor='w', pady=12)

    def build_cleanup_panel(self, page):
        self.cleanup_mode = tk.StringVar(value='reset_memory')
        self.wipe_plan = None
        self.cleanup_accept_unlisted = False
        self.cleanup_cowork_export = None
        for mode, label in WIPE_MODES.items():
            ttk.Radiobutton(page, text=label, variable=self.cleanup_mode, value=mode).pack(anchor='w')
        ttk.Label(page, text='Сброс использует выбранные компоненты и существующий план. '
                  'Стирание охватывает Desktop и Claude-Data/Cowork независимо от версии, Code и хранилище расширения. '
                  'Сохранённые пароли Claude удаляются. Ключи Windows, базы редактора и сайты проверяются отдельно.',
                  wraplength=900).pack(anchor='w', pady=8)
        row = ttk.Frame(page)
        row.pack(fill='x')
        ttk.Button(row, text='Предпросмотр и размеры', command=self.cleanup_preview).pack(side='left')
        ttk.Button(row, text='Проверить остатки файлов', command=self.cleanup_audit).pack(side='left', padx=8)
        ttk.Button(row, text='Выполнить выбранную очистку', command=self.cleanup_apply).pack(side='left')
        resolve = ttk.Frame(page)
        resolve.pack(fill='x', pady=6)
        for label, action in [('Устранить: дополнительные записи', self.plan_customizations),
                              ('Применить удаление записей', self.apply_customizations),
                              ('Устранить: экспорт Cowork', self.export_cowork),
                              ('Устранить: неизвестная версия', self.cleanup_accept_version)]:
            ttk.Button(resolve, text=label, command=action).pack(side='left', padx=3)
        owners = ttk.Frame(page)
        owners.pack(fill='x', pady=6)
        ttk.Button(owners, text='Закрыть процессы Claude', command=self.cleanup_close_processes).pack(side='left')
        ttk.Button(owners, text='Остановить службу Cowork', command=self.cleanup_stop_service).pack(side='left', padx=6)
        sites = ttk.Frame(page)
        sites.pack(fill='x', pady=4)
        ttk.Button(sites, text='Данные сайтов Chrome / Edge', command=self.preview_browser_sites).pack(side='left')
        ttk.Button(sites, text='Удалить cookies и IndexedDB Claude', command=self.clear_browser_sites).pack(side='left', padx=6)
        ttk.Button(sites, text='Проекты и среды: границы отчёта', command=self.report_external_scope).pack(side='left')
        ttk.Button(page, text='Остальные данные сайта: выбрать профиль и открыть настройки',
                   command=self.browser_site_settings).pack(anchor='w')
        keys = ttk.Frame(page)
        keys.pack(fill='x', pady=4)
        for label, action in [('План ключей Desktop', self.plan_desktop_keys),
                              ('Применить план ключей', self.apply_desktop_keys),
                              ('Проверить новый ключ', self.verify_desktop_key)]:
            ttk.Button(keys, text=label, command=action).pack(side='left', padx=3)
        ttk.Label(page, text='Ключи: сначала отдельный план и сброс, затем файловое стирание. Только проверенная версия MSIX. '
                  'Браузеры: общий Local Storage и кэш остаются для ручной очистки.', wraplength=930).pack(anchor='w')
        self.cleanup_text = tk.Text(page, wrap='word', height=18)
        self.cleanup_text.pack(fill='both', expand=True, pady=8)
        self.cleanup_text.insert('1.0', 'Предпросмотр ничего не удаляет. Для стирания нужен свежий план и слово СТЕРЕТЬ. Память Cowork экспортируется отдельно.')
        self.cleanup_text.configure(state='disabled')

    def preview_browser_sites(self):
        self.run(lambda: self.browser_sites.site_data(self.paths), self.show_json)

    def browser_site_settings(self):
        if self.busy:
            return
        def choose(rows):
            self.show_json({'profiles': rows, 'status': Reset.MANUAL_ACTION_REQUIRED})
            if not rows:
                return
            choices = '\n'.join(f"{row['profile_number']}: {row['browser']}" for row in rows)
            number = self.dialogs.askinteger('Данные сайта — ручной шаг',
                choices + '\nВведите номер профиля. Откроются настройки; само открытие ничего не очищает.',
                minvalue=1, maxvalue=len(rows))
            if number is not None:
                self.run(lambda: self.browser_sites.open_site_settings(self.paths, number), self.show_json)
        self.run(lambda: self.browser_sites.manual_cleanup_profiles(self.paths), choose)

    def clear_browser_sites(self):
        if self.busy:
            return
        word = self.dialogs.askstring('Данные сайтов Claude',
            'Закройте Chrome и Edge. Во всех стандартных профилях будут удалены cookies claude.ai '
            'и IndexedDB https://claude.ai. Общие хранилища и кэш требуют ручной очистки. '
            'Профили сохранятся. Введите СТЕРЕТЬ:')
        if word == 'СТЕРЕТЬ':
            self.run(lambda: self.browser_sites.site_data(self.paths, erase=True, confirmation=Confirmation.ERASE),
                     self.show_json)

    def report_external_scope(self):
        from ..reset.browser_sites import external_scope_report
        self.run(external_scope_report, self.show_json)

    def cleanup_preview(self):
        mode = self.cleanup_mode.get()
        if mode == 'reset_memory':
            self.tabs.select(self.analysis)
            self.analyze()
            return
        self.wipe_plan = None
        accepted = self.cleanup_accept_unlisted
        export = self.cleanup_cowork_export
        def work():
            plan = self.cleanup.prepare_wipe(self.paths, mode, accept_unlisted=accepted, cowork_export=export)
            result = self.cleanup.preview(self.paths, mode)
            result['credential_count'] = len(plan.credentials)
            return plan, result
        def ready(value):
            plan, result = value
            if self.cleanup_mode.get() != mode:
                return
            self.wipe_plan = plan
            result['blockers'] = plan.blockers
            self.show_cleanup(result)
        self.run(work, ready)

    def cleanup_accept_version(self):
        if self.busy:
            return
        if self.dialogs.askyesno('Непроверенная версия',
                              'Разрешить стирание фиксированных каталогов для непроверенной версии? '
                              'Данные вне списка не проверены. Выбор будет записан в отчёт.'):
            self.cleanup_accept_unlisted = True
            self.cleanup_preview()

    def cleanup_close_processes(self):
        self.cleanup_resolve(lambda: self.cleanup_actions.resolve_processes(clients.CLOSABLE_APPS), 'Закрыть процессы Claude? Несохранённые данные могут быть потеряны. '
                             'Общий редактор и текущий исполнитель сохраняются; дочерние инструменты могут потребовать ручного закрытия.')

    def cleanup_stop_service(self):
        self.cleanup_resolve(self.cleanup_actions.resolve_service, 'Остановить службу Cowork? Сначала сохраните работу. '
                             'При отказе доступа потребуется отдельная остановка владельцем с правами администратора.')

    def cleanup_resolve(self, action, question):
        if self.busy or not self.dialogs.askyesno('Устранение блокировки', question) or self.busy:
            return
        self.wipe_plan = None
        self.invalidate()
        def done(result):
            self.show_json(result)
            self.cleanup_preview()
        self.run(action, done)

    def cleanup_apply(self):
        if self.busy:
            return
        if self.cleanup_mode.get() == 'reset_memory':
            self.apply()
            return
        plan = self.wipe_plan
        if plan is None or plan.mode != self.cleanup_mode.get() or plan.blockers:
            return self.dialogs.showinfo('Очистка', 'Получите новый предпросмотр и устраните блокеры.')
        if not self.server_done.get():
            return self.dialogs.showinfo('Серверный этап', 'Сначала выполните и отметьте отзыв на сервере.')
        word = self.dialogs.askstring('Необратимое стирание',
                                      'Будут удалены данные из предпросмотра, включая историю и вход. '
                                      'Память Cowork экспортируйте отдельно. Введите СТЕРЕТЬ:', parent=self.root)
        if word != 'СТЕРЕТЬ':
            return
        if (self.busy or self.wipe_plan is not plan or self.cleanup_mode.get() != plan.mode
                or not self.server_done.get()):
            return self.dialogs.showinfo('Очистка', 'План изменился. Повторите предпросмотр.')
        self.wipe_plan = None
        self.run(lambda: self.cleanup.WipeExecutor(self.paths).apply(plan, confirmation=Confirmation.ERASE, consent_id=plan.id,
                 server_step_complete=True), self.cleanup_finished)

    def cleanup_finished(self, result):
        self.show_cleanup(result['audit'])
        self.show_json(result)

    def cleanup_audit(self):
        self.run(lambda: self.cleanup.audit(self.paths), self.show_cleanup)

    def show_cleanup(self, result):
        statuses = {'present': 'найдено', 'absent': 'нет', 'unavailable': 'не удалось проверить'}
        lines = [f"{r['label']}: {statuses[r['status']]}; файлов: {r['files']}; байт: {r['bytes']}"
                 for r in result['rows']]
        lines.append(f"Итого проверено байт: {result['bytes']}")
        if 'credential_count' in result:
            lines.append(f"Сохранённых паролей Claude к удалению: {result['credential_count']}")
        lines.extend('Блокер: ' + WIPE_BLOCKERS[key] for key in result.get('blockers', ()))
        if 'zero_file_remainder' in result:
            lines.append('Остатки в фиксированных каталогах: ' +
                         ('не обнаружены' if result['zero_file_remainder'] else 'есть или проверка неполна'))
        lines.append('Полный нулевой остаток не подтверждён: ключи, пароли, базы редактора, сайты, проекты и сервер вне этой проверки.')
        self.cleanup_text.configure(state='normal')
        self.cleanup_text.delete('1.0', 'end')
        self.cleanup_text.insert('1.0', '\n'.join(lines))
        self.cleanup_text.configure(state='disabled')

    @property
    def busy(self):
        return self.worker.busy

    def invalidate(self):
        self.plan_revision = getattr(self, 'plan_revision', 0) + 1
        self.plan = None
        self.policy_file = None
        self.status.set('Состав операций изменён. Выполните анализ заново.')

    def close(self):
        if self.busy:
            self.dialogs.showinfo('Операция выполняется', 'Дождитесь результата текущей операции перед закрытием программы.')
            return
        from ..elevation.claims import blocked
        if hasattr(self, 'paths') and blocked(self.paths):
            if not self.dialogs.askyesno('Исход операции не подтверждён', gui_message('uac_close_unknown')):
                return
        self.root.destroy()

    def safe(self, action):
        if self.busy:
            return
        try:
            return action()
        except Exception:
            self.show_operation_error('operation_failed')

    def show_operation_error(self, key):
        message = gui_message(key)
        self.status.set(message)
        self.dialogs.showerror('Операция остановлена', message)

    def callback_exception(self, _kind, _value, _traceback):
        # Tk's default handler prints the raw exception and traceback to stderr.
        self.show_operation_error('callback_failed')

    def run(self, action, callback, *, waiting_uac=False):
        return self.run_steps(lambda context: context.step(action, waiting_uac=waiting_uac), callback)

    def run_steps(self, action, callback):
        if self.busy:
            return
        self.result_callback = callback
        self.operation = self.worker.start(action)
        self.status.set(gui_message('queued'))

    def cancel(self):
        if not self.worker.cancel():
            self.status.set(gui_message('cancel_unavailable'))

    def poll(self):
        try:
            # Bounded batch: progress cannot starve the Tk event loop.
            for _ in range(32):
                event = self.events.get_nowait()
                if event.operation != self.operation:
                    continue
                message = gui_message(event.state)
                if event.step:
                    message = gui_message('step').format(step=event.step) + message
                self.status.set(message)
                self.cancel_button.configure(state='normal' if event.cancellable else 'disabled')
                if event.state in FINISHED:
                    result = self.worker.take_result(event.operation)
                    callback, self.result_callback = self.result_callback, None
                    self.operation = None
                    if event.state in (Phase.OPERATION_FAILED, Phase.WORKER_START_FAILED):
                        self.show_operation_error(event.state)
                    elif event.state == Phase.COMPLETED:
                        try:
                            callback(result)
                        except Exception:
                            self.show_operation_error('callback_failed')
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.poll)

    def display(self, content):
        self.text.configure(state='normal')
        self.text.delete('1.0', 'end')
        self.text.insert('1.0', content)
        self.text.configure(state='disabled')

    def analyze(self):
        components = [k for k, v in self.components.items() if v.get()]
        if not components:
            return self.dialogs.showinfo('Выбор', 'Выберите хотя бы один компонент.')
        selection = copy.deepcopy(self.selection)
        self.run(lambda: build_plan(self.paths, components, selection=selection, platform_state=self.inspect()),
                 self.show_plan)

    def choose_state_location(self):
        if self.busy:
            return
        directory = self.dialogs.askdirectory(parent=self.root, initialdir=str(self.paths.state),
                                             title='Выберите существующее хранилище ClaudeReset — файлы не перемещаются', mustexist=True)
        if not directory:
            return
        from ..layout import select
        try:
            select(self.paths.home, Path(directory))
        except (SafetyError, OSError):
            return self.show_operation_error('operation_failed')
        self.dialogs.showinfo('Хранилище выбрано', 'Архивы не перемещались. Новый путь будет использоваться после перезапуска ClaudeReset. Текущий запуск продолжает использовать прежний путь.')

    def show_plan(self, plan):
        self.plan_revision = getattr(self, 'plan_revision', 0) + 1
        self.plan = plan
        lines = ['ПЛАН ЛОКАЛЬНЫХ ОПЕРАЦИЙ', '', f'Найдено файлов памяти: {plan.memory_count}',
                 (f'Объём выбранных объектов: {plan.data_size["files"]} файлов, {plan.data_size["bytes"]:,} байт' if plan.data_size.get('complete', True) else
                  'Объём не подсчитан полностью: сначала нужно устранить блокирующие условия'),
                 'Ключи Desktop: сохраняются; Cowork VM: отдельная непроверенная среда', '', 'Найденные профили:']
        if plan.inventory:
            lines += [f'• [{p.component}] {"выбран" if p.selected else "исключён"}: {p.path}' for p in plan.inventory.profiles]
        lines += ['', 'Операции:']
        lines += [f'• [{a.component}] {say(a.description, 'ru')}\n  {a.target}' for a in plan.actions]
        lines += ['', 'Блокирующие условия:'] + (['• ' + say(b, 'ru') for b in plan.blockers] or ['Нет обнаруженных блокировок для перечисленных локальных операций.'])
        lines += ['', 'Ограничения и наблюдения:'] + ['• ' + say(n, 'ru') for n in plan.observations]
        if any(plan.memory_risks.values()):
            lines += ['', 'В памяти обнаружены возможные секреты/географические маркеры. Текст не изменяется и не выводится.']
        self.display('\n'.join(lines))

    def apply(self):
        if self.busy:
            return
        if not self.plan:
            return self.dialogs.showinfo('Нужен план', 'Сначала выполните анализ.')
        if self.plan.blockers:
            return self.dialogs.showerror('Есть блокировки', 'Устраните перечисленные блокировки и повторите анализ. Ничего не изменено.')
        if not self.server_done.get():
            return self.dialogs.showinfo('Серверный этап', 'Сначала выполните нужные действия на вкладке «Серверные действия».')
        plan = self.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(self, 'plan_revision', 0)
        if not self.dialogs.askyesno('Выполнить показанные операции?',
            'Будут удалены выбранные локальные данные входа и история Claude Code, сброшено выбранное состояние расширения. '
            'Память сохранится без изменения текста и будет возвращена. Если выбран Desktop, будут сброшены перечисленные хранилища; ключи сохранятся. Продолжить?'):
            return
        if not self.confirmed_plan_current(plan, snapshot, revision) or not self.server_done.get():
            return
        word = self.dialogs.askstring('Подтверждение сброса', 'Введите СБРОСИТЬ:', parent=self.root)
        if word != 'СБРОСИТЬ':
            return
        if not self.confirmed_plan_current(plan, snapshot, revision) or not self.server_done.get():
            return
        self.plan = None
        self.run(lambda: self.executor(self.paths).apply(snapshot, consent_id=snapshot.id, server_step_complete=True),
                 self.applied)

    def confirmed_plan_current(self, plan, snapshot, revision):
        # Modal dialogs process Tk events: approval must not follow a replaced,
        # invalidated or edited plan, or race an operation started in the dialog.
        if (self.busy or self.plan is not plan or self.plan != snapshot
                or getattr(self, 'plan_revision', 0) != revision):
            self.show_operation_error('plan_changed')
            return False
        return True

    def applied(self, result):
        self.last_run = result['run']
        self.display(json.dumps(render(result, 'ru'), ensure_ascii=False, indent=2))

    def show_json(self, result):
        # Freeze the displayed value before any modal event loop can run; shown and saved without secrets.
        from .public_view import redact
        serialized = json.dumps(redact(render(result, 'ru')), ensure_ascii=False, indent=2)
        snapshot = json.loads(serialized)
        window = tk.Toplevel(self.root)
        window.title('Результат проверки')
        width = max(360, min(900, self.root.winfo_screenwidth() - 80))
        height = max(300, min(700, self.root.winfo_screenheight() - 120))
        window.geometry(f'{width}x{height}')
        window.transient(self.root)
        frame = ttk.Frame(window, padding=12)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Настройки и наблюдения указаны отдельно. «Не проверено» не означает успешную проверку.',
                  wraplength=width-40).pack(anchor='w', pady=(0, 8))
        text = scrolledtext.ScrolledText(frame, wrap='word', font=('Consolas', 10))
        text.pack(fill='both', expand=True)
        text.insert('1.0', serialized)
        text.configure(state='disabled')
        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(8, 0))
        def save():
            file = self.dialogs.asksaveasfilename(parent=window, defaultextension='.json',
                initialfile='claude-reset-check.json', filetypes=[('JSON', '*.json')])
            if file:
                self.safe(lambda: atomic_json(Path(file), snapshot, Path(file).parent))
        ttk.Button(buttons, text='Сохранить JSON', command=save).pack(side='left')
        ttk.Button(buttons, text='Закрыть', command=window.destroy).pack(side='right')
        window.bind('<Escape>', lambda _: window.destroy())
        return window

    def open_help(self, kind):
        from .help_docs import read_document, check_bundle

        def show():
            title, content = (check_bundle(root=self.help_root) if kind == 'bundle'
                              else read_document(kind, root=self.help_root))
            window = tk.Toplevel(self.root)
            window.title(title)
            window.geometry('850x600')
            window.transient(self.root)
            text = scrolledtext.ScrolledText(window, wrap='word', font=('Segoe UI', 10))
            text.pack(fill='both', expand=True)
            text.insert('1.0', content)
            text.configure(state='disabled')
            ttk.Button(window, text='Закрыть', command=window.destroy).pack(pady=8)

        self.safe(show)

    def run_diagnostics(self):
        self.run(lambda: self.diagnostics.collect(self.paths), self.show_json)

    def show_operation_history(self):
        self.run(lambda: self.diagnostics.operation_history(self.paths), self.show_json)

    def show_privacy_observations(self):
        from ..privacy.observations import summarize
        path = self.dialogs.askopenfilename(title='Сохранённый журнал назначений реле (до 64 КиБ)',
                                         filetypes=[('Журнал JSONL', '*.jsonl')])
        if path:
            self.run(lambda: summarize(Path(path)), self.show_json)

    def run_advisor(self):
        country = self.advisor_country.get()
        self.run(lambda: self.diagnostics.advise(country), self.show_json)

    def open_advisor_settings(self, kind):
        self.safe(lambda: self.diagnostics.open_settings(kind))

    def save_report(self):
        if not self.plan:
            return self.dialogs.showinfo('Отчёт', 'Сначала выполните анализ.')
        from .public_view import redact
        snapshot = redact(render(self.plan.redacted(), 'en'))
        file = self.dialogs.asksaveasfilename(defaultextension='.json', initialfile='claude-reset-audit.json', filetypes=[('JSON', '*.json')])
        if file:
            self.safe(lambda: atomic_json(Path(file), snapshot, Path(file).parent))

    def change_timezone(self):
        if self.dialogs.askyesno('Системный часовой пояс', 'Изменить пояс всей Windows на Стамбул, только если время на часах сохранится?'):
            self.plan = None
            self.run(set_istanbul_same_offset, self.show_json)

    def open_chrome(self):
        if not self.last_run:
            try:
                profiles = managed_chrome_profiles(self.paths)
            except (OSError, SafetyError):
                return self.dialogs.showerror('Профиль Chrome', 'Не удалось проверить сохранённые профили Chrome. Данные не изменены.')
            if len(profiles) == 1:
                self.last_run = profiles[0]
        if not self.last_run:
            file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.CHROME_PROFILES), filetypes=[('Профиль', layout.PROFILE_MARKER)])
            if not file:
                return
            self.last_run = Path(file).parent.name
        self.safe(lambda: self.launch_chrome(self.paths, self.last_run))

    def open_oauth(self):
        if not self.last_run:
            return self.dialogs.showinfo('Профиль', 'Сначала создайте или откройте управляемый профиль Chrome.')
        url = self.dialogs.askstring('OAuth', 'Вставьте ссылку HTTPS на claude.ai, claude.com или platform.claude.com. Ссылка не записывается в отчёт.')
        if url:
            self.safe(lambda: self.launch_chrome(self.paths, self.last_run, url))

    def probe_browser(self):
        if not self.last_run:
            return self.dialogs.showinfo('Профиль', 'Сначала создайте или откройте управляемый профиль Chrome.')
        run_id = self.last_run
        self.run(lambda: browser_measurement(lambda url: self.launch_chrome(self.paths, run_id, url, loopback_probe=True),
                                         PROBE_PAGE), self.show_json)

    def recover(self):
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.RUNS), filetypes=[('Memory DPAPI', 'memory.dpapi')])
        if file:
            run_id = Path(file).parent.name
            self.run(lambda: str(recover_memory(self.paths, run_id)), lambda value: self.dialogs.showinfo('Память экспортирована', value))

    def resume(self):
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.RUNS), filetypes=[('Журнал', 'journal.dpapi')])
        if file:
            run_id = Path(file).parent.name
            self.run(lambda: self.executor(self.paths).resume(run_id), self.applied)

    def set_privacy(self):
        self.selection.privacy = 'strict' if self.strict.get() else 'compatible'
        self.invalidate()

    def add_project(self):
        directory = self.dialogs.askdirectory(title='Проект: только проверка, файлы не удаляются')
        if directory and directory not in self.selection.projects:
            self.selection.projects.append(directory)
            self.invalidate()

    def choose_profiles(self):
        if not self.plan or not self.plan.inventory:
            return self.dialogs.showinfo('Профили', 'Сначала выполните анализ.')
        plan = self.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(self, 'plan_revision', 0)
        profiles = [p for p in snapshot.inventory.profiles if p.component in ('code', 'vscode', 'desktop')]
        window = tk.Toplevel(self.root)
        window.title('Область следующего анализа')
        window.geometry('900x360')
        listing = tk.Listbox(window, selectmode='multiple', exportselection=False)
        listing.pack(fill='both', expand=True, padx=12, pady=12)
        for i, p in enumerate(profiles):
            listing.insert('end', f'[{p.component}] {p.path}')
            if p.selected:
                listing.selection_set(i)
        def selected():
            if not self.confirmed_plan_current(plan, snapshot, revision):
                return
            self.selection.profiles = [profiles[i].path for i in listing.curselection()]
            self.invalidate()
            window.destroy()
            self.analyze()
        ttk.Button(window, text='Применить выбор и пересчитать план', command=selected).pack(pady=12)

    def save_policy(self):
        if self.busy:
            return
        if not self.plan or self.plan.blockers:
            return self.dialogs.showinfo('Политика', 'Нужен проверенный план без блокирующих условий.')
        plan = self.plan
        snapshot = copy.deepcopy(plan)
        revision = getattr(self, 'plan_revision', 0)
        file = self.dialogs.asksaveasfilename(defaultextension='.dpapi', initialfile='policy.dpapi')
        if file:
            if not self.confirmed_plan_current(plan, snapshot, revision):
                return
            if not self.dialogs.askyesno('Автоматическое выполнение', 'Разрешить будущие локальные сбросы в показанной области без повторного просмотра? Новые профили и версии будут блокироваться.'):
                return
            if not self.confirmed_plan_current(plan, snapshot, revision):
                return
            self.safe(lambda: self.policy.save_policy(Path(file), snapshot, consent_id=snapshot.id))

    def load_policy(self):
        file = self.dialogs.askopenfilename(filetypes=[('Политика DPAPI', '*.dpapi')])
        if file:
            def loaded(plan):
                self.selection = plan.selection
                self.strict.set(plan.selection.privacy == 'strict')
                for key, variable in self.components.items():
                    variable.set(key in plan.components)
                self.show_plan(plan)
            self.run(lambda: policy_plan(self.paths, Path(file)), loaded)

    def acceptance_template(self):
        if not self.last_run:
            return self.dialogs.showinfo('Приёмка', 'Сначала выполните локальные операции. Бланк привязывается к конкретному запуску.')
        file = self.dialogs.asksaveasfilename(defaultextension='.json', initialfile='acceptance.json')
        if file:
            self.safe(lambda: atomic_json(Path(file), template_for_run(self.paths, self.last_run), Path(file).parent))

    def verify_identifiers(self):
        if not self.last_run:
            file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.RUNS), filetypes=[('Журнал', 'journal.dpapi')])
            if not file:
                return
            self.last_run = Path(file).parent.name
        run_id = self.last_run
        self.run(lambda: verify_run(self.paths, run_id), self.show_json)

    def mainloop(self):
        self.root.mainloop()

    def plan_desktop_keys(self):
        from ..reset.desktop_keys import create_plan
        profile = layout.desktop_data(self.paths)
        self.run(lambda: create_plan(self.paths, profile, desktop=self.desktop), self.show_json)

    def apply_desktop_keys(self):
        from ..reset.desktop_keys import apply_plan, review_plan
        if not self.server_done.get():
            return self.dialogs.showinfo('Серверный этап', 'Сначала выполните отзыв устройств и сессий на сервере и отметьте этот этап.')
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.KEY_RUNS), filetypes=[('План ключей DPAPI', 'plan.dpapi')])
        if not file:
            return
        run_id = Path(file).parent.name
        def reviewed(report):
            if self.dialogs.askyesno('Удаление ключей приложения', f'План {run_id}: аккаунтов {report["accounts"]}, ключей {report["keys"]}. Удалить эти ключи и регистрацию? Действие необратимо. Desktop и служба Cowork должны быть остановлены.'):
                self.run(lambda: apply_plan(self.paths, run_id, server_step_complete=True, desktop=self.desktop),
                         self.show_json)
        self.run(lambda: review_plan(self.paths, run_id), reviewed)

    def export_cowork(self):
        def ready(result):
            self.cleanup_cowork_export = (tuple(result['runs']) if result.get('status') == Export.ENCRYPTED_EXPORT_VERIFIED else None)
            self.wipe_plan = None
            self.show_json(result)
        self.run(lambda: self.cowork.export_all(self.paths), ready)

    def apply_after_server(self, runs, plan_label, title, question, apply) -> None:
        """A plan that needs the server step first: pick its plan.dpapi, ask, apply it."""
        if not self.server_done.get():
            return self.dialogs.showinfo('Серверный этап', 'Сначала выполните и отметьте отзыв на сервере.')
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / runs), filetypes=[(plan_label, 'plan.dpapi')])
        if file and self.dialogs.askyesno(title, question):
            self.run(lambda: apply(self.paths, Path(file).parent.name, server_step_complete=True), self.show_json)

    def reset_cowork(self):
        from ..reset.cowork import reset_exported
        self.apply_after_server(layout.COWORK_RUNS, 'План экспорта DPAPI', 'Сброс Cowork',
                                'Удалить локальные сессии и sessiondata.vhdx после проверки этого экспорта? Память и '
                                'выбранные результаты останутся в отдельном DPAPI-архиве; импорт в новый аккаунт '
                                'выполняется отдельно. Остальная история будет удалена.', reset_exported)

    def recover_from_plan(self, runs, plan_label, title, recover) -> None:
        """Recover an export into a separate folder: pick its plan.dpapi, then show where it went."""
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / runs), filetypes=[(plan_label, 'plan.dpapi')])
        if file:
            self.run(lambda: str(recover(self.paths, Path(file).parent.name)), lambda p: self.dialogs.showinfo(title, p))

    def recover_cowork(self):
        from ..reset.cowork import recover_export
        self.recover_from_plan(layout.COWORK_RUNS, 'План экспорта DPAPI', 'Экспорт Cowork', recover_export)

    def verify_desktop_key(self):
        from ..reset.desktop_keys import verify_after_reset
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / layout.KEY_RUNS), filetypes=[('План ключей DPAPI', 'plan.dpapi')])
        if file:
            self.run(lambda: verify_after_reset(self.paths, Path(file).parent.name, desktop=self.desktop), self.show_json)

    def audit_privacy(self):
        from ..privacy.inventory import audit
        profiles = None
        if self.plan and self.plan.inventory:
            profiles = [(p.component, Path(p.path)) for p in self.plan.inventory.profiles if p.selected]
        self.run(lambda: audit(self.paths, profiles), self.show_json)

    def plan_customizations(self):
        try:
            entries = self.customizations.extra_entries(layout.code_home(self.paths))
        except (OSError, SafetyError):
            return self.dialogs.showerror('Дополнительные файлы', 'Не удалось безопасно прочитать профиль Code.')
        window = tk.Toplevel(self.root)
        window.title('Экспорт пользовательских исходников')
        window.geometry('740x460')
        ttk.Label(window, text='Выберите исходники для отдельного зашифрованного архива. При применении плана все перечисленные объекты будут удалены из активного Code, включая невыбранные. Учётные данные экспортировать нельзя. Память здесь не затрагивается.', wraplength=700).pack(padx=12,pady=12)
        listing = tk.Listbox(window, selectmode='multiple', exportselection=False)
        listing.pack(fill='both',expand=True,padx=12)
        for entry in entries:
            listing.insert('end', entry)
        listing.selection_set(0,'end')
        def prepare():
            if self.busy:
                self.show_operation_error('operation_busy')
                return
            selected = [entries[i] for i in listing.curselection()]
            window.destroy()
            self.run(lambda: self.customizations.create_plan(self.paths, selected), self.show_json)
        ttk.Button(window,text='Создать архив и план без удаления',command=prepare).pack(pady=12)

    def apply_customizations(self):
        from ..reset.customizations import apply_plan
        self.apply_after_server(layout.CUSTOMIZATION_RUNS, 'План DPAPI', 'Удаление дополнительных файлов',
                                'Применить выбранный план? Исходники сохранятся в отдельном архиве; невыбранные '
                                'объекты будут удалены без экспорта. Старые настройки автоматически не возвращаются.',
                                apply_plan)

    def guard_status(self):
        from ..backend.location import status
        self.run(lambda: status(self.paths), self.show_json)

    def proxy_check(self):
        from ..services.proxy import ProxyDraft
        def start():
            try:
                draft = ProxyDraft(proxy_type=self.proxy_type.get(), probe=self.probe,
                                   **{key: value.get() for key, value in self.proxy_fields.items()})
            except SafetyError as exc:
                # The draft raises only a fixed input hint, never the entered values.
                self.status.set(error_text(exc, 'ru'))
                self.dialogs.showwarning('Проверьте поля прокси', error_text(exc, 'ru'))
                return
            self.proxy_draft = draft
            self.run(draft.check, self.proxy_result)
        self.safe(start)

    def proxy_result(self, result):
        self.status.set(PROXY_MESSAGES.get(result['status'], 'Проверка прокси не завершена. Повторите проверку.'))

    def proxy_save(self):
        if self.busy:
            return
        draft = self.proxy_draft
        if draft is None or draft.expected is None or draft.proxy_type != self.proxy_type.get() or any(
                str(draft.profile[key]) != value.get().strip() if key in ('host', 'port')
                else draft.profile[key] != value.get() for key, value in self.proxy_fields.items()):
            self.proxy_result({'status': Proxy.PROXY_CONFIRMATION_REQUIRED})
            return
        if self.dialogs.askyesno('Подтвердить ожидаемый выход',
                'Измеренный адрес: ' + draft.expected['expected_exit_ips'][0] +
                '\nСохранить его как ожидаемый? Адрес хранится только в профиле DPAPI.'):
            self.run(lambda: draft.save(self.paths, confirmed=True), self.proxy_result)

    def connection_save(self):
        from ..network.connections import save
        profile = {'schema': 1, 'local_proxy': self.connection_local.get().strip(),
                   'router_proxy': None,
                   'expected_exit_ips': [s.strip() for s in self.connection_ips.get().split(',') if s.strip()]}
        self.run(lambda: save(self.paths, profile), self.show_json)

    def backend_import(self):
        from ..services.proxy import import_vless
        if self.busy:
            return
        file = self.dialogs.askopenfilename(title='Профиль VLESS+Reality с параметрами движка (JSON)', filetypes=[('JSON','*.json')])
        if file:
            self.run(lambda: import_vless(self.paths, Path(file)), self.proxy_result)

    def engine_install(self):
        from ..services.proxy import install_engine
        if self.busy:
            return
        profile = self.dialogs.askopenfilename(title='Профиль VLESS+Reality с параметрами движка (JSON)', filetypes=[('JSON', '*.json')])
        if not profile:
            return
        archive = None
        if self.dialogs.askyesno('Архив движка', 'Есть локальный архив движка закреплённой версии?\n'
                               '«Нет» — скачать закреплённую версию с официальной страницы выпусков; хеш проверяется.'):
            archive = self.dialogs.askopenfilename(title='Архив движка', filetypes=[('ZIP', '*.zip')]) or None
            if archive is None:
                return
        if not self.dialogs.askyesno('Установка движка VLESS',
                                   'Установить локальный туннель как задачу текущего пользователя? '
                                   'Клиенты Claude не меняются; после установки выход будет измерен и предложен для подтверждения.'):
            return
        self.run(lambda: install_engine(self.paths, Path(profile), Path(archive) if archive else None), self.engine_installed)

    def engine_installed(self, result):
        from ..services.proxy import LocalBackendDraft
        self.proxy_result(result)
        if result['status'] not in (Proxy.ENGINE_INSTALLED, Proxy.ENGINE_NEEDS_ATTENTION):
            return
        draft = LocalBackendDraft(self.paths, first=True, probe=self.probe)
        def checked(outcome):
            self.proxy_result(outcome)
            if outcome['status'] == Proxy.PROXY_CHECKED and self.dialogs.askyesno(
                    'Подтвердить ожидаемый выход', 'Измеренный адрес: ' + draft.expected['expected_exit_ips'][0] +
                    '\nСохранить его как ожидаемый? Адрес хранится только в профиле DPAPI.'):
                self.run(lambda: draft.save(self.paths, confirmed=True), self.proxy_result)
        self.run(draft.check, checked)

    def backend_remove(self):
        from ..services.proxy import remove_backend
        if self.busy or not self.dialogs.askyesno('Снять прокси или движок',
                'Удалить задачу движка VLESS и сохранённый удалённый прокси? Защита L1 при этом должна быть снята '
                'или остановлена: пока реле открыто, удаление будет отклонено. Ожидаемый выход сохраняется.'):
            return
        self.run(lambda: remove_backend(self.paths), self.proxy_result)

    def wizard_refresh(self):
        from ..services.progress import progress
        if self.busy:
            return
        server_done = bool(self.server_done.get())
        def shown(result):
            for step in result['steps']:
                self.wizard_states[step['key']].set(gui_message('wizard_state_' + step['state']))
            self.wizard_next = result['next']
        self.run(lambda: progress(self.paths, server_done=server_done), shown)

    def backend_catalog(self):
        from ..backend.profiles import catalog
        self.run(lambda: catalog(self.paths), self.show_backend_catalog)

    def show_backend_catalog(self, result):
        self.status.set('Список профилей прочитан. Туннель и Claude не запускались.')
        dialog = tk.Toplevel(self.root)
        dialog.title('Профили локального туннеля')
        dialog.geometry('880x410')
        dialog.minsize(740,320)
        dialog.transient(self.root)
        frame = ttk.Frame(dialog,padding=16)
        frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='Импортированные профили',font=('Segoe UI',13,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Все профили неактивны. Для запуска требуется установленная и проверенная защита.',
                  wraplength=810).pack(anchor='w',pady=(8,12))
        if not result['profiles']:
            ttk.Label(frame,text='Профили ещё не импортированы. Вернитесь на вкладку «Соединение» и выберите JSON-файл.').pack(anchor='w',pady=15)
        else:
            table=ttk.Treeview(frame,columns=('id','version','state'),show='headings',height=7)
            for key,label,width in [('id','Идентификатор',290),('version','Заявленная версия',150),('state','Состояние',240)]:
                table.heading(key,text=label)
                table.column(key,width=width,minwidth=100)
            for profile in result['profiles']:
                state='Неактивен' if profile['status']==Backend.IMPORTED_INACTIVE else 'Не удалось прочитать'
                table.insert('', 'end', values=(profile['profile_id'],profile.get('declared_engine_version','—'),state))
            table.pack(fill='both',expand=True)
        buttons=ttk.Frame(frame)
        buttons.pack(side='bottom',fill='x',pady=(12,0))
        ttk.Button(buttons,text='Диагностический отчёт',command=lambda:self.show_json(result)).pack(side='left')
        ttk.Button(buttons,text='Закрыть',command=dialog.destroy).pack(side='right')

    def build_protection_panel(self, page, connection):
        self.protection_text = tk.StringVar(value='Состояние ещё не проверялось. Открытие окна ничего не меняет.')
        self.protect_extension = tk.BooleanVar(value=False)
        self.protection_extension_choice = None
        self.protection_proxy_draft = None
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
                        variable=self.protect_extension, command=self.protection_extension_changed).pack(anchor='w', pady=8)
        ttk.Label(page, text='Без выбора сохраняется прежняя область; при первой установке расширение исключено. '
                  'Примените выбор отдельной кнопкой. Сеансы Claude Code могут потерять сеть. '
                  'После применения выполните Developer: Reload Window в VS Code и /resume в Claude Code.',
                  wraplength=930).pack(anchor='w', pady=8)
        ttk.Button(page, text='Применить выбор расширения', command=lambda: self.protection_action('extension')).pack(anchor='w', pady=5)
        ttk.Button(page, text='Применить проверенный прокси', command=self.protection_change_proxy).pack(anchor='w', pady=5)
        ttk.Button(page, text='Повторить проверку / проверить новый выход', command=self.protection_retry).pack(anchor='w', pady=5)
        ttk.Button(page, text='Подтвердить новый выход и перезапустить', command=lambda: self.protection_change_proxy(saved=True)).pack(anchor='w', pady=5)
        ttk.Button(page, text='Ввести реквизиты / выбрать другой прокси', command=lambda: self.tabs.select(connection)).pack(anchor='w', pady=5)
        ttk.Button(page, text='Настроить соединение', command=lambda: self.tabs.select(connection)).pack(anchor='w', pady=5)
        ttk.Label(page, text='L1 имеет открытые границы DNS, посредников и Cowork. Полный доступ к файлам сохраняется.',
                  wraplength=930).pack(anchor='w', pady=8)

    def protection_retry(self):
        from ..services.proxy import check_saved
        if self.busy:
            return
        self.protection_proxy_draft = None
        def checked(pair):
            self.protection_proxy_draft, outcome = pair
            self.proxy_result(outcome)
            self.protection_text.set(self.status.get())
        self.run(lambda: check_saved(self.paths, probe=self.probe), checked)

    def protection_change_proxy(self, saved=False):
        from . import protection_panel
        if self.busy:
            return
        draft = self.protection_proxy_draft if saved else self.proxy_draft
        if draft is None or draft.expected is None or (not saved and (draft.proxy_type != self.proxy_type.get() or any(
                str(draft.profile[k]) != v.get().strip() if k in ('host', 'port')
                else draft.profile[k] != v.get() for k, v in self.proxy_fields.items()))):
            self.protection_result({'text': protection_panel.RESULTS['proxy_confirmation_required']})
            return
        if self.dialogs.askyesno('Смена прокси / ожидаемого выхода',
                'Подтвердить измеренный выход: ' + draft.expected['expected_exit_ips'][0] +
                '\nСохранить профиль DPAPI и перезапустить установленный контроллер без переустановки? '
                'Клиенты временно потеряют сеть. При частичном исходе нужна проверка состояния.'):
            self.protection_text.set('Применение профиля; прежнее состояние не актуально.')
            self.run(lambda: protection_panel.perform(self.paths, 'change_proxy', confirmed=True,
                                                       proxy_draft=draft, l1=self.l1), self.protection_result)

    def protection_extension_changed(self):
        self.protection_extension_choice = bool(self.protect_extension.get())

    def protection_result(self, result):
        self.protection_text.set(result['text'])

    def protection_action(self, action):
        from . import protection_panel
        if self.busy:
            return
        if action == 'status':
            self.protection_text.set('Идёт новая проверка состояния…')
            self.run(lambda: protection_panel.status(self.paths, l1=self.l1), self.protection_result)
            return
        extension = self.protection_extension_choice
        def confirm(limits=None):
            if self.busy:
                return
            if action in ('install', 'reinstall'):
                if not limits['known']:
                    self.protection_result({'text': 'Новая граница L1: установка из окна недоступна.'})
                    return
                text = 'Вы принимаете следующие открытые границы L1?\n\n' + '\n'.join(limits['lines'])
                text += '\n\nУстановка запросит UAC. Защищённые клиенты могут временно потерять сеть.'
                if action == 'reinstall':
                    text += '\nКонтроллер будет остановлен и заменён текущей сборкой программы; прокси и выход сохраняются.'
                if extension is not None:
                    text += '\nБудет изменена область Claude Code в VS Code; сохраните работу и затем перезагрузите окно VS Code.'
            elif action == 'extension':
                text = 'Применить выбор к установленному контроллеру и перезапустить его? Сохраните работу Claude Code; затем выполните Developer: Reload Window и /resume. При исключении потребуется UAC для удаления только фильтров установленных бинарников расширения; будут сняты только точные настройки проекта. Расширение останется без защиты L1. Фильтры удалённых версий требуют отдельной проверки.'
            elif action == 'restart':
                text = 'Перезапустить контроллер? Клиенты временно останутся без сети; время будет показано в результате.'
            else:
                text = 'Снять защиту L1? Будут удалены её фильтры, автозапуск, backend, профиль соединения и согласие. Потребуется UAC. До завершения клиенты могут быть без сети.'
            if self.dialogs.askyesno('Подтверждение операции L1', text):
                self.protection_text.set('Операция выполняется; прежнее состояние больше не актуально.')
                self.run(lambda: protection_panel.perform(self.paths, action, confirmed=True,
                                                          protect_extension=extension, l1=self.l1),
                         self.protection_result, waiting_uac=action in ('install', 'reinstall', 'remove') or (action == 'extension' and extension is False))
        if action in ('install', 'reinstall'):
            self.run(lambda: protection_panel.limits(self.paths, l1=self.l1), confirm)
        else:
            confirm()

    def isolation_audit(self):
        from ..network.isolation_audit import audit
        self.run(lambda: audit(self.paths), self.show_json)

    def connection_load(self):
        from ..network.connections import load
        def loaded(profile):
            if profile is None:
                self.status.set('Профиль соединения пока не сохранён.')
                return
            self.connection_local.set(profile['local_proxy'])
            self.connection_router.set(profile['router_proxy'] or '')
            self.connection_ips.set(', '.join(profile['expected_exit_ips']))
            self.status.set('Профиль соединения загружен. Сетевых запросов не было.')
        self.run(lambda: load(self.paths), loaded)

    def connection_check(self, include_router):
        from ..network.remote_backend import check_saved
        self.run(lambda: check_saved(self.paths, include_router=include_router), self.show_json)

    def guard_probe(self):
        from ..network.legacy_guard import probe
        if self.dialogs.askyesno('Сетевая проба', 'Будут запущены короткие процессы в пакетах Desktop и защищённых запусков: прямое TCP-соединение '
                               '(должно быть запрещено) и HTTPS через локальный прокси. Настройки сети не меняются. Продолжить?'):
            self.run(lambda: probe(self.paths), self.show_json)

    def guard_filters(self):
        from ..network.legacy_guard import elevated_filters
        self.run(lambda: elevated_filters(self.paths), self.show_json, waiting_uac=True)

    def guard_launch(self, target):
        from ..network.legacy_guard import guarded_launch
        self.run(lambda: guarded_launch(self.paths, target), self.show_json)

    def recover_customizations(self):
        from ..reset.customizations import recover
        self.recover_from_plan(layout.CUSTOMIZATION_RUNS, 'План DPAPI', 'Экспорт исходников Code', recover)


# The words of the next step on the command line; the operations only name the step.
