"""The first tabs of the specialist window: the wizard (the steps in order and the help documents) and the server
steps the person does in the old account."""
import tkinter as tk
from tkinter import scrolledtext, ttk

from ...reset.new_account import open_server_page
from ..text import gui_message

__all__ = ['SERVER_STEPS', 'ServerTab', 'WizardTab']

# The server steps the person does in the old account.
SERVER_STEPS = (
    'В старом аккаунте открыть Settings → Account и завершить нужные сессии. Выход со всех устройств затронет '
    'также другие ПК и телефоны.',
    'Отдельно открыть Settings → Claude Code и отозвать нужные токены. Выход из веб-сессий не засчитывается как '
    'этот шаг.',
    'Проверить доступные в аккаунте устройства Cowork/Remote Control и сопряжения. Неподдерживаемый интерфейс не '
    'считать автоматически очищенным.',
    'Повторить для каждого прежнего аккаунта, для которого нужен отзыв. Без доступа к аккаунту серверный отзыв '
    'здесь не выполняется.',
    'Сохранить/экспортировать нужную облачную память до выхода. Программа сохраняет только найденную локальную '
    'память.',
)


class WizardTab:
    """The steps in the order the program requires, each opening its tab, and the help documents."""

    def __init__(self, app):
        self.app = app

    def build(self, wizard, pages):
        """The steps in the order the program requires, each opening its tab."""
        app = self.app
        ttk.Label(wizard, text=gui_message('wizard_intro'), wraplength=930).pack(anchor='w', pady=12)
        self.wizard_pages = pages
        self.wizard_states, self.wizard_next = {}, 'server'
        for key, page in self.wizard_pages.items():
            row = ttk.Frame(wizard)
            row.pack(anchor='w', fill='x', pady=4)
            ttk.Button(row, text=gui_message('wizard_' + key),
                       command=lambda p=page: app.tabs.select(p)).pack(side='left')
            self.wizard_states[key] = tk.StringVar(value=gui_message('wizard_state_unchecked'))
            ttk.Label(row, textvariable=self.wizard_states[key]).pack(side='left', padx=12)
        row = ttk.Frame(wizard)
        row.pack(anchor='w', pady=8)
        ttk.Button(row, text='Обновить ход', command=self.wizard_refresh).pack(side='left')
        ttk.Button(row, text='Следующий шаг',
                   command=lambda: app.tabs.select(self.wizard_pages[self.wizard_next])).pack(side='left', padx=8)
        ttk.Label(wizard, text=gui_message('wizard_unverified'), wraplength=930).pack(anchor='w', pady=12)
        from ..help_docs import DOCUMENTS
        for kind, (label, _) in DOCUMENTS.items():
            ttk.Button(wizard, text=label, command=lambda k=kind: self.open_help(k)).pack(anchor='w', pady=4)
        ttk.Button(wizard, text='Проверить комплект справки',
                   command=lambda: self.open_help('bundle')).pack(anchor='w', pady=4)

    def wizard_refresh(self):
        from ...services.progress import progress
        app = self.app
        if app.busy:
            return
        server_done = bool(app.server_done.get())

        def shown(result):
            for step in result.steps:
                self.wizard_states[step.key].set(gui_message('wizard_state_' + step.state))
            self.wizard_next = result.next
        app.run(lambda: progress(app.paths, server_done=server_done), shown)

    def open_help(self, kind):
        from ..help_docs import check_bundle, read_document
        app = self.app

        def show():
            title, content = (check_bundle(root=app.help_root) if kind == 'bundle'
                              else read_document(kind, root=app.help_root))
            window = tk.Toplevel(app.root)
            window.title(title)
            window.geometry('850x600')
            window.transient(app.root)
            text = scrolledtext.ScrolledText(window, wrap='word', font=('Segoe UI', 10))
            text.pack(fill='both', expand=True)
            text.insert('1.0', content)
            text.configure(state='disabled')
            ttk.Button(window, text='Закрыть', command=window.destroy).pack(pady=8)

        app.safe(show)


class ServerTab:
    """What the person does in the old account before the reset; the window cannot check the server."""

    def __init__(self, app):
        self.app = app

    def build(self, server):
        """What the person does in the old account before the reset."""
        app = self.app
        ttk.Label(server, text='Выполните до удаления старого входа', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        for i, text in enumerate(SERVER_STEPS, 1):
            ttk.Label(server, text=f'{i}. {text}', wraplength=930).pack(anchor='w', pady=8)
        links = ttk.Frame(server)
        links.pack(anchor='w', pady=12)
        for kind, label in [('sessions', 'Сессии аккаунта'), ('code_tokens', 'Токены Claude Code'),
                            ('help', 'Официальная инструкция')]:
            ttk.Button(links, text=label,
                       command=lambda k=kind: app.safe(lambda: open_server_page(k))).pack(side='left', padx=(0, 10))
        ttk.Checkbutton(server, text='Я выполнил нужный отзыв на сервере и сохранил облачную память, если она нужна',
                        variable=app.server_done).pack(anchor='w')
        ttk.Label(server, text='Эта отметка — подтверждение пользователя. Программа не проверяет сервер. '
                  'Автоматическое открытие ссылок в общем браузере отключено до готовности защищённого запуска.',
                  wraplength=930).pack(anchor='w', pady=8)
