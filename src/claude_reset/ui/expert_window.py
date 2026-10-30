"""The specialist window (`--expert`, in Russian): every tool of the program on tabs, for diagnosis and manual steps.

This module is the window: the header, the notebook, background work, dialogs and what the tabs share (the reset
plan, the chosen components, the server step). Each tab is its own object in ui/expert.
"""
from __future__ import annotations

import json
import queue
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from .. import __version__, layout
from ..layout import Paths
from ..model.reset import Selection
from ..network.probe import Probe
from ..reset import browser_sites, cleanup, cowork, customizations
from ..reset import policy as reset_policy
from ..reset.desktop_keys import Desktop
from ..reset.execution import Executor
from ..reset.memory import SUPPORTED
from ..reset.new_account import launch_clean_chrome
from ..safeio import atomic_json
from ..services import diagnostics
from ..services.protection import L1
from ..windows import cleanup_actions
from ..windows.inventory import inspect_windows
from .expert.analysis import AnalysisTab
from .expert.cleanup import CleanupTab
from .expert.connection import ConnectionTab
from .expert.diagnostics import DiagnosticsTab
from .expert.policy import PolicyTab
from .expert.protection import GuardTab, ProtectionTab
from .expert.settings import SettingsTab
from .expert.wizard import ServerTab, WizardTab
from .text import JSON_FILES, gui_message, render
from .worker import FINISHED, Phase, Worker

__all__ = ['App', 'Dialogs']


class Dialogs:
    """The Tk dialogs the specialist window asks with: the port tests replace with scripted answers."""

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
    """The specialist window. What it reaches of the program comes in as keyword arguments; a test passes doubles.

    The tabs (`wizard_tab`, `analysis_tab`, `cleanup_tab`, `server_tab`, `settings_tab`, `guard_tab`,
    `connection_tab`, `protection_tab`, `policy_tab`, `diagnostics_tab`) reach these and the shared state through
    the window."""

    def __init__(self, root=None,   # None: a new Tk root window
                 paths=None,   # None: Paths.current(), the folders of this session
                 dialogs=Dialogs(), *, probe=Probe(), desktop=Desktop(), l1=L1(), diagnostics=diagnostics,
                 cleanup=cleanup, cleanup_actions=cleanup_actions, cowork=cowork, browser_sites=browser_sites,
                 customizations=customizations, executor=Executor, policy=reset_policy, help_root=layout.PROGRAM_DIR,
                 inspect=inspect_windows, launch_chrome=launch_clean_chrome):
        # probe: the network checks of proxy drafts; desktop: the PC-facing steps of the Desktop key reset;
        # l1: the L1 checks and operations behind the protection tab.
        self.dialogs, self.probe, self.desktop, self.l1 = dialogs, probe, desktop, l1
        # The areas behind the tabs.
        self.diagnostics, self.cleanup, self.cleanup_actions = diagnostics, cleanup, cleanup_actions
        self.cowork, self.browser_sites, self.customizations = cowork, browser_sites, customizations
        # executor runs a reviewed reset plan, policy saves one as a policy file; help_root is the program folder the
        # help sections are read from; inspect reads processes, time zone and restore points of this PC;
        # launch_chrome opens the clean Chrome profile of a reset run.
        self.executor, self.policy, self.help_root = executor, policy, help_root
        self.inspect, self.launch_chrome = inspect, launch_chrome
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
        self.wizard_tab, self.analysis_tab, self.cleanup_tab = WizardTab(self), AnalysisTab(self), CleanupTab(self)
        self.server_tab, self.settings_tab, self.guard_tab = ServerTab(self), SettingsTab(self), GuardTab(self)
        self.connection_tab, self.protection_tab = ConnectionTab(self), ProtectionTab(self)
        self.policy_tab, self.diagnostics_tab = PolicyTab(self), DiagnosticsTab(self)
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Claude Reset', font=('Segoe UI', 22, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Сброс выбранных локальных данных с сохранением памяти. Ключи Desktop, Cowork и сетевые '
                  'проверки имеют отдельные статусы.', wraplength=970).pack(anchor='w', pady=(4, 12))
        options = ttk.Frame(frame)
        options.pack(fill='x')
        for key, label in [('code', 'Claude Code'), ('vscode', 'VS Code'), ('chrome', 'Новый Chrome'),
                           ('desktop', 'Состояние Desktop')]:
            ttk.Checkbutton(options, text=label, variable=self.components[key],
                            command=self.invalidate).pack(side='left', padx=(0, 16))
        self.build_tabs(frame)
        ttk.Label(frame, textvariable=self.status, wraplength=970).pack(anchor='w', pady=(4, 0))
        self.cancel_button = ttk.Button(frame, text=gui_message('cancel'), command=self.cancel, state='disabled')
        self.cancel_button.pack(anchor='w', pady=4)
        self.root.after(100, self.poll)

    def build_tabs(self, frame):
        """The notebook: a frame per tab, added in the order the person reads them, then each tab builds on its own."""
        tabs = ttk.Notebook(frame)
        self.tabs = tabs
        tabs.pack(fill='both', expand=True, pady=12)
        wizard = ttk.Frame(tabs, padding=10)
        tabs.add(wizard, text=gui_message('wizard'))
        analysis = ttk.Frame(tabs, padding=10)
        server = ttk.Frame(tabs, padding=10)
        settings_page, settings = self.scrollable(tabs)
        policy_page = ttk.Frame(tabs, padding=10)
        guard = ttk.Frame(tabs, padding=10)
        connection = ttk.Frame(tabs, padding=10)
        strict_page = ttk.Frame(tabs, padding=10)
        tabs.add(analysis, text='Анализ и операции')
        cleanup_page = ttk.Frame(tabs, padding=10)
        tabs.add(cleanup_page, text='Очистка')
        self.cleanup_tab.build(cleanup_page)
        tabs.add(server, text='Серверные действия')
        tabs.add(settings_page, text='Пояс, сеть и память')
        tabs.add(guard, text='Сетевая защита Claude')
        tabs.add(connection, text='Соединение')
        tabs.add(strict_page, text='Windows-защита')
        self.protection_tab.build(strict_page, connection)
        tabs.add(policy_page, text='Профили и автоматизация')
        diagnostics_page = ttk.Frame(tabs, padding=10)
        tabs.add(diagnostics_page, text='Диагностика')
        self.diagnostics_tab.build(diagnostics_page)
        self.wizard_tab.build(wizard, {'server': server, 'cleanup': cleanup_page, 'connection': connection,
                                       'protection': strict_page, 'checks': diagnostics_page})
        self.analysis_tab.build(analysis)
        self.server_tab.build(server)
        self.settings_tab.build(settings)
        self.guard_tab.build(guard)
        self.connection_tab.build(connection)
        self.policy_tab.build(policy_page)

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
        settings_canvas.bind('<Configure>',
                             lambda event: settings_canvas.itemconfigure(settings_item, width=event.width))
        return settings_page, settings

    @property
    def busy(self):
        return self.worker.busy

    def invalidate(self):
        self.plan_revision = getattr(self, 'plan_revision', 0) + 1
        self.plan = None
        self.policy_file = None
        self.status.set('Состав операций изменён. Выполните анализ заново.')

    def confirmed_plan_current(self, plan, snapshot, revision):
        # Modal dialogs process Tk events: approval must not follow a replaced,
        # invalidated or edited plan, or race an operation started in the dialog.
        if (self.busy or self.plan is not plan or self.plan != snapshot
                or getattr(self, 'plan_revision', 0) != revision):
            self.show_operation_error('plan_changed')
            return False
        return True

    def close(self):
        if self.busy:
            self.dialogs.showinfo('Операция выполняется',
                                  'Дождитесь результата текущей операции перед закрытием программы.')
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
                                                  initialfile='claude-reset-check.json', filetypes=JSON_FILES)
            if file:
                self.safe(lambda: atomic_json(Path(file), snapshot, Path(file).parent))
        ttk.Button(buttons, text='Сохранить JSON', command=save).pack(side='left')
        ttk.Button(buttons, text='Закрыть', command=window.destroy).pack(side='right')
        window.bind('<Escape>', lambda _: window.destroy())
        return window

    def apply_after_server(self, runs, plan_label, title, question, apply) -> None:
        """A plan that needs the server step first: pick its plan.dpapi, ask, apply it."""
        if not self.server_done.get():
            return self.dialogs.showinfo('Серверный этап', 'Сначала выполните и отметьте отзыв на сервере.')
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / runs),
                                            filetypes=[(plan_label, layout.PLAN_FILE)])
        if file and self.dialogs.askyesno(title, question):
            self.run(lambda: apply(self.paths, Path(file).parent.name, server_step_complete=True), self.show_json)

    def recover_from_plan(self, runs, plan_label, title, recover) -> None:
        """Recover an export into a separate folder: pick its plan.dpapi, then show where it went."""
        file = self.dialogs.askopenfilename(initialdir=str(self.paths.state / runs),
                                            filetypes=[(plan_label, layout.PLAN_FILE)])
        if file:
            self.run(lambda: str(recover(self.paths, Path(file).parent.name)),
                     lambda p: self.dialogs.showinfo(title, p))

    def mainloop(self):
        self.root.mainloop()
