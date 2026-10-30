"""Step 2 of the main window: the proxy and protection page — the state card, the proxy form and their actions."""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from ...model.status import Fix, ProtectionState, Proxy
from .. import brand, proxy_flow
from ..text import JSON_FILES

__all__ = ['ProxyPage']


class ProxyPage:
    """The protection card shows what is on this computer; the form checks a proxy before anything is switched on."""

    def __init__(self, shell):
        self.shell = shell

    def build(self, page):
        shell, px = self.shell, self.shell.theme.px
        shell.label(page, shell.tr('ШАГ 2 · ПРОКСИ И ЗАЩИТА'), 'tag')
        shell.label(page, shell.tr('Прокси и защита'), 'h1', pady=(px(6), px(8)))
        shell.label(page, shell.tr('Защита пускает Claude в интернет только через ваш прокси. Остальные программы — '
                                   'браузер, игры, Discord — работают как обычно.'), 'lead', pady=(0, px(24)))
        self.proxy_state = shell.card(page, pady=(0, px(28)))
        shell.label(page, shell.tr('Ваш прокси'), 'h3', pady=(0, px(4)))
        self.form_hint = shell.label(page, shell.tr('Данные выдаёт ваш провайдер прокси. Пароль хранится только на '
                                                    'этом компьютере в зашифрованном виде.'),
                                     'small', pady=(0, px(14)))
        self.proxy_kind = tk.StringVar(master=shell.root, value='socks5')
        chips = ttk.Frame(page, style='Paper.TFrame')
        chips.pack(anchor='w', pady=(0, px(16)))
        self.chips = {}
        for value, label in (('socks5', 'SOCKS5'), ('http', 'HTTP'), ('vless', shell.tr('VLESS — файл профиля'))):
            chip = ttk.Button(chips, text=label, command=lambda v=value: self.proxy_kind.set(v),
                              style='Chip.Paper.TButton')
            chip.pack(side='left', padx=(0, px(8)))
            self.chips[value] = chip
        self.proxy_kind.trace_add('write', lambda *_: self.paint_form())
        self.fields = {k: tk.StringVar(master=shell.root) for k in ('host', 'port', 'username', 'password')}
        self.form = ttk.Frame(page, style='Paper.TFrame')
        self.form.pack(fill='x')
        grid = ttk.Frame(self.form, style='Paper.TFrame')
        grid.pack(anchor='w')
        for index, (key, label, hint, width) in enumerate((
                ('host', shell.tr('Адрес сервера'), shell.tr('Например 203.0.113.10'), 22),
                ('port', shell.tr('Порт'), shell.tr('Например 1080'), 8),
                ('username', shell.tr('Логин'), shell.tr('Если выдан'), 18),
                ('password', shell.tr('Пароль'), shell.tr('Если выдан'), 18))):
            cell = ttk.Frame(grid, style='Paper.TFrame')
            cell.grid(row=index // 2, column=index % 2, sticky='w', padx=(0, px(20)), pady=(0, px(14)))
            ttk.Label(cell, text=label, style='Paper.strong.TLabel').pack(anchor='w')
            ttk.Entry(cell, textvariable=self.fields[key], style='Brand.TEntry', width=width,
                      font=shell.theme.fonts['field'],
                      show='•' if key == 'password' else '').pack(anchor='w', pady=(px(6), px(2)))
            ttk.Label(cell, text=hint, style='Paper.small.TLabel').pack(anchor='w')
        self.vless = ttk.Frame(page, style='Paper.TFrame')
        self.vless_file = tk.StringVar(master=shell.root)
        self.vless_archive = tk.StringVar(master=shell.root)
        for label, variable, title, types in (
                (shell.tr('Файл профиля VLESS (.json)'), self.vless_file, shell.tr('Профиль VLESS+Reality'),
                 JSON_FILES),
                (shell.tr('Архив движка — если есть; иначе скачаем сами'), self.vless_archive,
                 shell.tr('Архив движка'), [('ZIP', '*.zip')])):
            line = ttk.Frame(self.vless, style='Paper.TFrame')
            line.pack(anchor='w', pady=(0, px(12)))
            ttk.Label(line, text=label, style='Paper.strong.TLabel').pack(anchor='w')
            row = ttk.Frame(line, style='Paper.TFrame')
            row.pack(anchor='w', pady=(px(6), 0))
            shell.small_button(row, shell.tr('Выбрать файл…'), lambda v=variable, t=title, f=types: v.set(
                filedialog.askopenfilename(title=t, filetypes=f) or v.get())).pack(side='left')
            ttk.Label(row, textvariable=variable, style='Paper.small.TLabel').pack(side='left', padx=(px(10), 0))
        self.form_end = ttk.Frame(page, style='Paper.TFrame')
        self.form_end.pack(fill='x')
        self.protect_extension = tk.BooleanVar(master=shell.root, value=False)
        ttk.Checkbutton(self.form_end, text=shell.tr('Также защищать Claude Code внутри VS Code'),
                        variable=self.protect_extension, style='Paper.TCheckbutton').pack(anchor='w', pady=(px(4), 0))
        shell.label(self.form_end, shell.tr('После включения перезагрузите окно VS Code: Ctrl+Shift+P → «Reload '
                                            'Window», затем продолжите разговор командой /resume.'),
                    'small', pady=(px(2), px(20)))
        self.proxy_error = shell.label(self.form_end, '', 'bad', pady=(0, px(10)))
        self.proxy_button = shell.button(self.form_end, shell.tr('Проверить и включить защиту'), self.proxy_go)
        self.proxy_button.pack(anchor='w')
        self.paint_form()

    def paint_form(self):
        kind = self.proxy_kind.get()
        for value, chip in self.chips.items():
            chip.configure(style='ChipOn.Paper.TButton' if value == kind else 'Chip.Paper.TButton')
        if kind == 'vless':
            self.form.pack_forget()
            self.vless.pack(fill='x', before=self.form_end)
        else:
            self.vless.pack_forget()
            self.form.pack(fill='x', before=self.form_end)
        self.proxy_error.configure(text='')

    def refresh_proxy(self):
        shell = self.shell
        if shell.worker.busy:
            return
        shell.run(lambda step: step('summary', lambda: shell.program.protection(shell.paths)), self.paint_proxy)

    def paint_proxy(self, summary):
        shell = self.shell
        px, colors = shell.theme.px, shell.theme.colors
        shell.protection = summary
        frame = self.proxy_state
        shell.clear(frame)
        state = summary['state']
        head = ttk.Frame(frame, style='Marble.TFrame')
        head.pack(anchor='w')
        color = {ProtectionState.ON: 'good', ProtectionState.PROBLEM: 'bad', ProtectionState.PARTIAL: 'bad',
                 ProtectionState.PAUSED: 'graphite2'}.get(state, 'stone')
        dot = shell.theme.image(f'dot-{color}', brand.dot(px(10), colors[color], background=colors['marble']))
        ttk.Label(head, image=dot, style='Marble.body.TLabel').pack(side='left')
        ttk.Label(head, text=shell.tr(summary['title']), style='Marble.h2.TLabel').pack(side='left', padx=(px(12), 0))
        shell.label(frame, shell.tr(summary['text']), bg='marble', pady=(px(6), px(4)))
        if summary.get('proxy'):
            shell.label(frame, shell.tr('Прокси: {name}', name=summary["proxy"]), 'small', bg='marble')
        clients = ' · '.join(shell.tr(c['name']) for c in summary['clients'] if c['present'])
        if clients and state != ProtectionState.UNKNOWN:
            shell.label(frame, (shell.tr('Под защитой: ') if state == ProtectionState.ON else shell.tr('Найдены: '))
                        + clients, 'small', bg='marble')
        buttons = ttk.Frame(frame, style='Marble.TFrame')
        buttons.pack(anchor='w', pady=(px(16), 0))
        if summary.get('fix'):
            shell.button(buttons, shell.tr(proxy_flow.FIXES[summary['fix']]),
                         lambda f=summary['fix']: self.proxy_fix(f), bg='marble').pack(side='left', padx=(0, px(10)))
        if state == ProtectionState.ON:
            shell.button(buttons, shell.tr('Проверить сейчас'), self.refresh_proxy, kind='Ghost',
                         bg='marble').pack(side='left', padx=(0, px(10)))
            shell.button(buttons, shell.tr('Перезапустить'), lambda: self.proxy_fix(Fix.RESTART), kind='Ghost',
                         bg='marble').pack(side='left', padx=(0, px(10)))
        if state in (ProtectionState.ON, ProtectionState.PROBLEM, ProtectionState.PARTIAL, ProtectionState.PAUSED):
            shell.button(buttons, shell.tr('Выключить защиту'), self.protection_off, kind='Ghost',
                         bg='marble').pack(side='left', padx=(0, px(10)))
        if state == ProtectionState.UNKNOWN:
            shell.button(buttons, shell.tr('Обновить'), self.refresh_proxy, kind='Ghost',
                         bg='marble').pack(side='left')
        if state == ProtectionState.OFF and summary.get('proxy_saved'):
            shell.button(buttons, shell.tr('Удалить сохранённый прокси'), self.backend_remove, kind='Ghost',
                         bg='marble').pack(side='left')
        if state == ProtectionState.ON:
            extra = ttk.Frame(frame, style='Marble.TFrame')
            extra.pack(anchor='w', pady=(px(10), 0))
            shell.button(extra, shell.tr('Обновить защиту после обновления программы'),
                         lambda: self.protection_install('reinstall'),
                         kind='Small', bg='marble').pack(side='left', padx=(0, px(10)))
            shell.button(extra, shell.tr('Применить выбор для VS Code'), self.extension_apply, kind='Small',
                         bg='marble').pack(side='left')
        installed = state in (ProtectionState.ON, ProtectionState.PROBLEM)
        self.proxy_button.configure(text=shell.tr('Проверить и применить новый прокси') if installed
                                    else shell.tr('Проверить и включить защиту'))

    def proxy_go(self):
        shell = self.shell
        self.proxy_error.configure(text='')
        if self.proxy_kind.get() == 'vless':
            return self.engine_go()
        values = {k: v.get().strip() if k in ('host', 'port') else v.get() for k, v in self.fields.items()}
        checked, error = proxy_flow.draft(self.proxy_kind.get(), values['host'], values['port'], values['username'],
                                          values['password'], language=shell.language, probe=shell.program.probe)
        if error:
            self.proxy_error.configure(text=error)
            return
        shell.run(lambda step: step('proxy_check', checked.check), lambda outcome: self.proxy_checked(checked, outcome))

    def proxy_checked(self, checked, outcome):
        shell = self.shell
        if outcome.status != Proxy.PROXY_CHECKED:
            self.proxy_error.configure(text=shell.tr(proxy_flow.message(outcome.status)))
            return
        if not self.confirm_exit(checked):
            return
        if shell.protection.get('state') in (ProtectionState.ON, ProtectionState.PROBLEM):
            if shell.confirm(shell.tr('Применить новый прокси?'),
                             shell.tr('Защита перезапустится. Claude на несколько секунд останется без сети.'),
                             shell.tr('Применить')):
                shell.run(lambda step: step('change', lambda: proxy_flow.connect(
                    shell.paths, checked, installed=True, perform=shell.program.perform)), self.proxy_connected)
            return
        self.protection_install('install', checked)

    def confirm_exit(self, checked):
        shell = self.shell
        address = checked.expected['expected_exit_ips'][0]
        return shell.confirm(shell.tr('Прокси работает ✓'),
                             shell.tr('Claude будет выходить в интернет с этого адреса. Он совпадает с тем, '
                                      'что выдал ваш провайдер прокси?'), shell.tr('Да, всё верно'), no=shell.tr('Нет'),
                             lines=[address])

    def protection_install(self, action, checked=None):
        shell = self.shell

        def consent(limits):
            if not limits['known']:
                shell.ask(shell.tr('Нужна новая версия'),
                          shell.tr('Список того, что защита не закрывает, изменился. Включите защиту в «Режиме для '
                                   'специалистов».'))
                return
            title = shell.tr('Перед включением') if action == 'install' else shell.tr('Включить защиту заново?')
            text = (shell.tr('Защита закрывает собственные соединения Claude. Вот что она не закрывает — это '
                             'ограничения Windows, а не ошибки. Windows попросит разрешение: нажмите «Да».'))
            if action == 'reinstall':
                text = shell.tr('Программа поставит защиту текущей версии и включит её. ') + text
            if not shell.confirm(title, text, shell.tr('Включить защиту'), lines=limits['lines']):
                return
            extension = bool(self.protect_extension.get())

            def job(step):
                if checked is not None:
                    return step('install', lambda: proxy_flow.connect(shell.paths, checked, installed=False,
                                                                       protect_extension=extension,
                                                                       perform=shell.program.perform), uac=True)
                done = step(action, lambda: shell.program.perform(shell.paths, action, confirmed=True,
                                                                  protect_extension=extension), uac=True)
                return {'text': done['text'], 'ok': True}
            shell.run(job, self.proxy_connected)
        shell.run(lambda step: step('limits', lambda: shell.program.limits(shell.paths)), consent)

    def proxy_connected(self, result):
        shell = self.shell
        shell.ask(shell.tr('Готово') if result.get('ok') else shell.tr('Не получилось'), shell.tr_text(result['text']))
        shell.root.after(200, self.refresh_proxy)

    def engine_go(self):
        from ...services.proxy import LocalBackendDraft, install_engine
        shell = self.shell
        profile = self.vless_file.get()
        if not profile:
            self.proxy_error.configure(text=shell.tr('Выберите файл профиля VLESS.'))
            return
        if shell.protection.get('state') in (ProtectionState.ON, ProtectionState.PROBLEM):
            shell.ask(shell.tr('Сначала выключите защиту'),
                      shell.tr('Чтобы перейти на VLESS, выключите защиту, затем установите профиль.'))
            return
        archive = self.vless_archive.get() or None
        checked = LocalBackendDraft(shell.paths, first=True, probe=shell.program.probe)

        def job(step):
            result = step('engine', lambda: install_engine(shell.paths, Path(profile),
                                                           Path(archive) if archive else None))
            if result.status not in (Proxy.ENGINE_INSTALLED, Proxy.ENGINE_NEEDS_ATTENTION):
                return result
            return step('proxy_check', checked.check)
        shell.run(job, lambda outcome: self.proxy_checked(checked, outcome))

    def proxy_fix(self, fix):
        shell = self.shell
        if fix == Fix.REENTER:
            shell.status.set(shell.tr('Введите данные прокси ниже и нажмите «Проверить и применить новый прокси».'))
            return
        if fix == Fix.INSTALL:
            return self.protection_install('install')
        if fix == Fix.RESUME:
            return self.protection_install('reinstall')
        if fix == Fix.RESTART:
            if shell.confirm(shell.tr('Перезапустить защиту?'),
                             shell.tr('Claude на несколько секунд останется без сети.'), shell.tr('Перезапустить')):
                shell.run(lambda step: {'text': step('restart', lambda: shell.program.perform(
                    shell.paths, 'restart', confirmed=True))['text'], 'ok': True}, self.proxy_connected)
            return

        def checked_again(pair):
            checked, info = pair
            if checked is None:
                shell.ask(shell.tr('Прокси не работает'),
                          shell.tr(info['text']) + shell.tr(' Если не поможет — введите прокси заново ниже.'))
                return
            if info['same_exit']:
                shell.run(lambda step: {'text': step('restart', lambda: shell.program.perform(
                    shell.paths, 'restart', confirmed=True))['text'], 'ok': True}, self.proxy_connected)
            elif self.confirm_exit(checked):
                shell.run(lambda step: step('change', lambda: proxy_flow.connect(
                    shell.paths, checked, installed=True, perform=shell.program.perform)), self.proxy_connected)
        shell.run(lambda step: step('proxy_check', lambda: proxy_flow.recheck(shell.paths,
                                                                              check_saved=shell.program.check_saved)),
                  checked_again)

    def protection_off(self):
        shell = self.shell
        if shell.confirm(shell.tr('Выключить защиту?'),
                         shell.tr('Claude снова будет выходить в интернет напрямую, без прокси. '
                                  'Сохранённый прокси и адрес выхода тоже будут удалены. Windows попросит разрешение.'),
                         shell.tr('Выключить')):
            shell.run(lambda step: {'text': step('remove', lambda: shell.program.perform(
                shell.paths, 'remove', confirmed=True), uac=True)['text'], 'ok': True}, self.proxy_connected)

    def extension_apply(self):
        shell = self.shell
        value = bool(self.protect_extension.get())
        text = (shell.tr('Claude Code в VS Code тоже будет выходить только через прокси.') if value
                else shell.tr('Claude Code в VS Code снова будет выходить напрямую.'))
        if shell.confirm(shell.tr('Применить выбор для VS Code?'),
                         text + shell.tr(' Сохраните работу: после применения перезагрузите окно VS Code '
                                         '(Ctrl+Shift+P → «Reload Window») и продолжите командой /resume.'),
                         shell.tr('Применить')):
            shell.run(lambda step: {'text': step('extension', lambda: shell.program.perform(
                shell.paths, 'extension', confirmed=True, protect_extension=value), uac=not value)['text'], 'ok': True},
                self.proxy_connected)

    def backend_remove(self):
        from ...services.proxy import remove_backend
        shell = self.shell
        if shell.confirm(shell.tr('Удалить сохранённый прокси?'),
                         shell.tr('Адрес, логин и пароль прокси будут удалены с этого компьютера.'),
                         shell.tr('Удалить')):
            shell.run(lambda step: step('backend_remove', lambda: remove_backend(shell.paths)),
                      lambda r: (shell.ask(shell.tr('Прокси'), shell.tr(proxy_flow.message(r.status))),
                                 self.refresh_proxy()))
