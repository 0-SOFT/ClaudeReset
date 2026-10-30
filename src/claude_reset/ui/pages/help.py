"""The help page of the main window: documents, the report, the time zone advice, appearance and uninstall."""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from ...model.status import Diagnosis, Uninstall
from ..text import JSON_FILES

__all__ = ['HelpPage']


class HelpPage:
    """Help: the guide and the limits, a report, the time zone comparison, the look, and removing the program."""

    def __init__(self, shell):
        self.shell = shell

    def build(self, page):
        shell, px = self.shell, self.shell.theme.px
        shell.label(page, shell.tr('ПОМОЩЬ'), 'tag')
        shell.label(page, shell.tr('Помощь'), 'h1', pady=(px(6), px(24)))
        for title, text, buttons in (
                (shell.tr('Руководство'), shell.tr('Пошагово: сброс, прокси, вход в новый аккаунт.'),
                 (('Primary', shell.tr('Открыть руководство'), lambda: self.open_doc('guide')),)),
                (shell.tr('Что-то не работает'),
                 shell.tr('Сохраните отчёт и отправьте тому, кто вам помогает. В отчёте нет паролей, '
                          'адресов прокси и имени пользователя.'),
                 (('Primary', shell.tr('Сохранить отчёт'), self.save_report),)),
                (shell.tr('Язык и часовой пояс'),
                 shell.tr('Сайты сравнивают часовой пояс и язык компьютера со страной, из которой вы заходите. '
                          'Укажите страну вашего прокси: DE, TR или GB.'), ()),
                (shell.tr('Ограничения и лицензии'),
                 shell.tr('Что защита не закрывает и чьи компоненты использует программа.'),
                 (('Ghost', shell.tr('Ограничения'), lambda: self.open_doc('limits')),
                  ('Ghost', shell.tr('Лицензии'), lambda: self.open_doc('licenses'))))):
            card = shell.card(page, pady=(0, px(16)))
            shell.label(card, title, 'h3', bg='marble')
            shell.label(card, text, bg='marble', pady=(px(6), px(14)))
            row = ttk.Frame(card, style='Marble.TFrame')
            row.pack(anchor='w')
            for kind, label, command in buttons:
                shell.button(row, label, command, kind=kind, bg='marble').pack(side='left', padx=(0, px(10)))
            if title == shell.tr('Язык и часовой пояс'):
                self.country = tk.StringVar(master=shell.root)
                ttk.Entry(row, textvariable=self.country, style='Brand.TEntry', width=6,
                          font=shell.theme.fonts['field']).pack(side='left', padx=(0, px(10)))
                shell.button(row, shell.tr('Сравнить'), self.advice, kind='Small',
                             bg='marble').pack(side='left', padx=(0, px(10)))
                shell.button(row, shell.tr('Настройки времени'), lambda: self.settings('timezone'), kind='Small',
                             bg='marble').pack(side='left', padx=(0, px(10)))
                shell.button(row, shell.tr('Настройки языка'), lambda: self.settings('language'), kind='Small',
                             bg='marble').pack(side='left')
                self.advice_text = shell.label(card, '', 'small', bg='marble', pady=(px(10), 0))
        card = shell.card(page, pady=(0, px(16)))
        shell.label(card, shell.tr('Оформление'), 'h3', bg='marble')
        shell.label(card,
                    shell.tr('Тема и язык окна. Клавиши: Tab — следующая кнопка, Enter — нажать, Alt+1…4 — страницы.'),
                    bg='marble', pady=(px(6), px(14)))
        row = ttk.Frame(card, style='Marble.TFrame')
        row.pack(anchor='w')
        for value, label in (('system', shell.tr('Как в Windows')), ('light', shell.tr('Светлая')),
                             ('dark', shell.tr('Тёмная'))):
            style = 'ChipOn.Marble.TButton' if value == shell.theme_choice else 'Chip.Marble.TButton'
            ttk.Button(row, text=label, style=style,
                       command=lambda v=value: shell.set_theme(v)).pack(side='left', padx=(0, px(8)))
        row = ttk.Frame(card, style='Marble.TFrame')
        row.pack(anchor='w', pady=(px(10), 0))
        # Language names are written in their own language so a person who cannot read the other one finds theirs.
        for value, label in (('ru', 'Русский'), ('en', 'English')):
            style = 'ChipOn.Marble.TButton' if value == shell.language.code else 'Chip.Marble.TButton'
            ttk.Button(row, text=label, style=style,
                       command=lambda v=value: shell.set_language_choice(v)).pack(side='left', padx=(0, px(8)))
        from ...services.program_setup import installation
        if installation() is not None:
            card = shell.card(page, pady=(0, px(16)))
            shell.label(card, shell.tr('Удалить программу'), 'h3', bg='marble')
            shell.label(card, shell.tr('Сначала выключит защиту, если она включена, затем удалит ClaudeReset, его '
                                       'ярлыки и запись в «Приложениях». Сохранённые копии памяти останутся.'),
                        bg='marble', pady=(px(6), px(14)))
            shell.button(card, shell.tr('Удалить ClaudeReset'), self.uninstall_program, kind='Ghost',
                         bg='marble').pack(anchor='w')

    def uninstall_program(self):
        from ...services import program_setup
        shell = self.shell
        shell.show('help')

        def planned(plan):
            if not plan.installed:
                shell.ask(shell.tr('Удаление'),
                          shell.tr('Эта копия не установлена установщиком. Чтобы убрать её, удалите её папку.'))
                return
            text = (shell.tr('ClaudeReset будет удалён с компьютера. ')
                    + (shell.tr('Сначала программа выключит защиту: Claude снова будет выходить в интернет напрямую, '
                                'а Windows попросит разрешение. ') if plan.protection else ''))
            lines = [shell.tr('Ярлыки и запись в «Приложениях»'), shell.tr('Папка программы')]
            if plan.archives:
                text += shell.tr('Копии памяти и отчёты останутся в папке ниже — удалите её сами, если они не нужны.')
            if not shell.confirm(shell.tr('Удалить ClaudeReset?'), text, shell.tr('Удалить'), lines=lines + (
                    [plan.archives_folder] if plan.archives else []), typed=shell.tr('УДАЛИТЬ')):
                return
            shell.run(lambda step: program_setup.uninstall(shell.paths, step=step), finished, uac_steps=('remove',))

        def finished(result):
            if result.status == Uninstall.REMOVED:
                shell.ask(shell.tr('ClaudeReset удалён'),
                          shell.tr('Окно закроется, папка программы удалится через несколько секунд.'))
                shell.root.destroy()
            elif result.status == Uninstall.PROTECTION_NOT_REMOVED:
                shell.ask(shell.tr('Удаление остановлено'),
                          shell.tr('Защиту выключить не удалось, поэтому программа не удалена: иначе Claude мог '
                                   'остаться без сети. Попробуйте ещё раз или выключите защиту на шаге 2.'))
            else:
                shell.ask(shell.tr('Удаление'),
                          shell.tr('Эта копия не установлена установщиком. Чтобы убрать её, удалите её папку.'))
        shell.run(lambda step: step('summary', lambda: program_setup.plan(shell.paths)), planned)

    def open_doc(self, kind):
        from ..help_docs import read_document
        shell = self.shell
        try:
            title, content = read_document(kind, shell.language.code)
            title = shell.tr(title)
        except Exception:
            shell.ask(shell.tr('Справка недоступна'), shell.tr('Файл справки не найден рядом с программой.'))
            return
        px, colors, root = shell.theme.px, shell.theme.colors, shell.root
        window = tk.Toplevel(root, background=colors['paper'])
        window.title(title)
        window.geometry(f'{min(px(880), int(root.winfo_screenwidth() * .9))}x'
                        f'{min(px(700), int(root.winfo_screenheight() * .85))}')
        window.transient(root)
        foot = ttk.Frame(window, style='Paper.TFrame', padding=px(16))
        foot.pack(side='bottom', fill='x')
        ttk.Button(foot, text=shell.tr('Закрыть'), command=window.destroy,
                   style='Ghost.Paper.TButton').pack(side='right')
        bar = ttk.Scrollbar(window, orient='vertical', style='Brand.Vertical.TScrollbar')
        bar.pack(side='right', fill='y')
        text = tk.Text(window, wrap='word', font=shell.theme.fonts['body'], background=colors['paper'],
                       foreground=colors['graphite'], relief='flat', padx=px(36), pady=px(28), spacing1=px(2),
                       spacing3=px(4), highlightthickness=0, selectbackground=colors['accent'],
                       selectforeground=colors['on_accent'], yscrollcommand=bar.set, cursor='arrow', insertwidth=0)
        bar.configure(command=text.yview)
        text.pack(fill='both', expand=True)
        self.render_markdown(text, content)
        text.configure(state='disabled')
        window.bind('<Escape>', lambda _e: window.destroy())
        text.focus_set()
        from .. import settings as ui_settings
        window.after(60, lambda: ui_settings.dark_title_bar(window, shell.theme.mode == 'dark'))

    def render_markdown(self, text, content):
        from .. import markdown_view
        theme = self.shell.theme
        px, fonts, colors = theme.px, theme.fonts, theme.colors
        text.tag_configure('h1', font=fonts['h2'], foreground=colors['ink'], spacing1=px(20), spacing3=px(10))
        text.tag_configure('h2', font=fonts['h3'], foreground=colors['ink'], spacing1=px(18), spacing3=px(6))
        text.tag_configure('h3', font=fonts['strong'], foreground=colors['ink'], spacing1=px(12), spacing3=px(4))
        text.tag_configure('para', spacing3=px(8))
        for depth in range(4):
            text.tag_configure(f'item{depth}', lmargin1=px(12 + 22 * depth), lmargin2=px(34 + 22 * depth),
                               spacing3=px(4))
        text.tag_configure('block', font=fonts['mono'], background=colors['mist'], lmargin1=px(16), lmargin2=px(16),
                           rmargin=px(16), spacing1=px(6), spacing3=px(10))
        text.tag_configure('bold', font=fonts['strong'], foreground=colors['ink'])
        text.tag_configure('code', font=fonts['mono'], background=colors['mist'])
        text.tag_configure('link', underline=True, foreground=colors['ink'])
        text.tag_configure('rule', foreground=colors['stone'], spacing1=px(8), spacing3=px(8))

        def put(line, block):
            for segment, style in markdown_view.inline(line):
                text.insert('end', segment, (block,) if style == 'text' else (block, style))
            text.insert('end', '\n', (block,))
        for kind, payload in markdown_view.blocks(content):
            if kind in ('h1', 'h2', 'h3', 'para'):
                put(payload, kind)
            elif kind == 'bullet':
                put('•  ' + payload[1], f'item{min(payload[0], 3)}')
            elif kind == 'number':
                put(f'{payload[1]}.  {payload[2]}', f'item{min(payload[0], 3)}')
            elif kind == 'code':
                text.insert('end', payload + '\n', ('block',))
            elif kind == 'rule':
                text.insert('end', '—' * 12 + '\n', ('rule',))
            elif kind == 'table' and payload:
                head, rows = payload[0], payload[1:]
                for row in rows:
                    first, rest = row[0].replace('`', ''), [cell for cell in row[1:] if cell]
                    line = f'**{first}**' if first else ''
                    line += (' — ' if first and rest else '') + ' · '.join(rest)
                    put('•  ' + line, 'item0')
                if not rows:
                    put(' · '.join(head), 'para')

    def save_report(self):
        from ...safeio import atomic_json
        from ...services.diagnostics import collect
        shell = self.shell

        def done(report):
            file = filedialog.asksaveasfilename(title=shell.tr('Сохранить отчёт'), defaultextension='.json',
                                                initialfile='claudereset-report.json', filetypes=JSON_FILES)
            if file:
                from ..public_view import redact
                path = Path(file)
                atomic_json(path, redact(shell.language.render(report.to_json())), path.parent)
                shell.status.set(shell.tr('Отчёт сохранён. В нём нет паролей, адресов прокси и имени пользователя.'))
        shell.run(lambda step: step('report', lambda: collect(shell.paths)), done)

    def advice(self):
        from ...services.diagnostics import advise
        country = self.country.get()
        self.shell.run(lambda step: step('advice', lambda: advise(country)), self.show_advice)

    def show_advice(self, result):
        shell = self.shell
        text = shell.language.say(result.text)
        if result.status == Diagnosis.COMPARED:
            text += (shell.tr(' Пояс: ') + (shell.tr('совпадает ✓') if result.timezone_matches
                                            else shell.tr('не совпадает'))
                     + shell.tr('. Язык: ') + (shell.tr('совпадает ✓') if result.language_matches
                                               else shell.tr('не совпадает — это ваш выбор, менять не обязательно'))
                     + '.')
        self.advice_text.configure(text=text)

    def settings(self, kind):
        from ...services.diagnostics import open_settings
        try:
            open_settings(kind)
        except Exception:
            self.shell.ask(self.shell.tr('Не открылось'), self.shell.tr('Откройте настройки Windows вручную.'))
