"""Step 1 of the main window: the reset page — what to keep, the site step, the check, the confirmation, the wipe."""
import tkinter as tk
from tkinter import ttk

from ...model.confirmation import Confirmation
from ...model.status import BlockerKind, Browsers, DesktopKeys, Location, Reset
from ...services import reset as reset_service
from .. import reset_flow

__all__ = ['OUTSIDE', 'ResetPage']

# What the reset leaves for the person to check by hand.
OUTSIDE = ('Данные claude.ai в браузерах, кроме cookies и IndexedDB: кэш и локальное хранилище — через настройки '
           'браузера.',
           'Ваши проекты и папки с кодом на диске — программа их не трогает.',
           'Переменные среды, WSL, Docker и SSH — если вы настраивали в них Claude.')


class ResetPage:
    """The reset step. The session of one reset (its checks and its wipe) lives here until the wipe is done."""

    WATCH_MS, WATCH_LIMIT = 6000, 100  # about ten minutes of waiting for the person

    def __init__(self, shell):
        self.shell = shell
        self.session = None
        self.watch = None

    def build(self, page):
        shell, px = self.shell, self.shell.theme.px
        self.session = None
        shell.label(page, shell.tr('ШАГ 1 · СБРОС'), 'tag')
        shell.label(page, shell.tr('Сброс Claude'), 'h1', pady=(px(6), px(8)))
        shell.label(page, shell.tr('Сотрём всё, что Claude хранит на этом компьютере: вход, историю, настройки и '
                                   'сохранённые пароли. Сами программы останутся — после сброса они откроются как в '
                                   'первый раз.'), 'lead', pady=(0, px(28)))

        shell.label(page, shell.tr('Что сохранить'), 'h3', pady=(0, px(12)))
        self.keep_memory = tk.StringVar(master=shell.root, value='keep')
        row = ttk.Frame(page, style='Paper.TFrame')
        row.pack(fill='x', pady=(0, px(28)))
        row.columnconfigure((0, 1), weight=1, uniform='choice')
        self.choices = []
        for column, value, title, text in (
                (0, 'keep', shell.tr('Стереть всё, но оставить память'),
                 shell.tr('Ваши заметки и инструкции для Claude Code (файлы CLAUDE.md) '
                          'вернутся на место. Всё остальное будет удалено.')),
                (1, 'none', shell.tr('Стереть всё'), shell.tr('Ничего не сохраняется. Полностью с нуля.'))):
            self.choices.append(self.choice(row, column, value, title, text))
        self.keep_memory.trace_add('write', lambda *_: self.paint_choices())
        self.paint_choices()

        shell.label(page, shell.tr('Сначала — на сайте Claude'), 'h3', pady=(0, px(8)))
        shell.label(page, shell.tr('В браузере, где вы вошли в старый аккаунт, выйдите на всех устройствах и отзовите '
                                   'доступ Claude Code. Иначе сервер свяжет новый вход со старым. Скопируйте адрес и '
                                   'вставьте его в браузер.'),
                    'body', pady=(0, px(12)))
        links = ttk.Frame(page, style='Paper.TFrame')
        links.pack(anchor='w', pady=(0, px(12)))
        from ...reset.new_account import SERVER_LINKS
        for kind, label in (('sessions', shell.tr('Скопировать адрес: сессии')),
                            ('code_tokens', shell.tr('Скопировать адрес: доступ Claude Code'))):
            shell.small_button(links, label, lambda u=SERVER_LINKS[kind]: self.copy(u)).pack(side='left',
                                                                                            padx=(0, px(10)))
        self.server_done = tk.BooleanVar(master=shell.root, value=False)
        ttk.Checkbutton(page, text=shell.tr('Готово: я вышел на всех устройствах и сохранил нужное из облака'),
                        variable=self.server_done, style='Paper.TCheckbutton').pack(anchor='w', pady=(0, px(28)))

        shell.label(page, shell.tr('Браузеры'), 'h3', pady=(0, px(8)))
        self.browsers = tk.BooleanVar(master=shell.root, value=True)
        ttk.Checkbutton(page, text=shell.tr('Также выйти из claude.ai в Chrome и Edge (закройте их перед сбросом)'),
                        variable=self.browsers, style='Paper.TCheckbutton').pack(anchor='w', pady=(0, px(28)))

        actions = ttk.Frame(page, style='Paper.TFrame')
        actions.pack(anchor='w')
        self.reset_button = shell.button(actions, shell.tr('Проверить и очистить'), self.reset_start)
        self.reset_button.pack(side='left')
        shell.button(actions, shell.tr('Только посмотреть, что найдено'), lambda: self.reset_start(dry=True),
                     kind='Ghost').pack(side='left', padx=(px(12), 0))
        shell.label(page, shell.tr('Программа сама закроет Claude, остановит службу Cowork и сохранит копии ваших '
                                   'файлов. Перед удалением она покажет, что найдено, и попросит подтверждение.'),
                    'small', pady=(px(12), 0))
        self.reset_result = ttk.Frame(page, style='Paper.TFrame')
        self.reset_result.pack(fill='x', pady=(px(24), 0))

    def choice(self, row, column, value, title, text):
        px = self.shell.theme.px
        frame = ttk.Frame(row, style='Choice.TFrame', padding=px(22))
        frame.grid(row=0, column=column, sticky='nsew', padx=(0, px(10)) if column == 0 else (px(10), 0))
        head = ttk.Label(frame, text=title, style='Marble.h3.TLabel', wraplength=px(330), justify='left')
        head.pack(anchor='w')
        body = ttk.Label(frame, text=text, style='Marble.body.TLabel', wraplength=px(330), justify='left')
        body.pack(anchor='w', pady=(px(6), 0))
        for widget in (frame, head, body):
            widget.bind('<Button-1>', lambda _e: self.keep_memory.set(value))
            widget.configure(cursor='hand2')
        # Keyboard: Tab reaches the card, Space or Enter chooses it, the focused card shows a ring.
        frame.configure(takefocus=True)
        for key in ('<space>', '<Return>'):
            frame.bind(key, lambda _e: self.keep_memory.set(value))
        frame.bind('<FocusIn>', lambda _e: self.paint_choices(), add='+')
        frame.bind('<FocusOut>', lambda _e: self.paint_choices(), add='+')
        return value, frame, head, body

    def paint_choices(self):
        focus = self.shell.root.focus_get()
        for value, frame, head, body in self.choices:
            on = self.keep_memory.get() == value
            style = 'ChoiceOn' if on else 'Choice'
            frame.configure(style=style + ('Focus' if focus is frame else '') + '.TFrame')
            head.configure(style='Accent.h3.TLabel' if on else 'Marble.h3.TLabel')
            body.configure(style='Accent.body.TLabel' if on else 'Marble.body.TLabel')

    def copy(self, text):
        root = self.shell.root
        root.clipboard_clear()
        root.clipboard_append(text)
        self.shell.status.set(self.shell.tr('Адрес скопирован. Вставьте его в адресную строку браузера.'))

    def reset_start(self, dry=False):
        shell = self.shell
        if shell.worker.busy:
            return
        self.stop_watch()
        if not dry and not self.server_done.get():
            shell.ask(shell.tr('Сначала сайт Claude'),
                      shell.tr('Выйдите из старого аккаунта на всех устройствах и поставьте отметку «Готово». '
                               'Без этого новый вход может связаться со старым.'))
            return
        keep = self.keep_memory.get() == 'keep'
        if self.session is None or self.session.keep_memory != keep:
            self.session = shell.program.reset(shell.paths, keep_memory=keep)
        session = self.session
        shell.run(lambda step: reset_flow.shown(session.check(step)), lambda result: self.reset_checked(result, dry))

    def watch_blockers(self, dry, keys, attempt=0):
        """While the person closes VS Code or a browser, check again now and then and continue by itself."""
        self.stop_watch()
        if attempt >= self.WATCH_LIMIT:
            return
        shell = self.shell

        def again():
            self.watch = None
            if shell.current != 'reset' or self.session is None:
                return
            if shell.worker.busy:
                return self.watch_blockers(dry, keys, attempt + 1)
            session = self.session

            def seen(result):
                left = {b['key'] for b in result['blockers'] if b['kind'] == BlockerKind.USER}
                if not left or left != keys:
                    self.reset_checked(result, dry)  # done, or something else changed: show it
                else:
                    self.watch_blockers(dry, keys, attempt + 1)
            shell.run(lambda step: reset_flow.shown(session.check(step)), seen)
        self.watch = shell.root.after(self.WATCH_MS, again)

    def stop_watch(self):
        if self.watch:
            try:
                self.shell.root.after_cancel(self.watch)
            except tk.TclError:
                pass
        self.watch = None

    def reset_checked(self, result, dry):
        self.stop_watch()
        shell, px = self.shell, self.shell.theme.px
        frame = self.reset_result
        shell.clear(frame)
        card = shell.card(frame)
        if result['nothing_found']:
            shell.label(card, shell.tr('Здесь пусто'), 'h2', bg='marble')
            shell.label(card, shell.tr('Данных Claude на этом компьютере не найдено. Начнём с нуля — переходите к '
                                       'прокси.'), bg='marble', pady=(px(6), px(16)))
            shell.button(card, shell.tr('Дальше: прокси и защита →'), lambda: shell.show('proxy'),
                         bg='marble').pack(anchor='w')
            return
        shell.label(card, shell.tr('Что найдено'), 'h3', bg='marble', pady=(0, px(10)))
        for row in result['rows']:
            line = ttk.Frame(card, style='Marble.TFrame')
            line.pack(fill='x', pady=px(2))
            ttk.Label(line, text=shell.tr(row['label']), style='Marble.body.TLabel').pack(side='left')
            size = shell.sizes(row['size']) if row['status'] == Location.PRESENT else shell.tr('не прочиталось')
            ttk.Label(line, text=size, style='Marble.mono.TLabel').pack(side='right')
        if result['credentials']:
            shell.label(card, shell.tr('Сохранённые пароли Claude в Windows: {n}', n=result["credentials"]),
                        bg='marble', pady=(px(2), 0))
        shell.label(card, shell.tr('Всего файлов на {size}', size=shell.sizes(result["total"])), 'small', bg='marble',
                    pady=(px(8), 0))
        auto = [b for b in result['blockers'] if b['kind'] == BlockerKind.AUTO]
        ask = [b for b in result['blockers'] if b['kind'] == BlockerKind.ASK]
        user = [b for b in result['blockers'] if b['kind'] == BlockerKind.USER]
        if auto:
            shell.label(card, shell.tr('Программа сделает сама'), 'h3', bg='marble', pady=(px(18), px(6)))
            for b in auto:
                shell.label(card, '•  ' + shell.tr(b['text']), bg='marble')
        if user:
            shell.label(card, shell.tr('Нужно сделать вам'), 'h3', bg='marble', pady=(px(18), px(6)))
            for b in user:
                shell.label(card, '•  ' + shell.tr(b['text']), 'strong', bg='marble')
            buttons = ttk.Frame(card, style='Marble.TFrame')
            buttons.pack(anchor='w', pady=(px(14), 0))
            shell.button(buttons, shell.tr('Проверить снова'), lambda: self.reset_start(dry),
                         bg='marble').pack(side='left')
            if any(b['key'] == 'restore_sources' for b in user):
                shell.button(buttons, shell.tr('Открыть автозагрузку'), self.open_startup, kind='Ghost',
                             bg='marble').pack(side='left', padx=(px(10), 0))
            if any(b['key'] in ('inventory', 'cowork_location') for b in user):
                shell.button(buttons, shell.tr('Режим для специалистов'), shell.open_expert, kind='Ghost',
                             bg='marble').pack(side='left', padx=(px(10), 0))
            shell.label(card, shell.tr('Окно проверяет само каждые несколько секунд и продолжит, как только всё будет '
                                       'готово.'), 'small', bg='marble', pady=(px(10), 0))
            self.watch_blockers(dry, {b['key'] for b in user})
            return
        if dry:
            shell.button(card, shell.tr('Очистить'), lambda: self.reset_start(), bg='marble').pack(anchor='w',
                                                                                                 pady=(px(18), 0))
            return
        if ask and not self.session.accept_unlisted:
            if not shell.confirm(shell.tr('Непроверенная версия Claude'),
                                 shell.tr('Эта версия Claude ещё не проверялась с программой. '
                                          'Программа сотрёт те же папки, что и обычно, но новые места хранения, если '
                                          'версия их добавила, не найдёт. Продолжить?'),
                                 shell.tr('Продолжить'), no=shell.tr('Не сейчас')):
                return
            self.session.accept_unlisted = True
            session = self.session
            shell.run(lambda step: reset_flow.shown(session.check(step)), lambda r: self.reset_checked(r, dry))
            return
        self.reset_confirm(result, auto)

    def reset_confirm(self, result, auto):
        shell = self.shell
        keep = self.session.keep_memory
        lines = [f'{shell.tr(r["label"])} — {shell.sizes(r["size"])}' for r in result['rows']]
        if result['credentials']:
            lines.append(shell.tr('Сохранённые пароли Claude в Windows: {n}', n=result["credentials"]))
        if self.browsers.get():
            lines.append(shell.tr('Вход на claude.ai в Chrome и Edge'))
        text = (shell.tr('Это нельзя отменить. ')
                + (shell.tr('Память Claude Code вернётся на место после очистки. ') if keep
                   else shell.tr('Ничего не сохранится. '))
                + (shell.tr('Перед удалением программа закроет Claude и сохранит копии ваших файлов. ') if auto else '')
                + shell.tr('Будет удалено:'))
        if not shell.confirm(shell.tr('Стереть данные Claude?'), text, shell.tr('Стереть'), lines=lines,
                             typed=shell.tr('СТЕРЕТЬ')):
            return
        session, browsers = self.session, self.browsers.get()

        def job(step):
            checked = session.resolve(step) if auto else session.check(step)
            if checked.blockers:
                return {'stage': 'blocked', 'check': reset_flow.shown(checked)}
            return {'stage': 'wiped', 'result': session.wipe(Confirmation.ERASE, browsers=browsers, step=step)}
        shell.run(job, self.reset_done)

    def reset_done(self, outcome):
        shell = self.shell
        if outcome['stage'] == 'blocked':
            shell.ask(shell.tr('Остановились перед удалением'),
                      shell.tr('Не всё получилось сделать автоматически. Ничего не удалено. '
                               'Посмотрите, что осталось сделать, и нажмите «Проверить снова».'))
            self.reset_checked(outcome['check'], False)
            return
        result = outcome['result']
        px = shell.theme.px
        shell.clear(self.reset_result)
        card = shell.card(self.reset_result)
        if result.status == Reset.FAILED:
            shell.label(card, shell.tr('Стирание остановилось'), 'h2', bg='marble')
            shell.label(card, shell.tr('Часть данных могла остаться. Копия памяти, если вы её сохраняли, не потеряна. '
                                       'Нажмите «Проверить и очистить» ещё раз; если ошибка повторится — сохраните '
                                       'отчёт на странице «Помощь».'),
                        bg='marble', pady=(px(6), 0))
            return
        shell.label(card, shell.tr('Готово ✓') if result.no_files_left else shell.tr('Почти готово'), 'h2',
                    bg='marble')
        lines = [shell.tr('Данные Claude стёрты. В проверенных папках ничего не осталось.') if result.no_files_left
                 else shell.tr('Данные стёрты, но в проверенных папках что-то осталось. Нажмите «Проверить и '
                               'очистить» ещё раз.')]
        if result.memory == 'restored_verbatim':
            lines.append(shell.tr('Память Claude Code возвращена на место.'))
        if result.passwords_removed:
            lines.append(shell.tr('Удалено сохранённых паролей Claude: {n}.', n=result.passwords_removed))
        keys = {
            DesktopKeys.RESET: shell.tr('Ключ устройства Claude Desktop сброшен: Desktop увидит новое устройство.'),
            DesktopKeys.NOT_SUPPORTED: shell.tr('Ключ устройства Claude Desktop не сброшен: эта версия Desktop '
                                                'ещё не проверена. Desktop может узнать этот компьютер.'),
            DesktopKeys.FAILED: shell.tr('Ключ устройства Claude Desktop не сброшен из-за ошибки.'),
        }
        signed_out = {
            Browsers.CLEARED: shell.tr('Вы вышли из claude.ai в Chrome и Edge.'),
            Browsers.BROWSERS_OPEN: shell.tr('Chrome или Edge были открыты, поэтому вход на claude.ai там остался.'),
            Browsers.FAILED: shell.tr('Выйти из claude.ai в браузерах не получилось.'),
        }
        lines += [keys.get(result.desktop_keys, ''), signed_out.get(result.browsers, '')]
        for line in filter(None, lines):
            shell.label(card, line, bg='marble', pady=(px(4), 0))
        shell.label(card, shell.tr('Проверьте вручную'), 'h3', bg='marble', pady=(px(18), px(6)))
        for line in OUTSIDE:
            shell.label(card, '•  ' + shell.tr(line), 'small', bg='marble')
        buttons = ttk.Frame(card, style='Marble.TFrame')
        buttons.pack(anchor='w', pady=(px(18), 0))
        shell.button(buttons, shell.tr('Дальше: прокси и защита →'), lambda: shell.show('proxy'),
                     bg='marble').pack(side='left')
        if result.browsers in (Browsers.BROWSERS_OPEN, Browsers.FAILED):
            shell.button(buttons, shell.tr('Выйти из claude.ai в браузерах'), self.clear_browsers, kind='Ghost',
                         bg='marble').pack(side='left', padx=(px(10), 0))
        self.session = None

    def clear_browsers(self):
        shell = self.shell
        if not shell.confirm(shell.tr('Выйти из claude.ai в браузерах?'),
                             shell.tr('Сначала закройте Chrome и Edge. Профили браузеров и другие сайты '
                                      'не пострадают — удаляются только cookies и данные claude.ai.'),
                             shell.tr('Выйти'), typed=shell.tr('СТЕРЕТЬ')):
            return
        actions = reset_service.Actions(shell.paths)
        shell.run(lambda step: step('browsers', actions.clear_browsers), lambda r: shell.ask(
            shell.tr('Браузеры'), {Browsers.CLEARED: shell.tr('Готово ✓ Вы вышли из claude.ai в Chrome и Edge.'),
                                   Browsers.BROWSERS_OPEN: shell.tr('Chrome или Edge ещё открыты. Закройте их '
                                                                    'полностью и повторите.')}.get(
                r, shell.tr('Не получилось. Повторите после закрытия браузеров.'))))

    def open_startup(self):
        from ...services.diagnostics import open_settings
        try:
            open_settings('startup')
        except Exception:
            self.shell.ask(self.shell.tr('Не открылось'),
                           self.shell.tr('Откройте вручную: Параметры Windows → Приложения → Автозагрузка.'))
