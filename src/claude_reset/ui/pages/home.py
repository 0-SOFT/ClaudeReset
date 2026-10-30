"""The home page of the main window: the two steps, each with the state this computer shows for it."""
from tkinter import ttk

from ...model.status import ProtectionState, Reset
from .. import brand

__all__ = ['HomePage']


class HomePage:
    """A card per step with its state; reading the states changes nothing."""

    def __init__(self, shell):
        self.shell = shell

    def build(self, page):
        shell, px = self.shell, self.shell.theme.px
        shell.label(page, 'CLAUDERESET', 'tag')
        shell.label(page, shell.tr('Начнём с нуля'), 'h1', pady=(px(6), px(8)))
        shell.label(page, shell.tr('Два шага, чтобы Claude увидел вас как нового пользователя: сначала сотрите его '
                                   'следы на этом компьютере, затем направьте его через ваш прокси.'),
                    'lead', pady=(0, px(28)))
        row = ttk.Frame(page, style='Paper.TFrame')
        row.pack(fill='x')
        row.columnconfigure((0, 1), weight=1, uniform='cards')
        self.home_status = {}
        for column, key, step, title, text, action in (
                (0, 'reset', shell.tr('ШАГ 1'), shell.tr('Сброс'),
                 shell.tr('Удаляет вход, историю и данные Claude Desktop и Claude Code. '
                          'Сами программы остаются установленными.'), shell.tr('Перейти к сбросу →')),
                (1, 'proxy', shell.tr('ШАГ 2'), shell.tr('Прокси и защита'),
                 shell.tr('Claude будет выходить в интернет только через ваш прокси. '
                          'Если прокси пропадёт, Claude останется без сети, а не выйдет напрямую.'),
                 shell.tr('Настроить прокси →'))):
            card = ttk.Frame(row, style='Card.TFrame', padding=px(26))
            card.grid(row=0, column=column, sticky='nsew', padx=(0, px(10)) if column == 0 else (px(10), 0))
            shell.label(card, step, 'tag', bg='marble')
            shell.label(card, title, 'h2', bg='marble', pady=(px(4), px(8)))
            text_label = shell.label(card, text, 'body', bg='marble', pady=(0, px(16)))
            text_label.configure(wraplength=px(330))
            status = ttk.Frame(card, style='Marble.TFrame')
            status.pack(anchor='w', pady=(0, px(18)))
            dot = ttk.Label(status, style='Marble.body.TLabel')
            dot.pack(side='left')
            words = ttk.Label(status, text=shell.tr('Проверяем…'), style='Marble.small.TLabel')
            words.pack(side='left', padx=(px(8), 0))
            self.home_status[key] = (dot, words)
            shell.button(card, action, lambda k=key: shell.show(k), bg='marble').pack(anchor='w')
        notice = shell.card(page, 'Notice', pady=(px(24), 0))
        shell.label(notice, shell.tr('После обоих шагов откройте Claude и войдите под новым аккаунтом. '
                                     'Порядок важен: сначала сброс, потом прокси.'), 'body', bg='mist')

    def set_status_dot(self, key, color, text):
        dot, words = self.home_status[key]
        theme = self.shell.theme
        colors = theme.colors
        dot.configure(image=theme.image(f'dot-{color}', brand.dot(theme.px(10), colors[color],
                                                                  background=colors['marble'])))
        words.configure(text=text)

    def refresh_home(self):
        shell = self.shell
        if shell.worker.busy or not hasattr(self, 'home_status'):
            return

        def job(step):
            history = shell.program.history(shell.paths)
            wiped = any(r.status == Reset.FIXED_LOCATIONS_WIPED for r in history.rows)
            return {'wiped': wiped, 'protection': step('summary', lambda: shell.program.protection(shell.paths))}

        def done(result):
            shell.protection = result['protection']
            if result['wiped']:
                self.set_status_dot('reset', 'good', shell.tr('Сброс уже выполнялся на этом компьютере'))
            else:
                self.set_status_dot('reset', 'stone', shell.tr('Ещё не выполнялся'))
            state = shell.protection['state']
            color = {ProtectionState.ON: 'good', ProtectionState.PROBLEM: 'bad', ProtectionState.PARTIAL: 'bad',
                     ProtectionState.PAUSED: 'graphite2'}.get(state, 'stone')
            self.set_status_dot('proxy', color, shell.tr(shell.protection['title']))
            shell.status.set(shell.tr('Готово к работе. Открытие окна ничего не меняет.'))
        shell.run(job, done)
