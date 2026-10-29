"""The ClaudeReset window: two actions — reset, then proxy — in the 0-soft brand.

No Windows logic here. Buttons call reset_flow, proxy_flow and the tested functions behind
them; the specialist window (app.App with every tool) opens as a separate process.
"""
import base64
import queue
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, font as tkfont, ttk

from . import brand, proxy_flow, reset_flow
from .gui_worker import Worker
from .i18n import gui_message
from .ui_text import set_language, sizes, tr, tr_text

C = dict(brand.LIGHT)  # the active palette; Theme fills it for the chosen mode
STEPS = {
    'check': 'Проверяем компьютер…', 'close_claude': 'Закрываем Claude…', 'stop_cowork': 'Останавливаем службу Cowork…',
    'export_cowork': 'Сохраняем копию работы Cowork…', 'archive_extras': 'Сохраняем копию ваших файлов Claude Code…',
    'desktop_keys': 'Сбрасываем ключ устройства Claude Desktop…', 'wipe': 'Стираем данные Claude…',
    'browsers': 'Выходим из claude.ai в Chrome и Edge…', 'proxy_check': 'Проверяем прокси: связь, вход и адрес выхода…',
    'engine': 'Устанавливаем движок VLESS…', 'limits': 'Готовим описание защиты…', 'install': 'Включаем защиту…',
    'change': 'Применяем новый прокси…', 'restart': 'Перезапускаем защиту…', 'remove': 'Выключаем защиту…',
    'reinstall': 'Обновляем защиту…', 'extension': 'Применяем выбор для VS Code…', 'summary': 'Проверяем состояние…',
    'report': 'Собираем отчёт…', 'advice': 'Сравниваем пояс и язык…', 'backend_remove': 'Удаляем сохранённый прокси…',
}
READ_ONLY = {'check', 'summary', 'limits', 'report', 'advice', 'proxy_check'}  # steps that only read
UAC_TEXT = 'Windows просит разрешение. Нажмите «Да» в окне запроса — без него защита не включится.'
OUTSIDE = ('Данные claude.ai в браузерах, кроме cookies и IndexedDB: кэш и локальное хранилище — через настройки браузера.',
           'Ваши проекты и папки с кодом на диске — программа их не трогает.',
           'Переменные среды, WSL, Docker и SSH — если вы настраивали в них Claude.')


def expert_command():
    """Command that opens the specialist window (every tool of the program) as its own process."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--expert']
    interpreter = Path(sys.executable)
    windowless = interpreter.with_name('pythonw.exe')
    launcher = Path(__file__).resolve().parents[1] / 'launcher.py'
    return [str(windowless if windowless.is_file() else interpreter), str(launcher), '--expert']


class Theme:
    """ttk styles, fonts and images from the brand tokens, scaled for the display."""

    TEXT = {'h1': ('display', 46), 'h2': ('display', 32), 'h3': ('semibold', 19), 'lead': ('body', 17),
            'body': ('body', 15), 'strong': ('medium', 15), 'small': ('body', 13.5), 'tag': ('mono', 11.5),
            'button': ('medium', 15), 'button_sm': ('medium', 14), 'nav': ('medium', 15), 'brand': ('semibold', 18),
            'field': ('body', 15), 'mono': ('mono', 13)}
    COLORS = {'h1': 'ink', 'h2': 'ink', 'h3': 'ink', 'lead': 'graphite', 'body': 'graphite', 'strong': 'ink',
              'small': 'graphite2', 'tag': 'graphite2', 'good': 'good', 'bad': 'bad', 'brand': 'ink', 'mono': 'graphite'}

    def __init__(self, root, mode='light'):
        self.root, self.mode = root, mode if mode in brand.PALETTES else 'light'
        C.clear()
        C.update(brand.PALETTES[self.mode])
        self.scale = max(1.0, root.winfo_fpixels('1i') / 96)
        families = set(tkfont.families(root))
        self.fonts = {}
        for name, (kind, size) in self.TEXT.items():
            family = brand.FONTS[kind] if brand.FONTS[kind] in families else brand.FALLBACK[kind]
            self.fonts[name] = tkfont.Font(root, family=family, size=-self.px(size))
        self.fonts['good'] = self.fonts['bad'] = self.fonts['strong']
        self.fonts['body_focus'] = tkfont.Font(root, family=self.fonts['body'].cget('family'), size=-self.px(15), underline=1)
        self.brand_fonts = all(brand.FONTS[k] in families for k in ('display', 'body', 'mono'))
        # Elements and their images belong to the Tk interpreter and cannot be redefined: they are created once
        # per interpreter and theme (names carry the mode), while styles are re-pointed on every build.
        self.images = self.CACHE.setdefault(id(root.tk), {})
        self.style = ttk.Style(root)
        self.style.theme_use('clam')
        self.elements = set(self.style.element_names())
        self.configure()

    CACHE = {}

    def element(self, name, *spec, **options):
        name = f'{self.mode}.{name}'
        if name not in self.elements:
            self.style.element_create(name, 'image', *spec, **options)
            self.elements.add(name)
        return name

    def px(self, value):
        return max(1, round(value * self.scale))

    def image(self, key, data):
        key = f'{self.mode}:{self.scale:.3f}:{key}'
        if key not in self.images:
            self.images[key] = tk.PhotoImage(master=self.root, data=base64.b64encode(data).decode('ascii'))
        return self.images[key]

    def configure(self):
        s, px = self.style, self.px
        s.configure('.', background=C['paper'], foreground=C['graphite'], font=self.fonts['body'],
                    borderwidth=0, focuscolor=C['graphite'], troughcolor=C['mist'])
        for bg in ('paper', 'marble', 'mist', 'accent'):
            name = bg.capitalize()
            s.configure(f'{name}.TFrame', background=C[bg])
            for kind, color in self.COLORS.items():
                # Text on turquoise is always ink (#0e0e0e), in both themes.
                s.configure(f'{name}.{kind}.TLabel', background=C[bg], foreground=C['on_accent' if bg == 'accent' else color],
                            font=self.fonts[kind])
        self.panel('Card', C['marble'], C['haze'], 18)
        self.panel('Choice', C['marble'], C['haze'], 18)
        self.panel('ChoiceOn', C['accent'], None, 18)
        self.panel('ChoiceFocus', C['marble'], C['ink'], 18, ring_width=2)
        self.panel('ChoiceOnFocus', C['accent'], C['on_accent'], 18, ring_width=2)
        self.panel('Notice', C['mist'], None, 14)
        dark, on = C['on_accent'], C['accent']
        for bg in ('paper', 'marble', 'mist'):
            # Focus: a 2 px ring in the text colour (on ink buttons the turquoise, which has 11:1 contrast there).
            self.pill('Primary', bg, 48, 'button', 22, C['paper'], {
                '': (C['ink'], None), 'active': (on, None), 'pressed': (on, C['graphite']),
                'disabled': (C['stone'], None), 'focus': (C['ink'], on)},
                {'active': dark, 'pressed': dark, 'disabled': C['marble']})
            self.pill('Ghost', bg, 48, 'button', 22, C['ink'], {
                '': (None, C['graphite']), 'active': (None, on), 'pressed': (on, None),
                'disabled': (None, C['stone']), 'focus': (None, C['ink'])}, {'pressed': dark, 'disabled': C['stone']})
            self.pill('Small', bg, 40, 'button_sm', 16, C['ink'], {
                '': (None, C['graphite']), 'active': (None, on), 'pressed': (on, None),
                'disabled': (None, C['stone']), 'focus': (None, C['ink'])}, {'pressed': dark, 'disabled': C['stone']})
            self.pill('Chip', bg, 40, 'button_sm', 16, C['graphite'], {
                '': (C['marble'], C['haze']), 'active': (C['marble'], C['stone']), 'pressed': (on, None),
                'focus': (C['marble'], C['ink'])}, {'active': C['ink'], 'pressed': dark})
            self.pill('ChipOn', bg, 40, 'button_sm', 16, dark, {'': (on, None), 'focus': (on, dark)}, {})
            self.check(bg)
        s.configure('Nav.TButton', background=C['mist'], foreground=C['graphite2'], font=self.fonts['nav'],
                    padding=(px(14), px(10)), anchor='w', relief='flat', bordercolor=C['mist'],
                    lightcolor=C['mist'], darkcolor=C['mist'])
        s.map('Nav.TButton', background=[('active', C['mist'])], foreground=[('active', C['ink'])])
        s.configure('NavOn.TButton', background=C['mist'], foreground=C['ink'], font=self.fonts['nav'],
                    padding=(px(14), px(10)), anchor='w', relief='flat', bordercolor=C['mist'],
                    lightcolor=C['mist'], darkcolor=C['mist'])
        s.map('NavOn.TButton', background=[('active', C['mist'])])
        s.configure('Brand.TEntry', fieldbackground=C['marble'], foreground=C['ink'], bordercolor=C['stone'],
                    lightcolor=C['marble'], darkcolor=C['marble'], insertcolor=C['ink'], padding=(px(12), px(9)),
                    selectbackground=C['accent'], selectforeground=C['on_accent'], font=self.fonts['field'])
        s.map('Brand.TEntry', bordercolor=[('focus', C['graphite'])], lightcolor=[('focus', C['marble'])])
        s.configure('Brand.Horizontal.TProgressbar', troughcolor=C['mist'], background=C['accent'],
                    bordercolor=C['mist'], lightcolor=C['accent'], darkcolor=C['accent'], thickness=px(4))
        s.configure('Idle.Horizontal.TProgressbar', troughcolor=C['paper'], background=C['paper'],
                    bordercolor=C['paper'], lightcolor=C['paper'], darkcolor=C['paper'], thickness=px(4))
        s.layout('Brand.Vertical.TScrollbar', [('Vertical.Scrollbar.trough', {'sticky': 'ns', 'children': [
            ('Vertical.Scrollbar.thumb', {'expand': '1', 'sticky': 'nswe'})]})])
        s.configure('Brand.Vertical.TScrollbar', troughcolor=C['paper'], background=C['haze'], bordercolor=C['paper'],
                    lightcolor=C['haze'], darkcolor=C['haze'], gripcount=0, width=px(10), arrowsize=px(10))
        s.map('Brand.Vertical.TScrollbar', background=[('active', C['stone'])])

    def panel(self, name, fill, ring, radius, ring_width=1.0):
        r = self.px(radius)
        size = 2 * r + 128  # ttk tiles the centre: a large centre keeps redraws cheap
        image = self.image(f'panel-{name}', brand.rounded(size, size, r, fill=fill, ring=ring,
                                                          ring_width=ring_width * self.scale, background=C['paper']))
        element = self.element(f'{name}.panel', image, border=r, sticky='nsew', padding=0)
        self.style.layout(f'{name}.TFrame', [(element, {'sticky': 'nsew'})])
        self.style.configure(f'{name}.TFrame', background=fill)

    def pill(self, name, bg, height, font, pad, color, states, colors):
        h = self.px(height)
        r = h // 2
        ring = max(1.0, self.scale)
        images = {state: self.image(f'pill-{name}-{bg}-{state}', brand.rounded(
            h + 64, h, r, fill=fill, ring=edge, ring_width=ring * (2 if state == 'focus' else 1), background=C[bg]))
            for state, (fill, edge) in states.items()}
        spec = [images['']] + [(state, images[state]) for state in ('disabled', 'pressed', 'active', 'focus') if state in images]
        if len(spec) == 1:
            spec.append(('disabled', images['']))  # Tk needs at least one state map entry
        element = self.element(f'{name}.{bg}.pill', *spec, border=(r, r - 1, r, r - 1), sticky='nsew', padding=0)
        style = f'{name}.{bg.capitalize()}.TButton'
        self.style.layout(style, [(element, {'sticky': 'nsew', 'children': [('Button.padding', {
            'sticky': 'nsew', 'children': [('Button.label', {'sticky': 'nsew'})]})]})])
        self.style.configure(style, padding=(self.px(pad), self.px(4)), font=self.fonts[font], foreground=color,
                             background=C[bg], anchor='center')
        self.style.map(style, foreground=[(state, value) for state, value in colors.items()])

    def check(self, bg):
        size, gap = self.px(22), self.px(12)
        colours = dict(box=C['marble'], ring=C['stone'], on=C['accent'], mark_color=C['on_accent'], background=C[bg], gap=gap)
        off = self.image(f'check-off-{bg}', brand.checkbox(size, False, **colours))
        on = self.image(f'check-on-{bg}', brand.checkbox(size, True, **colours))
        element = self.element(f'Brand.{bg}.indicator', off, ('selected', on), sticky='')
        style = f'{bg.capitalize()}.TCheckbutton'
        self.style.layout(style, [('Checkbutton.padding', {'sticky': 'nsew', 'children': [
            (element, {'side': 'left', 'sticky': ''}), ('Checkbutton.label', {'side': 'left', 'sticky': 'nsew'})]})])
        self.style.configure(style, background=C[bg], foreground=C['graphite'], font=self.fonts['body'], padding=(0, self.px(4)))
        # Keyboard focus: the label is underlined and in the text colour.
        self.style.map(style, background=[('active', C[bg])], foreground=[('focus', C['ink']), ('active', C['ink'])],
                       font=[('focus', self.fonts['body_focus'])])


class Scroll(ttk.Frame):
    """A vertically scrolling page; the inner frame follows the window width."""

    def __init__(self, master, theme):
        super().__init__(master, style='Paper.TFrame')
        self.canvas = tk.Canvas(self, background=C['paper'], highlightthickness=0, borderwidth=0)
        bar = ttk.Scrollbar(self, orient='vertical', style='Brand.Vertical.TScrollbar', command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas, style='Paper.TFrame', padding=(theme.px(48), theme.px(40), theme.px(48), theme.px(48)))
        window = self.canvas.create_window(0, 0, anchor='nw', window=self.inner)
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side='left', fill='both', expand=True)
        bar.pack(side='right', fill='y')
        self.inner.bind('<Configure>', lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox('all')))
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfigure(window, width=e.width))

    def owns(self, widget):
        while widget is not None:
            if widget is self:
                return True
            widget = getattr(widget, 'master', None)
        return False

    def wheel(self, delta):
        if self.inner.winfo_height() > self.canvas.winfo_height():
            self.canvas.yview_scroll(int(-delta / 120), 'units')

    def ensure_visible(self, widget):
        """Keyboard focus moved to a widget outside the view: scroll so it is seen with a little room."""
        total = self.inner.winfo_height()
        view = self.canvas.winfo_height()
        if total <= view:
            return
        top = widget.winfo_rooty() - self.inner.winfo_rooty()
        bottom = top + widget.winfo_height()
        shown = self.canvas.canvasy(0)
        margin = view // 6
        if top < shown:
            self.canvas.yview_moveto(max(0, top - margin) / total)
        elif bottom > shown + view:
            self.canvas.yview_moveto(max(0, bottom + margin - view) / total)

    def top(self):
        self.canvas.yview_moveto(0)


class Dialog(tk.Toplevel):
    """A modal question in the brand. Returns the value of the pressed button, or None."""

    def __init__(self, shell, title, text, *, buttons=(('Primary', tr('Понятно'), True),), lines=(), typed=None):
        super().__init__(shell.root, background=C['paper'])
        theme, px = shell.theme, shell.theme.px
        self.result = None
        self.withdraw()
        self.title('ClaudeReset')
        self.transient(shell.root)
        self.resizable(False, False)
        body = ttk.Frame(self, style='Paper.TFrame', padding=(px(32), px(28), px(32), px(24)))
        body.pack(fill='both', expand=True)
        width = px(520)
        ttk.Label(body, text=title, style='Paper.h2.TLabel', wraplength=width).pack(anchor='w')
        ttk.Label(body, text=text, style='Paper.body.TLabel', wraplength=width, justify='left').pack(anchor='w', pady=(px(10), 0))
        if lines:
            box = ttk.Frame(body, style='Notice.TFrame')
            box.pack(fill='x', pady=(px(16), 0))
            for line in lines:
                ttk.Label(box, text='•  ' + tr_text(line), style='Mist.body.TLabel', wraplength=width - px(40), justify='left').pack(anchor='w', pady=px(2))
        self.entry = None
        row = ttk.Frame(body, style='Paper.TFrame')
        primary = []
        if typed:
            ttk.Label(body, text=tr('Чтобы подтвердить, введите {word}', word=typed), style='Paper.small.TLabel').pack(anchor='w', pady=(px(18), px(6)))
            self.word = tk.StringVar(master=self)
            self.entry = ttk.Entry(body, textvariable=self.word, style='Brand.TEntry', font=theme.fonts['field'], width=24)
            self.entry.pack(anchor='w')
            self.word.trace_add('write', lambda *_: [b.state(['!disabled'] if self.word.get().strip() == typed else ['disabled']) for b in primary])
        row.pack(fill='x', pady=(px(24), 0))
        self.first = None
        for style, label, value in buttons:
            button = ttk.Button(row, text=label, style=f'{style}.Paper.TButton', command=lambda v=value: self.close(v))
            button.pack(side='left', padx=(0, px(10)))
            self.first = self.first or button
            if typed and style == 'Primary':
                button.state(['disabled'])
                primary.append(button)
        # Enter confirms (only when the typed word is right), Esc cancels.
        if self.entry is not None:
            self.entry.bind('<Return>', lambda _e: self.first.invoke() if self.first.instate(['!disabled']) else None)
        self.bind('<Escape>', lambda _e: self.close(None))
        self.protocol('WM_DELETE_WINDOW', lambda: self.close(None))
        self.update_idletasks()
        x = shell.root.winfo_rootx() + (shell.root.winfo_width() - self.winfo_reqwidth()) // 2
        y = shell.root.winfo_rooty() + max(0, (shell.root.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry(f'+{max(0, x)}+{max(0, y)}')

    def close(self, value):
        self.result = value
        self.grab_release()
        self.destroy()

    def show(self):
        from . import ui_settings
        self.deiconify()
        ui_settings.dark_title_bar(self, C['paper'] == brand.DARK['paper'])
        self.grab_set()
        (self.entry or self.first or self).focus_set()
        self.wait_window()
        return self.result


class Shell:
    def __init__(self, paths, root=None, *, start=None, theme=None, language=None):
        from . import ui_settings
        self.paths = paths
        self.root = root or tk.Tk()
        self.language_choice = language or ui_settings.language(paths)
        set_language(self.language_choice)
        self.theme_choice = theme or ui_settings.theme(paths)
        self.theme = Theme(self.root, ui_settings.resolve(self.theme_choice))
        px = self.theme.px
        self.root.title('ClaudeReset')
        # The window fits the screen at any display scale; the layout scrolls and wraps inside.
        width = min(px(1160), int(self.root.winfo_screenwidth() * .92))
        height = min(px(800), int(self.root.winfo_screenheight() * .88))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(min(px(980), width), min(px(660), height))
        try:
            self.root.iconphoto(True, self.theme.image('icon-64', brand.app_icon(64)), self.theme.image('icon-32', brand.app_icon(32)))
        except tk.TclError:
            pass
        self.worker, self.operation, self.callback, self.step_text = Worker(), None, None, ''
        self.waiting_uac = self.changing = False
        self.session = None
        self.protection = {'state': 'unknown'}
        self.last_reset = None
        self.current = 'home'
        self.ask = self.dialog  # tests replace this to answer questions
        self.wrapped, self.fitting = {}, set()
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        # Keyboard: Enter presses the focused button, Alt+1..4 open the pages, focus scrolls into view.
        self.root.bind_class('TButton', '<Return>', lambda e: e.widget.invoke())
        self.root.bind_class('TButton', '<KP_Enter>', lambda e: e.widget.invoke())
        for number, key in enumerate(('home', 'reset', 'proxy', 'help'), 1):
            self.root.bind(f'<Alt-Key-{number}>', lambda _e, k=key: self.show(k))
        self.root.bind_all('<MouseWheel>', self.wheel, add='+')
        self.root.bind_all('<FocusIn>', self.focused, add='+')
        self.dress()
        self.build()
        self.show('home')
        self.root.after(100, self.poll)
        if start == 'uninstall':
            self.root.after(500, self.uninstall_program)

    def dress(self):
        from . import ui_settings
        self.root.configure(background=C['paper'])
        self.root.after(60, lambda: ui_settings.dark_title_bar(self.root, self.theme.mode == 'dark'))

    def page_of(self, widget):
        for page in getattr(self, 'pages', {}).values():
            try:
                if page.owns(widget):
                    return page
            except tk.TclError:
                return None
        return None

    def wheel(self, event):
        page = self.page_of(event.widget) if isinstance(event.widget, tk.Misc) else None
        if page is not None:
            page.wheel(event.delta)

    def focused(self, event):
        widget = event.widget
        page = self.page_of(widget) if isinstance(widget, tk.Misc) else None
        if page is not None and widget is not page.inner:
            self.root.after_idle(lambda: widget.winfo_exists() and page.ensure_visible(widget))

    def set_theme(self, choice):
        """Remember the choice and rebuild the window in it; not while an action runs."""
        from . import ui_settings
        if self.worker.busy:
            self.status.set(tr('Тема сменится после текущего действия: выберите её ещё раз.'))
            return
        try:
            ui_settings.save_theme(self.paths, choice)
        except (OSError, ValueError):
            pass
        self.theme_choice = choice
        self.rebuild()

    def set_language_choice(self, choice):
        """Remember the language and rebuild the window in it; not while an action runs."""
        from . import ui_settings
        if self.worker.busy:
            self.status.set(tr('Язык сменится после текущего действия: выберите его ещё раз.'))
            return
        try:
            ui_settings.save_language(self.paths, choice)
        except (OSError, ValueError):
            pass
        self.language_choice = choice
        set_language(choice)
        self.rebuild()

    def rebuild(self):
        from . import ui_settings
        current = self.current
        for child in self.root.winfo_children():
            child.destroy()
        self.wrapped, self.fitting, self.session = {}, set(), None
        self.theme = Theme(self.root, ui_settings.resolve(self.theme_choice))
        self.dress()
        self.build()
        self.show(current)

    # ----- frame -----
    def build(self):
        px = self.theme.px
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        side = ttk.Frame(self.root, style='Mist.TFrame', padding=(px(20), px(28), px(20), px(20)), width=px(268))
        side.grid(row=0, column=0, sticky='ns')
        side.grid_propagate(False)
        side.pack_propagate(False)
        head = ttk.Frame(side, style='Mist.TFrame')
        head.pack(anchor='w', fill='x', padx=px(8))
        # The left zero takes the theme's text colour, the right one is always turquoise.
        ttk.Label(head, image=self.theme.image('mark', brand.mark(px(26), left=C['ink'], background=C['mist'])),
                  style='Mist.body.TLabel').pack(side='left')
        ttk.Label(head, text='ClaudeReset', style='Mist.brand.TLabel').pack(side='left', padx=(px(10), 0))
        ttk.Label(side, text=tr('0-SOFT · НАЧНЁМ С НУЛЯ'), style='Mist.tag.TLabel').pack(anchor='w', padx=px(8), pady=(px(6), px(14)))
        # The other language, in capitals so it is found at once; Russian is the default.
        other = ('en', 'ENGLISH') if self.language_choice == 'ru' else ('ru', 'РУССКИЙ')
        self.language_button = self.small_button(side, other[1], lambda: self.set_language_choice(other[0]), bg='mist')
        self.language_button.pack(anchor='w', padx=px(8), pady=(0, px(22)))
        lens_on = self.theme.image('lens-on', brand.lens(px(15), background=C['mist']))
        lens_off = self.theme.image('lens-off', brand.rounded(lens_on.width(), lens_on.height(), 1, background=C['mist']))
        self.lens = (lens_on, lens_off)
        self.nav = {}
        for key, label in (('home', tr('Главная')), ('reset', tr('Шаг 1 · Сброс')), ('proxy', tr('Шаг 2 · Прокси и защита')), ('help', tr('Помощь'))):
            button = ttk.Button(side, text=label, style='Nav.TButton', image=lens_off, compound='left',
                                command=lambda k=key: self.show(k), takefocus=True)
            button.pack(anchor='w', fill='x')
            self.nav[key] = button
        bottom = ttk.Frame(side, style='Mist.TFrame')
        bottom.pack(side='bottom', fill='x', padx=px(8))
        ttk.Label(bottom, text=tr('Все инструменты программы — для тех, кто знает, что делает.'), style='Mist.small.TLabel',
                  wraplength=px(210), justify='left').pack(anchor='w', pady=(0, px(8)))
        self.small_button(bottom, tr('Режим для специалистов'), self.open_expert, bg='mist').pack(anchor='w')

        main = ttk.Frame(self.root, style='Paper.TFrame')
        main.grid(row=0, column=1, sticky='nsew')
        main.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        self.pages = {}
        for key, builder in (('home', self.build_home), ('reset', self.build_reset), ('proxy', self.build_proxy), ('help', self.build_help)):
            page = Scroll(main, self.theme)
            page.grid(row=0, column=0, sticky='nsew')
            builder(page.inner)
            self.pages[key] = page
        bar = ttk.Frame(main, style='Paper.TFrame', padding=(px(48), px(10), px(48), px(14)))
        bar.grid(row=1, column=0, sticky='ew')
        self.progress = ttk.Progressbar(bar, mode='determinate', value=0, style='Idle.Horizontal.TProgressbar')
        self.progress.pack(fill='x')
        status_row = ttk.Frame(bar, style='Paper.TFrame')
        status_row.pack(fill='x', pady=(px(8), 0))
        self.status = tk.StringVar(master=self.root, value=tr('Готово к работе. Открытие окна ничего не меняет.'))
        ttk.Label(status_row, textvariable=self.status, style='Paper.small.TLabel').pack(side='left')
        self.cancel_button = self.small_button(status_row, tr('Остановить'), self.cancel, bg='paper')

    def small_button(self, master, text, command, *, bg='paper'):
        return ttk.Button(master, text=text, command=command, style=f'Small.{bg.capitalize()}.TButton')

    def button(self, master, text, command, *, kind='Primary', bg='paper'):
        return ttk.Button(master, text=text, command=command, style=f'{kind}.{bg.capitalize()}.TButton')

    def label(self, master, text='', kind='body', *, bg='paper', wrap=True, **pack):
        widget = ttk.Label(master, text=text, style=f'{bg.capitalize()}.{kind}.TLabel', justify='left')
        if wrap:
            widget.configure(wraplength=self.theme.px(760))
            if master not in self.wrapped:
                self.wrapped[master] = []
                master.bind('<Configure>', lambda _e, m=master: self.schedule_fit(m), add='+')
            self.wrapped[master].append(widget)
        widget.pack(anchor='w', **pack)
        return widget

    def schedule_fit(self, master):
        # One deferred refit per container: wrapping changes heights, never the container's width.
        if master not in self.fitting:
            self.fitting.add(master)
            self.root.after(40, lambda: self.fit(master))

    def fit(self, master):
        """Wrap text to the container: never wider than a comfortable line, never past the card edge."""
        self.fitting.discard(master)
        if not master.winfo_exists():
            self.wrapped.pop(master, None)
            return
        try:
            values = [int(float(str(v))) for v in self.root.tk.splitlist(master.cget('padding'))]
            pad = (values[0] + values[2]) if len(values) == 4 else 2 * values[0] if values else 0
        except (tk.TclError, ValueError):
            pad = 0
        wrap = max(self.theme.px(220), min(self.theme.px(760), master.winfo_width() - pad - 2))
        for widget in self.wrapped.get(master, []):
            if widget.winfo_exists() and abs(int(str(widget.cget('wraplength')) or 0) - wrap) >= 4:
                widget.configure(wraplength=wrap)

    PADDING = {'Card': 26, 'Choice': 22, 'ChoiceOn': 22, 'Notice': 18}

    def card(self, master, style='Card', **pack):
        frame = ttk.Frame(master, style=f'{style}.TFrame', padding=self.theme.px(self.PADDING[style]))
        frame.pack(fill='x', **pack)
        return frame

    def show(self, key):
        for name, page in self.pages.items():
            if name == key:
                page.tkraise()
                page.top()
        for name, button in self.nav.items():
            on = name == key
            button.configure(style='NavOn.TButton' if on else 'Nav.TButton', image=self.lens[0] if on else self.lens[1])
        self.current = key
        if key == 'home':
            self.refresh_home()
        elif key == 'proxy':
            self.refresh_proxy()

    # ----- background work -----
    def run(self, job, done, *, uac_steps=()):
        """job(step) runs in the background; step(label, fn) shows progress; done(result) runs in the window."""
        if self.worker.busy:
            self.status.set(tr('Подождите: предыдущее действие ещё выполняется.'))
            return False

        def action(context):
            def step(label, fn, uac=False):
                self.step_text = tr(STEPS.get(label, 'Выполняем…'))
                self.changing = self.changing or label not in READ_ONLY
                return context.step(fn, waiting_uac=uac or label in uac_steps)
            return job(step)
        self.callback = done
        self.changing = False
        self.step_text = tr('Выполняем…')
        self.operation = self.worker.start(action)
        self.status.set(self.step_text)
        self.progress.configure(mode='indeterminate', style='Brand.Horizontal.TProgressbar')
        self.progress.start(12)
        return True

    def poll(self):
        try:
            for _ in range(32):
                event = self.worker.events.get_nowait()
                if event.operation != self.operation:
                    continue
                self.waiting_uac = event.state == 'waiting_uac'
                if event.state == 'waiting_uac':
                    self.status.set(tr(UAC_TEXT))
                elif event.state in ('running', 'queued'):
                    self.status.set(self.step_text or tr('Выполняем…'))
                if event.cancellable:
                    self.cancel_button.pack(side='right')
                else:
                    self.cancel_button.pack_forget()
                if event.state in ('completed', 'cancelled', 'operation_failed', 'worker_start_failed'):
                    result = self.worker.take_result(event.operation)
                    callback, self.callback, self.operation = self.callback, None, None
                    self.progress.stop()
                    self.progress.configure(mode='determinate', value=0, style='Idle.Horizontal.TProgressbar')
                    self.cancel_button.pack_forget()
                    self.waiting_uac = False
                    if event.state == 'completed':
                        self.status.set(tr('Готово.'))
                        try:
                            callback(result)
                        except Exception:
                            self.status.set(tr(gui_message('callback_failed')))
                    elif event.state == 'cancelled':
                        self.status.set(tr(gui_message('cancelled')))
                    else:
                        self.status.set(tr('Не получилось.'))
                        self.ask(tr('Не получилось'), tr('Действие остановилось с ошибкой. Ничего не повторялось автоматически. '
                                 'Проверьте состояние ещё раз; если ошибка повторится — сохраните отчёт на странице «Помощь».'))
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.poll)

    def cancel(self):
        if not self.worker.cancel():
            self.status.set(tr(gui_message('cancel_unavailable')))

    def dialog(self, title, text, buttons=(('Primary', tr('Понятно'), True),), lines=(), typed=None):
        return Dialog(self, title, text, buttons=buttons, lines=lines, typed=typed).show()

    def confirm(self, title, text, yes, *, no=tr('Отмена'), lines=(), typed=None):
        return bool(self.ask(title, text, (('Primary', yes, True), ('Ghost', no, None)), lines, typed))

    def close(self):
        # Reading the state can simply stop; only an action that changes something asks first.
        if self.worker.busy and (self.changing or self.waiting_uac):
            text = tr(gui_message('uac_close_unknown')) if self.waiting_uac else \
                tr('Действие ещё выполняется. Если закрыть окно, оно продолжится без вас, а результат придётся проверить заново.')
            if not self.confirm(tr('Закрыть окно?'), text, tr('Закрыть'), no=tr('Остаться')):
                return
        self.root.destroy()

    def open_expert(self):
        try:
            subprocess.Popen(expert_command(), cwd=str(Path(__file__).resolve().parents[1]))
            self.status.set(tr('Режим для специалистов открывается в отдельном окне.'))
        except OSError:
            self.ask(tr('Не открылось'), tr('Не удалось открыть режим для специалистов. Запустите ClaudeReset.cmd ещё раз.'))

    # ----- home -----
    def build_home(self, page):
        px = self.theme.px
        self.label(page, 'CLAUDERESET', 'tag')
        self.label(page, tr('Начнём с нуля'), 'h1', pady=(px(6), px(8)))
        self.label(page, tr('Два шага, чтобы Claude увидел вас как нового пользователя: сначала сотрите его следы '
                   'на этом компьютере, затем направьте его через ваш прокси.'), 'lead', pady=(0, px(28)))
        row = ttk.Frame(page, style='Paper.TFrame')
        row.pack(fill='x')
        row.columnconfigure((0, 1), weight=1, uniform='cards')
        self.home_status = {}
        for column, key, step, title, text, action in (
                (0, 'reset', tr('ШАГ 1'), tr('Сброс'), tr('Удаляет вход, историю и данные Claude Desktop и Claude Code. '
                 'Сами программы остаются установленными.'), tr('Перейти к сбросу →')),
                (1, 'proxy', tr('ШАГ 2'), tr('Прокси и защита'), tr('Claude будет выходить в интернет только через ваш прокси. '
                 'Если прокси пропадёт, Claude останется без сети, а не выйдет напрямую.'), tr('Настроить прокси →'))):
            card = ttk.Frame(row, style='Card.TFrame', padding=px(26))
            card.grid(row=0, column=column, sticky='nsew', padx=(0, px(10)) if column == 0 else (px(10), 0))
            self.label(card, step, 'tag', bg='marble')
            self.label(card, title, 'h2', bg='marble', pady=(px(4), px(8)))
            text_label = self.label(card, text, 'body', bg='marble', pady=(0, px(16)))
            text_label.configure(wraplength=px(330))
            status = ttk.Frame(card, style='Marble.TFrame')
            status.pack(anchor='w', pady=(0, px(18)))
            dot = ttk.Label(status, style='Marble.body.TLabel')
            dot.pack(side='left')
            words = ttk.Label(status, text=tr('Проверяем…'), style='Marble.small.TLabel')
            words.pack(side='left', padx=(px(8), 0))
            self.home_status[key] = (dot, words)
            self.button(card, action, lambda k=key: self.show(k), bg='marble').pack(anchor='w')
        notice = self.card(page, 'Notice', pady=(px(24), 0))
        self.label(notice, tr('После обоих шагов откройте Claude и войдите под новым аккаунтом. '
                   'Порядок важен: сначала сброс, потом прокси.'), 'body', bg='mist')

    def set_status_dot(self, key, color, text):
        dot, words = self.home_status[key]
        dot.configure(image=self.theme.image(f'dot-{color}', brand.dot(self.theme.px(10), C[color], background=C['marble'])))
        words.configure(text=text)

    def refresh_home(self):
        if self.worker.busy or not hasattr(self, 'home_status'):
            return
        from .diagnostics import operation_history

        def job(step):
            history = operation_history(self.paths)
            wiped = any(r.get('status') == 'fixed_locations_wiped' for r in history.get('rows', []))
            return {'wiped': wiped, 'protection': step('summary', lambda: proxy_flow.summary(self.paths))}

        def done(result):
            self.protection = result['protection']
            if result['wiped']:
                self.set_status_dot('reset', 'good', tr('Сброс уже выполнялся на этом компьютере'))
            else:
                self.set_status_dot('reset', 'stone', tr('Ещё не выполнялся'))
            state = self.protection['state']
            color = {'on': 'good', 'problem': 'bad', 'partial': 'bad', 'paused': 'graphite2'}.get(state, 'stone')
            self.set_status_dot('proxy', color, tr(self.protection['title']))
            self.status.set(tr('Готово к работе. Открытие окна ничего не меняет.'))
        self.run(job, done)

    # ----- reset -----
    def build_reset(self, page):
        px = self.theme.px
        self.label(page, tr('ШАГ 1 · СБРОС'), 'tag')
        self.label(page, tr('Сброс Claude'), 'h1', pady=(px(6), px(8)))
        self.label(page, tr('Сотрём всё, что Claude хранит на этом компьютере: вход, историю, настройки и сохранённые пароли. '
                   'Сами программы останутся — после сброса они откроются как в первый раз.'), 'lead', pady=(0, px(28)))

        self.label(page, tr('Что сохранить'), 'h3', pady=(0, px(12)))
        self.keep_memory = tk.StringVar(master=self.root, value='keep')
        row = ttk.Frame(page, style='Paper.TFrame')
        row.pack(fill='x', pady=(0, px(28)))
        row.columnconfigure((0, 1), weight=1, uniform='choice')
        self.choices = []
        for column, value, title, text in (
                (0, 'keep', tr('Стереть всё, но оставить память'), tr('Ваши заметки и инструкции для Claude Code (файлы CLAUDE.md) '
                 'вернутся на место. Всё остальное будет удалено.')),
                (1, 'none', tr('Стереть всё'), tr('Ничего не сохраняется. Полностью с нуля.'))):
            self.choices.append(self.choice(row, column, value, title, text))
        self.keep_memory.trace_add('write', lambda *_: self.paint_choices())
        self.paint_choices()

        self.label(page, tr('Сначала — на сайте Claude'), 'h3', pady=(0, px(8)))
        self.label(page, tr('В браузере, где вы вошли в старый аккаунт, выйдите на всех устройствах и отзовите доступ '
                   'Claude Code. Иначе сервер свяжет новый вход со старым. Скопируйте адрес и вставьте его в браузер.'),
                   'body', pady=(0, px(12)))
        links = ttk.Frame(page, style='Paper.TFrame')
        links.pack(anchor='w', pady=(0, px(12)))
        from .services import SERVER_LINKS
        for kind, label in (('sessions', tr('Скопировать адрес: сессии')), ('code_tokens', tr('Скопировать адрес: доступ Claude Code'))):
            self.small_button(links, label, lambda u=SERVER_LINKS[kind]: self.copy(u)).pack(side='left', padx=(0, px(10)))
        self.server_done = tk.BooleanVar(master=self.root, value=False)
        ttk.Checkbutton(page, text=tr('Готово: я вышел на всех устройствах и сохранил нужное из облака'),
                        variable=self.server_done, style='Paper.TCheckbutton').pack(anchor='w', pady=(0, px(28)))

        self.label(page, tr('Браузеры'), 'h3', pady=(0, px(8)))
        self.browsers = tk.BooleanVar(master=self.root, value=True)
        ttk.Checkbutton(page, text=tr('Также выйти из claude.ai в Chrome и Edge (закройте их перед сбросом)'),
                        variable=self.browsers, style='Paper.TCheckbutton').pack(anchor='w', pady=(0, px(28)))

        actions = ttk.Frame(page, style='Paper.TFrame')
        actions.pack(anchor='w')
        self.reset_button = self.button(actions, tr('Проверить и очистить'), self.reset_start)
        self.reset_button.pack(side='left')
        self.button(actions, tr('Только посмотреть, что найдено'), lambda: self.reset_start(dry=True), kind='Ghost').pack(side='left', padx=(px(12), 0))
        self.label(page, tr('Программа сама закроет Claude, остановит службу Cowork и сохранит копии ваших файлов. '
                   'Перед удалением она покажет, что найдено, и попросит подтверждение.'), 'small', pady=(px(12), 0))
        self.reset_result = ttk.Frame(page, style='Paper.TFrame')
        self.reset_result.pack(fill='x', pady=(px(24), 0))

    def choice(self, row, column, value, title, text):
        px = self.theme.px
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
        focus = self.root.focus_get()
        for value, frame, head, body in self.choices:
            on = self.keep_memory.get() == value
            style = 'ChoiceOn' if on else 'Choice'
            frame.configure(style=style + ('Focus' if focus is frame else '') + '.TFrame')
            head.configure(style='Accent.h3.TLabel' if on else 'Marble.h3.TLabel')
            body.configure(style='Accent.body.TLabel' if on else 'Marble.body.TLabel')

    def copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.set(tr('Адрес скопирован. Вставьте его в адресную строку браузера.'))

    def clear(self, frame):
        for child in frame.winfo_children():
            child.destroy()

    def reset_start(self, dry=False):
        if self.worker.busy:
            return
        self.stop_watch()
        if not dry and not self.server_done.get():
            self.ask(tr('Сначала сайт Claude'), tr('Выйдите из старого аккаунта на всех устройствах и поставьте отметку «Готово». '
                     'Без этого новый вход может связаться со старым.'))
            return
        keep = self.keep_memory.get() == 'keep'
        if self.session is None or self.session.keep_memory != keep:
            self.session = reset_flow.ResetSession(self.paths, keep_memory=keep)
        session = self.session
        self.run(lambda step: session.check(step), lambda result: self.reset_checked(result, dry))

    WATCH_MS, WATCH_LIMIT = 6000, 100  # about ten minutes of waiting for the person

    def watch_blockers(self, dry, keys, attempt=0):
        """While the person closes VS Code or a browser, check again now and then and continue by itself."""
        self.stop_watch()
        if attempt >= self.WATCH_LIMIT:
            return

        def again():
            self.watch = None
            if self.current != 'reset' or self.session is None:
                return
            if self.worker.busy:
                return self.watch_blockers(dry, keys, attempt + 1)
            session = self.session

            def seen(result):
                left = {b['key'] for b in result['blockers'] if b['kind'] == 'user'}
                if not left or left != keys:
                    self.reset_checked(result, dry)  # done, or something else changed: show it
                else:
                    self.watch_blockers(dry, keys, attempt + 1)
            self.run(lambda step: session.check(step), seen)
        self.watch = self.root.after(self.WATCH_MS, again)

    def stop_watch(self):
        if getattr(self, 'watch', None):
            try:
                self.root.after_cancel(self.watch)
            except tk.TclError:
                pass
        self.watch = None

    def reset_checked(self, result, dry):
        self.stop_watch()
        px = self.theme.px
        frame = self.reset_result
        self.clear(frame)
        card = self.card(frame)
        if result['nothing_found']:
            self.label(card, tr('Здесь пусто'), 'h2', bg='marble')
            self.label(card, tr('Данных Claude на этом компьютере не найдено. Начнём с нуля — переходите к прокси.'), bg='marble', pady=(px(6), px(16)))
            self.button(card, tr('Дальше: прокси и защита →'), lambda: self.show('proxy'), bg='marble').pack(anchor='w')
            return
        self.label(card, tr('Что найдено'), 'h3', bg='marble', pady=(0, px(10)))
        for row in result['rows']:
            line = ttk.Frame(card, style='Marble.TFrame')
            line.pack(fill='x', pady=px(2))
            ttk.Label(line, text=tr(row['label']), style='Marble.body.TLabel').pack(side='left')
            ttk.Label(line, text=sizes(row['size']) if row['status'] == 'present' else tr('не прочиталось'),
                      style='Marble.mono.TLabel').pack(side='right')
        if result['credentials']:
            self.label(card, tr('Сохранённые пароли Claude в Windows: {n}', n=result["credentials"]), bg='marble', pady=(px(2), 0))
        self.label(card, tr('Всего файлов на {size}', size=sizes(result["total"])), 'small', bg='marble', pady=(px(8), 0))
        auto = [b for b in result['blockers'] if b['kind'] == 'auto']
        ask = [b for b in result['blockers'] if b['kind'] == 'ask']
        user = [b for b in result['blockers'] if b['kind'] == 'user']
        if auto:
            self.label(card, tr('Программа сделает сама'), 'h3', bg='marble', pady=(px(18), px(6)))
            for b in auto:
                self.label(card, '•  ' + tr(b['text']), bg='marble')
        if user:
            self.label(card, tr('Нужно сделать вам'), 'h3', bg='marble', pady=(px(18), px(6)))
            for b in user:
                self.label(card, '•  ' + tr(b['text']), 'strong', bg='marble')
            buttons = ttk.Frame(card, style='Marble.TFrame')
            buttons.pack(anchor='w', pady=(px(14), 0))
            self.button(buttons, tr('Проверить снова'), lambda: self.reset_start(dry), bg='marble').pack(side='left')
            if any(b['key'] == 'restore_sources' for b in user):
                self.button(buttons, tr('Открыть автозагрузку'), self.open_startup, kind='Ghost', bg='marble').pack(side='left', padx=(px(10), 0))
            if any(b['key'] in ('inventory', 'cowork_location') for b in user):
                self.button(buttons, tr('Режим для специалистов'), self.open_expert, kind='Ghost', bg='marble').pack(side='left', padx=(px(10), 0))
            self.label(card, tr('Окно проверяет само каждые несколько секунд и продолжит, как только всё будет готово.'),
                       'small', bg='marble', pady=(px(10), 0))
            self.watch_blockers(dry, {b['key'] for b in user})
            return
        if dry:
            self.button(card, tr('Очистить'), lambda: self.reset_start(), bg='marble').pack(anchor='w', pady=(px(18), 0))
            return
        if ask and not self.session.accept_unlisted:
            if not self.confirm(tr('Непроверенная версия Claude'), tr('Эта версия Claude ещё не проверялась с программой. '
                                'Программа сотрёт те же папки, что и обычно, но новые места хранения, если версия их добавила, '
                                'не найдёт. Продолжить?'), tr('Продолжить'), no=tr('Не сейчас')):
                return
            self.session.accept_unlisted = True
            session = self.session
            self.run(lambda step: session.check(step), lambda r: self.reset_checked(r, dry))
            return
        self.reset_confirm(result, auto)

    def reset_confirm(self, result, auto):
        keep = self.session.keep_memory
        lines = [f'{tr(r["label"])} — {sizes(r["size"])}' for r in result['rows']]
        if result['credentials']:
            lines.append(tr('Сохранённые пароли Claude в Windows: {n}', n=result["credentials"]))
        if self.browsers.get():
            lines.append(tr('Вход на claude.ai в Chrome и Edge'))
        text = (tr('Это нельзя отменить. ') + (tr('Память Claude Code вернётся на место после очистки. ') if keep else tr('Ничего не сохранится. '))
                + (tr('Перед удалением программа закроет Claude и сохранит копии ваших файлов. ') if auto else '')
                + tr('Будет удалено:'))
        if not self.confirm(tr('Стереть данные Claude?'), text, tr('Стереть'), lines=lines, typed=tr('СТЕРЕТЬ')):
            return
        session, browsers = self.session, self.browsers.get()

        def job(step):
            checked = session.resolve(step) if auto else session.check(step)
            if checked['blockers']:
                return {'stage': 'blocked', 'check': checked}
            return {'stage': 'wiped', 'result': session.wipe('СТЕРЕТЬ', browsers=browsers, step=step)}
        self.run(job, self.reset_done)

    def reset_done(self, outcome):
        if outcome['stage'] == 'blocked':
            self.ask(tr('Остановились перед удалением'), tr('Не всё получилось сделать автоматически. Ничего не удалено. '
                     'Посмотрите, что осталось сделать, и нажмите «Проверить снова».'))
            self.reset_checked(outcome['check'], False)
            return
        result = outcome['result']
        px = self.theme.px
        self.clear(self.reset_result)
        card = self.card(self.reset_result)
        if result['status'] == 'failed':
            self.label(card, tr('Стирание остановилось'), 'h2', bg='marble')
            self.label(card, tr('Часть данных могла остаться. Копия памяти, если вы её сохраняли, не потеряна. '
                       'Нажмите «Проверить и очистить» ещё раз; если ошибка повторится — сохраните отчёт на странице «Помощь».'),
                       bg='marble', pady=(px(6), 0))
            return
        self.label(card, tr('Готово ✓') if result['no_files_left'] else tr('Почти готово'), 'h2', bg='marble')
        lines = [tr('Данные Claude стёрты. В проверенных папках ничего не осталось.') if result['no_files_left']
                 else tr('Данные стёрты, но в проверенных папках что-то осталось. Нажмите «Проверить и очистить» ещё раз.')]
        if result.get('memory') == 'restored_verbatim':
            lines.append(tr('Память Claude Code возвращена на место.'))
        if result.get('passwords_removed'):
            lines.append(tr('Удалено сохранённых паролей Claude: {n}.', n=result["passwords_removed"]))
        lines.append({'reset': tr('Ключ устройства Claude Desktop сброшен: Desktop увидит новое устройство.'),
                      'not_supported': tr('Ключ устройства Claude Desktop не сброшен: эта версия Desktop ещё не проверена. '
                                       'Desktop может узнать этот компьютер.'),
                      'failed': tr('Ключ устройства Claude Desktop не сброшен из-за ошибки.')}.get(result.get('desktop_keys'), ''))
        lines.append({'cleared': tr('Вы вышли из claude.ai в Chrome и Edge.'),
                      'browsers_open': tr('Chrome или Edge были открыты, поэтому вход на claude.ai там остался.'),
                      'failed': tr('Выйти из claude.ai в браузерах не получилось.')}.get(result.get('browsers'), ''))
        for line in filter(None, lines):
            self.label(card, line, bg='marble', pady=(px(4), 0))
        self.label(card, tr('Проверьте вручную'), 'h3', bg='marble', pady=(px(18), px(6)))
        for line in OUTSIDE:
            self.label(card, '•  ' + tr(line), 'small', bg='marble')
        buttons = ttk.Frame(card, style='Marble.TFrame')
        buttons.pack(anchor='w', pady=(px(18), 0))
        self.button(buttons, tr('Дальше: прокси и защита →'), lambda: self.show('proxy'), bg='marble').pack(side='left')
        if result.get('browsers') in ('browsers_open', 'failed'):
            self.button(buttons, tr('Выйти из claude.ai в браузерах'), self.clear_browsers, kind='Ghost', bg='marble').pack(side='left', padx=(px(10), 0))
        self.session = None

    def clear_browsers(self):
        if not self.confirm(tr('Выйти из claude.ai в браузерах?'), tr('Сначала закройте Chrome и Edge. Профили браузеров и другие сайты '
                            'не пострадают — удаляются только cookies и данные claude.ai.'), tr('Выйти'), typed=tr('СТЕРЕТЬ')):
            return
        actions = reset_flow.Actions(self.paths)
        self.run(lambda step: step('browsers', actions.clear_browsers), lambda r: self.ask(
            tr('Браузеры'), {'cleared': tr('Готово ✓ Вы вышли из claude.ai в Chrome и Edge.'),
                         'browsers_open': tr('Chrome или Edge ещё открыты. Закройте их полностью и повторите.')}.get(
                r, tr('Не получилось. Повторите после закрытия браузеров.'))))

    def open_startup(self):
        from .diagnostics import open_settings
        try:
            open_settings('startup')
        except Exception:
            self.ask(tr('Не открылось'), tr('Откройте вручную: Параметры Windows → Приложения → Автозагрузка.'))

    # ----- proxy -----
    def build_proxy(self, page):
        px = self.theme.px
        self.label(page, tr('ШАГ 2 · ПРОКСИ И ЗАЩИТА'), 'tag')
        self.label(page, tr('Прокси и защита'), 'h1', pady=(px(6), px(8)))
        self.label(page, tr('Защита пускает Claude в интернет только через ваш прокси. Остальные программы — браузер, игры, '
                   'Discord — работают как обычно.'), 'lead', pady=(0, px(24)))
        self.proxy_state = self.card(page, pady=(0, px(28)))
        self.label(page, tr('Ваш прокси'), 'h3', pady=(0, px(4)))
        self.form_hint = self.label(page, tr('Данные выдаёт ваш провайдер прокси. Пароль хранится только на этом компьютере в зашифрованном виде.'),
                                    'small', pady=(0, px(14)))
        self.proxy_kind = tk.StringVar(master=self.root, value='socks5')
        chips = ttk.Frame(page, style='Paper.TFrame')
        chips.pack(anchor='w', pady=(0, px(16)))
        self.chips = {}
        for value, label in (('socks5', 'SOCKS5'), ('http', 'HTTP'), ('vless', tr('VLESS — файл профиля'))):
            chip = ttk.Button(chips, text=label, command=lambda v=value: self.proxy_kind.set(v), style='Chip.Paper.TButton')
            chip.pack(side='left', padx=(0, px(8)))
            self.chips[value] = chip
        self.proxy_kind.trace_add('write', lambda *_: self.paint_form())
        self.fields = {k: tk.StringVar(master=self.root) for k in ('host', 'port', 'username', 'password')}
        self.form = ttk.Frame(page, style='Paper.TFrame')
        self.form.pack(fill='x')
        grid = ttk.Frame(self.form, style='Paper.TFrame')
        grid.pack(anchor='w')
        for index, (key, label, hint, width) in enumerate((
                ('host', tr('Адрес сервера'), tr('Например 203.0.113.10'), 22), ('port', tr('Порт'), tr('Например 1080'), 8),
                ('username', tr('Логин'), tr('Если выдан'), 18), ('password', tr('Пароль'), tr('Если выдан'), 18))):
            cell = ttk.Frame(grid, style='Paper.TFrame')
            cell.grid(row=index // 2, column=index % 2, sticky='w', padx=(0, px(20)), pady=(0, px(14)))
            ttk.Label(cell, text=label, style='Paper.strong.TLabel').pack(anchor='w')
            ttk.Entry(cell, textvariable=self.fields[key], style='Brand.TEntry', width=width, font=self.theme.fonts['field'],
                      show='•' if key == 'password' else '').pack(anchor='w', pady=(px(6), px(2)))
            ttk.Label(cell, text=hint, style='Paper.small.TLabel').pack(anchor='w')
        self.vless = ttk.Frame(page, style='Paper.TFrame')
        self.vless_file = tk.StringVar(master=self.root)
        self.vless_archive = tk.StringVar(master=self.root)
        for label, variable, title, types in ((tr('Файл профиля VLESS (.json)'), self.vless_file, tr('Профиль VLESS+Reality'), [('JSON', '*.json')]),
                                              (tr('Архив движка — если есть; иначе скачаем сами'), self.vless_archive, tr('Архив движка'), [('ZIP', '*.zip')])):
            line = ttk.Frame(self.vless, style='Paper.TFrame')
            line.pack(anchor='w', pady=(0, px(12)))
            ttk.Label(line, text=label, style='Paper.strong.TLabel').pack(anchor='w')
            row = ttk.Frame(line, style='Paper.TFrame')
            row.pack(anchor='w', pady=(px(6), 0))
            self.small_button(row, tr('Выбрать файл…'), lambda v=variable, t=title, f=types: v.set(
                filedialog.askopenfilename(title=t, filetypes=f) or v.get())).pack(side='left')
            ttk.Label(row, textvariable=variable, style='Paper.small.TLabel').pack(side='left', padx=(px(10), 0))
        self.form_end = ttk.Frame(page, style='Paper.TFrame')
        self.form_end.pack(fill='x')
        self.protect_extension = tk.BooleanVar(master=self.root, value=False)
        ttk.Checkbutton(self.form_end, text=tr('Также защищать Claude Code внутри VS Code'), variable=self.protect_extension,
                        style='Paper.TCheckbutton').pack(anchor='w', pady=(px(4), 0))
        self.label(self.form_end, tr('После включения перезагрузите окно VS Code: Ctrl+Shift+P → «Reload Window», '
                   'затем продолжите разговор командой /resume.'), 'small', pady=(px(2), px(20)))
        self.proxy_error = self.label(self.form_end, '', 'bad', pady=(0, px(10)))
        self.proxy_button = self.button(self.form_end, tr('Проверить и включить защиту'), self.proxy_go)
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
        if self.worker.busy:
            return
        self.run(lambda step: step('summary', lambda: proxy_flow.summary(self.paths)), self.paint_proxy)

    def paint_proxy(self, summary):
        px = self.theme.px
        self.protection = summary
        frame = self.proxy_state
        self.clear(frame)
        state = summary['state']
        head = ttk.Frame(frame, style='Marble.TFrame')
        head.pack(anchor='w')
        color = {'on': 'good', 'problem': 'bad', 'partial': 'bad', 'paused': 'graphite2'}.get(state, 'stone')
        ttk.Label(head, image=self.theme.image(f'dot-{color}', brand.dot(px(10), C[color], background=C['marble'])),
                  style='Marble.body.TLabel').pack(side='left')
        ttk.Label(head, text=tr(summary['title']), style='Marble.h2.TLabel').pack(side='left', padx=(px(12), 0))
        self.label(frame, tr(summary['text']), bg='marble', pady=(px(6), px(4)))
        if summary.get('proxy'):
            self.label(frame, tr('Прокси: {name}', name=summary["proxy"]), 'small', bg='marble')
        clients = ' · '.join(tr(c['name']) for c in summary['clients'] if c['present'])
        if clients and state != 'unknown':
            self.label(frame, (tr('Под защитой: ') if state == 'on' else tr('Найдены: ')) + clients, 'small', bg='marble')
        buttons = ttk.Frame(frame, style='Marble.TFrame')
        buttons.pack(anchor='w', pady=(px(16), 0))
        if summary.get('fix'):
            self.button(buttons, tr(proxy_flow.FIXES[summary['fix']]), lambda f=summary['fix']: self.proxy_fix(f), bg='marble').pack(side='left', padx=(0, px(10)))
        if state == 'on':
            self.button(buttons, tr('Проверить сейчас'), self.refresh_proxy, kind='Ghost', bg='marble').pack(side='left', padx=(0, px(10)))
            self.button(buttons, tr('Перезапустить'), lambda: self.proxy_fix('restart'), kind='Ghost', bg='marble').pack(side='left', padx=(0, px(10)))
        if state in ('on', 'problem', 'partial', 'paused'):
            self.button(buttons, tr('Выключить защиту'), self.protection_off, kind='Ghost', bg='marble').pack(side='left', padx=(0, px(10)))
        if state == 'unknown':
            self.button(buttons, tr('Обновить'), self.refresh_proxy, kind='Ghost', bg='marble').pack(side='left')
        if state == 'off' and summary.get('proxy_saved'):
            self.button(buttons, tr('Удалить сохранённый прокси'), self.backend_remove, kind='Ghost', bg='marble').pack(side='left')
        if state == 'on':
            extra = ttk.Frame(frame, style='Marble.TFrame')
            extra.pack(anchor='w', pady=(px(10), 0))
            self.button(extra, tr('Обновить защиту после обновления программы'), lambda: self.protection_install('reinstall'),
                        kind='Small', bg='marble').pack(side='left', padx=(0, px(10)))
            self.button(extra, tr('Применить выбор для VS Code'), self.extension_apply, kind='Small', bg='marble').pack(side='left')
        installed = state in ('on', 'problem')
        self.proxy_button.configure(text=tr('Проверить и применить новый прокси') if installed else tr('Проверить и включить защиту'))

    def proxy_go(self):
        self.proxy_error.configure(text='')
        if self.proxy_kind.get() == 'vless':
            return self.engine_go()
        values = {k: v.get().strip() if k in ('host', 'port') else v.get() for k, v in self.fields.items()}
        checked, error = proxy_flow.draft(self.proxy_kind.get(), values['host'], values['port'], values['username'], values['password'])
        if error:
            self.proxy_error.configure(text=tr(error))
            return
        self.run(lambda step: step('proxy_check', checked.check), lambda outcome: self.proxy_checked(checked, outcome))

    def proxy_checked(self, checked, outcome):
        if outcome.get('status') != 'proxy_checked':
            self.proxy_error.configure(text=tr(proxy_flow.message(outcome.get('status'))))
            return
        if not self.confirm_exit(checked):
            return
        if self.protection.get('state') in ('on', 'problem'):
            if self.confirm(tr('Применить новый прокси?'), tr('Защита перезапустится. Claude на несколько секунд останется без сети.'), tr('Применить')):
                self.run(lambda step: step('change', lambda: proxy_flow.connect(self.paths, checked, installed=True)), self.proxy_connected)
            return
        self.protection_install('install', checked)

    def confirm_exit(self, checked):
        address = checked.expected['expected_exit_ips'][0]
        return self.confirm(tr('Прокси работает ✓'), tr('Claude будет выходить в интернет с этого адреса. Он совпадает с тем, '
                            'что выдал ваш провайдер прокси?'), tr('Да, всё верно'), no=tr('Нет'), lines=[address])

    def protection_install(self, action, checked=None):
        from . import protection_panel

        def consent(limits):
            if not limits['known']:
                self.ask(tr('Нужна новая версия'), tr('Список того, что защита не закрывает, изменился. Включите защиту в «Режиме для специалистов».'))
                return
            title = tr('Перед включением') if action == 'install' else tr('Включить защиту заново?')
            text = (tr('Защита закрывает собственные соединения Claude. Вот что она не закрывает — это ограничения Windows, '
                    'а не ошибки. Windows попросит разрешение: нажмите «Да».'))
            if action == 'reinstall':
                text = tr('Программа поставит защиту текущей версии и включит её. ') + text
            if not self.confirm(title, text, tr('Включить защиту'), lines=limits['lines']):
                return
            extension = bool(self.protect_extension.get())
            if checked is not None:
                job = lambda step: step('install', lambda: proxy_flow.connect(self.paths, checked, installed=False,
                                                                                protect_extension=extension), uac=True)
            else:
                job = lambda step: {'text': step(action, lambda: protection_panel.perform(
                    self.paths, action, confirmed=True, protect_extension=extension), uac=True)['text'], 'ok': True}
            self.run(job, self.proxy_connected)
        self.run(lambda step: step('limits', lambda: protection_panel.limits(self.paths)), consent)

    def proxy_connected(self, result):
        self.ask(tr('Готово') if result.get('ok') else tr('Не получилось'), tr_text(result['text']))
        self.root.after(200, self.refresh_proxy)

    def engine_go(self):
        from .proxy_form import LocalBackendDraft, install_engine
        profile = self.vless_file.get()
        if not profile:
            self.proxy_error.configure(text=tr('Выберите файл профиля VLESS.'))
            return
        if self.protection.get('state') in ('on', 'problem'):
            self.ask(tr('Сначала выключите защиту'), tr('Чтобы перейти на VLESS, выключите защиту, затем установите профиль.'))
            return
        archive = self.vless_archive.get() or None
        checked = LocalBackendDraft(self.paths, first=True)

        def job(step):
            result = step('engine', lambda: install_engine(self.paths, Path(profile), Path(archive) if archive else None))
            if result['status'] not in ('engine_installed', 'engine_needs_attention'):
                return result
            return step('proxy_check', checked.check)
        self.run(job, lambda outcome: self.proxy_checked(checked, outcome))

    def proxy_fix(self, fix):
        from . import protection_panel
        if fix == 'reenter':
            self.status.set(tr('Введите данные прокси ниже и нажмите «Проверить и применить новый прокси».'))
            return
        if fix == 'install':
            return self.protection_install('install')
        if fix == 'resume':
            return self.protection_install('reinstall')
        if fix == 'restart':
            if self.confirm(tr('Перезапустить защиту?'), tr('Claude на несколько секунд останется без сети.'), tr('Перезапустить')):
                self.run(lambda step: {'text': step('restart', lambda: protection_panel.perform(
                    self.paths, 'restart', confirmed=True))['text'], 'ok': True}, self.proxy_connected)
            return

        def checked_again(pair):
            checked, info = pair
            if checked is None:
                self.ask(tr('Прокси не работает'), tr(info['text']) + tr(' Если не поможет — введите прокси заново ниже.'))
                return
            if info['same_exit']:
                self.run(lambda step: {'text': step('restart', lambda: protection_panel.perform(
                    self.paths, 'restart', confirmed=True))['text'], 'ok': True}, self.proxy_connected)
            elif self.confirm_exit(checked):
                self.run(lambda step: step('change', lambda: proxy_flow.connect(self.paths, checked, installed=True)), self.proxy_connected)
        self.run(lambda step: step('proxy_check', lambda: proxy_flow.recheck(self.paths)), checked_again)

    def protection_off(self):
        from . import protection_panel
        if self.confirm(tr('Выключить защиту?'), tr('Claude снова будет выходить в интернет напрямую, без прокси. '
                        'Сохранённый прокси и адрес выхода тоже будут удалены. Windows попросит разрешение.'), tr('Выключить')):
            self.run(lambda step: {'text': step('remove', lambda: protection_panel.perform(
                self.paths, 'remove', confirmed=True), uac=True)['text'], 'ok': True}, self.proxy_connected)

    def extension_apply(self):
        from . import protection_panel
        value = bool(self.protect_extension.get())
        text = (tr('Claude Code в VS Code тоже будет выходить только через прокси.') if value
                else tr('Claude Code в VS Code снова будет выходить напрямую.'))
        if self.confirm(tr('Применить выбор для VS Code?'), text + tr(' Сохраните работу: после применения перезагрузите окно VS Code '
                        '(Ctrl+Shift+P → «Reload Window») и продолжите командой /resume.'), tr('Применить')):
            self.run(lambda step: {'text': step('extension', lambda: protection_panel.perform(
                self.paths, 'extension', confirmed=True, protect_extension=value), uac=not value)['text'], 'ok': True},
                self.proxy_connected)

    def backend_remove(self):
        from .proxy_form import remove_backend
        if self.confirm(tr('Удалить сохранённый прокси?'), tr('Адрес, логин и пароль прокси будут удалены с этого компьютера.'), tr('Удалить')):
            self.run(lambda step: step('backend_remove', lambda: remove_backend(self.paths)),
                     lambda r: (self.ask(tr('Прокси'), tr(proxy_flow.message(r['status']))), self.refresh_proxy()))

    # ----- help -----
    def build_help(self, page):
        px = self.theme.px
        self.label(page, tr('ПОМОЩЬ'), 'tag')
        self.label(page, tr('Помощь'), 'h1', pady=(px(6), px(24)))
        for title, text, buttons in (
                (tr('Руководство'), tr('Пошагово: сброс, прокси, вход в новый аккаунт.'),
                 (('Primary', tr('Открыть руководство'), lambda: self.open_doc('guide')),)),
                (tr('Что-то не работает'), tr('Сохраните отчёт и отправьте тому, кто вам помогает. В отчёте нет паролей, '
                 'адресов прокси и имени пользователя.'), (('Primary', tr('Сохранить отчёт'), self.save_report),)),
                (tr('Язык и часовой пояс'), tr('Сайты сравнивают часовой пояс и язык компьютера со страной, из которой вы заходите. '
                 'Укажите страну вашего прокси: DE, TR или GB.'), ()),
                (tr('Ограничения и лицензии'), tr('Что защита не закрывает и чьи компоненты использует программа.'),
                 (('Ghost', tr('Ограничения'), lambda: self.open_doc('limits')), ('Ghost', tr('Лицензии'), lambda: self.open_doc('licenses'))))):
            card = self.card(page, pady=(0, px(16)))
            self.label(card, title, 'h3', bg='marble')
            self.label(card, text, bg='marble', pady=(px(6), px(14)))
            row = ttk.Frame(card, style='Marble.TFrame')
            row.pack(anchor='w')
            for kind, label, command in buttons:
                self.button(row, label, command, kind=kind, bg='marble').pack(side='left', padx=(0, px(10)))
            if title == tr('Язык и часовой пояс'):
                self.country = tk.StringVar(master=self.root)
                ttk.Entry(row, textvariable=self.country, style='Brand.TEntry', width=6, font=self.theme.fonts['field']).pack(side='left', padx=(0, px(10)))
                self.button(row, tr('Сравнить'), self.advice, kind='Small', bg='marble').pack(side='left', padx=(0, px(10)))
                self.button(row, tr('Настройки времени'), lambda: self.settings('timezone'), kind='Small', bg='marble').pack(side='left', padx=(0, px(10)))
                self.button(row, tr('Настройки языка'), lambda: self.settings('language'), kind='Small', bg='marble').pack(side='left')
                self.advice_text = self.label(card, '', 'small', bg='marble', pady=(px(10), 0))
        card = self.card(page, pady=(0, px(16)))
        self.label(card, tr('Оформление'), 'h3', bg='marble')
        self.label(card, tr('Тема и язык окна. Клавиши: Tab — следующая кнопка, Enter — нажать, Alt+1…4 — страницы.'),
                   bg='marble', pady=(px(6), px(14)))
        row = ttk.Frame(card, style='Marble.TFrame')
        row.pack(anchor='w')
        for value, label in (('system', tr('Как в Windows')), ('light', tr('Светлая')), ('dark', tr('Тёмная'))):
            style = 'ChipOn.Marble.TButton' if value == self.theme_choice else 'Chip.Marble.TButton'
            ttk.Button(row, text=label, style=style, command=lambda v=value: self.set_theme(v)).pack(side='left', padx=(0, px(8)))
        row = ttk.Frame(card, style='Marble.TFrame')
        row.pack(anchor='w', pady=(px(10), 0))
        # Language names are written in their own language so a person who cannot read the other one finds theirs.
        for value, label in (('ru', 'Русский'), ('en', 'English')):
            style = 'ChipOn.Marble.TButton' if value == self.language_choice else 'Chip.Marble.TButton'
            ttk.Button(row, text=label, style=style, command=lambda v=value: self.set_language_choice(v)).pack(side='left', padx=(0, px(8)))
        from .program_setup import installation
        if installation() is not None:
            card = self.card(page, pady=(0, px(16)))
            self.label(card, tr('Удалить программу'), 'h3', bg='marble')
            self.label(card, tr('Сначала выключит защиту, если она включена, затем удалит ClaudeReset, его ярлыки и запись '
                       'в «Приложениях». Сохранённые копии памяти останутся.'), bg='marble', pady=(px(6), px(14)))
            self.button(card, tr('Удалить ClaudeReset'), self.uninstall_program, kind='Ghost', bg='marble').pack(anchor='w')

    def uninstall_program(self):
        from . import program_setup
        self.show('help')

        def planned(plan):
            if not plan['installed']:
                self.ask(tr('Удаление'), tr('Эта копия не установлена установщиком. Чтобы убрать её, удалите её папку.'))
                return
            text = (tr('ClaudeReset будет удалён с компьютера. ')
                    + (tr('Сначала программа выключит защиту: Claude снова будет выходить в интернет напрямую, '
                       'а Windows попросит разрешение. ') if plan['protection'] else ''))
            lines = [tr('Ярлыки и запись в «Приложениях»'), tr('Папка программы')]
            if plan['archives']:
                text += tr('Копии памяти и отчёты останутся в папке ниже — удалите её сами, если они не нужны.')
            if not self.confirm(tr('Удалить ClaudeReset?'), text, tr('Удалить'), lines=lines + (
                    [plan['archives_folder']] if plan['archives'] else []), typed=tr('УДАЛИТЬ')):
                return
            self.run(lambda step: program_setup.uninstall(self.paths, step=step), finished, uac_steps=('remove',))

        def finished(result):
            if result['status'] == 'removed':
                self.ask(tr('ClaudeReset удалён'), tr('Окно закроется, папка программы удалится через несколько секунд.'))
                self.root.destroy()
            elif result['status'] == 'protection_not_removed':
                self.ask(tr('Удаление остановлено'), tr('Защиту выключить не удалось, поэтому программа не удалена: '
                         'иначе Claude мог остаться без сети. Попробуйте ещё раз или выключите защиту на шаге 2.'))
            else:
                self.ask(tr('Удаление'), tr('Эта копия не установлена установщиком. Чтобы убрать её, удалите её папку.'))
        self.run(lambda step: step('summary', lambda: program_setup.plan(self.paths)), planned)

    def open_doc(self, kind):
        from .help_docs import read_document
        from .ui_text import language
        try:
            title, content = read_document(kind, language())
            title = tr(title)
        except Exception:
            self.ask(tr('Справка недоступна'), tr('Файл справки не найден рядом с программой.'))
            return
        px = self.theme.px
        window = tk.Toplevel(self.root, background=C['paper'])
        window.title(title)
        window.geometry(f'{min(px(880), int(self.root.winfo_screenwidth() * .9))}x'
                        f'{min(px(700), int(self.root.winfo_screenheight() * .85))}')
        window.transient(self.root)
        foot = ttk.Frame(window, style='Paper.TFrame', padding=px(16))
        foot.pack(side='bottom', fill='x')
        ttk.Button(foot, text=tr('Закрыть'), command=window.destroy, style='Ghost.Paper.TButton').pack(side='right')
        bar = ttk.Scrollbar(window, orient='vertical', style='Brand.Vertical.TScrollbar')
        bar.pack(side='right', fill='y')
        text = tk.Text(window, wrap='word', font=self.theme.fonts['body'], background=C['paper'], foreground=C['graphite'],
                       relief='flat', padx=px(36), pady=px(28), spacing1=px(2), spacing3=px(4), highlightthickness=0,
                       selectbackground=C['accent'], selectforeground=C['on_accent'], yscrollcommand=bar.set,
                       cursor='arrow', insertwidth=0)
        bar.configure(command=text.yview)
        text.pack(fill='both', expand=True)
        self.render_markdown(text, content)
        text.configure(state='disabled')
        window.bind('<Escape>', lambda _e: window.destroy())
        text.focus_set()
        from . import ui_settings
        window.after(60, lambda: ui_settings.dark_title_bar(window, self.theme.mode == 'dark'))

    def render_markdown(self, text, content):
        from . import markdown_view
        px, fonts = self.theme.px, self.theme.fonts
        text.tag_configure('h1', font=fonts['h2'], foreground=C['ink'], spacing1=px(20), spacing3=px(10))
        text.tag_configure('h2', font=fonts['h3'], foreground=C['ink'], spacing1=px(18), spacing3=px(6))
        text.tag_configure('h3', font=fonts['strong'], foreground=C['ink'], spacing1=px(12), spacing3=px(4))
        text.tag_configure('para', spacing3=px(8))
        for depth in range(4):
            text.tag_configure(f'item{depth}', lmargin1=px(12 + 22 * depth), lmargin2=px(34 + 22 * depth), spacing3=px(4))
        text.tag_configure('block', font=fonts['mono'], background=C['mist'], lmargin1=px(16), lmargin2=px(16),
                           rmargin=px(16), spacing1=px(6), spacing3=px(10))
        text.tag_configure('bold', font=fonts['strong'], foreground=C['ink'])
        text.tag_configure('code', font=fonts['mono'], background=C['mist'])
        text.tag_configure('link', underline=True, foreground=C['ink'])
        text.tag_configure('rule', foreground=C['stone'], spacing1=px(8), spacing3=px(8))

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
        from .diagnostics import collect
        from .safeio import atomic_json

        def done(report):
            file = filedialog.asksaveasfilename(title=tr('Сохранить отчёт'), defaultextension='.json',
                                                initialfile='claudereset-report.json', filetypes=[('JSON', '*.json')])
            if file:
                from .public_view import redact
                path = Path(file)
                atomic_json(path, redact(report), path.parent)
                self.status.set(tr('Отчёт сохранён. В нём нет паролей, адресов прокси и имени пользователя.'))
        self.run(lambda step: step('report', lambda: collect(self.paths)), done)

    def advice(self):
        from .diagnostics import advise
        country = self.country.get()
        self.run(lambda step: step('advice', lambda: advise(country)), self.show_advice)

    def show_advice(self, result):
        text = tr(result.get('text', ''))
        if result.get('status') == 'compared':
            text += tr(' Пояс: ') + (tr('совпадает ✓') if result['timezone_matches'] else tr('не совпадает')) + tr('. Язык: ') + (
                tr('совпадает ✓') if result['language_matches'] else tr('не совпадает — это ваш выбор, менять не обязательно')) + '.'
        self.advice_text.configure(text=text)

    def settings(self, kind):
        from .diagnostics import open_settings
        try:
            open_settings(kind)
        except Exception:
            self.ask(tr('Не открылось'), tr('Откройте настройки Windows вручную.'))

    def mainloop(self):
        self.root.mainloop()


def run(paths, *, start=None):
    brand.enable_dpi_awareness()
    brand.register_fonts()
    Shell(paths, start=start).mainloop()
