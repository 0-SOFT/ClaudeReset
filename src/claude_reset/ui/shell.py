"""The ClaudeReset window: two actions — reset, then proxy — in the 0-soft brand.

No Windows logic here. This module is the frame: the theme, the side menu, page switching, background work and
questions. The pages are ui/pages (home, reset, proxy and protection, help); their buttons call reset_flow, proxy_flow
and the tested functions behind them. The specialist window (ui/expert_window.py with every tool) opens as a separate
process.
"""
import base64
import queue
import sys
import tkinter as tk
from pathlib import Path
from tkinter import font as tkfont
from tkinter import ttk
from types import MappingProxyType

from .. import config, layout
from ..model.status import ProtectionState
from ..network.probe import Probe
from ..services import reset as reset_service
from ..services.diagnostics import History
from ..services.protection import L1
from ..services.proxy import ProxyResult
from ..windows import display
from . import brand, protection_panel, proxy_flow
from .pages.help import HelpPage
from .pages.home import HomePage
from .pages.proxy import ProxyPage
from .pages.reset import ResetPage
from .text import Language, gui_message
from .worker import FINISHED, Phase, Worker

__all__ = ['Dialog', 'Program', 'STEPS', 'Shell', 'UAC_TEXT', 'expert_command', 'run']

STEPS = MappingProxyType({
    'check': 'Проверяем компьютер…', 'close_claude': 'Закрываем Claude…', 'stop_cowork': 'Останавливаем службу Cowork…',
    'export_cowork': 'Сохраняем копию работы Cowork…', 'archive_extras': 'Сохраняем копию ваших файлов Claude Code…',
    'desktop_keys': 'Сбрасываем ключ устройства Claude Desktop…', 'wipe': 'Стираем данные Claude…',
    'browsers': 'Выходим из claude.ai в Chrome и Edge…', 'proxy_check': 'Проверяем прокси: связь, вход и адрес выхода…',
    'engine': 'Устанавливаем движок VLESS…', 'limits': 'Готовим описание защиты…', 'install': 'Включаем защиту…',
    'change': 'Применяем новый прокси…', 'restart': 'Перезапускаем защиту…', 'remove': 'Выключаем защиту…',
    'reinstall': 'Обновляем защиту…', 'extension': 'Применяем выбор для VS Code…', 'summary': 'Проверяем состояние…',
    'report': 'Собираем отчёт…', 'advice': 'Сравниваем пояс и язык…', 'backend_remove': 'Удаляем сохранённый прокси…',
})
READ_ONLY = frozenset({'check', 'summary', 'limits', 'report', 'advice', 'proxy_check'})  # steps that only read
UAC_TEXT = 'Windows просит разрешение. Нажмите «Да» в окне запроса — без него защита не включится.'


def expert_command():
    """Command that opens the specialist window (every tool of the program) as its own process."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--expert']
    interpreter = Path(sys.executable)
    windowless = interpreter.with_name(config.PYTHONW)
    launcher = layout.SOURCE_DIR / 'launcher.py'
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
        self.colors = brand.PALETTES[self.mode]
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
        s, px, c = self.style, self.px, self.colors
        s.configure('.', background=c['paper'], foreground=c['graphite'], font=self.fonts['body'],
                    borderwidth=0, focuscolor=c['graphite'], troughcolor=c['mist'])
        for bg in ('paper', 'marble', 'mist', 'accent'):
            name = bg.capitalize()
            s.configure(f'{name}.TFrame', background=c[bg])
            for kind, color in self.COLORS.items():
                # Text on turquoise is always ink (#0e0e0e), in both themes.
                s.configure(f'{name}.{kind}.TLabel', background=c[bg], foreground=c['on_accent' if bg == 'accent' else color],
                            font=self.fonts[kind])
        self.panel('Card', c['marble'], c['haze'], 18)
        self.panel('Choice', c['marble'], c['haze'], 18)
        self.panel('ChoiceOn', c['accent'], None, 18)
        self.panel('ChoiceFocus', c['marble'], c['ink'], 18, ring_width=2)
        self.panel('ChoiceOnFocus', c['accent'], c['on_accent'], 18, ring_width=2)
        self.panel('Notice', c['mist'], None, 14)
        dark, on = c['on_accent'], c['accent']
        for bg in ('paper', 'marble', 'mist'):
            # Focus: a 2 px ring in the text colour (on ink buttons the turquoise, which has 11:1 contrast there).
            self.pill('Primary', bg, 48, 'button', 22, c['paper'], {
                '': (c['ink'], None), 'active': (on, None), 'pressed': (on, c['graphite']),
                'disabled': (c['stone'], None), 'focus': (c['ink'], on)},
                {'active': dark, 'pressed': dark, 'disabled': c['marble']})
            self.pill('Ghost', bg, 48, 'button', 22, c['ink'], {
                '': (None, c['graphite']), 'active': (None, on), 'pressed': (on, None),
                'disabled': (None, c['stone']), 'focus': (None, c['ink'])}, {'pressed': dark, 'disabled': c['stone']})
            self.pill('Small', bg, 40, 'button_sm', 16, c['ink'], {
                '': (None, c['graphite']), 'active': (None, on), 'pressed': (on, None),
                'disabled': (None, c['stone']), 'focus': (None, c['ink'])}, {'pressed': dark, 'disabled': c['stone']})
            self.pill('Chip', bg, 40, 'button_sm', 16, c['graphite'], {
                '': (c['marble'], c['haze']), 'active': (c['marble'], c['stone']), 'pressed': (on, None),
                'focus': (c['marble'], c['ink'])}, {'active': c['ink'], 'pressed': dark})
            self.pill('ChipOn', bg, 40, 'button_sm', 16, dark, {'': (on, None), 'focus': (on, dark)}, {})
            self.check(bg)
        s.configure('Nav.TButton', background=c['mist'], foreground=c['graphite2'], font=self.fonts['nav'],
                    padding=(px(14), px(10)), anchor='w', relief='flat', bordercolor=c['mist'],
                    lightcolor=c['mist'], darkcolor=c['mist'])
        s.map('Nav.TButton', background=[('active', c['mist'])], foreground=[('active', c['ink'])])
        s.configure('NavOn.TButton', background=c['mist'], foreground=c['ink'], font=self.fonts['nav'],
                    padding=(px(14), px(10)), anchor='w', relief='flat', bordercolor=c['mist'],
                    lightcolor=c['mist'], darkcolor=c['mist'])
        s.map('NavOn.TButton', background=[('active', c['mist'])])
        s.configure('Brand.TEntry', fieldbackground=c['marble'], foreground=c['ink'], bordercolor=c['stone'],
                    lightcolor=c['marble'], darkcolor=c['marble'], insertcolor=c['ink'], padding=(px(12), px(9)),
                    selectbackground=c['accent'], selectforeground=c['on_accent'], font=self.fonts['field'])
        s.map('Brand.TEntry', bordercolor=[('focus', c['graphite'])], lightcolor=[('focus', c['marble'])])
        s.configure('Brand.Horizontal.TProgressbar', troughcolor=c['mist'], background=c['accent'],
                    bordercolor=c['mist'], lightcolor=c['accent'], darkcolor=c['accent'], thickness=px(4))
        s.configure('Idle.Horizontal.TProgressbar', troughcolor=c['paper'], background=c['paper'],
                    bordercolor=c['paper'], lightcolor=c['paper'], darkcolor=c['paper'], thickness=px(4))
        s.layout('Brand.Vertical.TScrollbar', [('Vertical.Scrollbar.trough', {'sticky': 'ns', 'children': [
            ('Vertical.Scrollbar.thumb', {'expand': '1', 'sticky': 'nswe'})]})])
        s.configure('Brand.Vertical.TScrollbar', troughcolor=c['paper'], background=c['haze'], bordercolor=c['paper'],
                    lightcolor=c['haze'], darkcolor=c['haze'], gripcount=0, width=px(10), arrowsize=px(10))
        s.map('Brand.Vertical.TScrollbar', background=[('active', c['stone'])])

    def panel(self, name, fill, ring, radius, ring_width=1.0):
        r = self.px(radius)
        size = 2 * r + 128  # ttk tiles the centre: a large centre keeps redraws cheap
        image = self.image(f'panel-{name}', brand.rounded(size, size, r, fill=fill, ring=ring,
                                                          ring_width=ring_width * self.scale,
                                                          background=self.colors['paper']))
        element = self.element(f'{name}.panel', image, border=r, sticky='nsew', padding=0)
        self.style.layout(f'{name}.TFrame', [(element, {'sticky': 'nsew'})])
        self.style.configure(f'{name}.TFrame', background=fill)

    def pill(self, name, bg, height, font, pad, color, states, colors):
        h = self.px(height)
        r = h // 2
        ring = max(1.0, self.scale)
        images = {state: self.image(f'pill-{name}-{bg}-{state}', brand.rounded(
            h + 64, h, r, fill=fill, ring=edge, ring_width=ring * (2 if state == 'focus' else 1),
            background=self.colors[bg]))
            for state, (fill, edge) in states.items()}
        spec = [images['']] + [(state, images[state]) for state in ('disabled', 'pressed', 'active', 'focus') if state in images]
        if len(spec) == 1:
            spec.append(('disabled', images['']))  # Tk needs at least one state map entry
        element = self.element(f'{name}.{bg}.pill', *spec, border=(r, r - 1, r, r - 1), sticky='nsew', padding=0)
        style = f'{name}.{bg.capitalize()}.TButton'
        self.style.layout(style, [(element, {'sticky': 'nsew', 'children': [('Button.padding', {
            'sticky': 'nsew', 'children': [('Button.label', {'sticky': 'nsew'})]})]})])
        self.style.configure(style, padding=(self.px(pad), self.px(4)), font=self.fonts[font], foreground=color,
                             background=self.colors[bg], anchor='center')
        self.style.map(style, foreground=[(state, value) for state, value in colors.items()])

    def check(self, bg):
        size, gap, c = self.px(22), self.px(12), self.colors
        colours = dict(box=c['marble'], ring=c['stone'], on=c['accent'], mark_color=c['on_accent'], background=c[bg], gap=gap)
        off = self.image(f'check-off-{bg}', brand.checkbox(size, False, **colours))
        on = self.image(f'check-on-{bg}', brand.checkbox(size, True, **colours))
        element = self.element(f'Brand.{bg}.indicator', off, ('selected', on), sticky='')
        style = f'{bg.capitalize()}.TCheckbutton'
        self.style.layout(style, [('Checkbutton.padding', {'sticky': 'nsew', 'children': [
            (element, {'side': 'left', 'sticky': ''}), ('Checkbutton.label', {'side': 'left', 'sticky': 'nsew'})]})])
        self.style.configure(style, background=c[bg], foreground=c['graphite'], font=self.fonts['body'], padding=(0, self.px(4)))
        # Keyboard focus: the label is underlined and in the text colour.
        self.style.map(style, background=[('active', c[bg])], foreground=[('focus', c['ink']), ('active', c['ink'])],
                       font=[('focus', self.fonts['body_focus'])])


class Scroll(ttk.Frame):
    """A vertically scrolling page; the inner frame follows the window width."""

    def __init__(self, master, theme):
        super().__init__(master, style='Paper.TFrame')
        self.canvas = tk.Canvas(self, background=theme.colors['paper'], highlightthickness=0, borderwidth=0)
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

    def __init__(self, shell, title, text, *,
                 buttons=None,   # None: one primary button saying "understood" in the shell's language
                 lines=(), typed=None):
        theme, px = shell.theme, shell.theme.px
        super().__init__(shell.root, background=theme.colors['paper'])
        self.dark = theme.mode == 'dark'
        buttons = (('Primary', shell.tr('Понятно'), True),) if buttons is None else buttons
        self.result = None
        self.withdraw()
        self.title(config.PRODUCT_NAME)
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
                ttk.Label(box, text='•  ' + shell.tr_text(line), style='Mist.body.TLabel', wraplength=width - px(40), justify='left').pack(anchor='w', pady=px(2))
        self.entry = None
        row = ttk.Frame(body, style='Paper.TFrame')
        primary = []
        if typed:
            ttk.Label(body, text=shell.tr('Чтобы подтвердить, введите {word}', word=typed), style='Paper.small.TLabel').pack(anchor='w', pady=(px(18), px(6)))
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
        from . import settings as ui_settings
        self.deiconify()
        ui_settings.dark_title_bar(self, self.dark)
        self.grab_set()
        (self.entry or self.first or self).focus_set()
        self.wait_window()
        return self.result


class Program:
    """What the main window asks of the rest of the program: its reads, the reset session, the proxy checks and
    the protection operations. The port tests replace with one that has scripted parts."""

    def __init__(self, *, probe: Probe = Probe(), l1: L1 = L1()) -> None:
        # probe: the network checks of a proxy draft; l1: the L1 checks and operations behind the protection card.
        self.probe, self.l1 = probe, l1

    def history(self, paths) -> History:
        from ..services.diagnostics import operation_history
        return operation_history(paths)

    def protection(self, paths) -> dict:
        return proxy_flow.summary(paths)

    def reset(self, paths, *, keep_memory: bool) -> reset_service.ResetSession:
        return reset_service.ResetSession(paths, keep_memory=keep_memory)

    def check_saved(self, paths) -> tuple[object, ProxyResult]:
        from ..services.proxy import check_saved
        return check_saved(paths, probe=self.probe)

    def limits(self, paths) -> dict:
        return protection_panel.limits(paths, l1=self.l1)

    def perform(self, paths, action: str, **options: object) -> dict:
        return protection_panel.perform(paths, action, l1=self.l1, **options)


class Shell:
    """The frame of the main window: the side menu, the page switching, the status bar and what every page shares —
    texts in the window's language, the theme, background work and questions. Each page is its own object
    (ui/pages); it is built on a frame the shell gives it and built again when the theme or language changes."""

    def __init__(self, paths,
                 root=None, *,   # None: a new Tk root window
                 start=None,
                 theme=None,   # None: the theme saved in paths
                 language=None,   # None: the language saved in paths
                 program=Program()):
        from . import settings as ui_settings
        self.paths = paths
        self.program = program
        self.root = root or tk.Tk()
        self.language = Language.of(language or ui_settings.language(paths))
        self.theme_choice = theme or ui_settings.theme(paths)
        self.theme = Theme(self.root, ui_settings.resolve(self.theme_choice))
        px = self.theme.px
        self.root.title(config.PRODUCT_NAME)
        # The window fits the screen at any display scale; the layout scrolls and wraps inside.
        width = min(px(1160), int(self.root.winfo_screenwidth() * .92))
        height = min(px(800), int(self.root.winfo_screenheight() * .88))
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(min(px(980), width), min(px(660), height))
        try:
            self.root.iconphoto(True, self.theme.image('icon-64', brand.app_icon(64)),
                                self.theme.image('icon-32', brand.app_icon(32)))
        except tk.TclError:
            pass
        self.worker, self.operation, self.callback, self.step_text = Worker(), None, None, ''
        self.waiting_uac = self.changing = False
        self.protection = {'state': ProtectionState.UNKNOWN}
        self.current = 'home'
        self.ask = self.dialog  # tests replace this to answer questions
        self.wrapped, self.fitting = {}, set()
        self.home_page, self.reset_page = HomePage(self), ResetPage(self)
        self.proxy_page, self.help_page = ProxyPage(self), HelpPage(self)
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
            self.root.after(500, self.help_page.uninstall_program)

    def dress(self):
        from . import settings as ui_settings
        self.root.configure(background=self.theme.colors['paper'])
        self.root.after(60, lambda: ui_settings.dark_title_bar(self.root, self.theme.mode == 'dark'))

    # Texts in the window's language (self.language), which its parts receive from here.
    def tr(self, text, **values):
        return self.language.tr(text, **values)

    def tr_text(self, text):
        return self.language.tr_text(text)

    def sizes(self, text):
        return self.language.sizes(text)

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
        from . import settings as ui_settings
        if self.worker.busy:
            self.status.set(self.tr('Тема сменится после текущего действия: выберите её ещё раз.'))
            return
        try:
            ui_settings.save_theme(self.paths, choice)
        except (OSError, ValueError):
            pass
        self.theme_choice = choice
        self.rebuild()

    def set_language_choice(self, choice):
        """Remember the language and rebuild the window in it; not while an action runs."""
        from . import settings as ui_settings
        if self.worker.busy:
            self.status.set(self.tr('Язык сменится после текущего действия: выберите его ещё раз.'))
            return
        try:
            ui_settings.save_language(self.paths, choice)
        except (OSError, ValueError):
            pass
        self.language = Language.of(choice)
        self.rebuild()

    def rebuild(self):
        from . import settings as ui_settings
        current = self.current
        for child in self.root.winfo_children():
            child.destroy()
        self.wrapped, self.fitting = {}, set()
        self.theme = Theme(self.root, ui_settings.resolve(self.theme_choice))
        self.dress()
        self.build()
        self.show(current)

    # ----- frame -----
    def build(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.build_side()
        px = self.theme.px
        main = ttk.Frame(self.root, style='Paper.TFrame')
        main.grid(row=0, column=1, sticky='nsew')
        main.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        self.pages = {}
        for key, page in (('home', self.home_page), ('reset', self.reset_page), ('proxy', self.proxy_page),
                          ('help', self.help_page)):
            scroll = Scroll(main, self.theme)
            scroll.grid(row=0, column=0, sticky='nsew')
            page.build(scroll.inner)
            self.pages[key] = scroll
        bar = ttk.Frame(main, style='Paper.TFrame', padding=(px(48), px(10), px(48), px(14)))
        bar.grid(row=1, column=0, sticky='ew')
        self.progress = ttk.Progressbar(bar, mode='determinate', value=0, style='Idle.Horizontal.TProgressbar')
        self.progress.pack(fill='x')
        status_row = ttk.Frame(bar, style='Paper.TFrame')
        status_row.pack(fill='x', pady=(px(8), 0))
        self.status = tk.StringVar(master=self.root, value=self.tr('Готово к работе. Открытие окна ничего не меняет.'))
        ttk.Label(status_row, textvariable=self.status, style='Paper.small.TLabel').pack(side='left')
        self.cancel_button = self.small_button(status_row, self.tr('Остановить'), self.cancel, bg='paper')

    def build_side(self):
        """The side menu: the brand, the other language, the pages and the way to the specialist window."""
        px, colors = self.theme.px, self.theme.colors
        side = ttk.Frame(self.root, style='Mist.TFrame', padding=(px(20), px(28), px(20), px(20)), width=px(268))
        side.grid(row=0, column=0, sticky='ns')
        side.grid_propagate(False)
        side.pack_propagate(False)
        head = ttk.Frame(side, style='Mist.TFrame')
        head.pack(anchor='w', fill='x', padx=px(8))
        # The left zero takes the theme's text colour, the right one is always turquoise.
        mark = self.theme.image('mark', brand.mark(px(26), left=colors['ink'], background=colors['mist']))
        ttk.Label(head, image=mark, style='Mist.body.TLabel').pack(side='left')
        ttk.Label(head, text=config.PRODUCT_NAME, style='Mist.brand.TLabel').pack(side='left', padx=(px(10), 0))
        ttk.Label(side, text=self.tr('0-SOFT · НАЧНЁМ С НУЛЯ'), style='Mist.tag.TLabel').pack(anchor='w', padx=px(8),
                                                                                           pady=(px(6), px(14)))
        # The other language, in capitals so it is found at once; Russian is the default.
        other = ('en', 'ENGLISH') if self.language.code == 'ru' else ('ru', 'РУССКИЙ')
        self.language_button = self.small_button(side, other[1], lambda: self.set_language_choice(other[0]), bg='mist')
        self.language_button.pack(anchor='w', padx=px(8), pady=(0, px(22)))
        lens_on = self.theme.image('lens-on', brand.lens(px(15), background=colors['mist']))
        lens_off = self.theme.image('lens-off', brand.rounded(lens_on.width(), lens_on.height(), 1,
                                                              background=colors['mist']))
        self.lens = (lens_on, lens_off)
        self.nav = {}
        for key, label in (('home', self.tr('Главная')), ('reset', self.tr('Шаг 1 · Сброс')),
                           ('proxy', self.tr('Шаг 2 · Прокси и защита')), ('help', self.tr('Помощь'))):
            button = ttk.Button(side, text=label, style='Nav.TButton', image=lens_off, compound='left',
                                command=lambda k=key: self.show(k), takefocus=True)
            button.pack(anchor='w', fill='x')
            self.nav[key] = button
        bottom = ttk.Frame(side, style='Mist.TFrame')
        bottom.pack(side='bottom', fill='x', padx=px(8))
        ttk.Label(bottom, text=self.tr('Все инструменты программы — для тех, кто знает, что делает.'),
                  style='Mist.small.TLabel', wraplength=px(210), justify='left').pack(anchor='w', pady=(0, px(8)))
        self.small_button(bottom, self.tr('Режим для специалистов'), self.open_expert, bg='mist').pack(anchor='w')

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

    def clear(self, frame):
        for child in frame.winfo_children():
            child.destroy()

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
            self.home_page.refresh_home()
        elif key == 'proxy':
            self.proxy_page.refresh_proxy()

    # ----- background work -----
    def run(self, job, done, *, uac_steps=()):
        """job(step) runs in the background; step(label, fn) shows progress; done(result) runs in the window."""
        if self.worker.busy:
            self.status.set(self.tr('Подождите: предыдущее действие ещё выполняется.'))
            return False

        def action(context):
            def step(label, fn, uac=False):
                self.step_text = self.tr(STEPS.get(label, 'Выполняем…'))
                self.changing = self.changing or label not in READ_ONLY
                return context.step(fn, waiting_uac=uac or label in uac_steps)
            return job(step)
        self.callback = done
        self.changing = False
        self.step_text = self.tr('Выполняем…')
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
                self.waiting_uac = event.state == Phase.WAITING_UAC
                if event.state == Phase.WAITING_UAC:
                    self.status.set(self.tr(UAC_TEXT))
                elif event.state in (Phase.RUNNING, Phase.QUEUED):
                    self.status.set(self.step_text or self.tr('Выполняем…'))
                if event.cancellable:
                    self.cancel_button.pack(side='right')
                else:
                    self.cancel_button.pack_forget()
                if event.state in FINISHED:
                    result = self.worker.take_result(event.operation)
                    callback, self.callback, self.operation = self.callback, None, None
                    self.progress.stop()
                    self.progress.configure(mode='determinate', value=0, style='Idle.Horizontal.TProgressbar')
                    self.cancel_button.pack_forget()
                    self.waiting_uac = False
                    if event.state == Phase.COMPLETED:
                        self.status.set(self.tr('Готово.'))
                        try:
                            callback(result)
                        except Exception:
                            self.status.set(self.tr(gui_message('callback_failed')))
                    elif event.state == Phase.CANCELLED:
                        self.status.set(self.tr(gui_message('cancelled')))
                    else:
                        self.status.set(self.tr('Не получилось.'))
                        self.ask(self.tr('Не получилось'),
                                 self.tr('Действие остановилось с ошибкой. Ничего не повторялось автоматически. '
                                         'Проверьте состояние ещё раз; если ошибка повторится — сохраните отчёт на '
                                         'странице «Помощь».'))
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.poll)

    def cancel(self):
        if not self.worker.cancel():
            self.status.set(self.tr(gui_message('cancel_unavailable')))

    def dialog(self, title, text, buttons=None, lines=(), typed=None):
        return Dialog(self, title, text, buttons=buttons, lines=lines, typed=typed).show()

    def confirm(self, title, text, yes, *,
                no=None,   # None: "cancel" in the window's language
                lines=(), typed=None):
        no = self.tr('Отмена') if no is None else no
        return bool(self.ask(title, text, (('Primary', yes, True), ('Ghost', no, None)), lines, typed))

    def close(self):
        # Reading the state can simply stop; only an action that changes something asks first.
        if self.worker.busy and (self.changing or self.waiting_uac):
            text = self.tr(gui_message('uac_close_unknown')) if self.waiting_uac else \
                self.tr('Действие ещё выполняется. Если закрыть окно, оно продолжится без вас, а результат придётся '
                        'проверить заново.')
            if not self.confirm(self.tr('Закрыть окно?'), text, self.tr('Закрыть'), no=self.tr('Остаться')):
                return
        self.root.destroy()

    def open_expert(self):
        try:
            display.start_program(expert_command(), layout.SOURCE_DIR)
            self.status.set(self.tr('Режим для специалистов открывается в отдельном окне.'))
        except OSError:
            self.ask(self.tr('Не открылось'),
                     self.tr('Не удалось открыть режим для специалистов. Запустите ClaudeReset.cmd ещё раз.'))

    def mainloop(self):
        self.root.mainloop()


def run(paths, *, start=None):
    brand.enable_dpi_awareness()
    brand.register_fonts()
    Shell(paths, start=start).mainloop()
