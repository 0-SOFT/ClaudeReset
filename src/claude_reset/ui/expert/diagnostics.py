"""The diagnostics tab of the specialist window: local checks and reports without secrets, the time zone and language
advice and the Windows settings it points to."""
import tkinter as tk
from pathlib import Path
from tkinter import ttk

__all__ = ['DiagnosticsTab']


class DiagnosticsTab:
    """Read-only reports: statuses and counts, never addresses, names or error texts."""

    def __init__(self, app):
        self.app = app

    def build(self, diagnostics_page):
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

    def run_diagnostics(self):
        app = self.app
        app.run(lambda: app.diagnostics.collect(app.paths).to_json(), app.show_json)

    def show_operation_history(self):
        app = self.app
        app.run(lambda: app.diagnostics.operation_history(app.paths).to_json(), app.show_json)

    def show_privacy_observations(self):
        from ...privacy.observations import summarize
        app = self.app
        path = app.dialogs.askopenfilename(title='Сохранённый журнал назначений реле (до 64 КиБ)',
                                           filetypes=[('Журнал JSONL', '*.jsonl')])
        if path:
            app.run(lambda: summarize(Path(path)), app.show_json)

    def run_advisor(self):
        app = self.app
        country = self.advisor_country.get()
        app.run(lambda: app.diagnostics.advise(country).to_json(), app.show_json)

    def open_advisor_settings(self, kind):
        app = self.app
        app.safe(lambda: app.diagnostics.open_settings(kind))
