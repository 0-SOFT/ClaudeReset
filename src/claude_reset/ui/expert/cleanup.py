"""The cleanup tab of the specialist window: preview, wipe and audit of a cleanup mode, what blocks it, the Cowork
export it needs and the browsers' Claude site data."""
import tkinter as tk
from tkinter import ttk
from types import MappingProxyType

from ...model import clients
from ...model.confirmation import Confirmation
from ...model.status import Export, Reset

__all__ = ['CleanupTab', 'WIPE_BLOCKERS', 'WIPE_MODES']

# What the specialist window says about each cleanup blocker and mode.
WIPE_BLOCKERS = MappingProxyType({
    'processes': 'Закройте Claude и сеанс расширения; общий редактор автоматически не закрывается.',
    'extra_entries': 'Архивируйте и удалите дополнительные записи Code.',
    'unlisted_version': 'Версия не проверена: требуется явное согласие на фиксированную область.',
    'inventory': 'Не удалось проверить расположения: устраните ссылки или ошибку доступа.',
    'restore_sources': 'Отключите восстановление старого состояния перед очисткой.',
    'cowork_service': 'Служба Cowork должна быть остановлена перед стиранием.',
    'cowork_export': 'Нужен проверенный экспорт работы Cowork; затем повторите предпросмотр.',
    'cowork_location': 'Работа Cowork найдена вне поддержанного профиля экспорта. Стирание заблокировано; нужен '
                       'адаптер этого расположения.',
})
WIPE_MODES = MappingProxyType({
    'reset_memory': 'Сброс, сохранив память',
    'wipe': 'Стереть всё',
    'wipe_memory': 'Стереть всё, сохранив память',
})


class CleanupTab:
    """A cleanup mode is previewed into a wipe plan, its blockers are resolved, then it is wiped after the word.

    The plan and the Cowork export it relies on live here; a change of mode or a resolved blocker drops the plan."""

    def __init__(self, app):
        self.app = app
        self.wipe_plan = None
        self.cleanup_accept_unlisted = False
        self.cleanup_cowork_export = None

    def build(self, page):
        app = self.app
        self.cleanup_mode = tk.StringVar(value='reset_memory')
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
        for label, action in [('Устранить: дополнительные записи', app.policy_tab.plan_customizations),
                              ('Применить удаление записей', app.policy_tab.apply_customizations),
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
        ttk.Button(sites, text='Удалить cookies и IndexedDB Claude',
                   command=self.clear_browser_sites).pack(side='left', padx=6)
        ttk.Button(sites, text='Проекты и среды: границы отчёта', command=self.report_external_scope).pack(side='left')
        ttk.Button(page, text='Остальные данные сайта: выбрать профиль и открыть настройки',
                   command=self.browser_site_settings).pack(anchor='w')
        keys = ttk.Frame(page)
        keys.pack(fill='x', pady=4)
        for label, action in [('План ключей Desktop', app.settings_tab.plan_desktop_keys),
                              ('Применить план ключей', app.settings_tab.apply_desktop_keys),
                              ('Проверить новый ключ', app.settings_tab.verify_desktop_key)]:
            ttk.Button(keys, text=label, command=action).pack(side='left', padx=3)
        ttk.Label(page, text='Ключи: сначала отдельный план и сброс, затем файловое стирание. Только проверенная '
                  'версия MSIX. Браузеры: общий Local Storage и кэш остаются для ручной очистки.',
                  wraplength=930).pack(anchor='w')
        self.cleanup_text = tk.Text(page, wrap='word', height=18)
        self.cleanup_text.pack(fill='both', expand=True, pady=8)
        self.cleanup_text.insert('1.0', 'Предпросмотр ничего не удаляет. Для стирания нужен свежий план и слово '
                                 'СТЕРЕТЬ. Память Cowork экспортируется отдельно.')
        self.cleanup_text.configure(state='disabled')

    def preview_browser_sites(self):
        app = self.app
        app.run(lambda: app.browser_sites.site_data(app.paths), app.show_json)

    def browser_site_settings(self):
        app = self.app
        if app.busy:
            return

        def choose(rows):
            app.show_json({'profiles': rows, 'status': Reset.MANUAL_ACTION_REQUIRED})
            if not rows:
                return
            choices = '\n'.join(f"{row['profile_number']}: {row['browser']}" for row in rows)
            number = app.dialogs.askinteger('Данные сайта — ручной шаг',
                                            choices + '\nВведите номер профиля. Откроются настройки; само открытие '
                                            'ничего не очищает.',
                                            minvalue=1, maxvalue=len(rows))
            if number is not None:
                app.run(lambda: app.browser_sites.open_site_settings(app.paths, number), app.show_json)
        app.run(lambda: app.browser_sites.manual_cleanup_profiles(app.paths), choose)

    def clear_browser_sites(self):
        app = self.app
        if app.busy:
            return
        word = app.dialogs.askstring('Данные сайтов Claude',
                                     'Закройте Chrome и Edge. Во всех стандартных профилях будут удалены cookies '
                                     'claude.ai и IndexedDB https://claude.ai. Общие хранилища и кэш требуют ручной '
                                     'очистки. Профили сохранятся. Введите СТЕРЕТЬ:')
        if word == 'СТЕРЕТЬ':
            app.run(lambda: app.browser_sites.site_data(app.paths, erase=True, confirmation=Confirmation.ERASE),
                    app.show_json)

    def report_external_scope(self):
        from ...reset.browser_sites import external_scope_report
        self.app.run(external_scope_report, self.app.show_json)

    def cleanup_preview(self):
        app = self.app
        mode = self.cleanup_mode.get()
        if mode == 'reset_memory':
            app.tabs.select(app.analysis_tab.page)
            app.analysis_tab.analyze()
            return
        self.wipe_plan = None
        accepted = self.cleanup_accept_unlisted
        export = self.cleanup_cowork_export

        def work():
            plan = app.cleanup.prepare_wipe(app.paths, mode, accept_unlisted=accepted, cowork_export=export)
            result = app.cleanup.preview(app.paths, mode)
            result['credential_count'] = len(plan.credentials)
            return plan, result

        def ready(value):
            plan, result = value
            if self.cleanup_mode.get() != mode:
                return
            self.wipe_plan = plan
            result['blockers'] = plan.blockers
            self.show_cleanup(result)
        app.run(work, ready)

    def cleanup_accept_version(self):
        app = self.app
        if app.busy:
            return
        if app.dialogs.askyesno('Непроверенная версия',
                                'Разрешить стирание фиксированных каталогов для непроверенной версии? '
                                'Данные вне списка не проверены. Выбор будет записан в отчёт.'):
            self.cleanup_accept_unlisted = True
            self.cleanup_preview()

    def cleanup_close_processes(self):
        self.cleanup_resolve(lambda: self.app.cleanup_actions.resolve_processes(clients.CLOSABLE_APPS),
                             'Закрыть процессы Claude? Несохранённые данные могут быть потеряны. '
                             'Общий редактор и текущий исполнитель сохраняются; дочерние инструменты могут потребовать '
                             'ручного закрытия.')

    def cleanup_stop_service(self):
        self.cleanup_resolve(self.app.cleanup_actions.resolve_service,
                             'Остановить службу Cowork? Сначала сохраните работу. '
                             'При отказе доступа потребуется отдельная остановка владельцем с правами администратора.')

    def cleanup_resolve(self, action, question):
        app = self.app
        if app.busy or not app.dialogs.askyesno('Устранение блокировки', question) or app.busy:
            return
        self.wipe_plan = None
        app.invalidate()

        def done(result):
            app.show_json(result)
            self.cleanup_preview()
        app.run(action, done)

    def cleanup_apply(self):
        app = self.app
        if app.busy:
            return
        if self.cleanup_mode.get() == 'reset_memory':
            app.analysis_tab.apply()
            return
        plan = self.wipe_plan
        if plan is None or plan.mode != self.cleanup_mode.get() or plan.blockers:
            return app.dialogs.showinfo('Очистка', 'Получите новый предпросмотр и устраните блокеры.')
        if not app.server_done.get():
            return app.dialogs.showinfo('Серверный этап', 'Сначала выполните и отметьте отзыв на сервере.')
        word = app.dialogs.askstring('Необратимое стирание',
                                     'Будут удалены данные из предпросмотра, включая историю и вход. '
                                     'Память Cowork экспортируйте отдельно. Введите СТЕРЕТЬ:', parent=app.root)
        if word != 'СТЕРЕТЬ':
            return
        if (app.busy or self.wipe_plan is not plan or self.cleanup_mode.get() != plan.mode
                or not app.server_done.get()):
            return app.dialogs.showinfo('Очистка', 'План изменился. Повторите предпросмотр.')
        self.wipe_plan = None
        app.run(lambda: app.cleanup.WipeExecutor(app.paths).apply(plan, confirmation=Confirmation.ERASE,
                                                                  consent_id=plan.id, server_step_complete=True),
                self.cleanup_finished)

    def cleanup_finished(self, result):
        self.show_cleanup(result['audit'])
        self.app.show_json(result)

    def cleanup_audit(self):
        app = self.app
        app.run(lambda: app.cleanup.audit(app.paths), self.show_cleanup)

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
        lines.append('Полный нулевой остаток не подтверждён: ключи, пароли, базы редактора, сайты, проекты и сервер '
                     'вне этой проверки.')
        self.cleanup_text.configure(state='normal')
        self.cleanup_text.delete('1.0', 'end')
        self.cleanup_text.insert('1.0', '\n'.join(lines))
        self.cleanup_text.configure(state='disabled')

    def export_cowork(self):
        app = self.app

        def ready(result):
            self.cleanup_cowork_export = (tuple(result['runs'])
                                          if result.get('status') == Export.ENCRYPTED_EXPORT_VERIFIED else None)
            self.wipe_plan = None
            app.show_json(result)
        app.run(lambda: app.cowork.export_all(app.paths), ready)
