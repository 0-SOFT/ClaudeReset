"""One-button reset: check, resolve the blockers that are safe to resolve, wipe, verify. No Tk.

Public results use fixed keys only: no paths, names or exception text. A step runner
`step(label, fn, uac=False)` lets the window show progress; by default steps run directly.
"""
from . import cleanup
from .safeio import SafetyError

# Plain-language blockers. 'auto' ones the reset resolves itself, the rest need the person.
BLOCKERS = {
    'processes': ('auto', 'Закроет Claude Desktop и Claude Code.'),
    'vscode': ('user', 'Открыт VS Code: в нём работает Claude Code. Сохраните файлы и закройте все окна VS Code.'),
    'claude_running': ('user', 'Claude не закрылся сам. Закройте Claude Desktop, в том числе значок у часов.'),
    'cowork_service': ('auto', 'Остановит службу Cowork.'),
    'cowork_export': ('auto', 'Сохранит копию вашей работы в Cowork.'),
    'extra_entries': ('auto', 'Сохранит копию ваших команд, агентов и настроек Claude Code.'),
    'unlisted_version': ('ask', 'Эта версия Claude ещё не проверялась с программой.'),
    'restore_sources': ('user', 'В автозагрузке Windows есть программа, которая снова запустит Claude. Отключите её в «Автозагрузке».'),
    'inventory': ('user', 'Не удалось прочитать часть папок Claude. Откройте «Режим для специалистов» → «Очистка».'),
    'cowork_location': ('user', 'Работа Cowork лежит в непроверенном месте. Нужен «Режим для специалистов».'),
}
LABELS = {
    'Desktop MSIX': 'Claude Desktop: программа из Microsoft Store',
    'Desktop': 'Claude Desktop: вход, история, настройки',
    'Desktop 3p': 'Claude Desktop: подключения',
    'Claude Code': 'Claude Code: история, проекты, память',
    'Конфигурация Code': 'Claude Code: файл настроек',
    'Хранилище расширения': 'Claude Code в VS Code',
    'Desktop / Cowork данные': 'Claude Desktop и Cowork: данные',
    'Резервная конфигурация Code': 'Claude Code: резервные копии настроек',
}
EDITOR_KINDS = ('Code.exe', 'Code - Insiders.exe')
CLAUDE_KINDS = ('Claude.exe', 'claude.exe', 'claude-desktop.exe', 'claude-child')


def direct(_label, fn, uac=False):
    return fn()


def size_text(count):
    for unit, factor in (('ГБ', 1024 ** 3), ('МБ', 1024 ** 2), ('КБ', 1024)):
        if count >= factor:
            return f'{count / factor:.1f} {unit}'.replace('.', ',')
    return f'{count} Б'


class ResetSession:
    """Private state between the window's steps; the window reads only public results."""

    def __init__(self, paths, *, keep_memory=True, inspect=None, actions=None):
        self.paths, self.keep_memory = paths, keep_memory
        self.inspect = inspect or cleanup.inspect_cleanup
        self.actions = actions or Actions(paths)
        self.accept_unlisted = False
        self.cowork_export = None
        self.plan = None
        self.kinds = set()

    @property
    def mode(self):
        return 'wipe_memory' if self.keep_memory else 'wipe'

    def check(self, step=direct):
        state = step('check', self.inspect)
        self.kinds = {p.get('kind') for p in state.get('processes', [])}
        self.plan = cleanup.prepare_wipe(self.paths, self.mode, accept_unlisted=self.accept_unlisted,
                                         inspect=lambda: state, cowork_export=self.cowork_export)
        found = cleanup.preview(self.paths, self.mode)
        rows = [{'label': LABELS.get(r['label'], r['label']), 'size': size_text(r['bytes']), 'status': r['status']}
                for r in found['rows'] if r['status'] != 'absent']
        return {'rows': rows, 'total': size_text(found['bytes']), 'credentials': len(self.plan.credentials),
                'blockers': self.blockers(), 'ready': not self.plan.blockers, 'nothing_found': not rows and not self.plan.credentials}

    def blockers(self):
        result = []
        for key in self.plan.blockers if self.plan else ():
            if key == 'processes':
                if self.kinds & set(EDITOR_KINDS):
                    result.append(self._blocker('vscode'))
                if self.kinds & set(CLAUDE_KINDS) or not self.kinds & set(EDITOR_KINDS):
                    result.append(self._blocker('processes'))
            else:
                result.append(self._blocker(key))
        return result

    @staticmethod
    def _blocker(key):
        kind, text = BLOCKERS.get(key, ('user', 'Нужна проверка в «Режиме для специалистов».'))
        return {'key': key, 'kind': kind, 'text': text}

    def resolve(self, step=direct):
        """Resolve every 'auto' blocker once, then check again. Returns the new check result and what was done."""
        done, failed = [], []
        keys = {b['key'] for b in self.blockers() if b['kind'] == 'auto'}
        if 'cowork-svc.exe' in self.kinds and self.plan and 'processes' in self.plan.blockers:
            keys.add('cowork_service')  # the service process is stopped by stopping the service
        for key, label, action in (('processes', 'close_claude', self.actions.close_claude),
                                   ('cowork_service', 'stop_cowork', self.actions.stop_cowork),
                                   ('cowork_export', 'export_cowork', self.actions.export_cowork),
                                   ('extra_entries', 'archive_extras', self.actions.archive_extras)):
            if key not in keys:
                continue
            try:
                outcome = step(label, action)
            except Exception:
                failed.append(key)
                continue
            if key == 'cowork_export':
                if outcome:
                    self.cowork_export = outcome
                else:
                    failed.append(key)
                    continue
            done.append(key)
        result = self.check(step)
        result.update(resolved=done, failed=failed)
        tried = 'processes' in done or 'processes' in failed
        if tried and any(b['key'] == 'processes' for b in result['blockers']):
            # Closing was already attempted: what is left needs the person.
            result['blockers'] = [self._blocker('claude_running') if b['key'] == 'processes' else b
                                  for b in result['blockers']]
        return result

    def wipe(self, confirmation, *, browsers=False, step=direct):
        """Desktop device keys first (they need the profile), then a fresh plan, the wipe and its audit."""
        if confirmation != 'СТЕРЕТЬ':
            raise SafetyError('Нужно слово СТЕРЕТЬ')
        if self.plan is None or self.plan.blockers:
            raise SafetyError('Сначала проверьте компьютер и устраните блокеры')
        keys = step('desktop_keys', self.actions.reset_desktop_keys)
        if keys == 'reset':
            self.check(step)
            if self.plan.blockers:
                raise SafetyError('После сброса ключей появились блокеры. Проверьте компьютер снова')
        try:
            report = step('wipe', lambda: self.actions.wipe(self.plan, confirmation))
        except SafetyError:
            # The executor wrote its own report; the archived memory (if any) is kept.
            self.plan = None
            return {'status': 'failed', 'desktop_keys': keys}
        self.plan = None
        site = step('browsers', self.actions.clear_browsers) if browsers else 'not_requested'
        audit = report.get('audit') or {}
        return {'status': 'done' if report.get('status') == 'fixed_locations_wiped' else 'partial',
                'memory': report.get('memory'), 'desktop_keys': keys, 'browsers': site,
                'passwords_removed': report.get('credentials_removed', 0),
                'no_files_left': bool(audit.get('zero_file_remainder')) if not self.keep_memory else bool(
                    (report.get('audit_before_memory_restore') or {}).get('zero_file_remainder'))}


class Actions:
    """The existing tested functions behind each automatic step."""

    def __init__(self, paths):
        self.paths = paths

    def close_claude(self):
        from .cleanup_actions import resolve_processes
        return resolve_processes()

    def stop_cowork(self):
        from .cleanup_actions import resolve_service
        return resolve_service()

    def export_cowork(self):
        from .cowork import export_all
        result = export_all(self.paths)
        return tuple(result['runs']) if result.get('status') == 'encrypted_export_verified' else None

    def archive_extras(self):
        """Archive every extra Code entry; entries that look like credentials are removed without a copy."""
        from .customizations import apply_plan, create_plan, extra_entries
        entries = extra_entries(self.paths.home / '.claude')
        try:
            report = create_plan(self.paths, entries)
        except SafetyError:
            report = create_plan(self.paths, [])
        return apply_plan(self.paths, report['run'], server_step_complete=True)

    def reset_desktop_keys(self):
        from . import desktop_keys
        from .native_worker import FAMILY
        profile = self.paths.local / 'Claude-Data' / FAMILY.lower()
        if not profile.exists():
            return 'not_present'
        try:
            plan = desktop_keys.create_plan(self.paths, profile)
        except Exception:
            return 'not_supported'
        if not plan.get('keys'):
            return 'no_keys'
        try:
            desktop_keys.apply_plan(self.paths, plan['run'], server_step_complete=True)
        except Exception:
            return 'failed'
        return 'reset'

    def wipe(self, plan, confirmation):
        return cleanup.WipeExecutor(self.paths).apply(plan, confirmation=confirmation, consent_id=plan.id,
                                                      server_step_complete=True)

    def clear_browsers(self):
        from .browser_sites import site_data
        try:
            site_data(self.paths, erase=True, confirmation='СТЕРЕТЬ')
        except SafetyError as exc:
            return 'browsers_open' if 'Закройте' in str(exc) else 'failed'
        except Exception:
            return 'failed'
        return 'cleared'
