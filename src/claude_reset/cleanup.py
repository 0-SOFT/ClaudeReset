"""Fixed-location cleanup inventory. Public results contain no user paths."""
from dataclasses import dataclass, field
from pathlib import Path
import stat
import uuid

from .safeio import SafetyError, guarded, tree_entries

from .safeio import fingerprint, remove_owned, atomic_json
from .execution import Executor, operation_lock
from .core import snapshot_memory, restore_memory, validate_memory_bundle
from .windows import inspect_windows, ps_json


def inspect_cleanup():
    from .cleanup_actions import credential_names
    state = inspect_windows()
    state['credentials'] = credential_names()
    state['cowork_service'] = ps_json("$s = Get-Service -Name CoworkVMService -ErrorAction SilentlyContinue; "
                                     "@{running=($null -ne $s -and $s.Status -ne 'Stopped')} | ConvertTo-Json")['running']
    return state


BLOCKERS = {
    'processes': 'Закройте Claude и сеанс расширения; общий редактор автоматически не закрывается.',
    'extra_entries': 'Архивируйте и удалите дополнительные записи Code.',
    'unlisted_version': 'Версия не проверена: требуется явное согласие на фиксированную область.',
    'inventory': 'Не удалось проверить расположения: устраните ссылки или ошибку доступа.',
    'restore_sources': 'Отключите восстановление старого состояния перед очисткой.',
    'cowork_service': 'Служба Cowork должна быть остановлена перед стиранием.',
    'cowork_export': 'Нужен проверенный экспорт работы Cowork; затем повторите предпросмотр.',
    'cowork_location': 'Работа Cowork найдена вне поддержанного профиля экспорта. Стирание заблокировано; нужен адаптер этого расположения.',
}


@dataclass(frozen=True)
class WipePlan:
    id: str
    mode: str
    snapshots: tuple
    versions: tuple
    accept_unlisted: bool
    blockers: tuple
    credentials: tuple = field(default=(), repr=False)
    cowork_export: str | tuple | None = None


def _inventory(paths):
    return tuple((str(t.path), t.kind, fingerprint(t.path, t.root))
                 for t in fixed_targets(paths))


def prepare_wipe(paths, mode='wipe', *, accept_unlisted=False, inspect=inspect_cleanup, cowork_export=None):
    from .catalog import CLI_VERSIONS, EXTENSION_VERSIONS
    from .customizations import extra_entries
    if mode not in ('wipe', 'wipe_memory'):
        raise SafetyError('Выберите режим стирания')
    state = inspect()
    blockers = []
    if any(p.get('kind') in ('Claude.exe', 'claude.exe', 'claude-desktop.exe',
                           'claude-child', 'cowork-svc.exe', 'Code.exe', 'Code - Insiders.exe')
           for p in state.get('processes', [])):
        blockers.append('processes')
    if state.get('restore_sources'):
        blockers.append('restore_sources')
    if state.get('cowork_service'):
        blockers.append('cowork_service')
    from .cowork import work_profiles
    if work_profiles(paths) and not cowork_export:
        blockers.append('cowork_export')
    versions = (state.get('cli_version'), tuple(state.get('extension_versions', [])),
                tuple(state.get('desktop_versions', []) or [p.get('Version') for p in state.get('packages', [])]))
    code_present = (paths.home / '.claude').exists() or (paths.home / '.claude.json').exists()
    known_code = ((versions[0] in CLI_VERSIONS or bool(versions[1]))
                  and (versions[0] is None or versions[0] in CLI_VERSIONS)
                  and all(v in EXTENSION_VERSIONS for v in versions[1]))
    if not accept_unlisted and code_present and not known_code:
        blockers.append('unlisted_version')
    try:
        snapshots = _inventory(paths)
        profile = paths.home / '.claude'
        if profile.exists() and extra_entries(profile):
            blockers.append('extra_entries')
    except (OSError, SafetyError):
        snapshots = ()
        blockers.append('inventory')
    return WipePlan(uuid.uuid4().hex, mode, snapshots, versions, bool(accept_unlisted), tuple(blockers),
                    tuple(state.get('credentials', ())), cowork_export)


class WipeExecutor:
    def __init__(self, paths, *, crypto=None, inspect=inspect_cleanup, delete_credential=None):
        from .cleanup_actions import delete_credential as native_delete
        self.delete_credential = delete_credential or native_delete
        self.paths, self.inspect = paths, inspect
        self.storage = Executor(paths, crypto=crypto, inspect=inspect)

    def _fresh(self, plan):
        current = prepare_wipe(self.paths, plan.mode, accept_unlisted=plan.accept_unlisted,
                               inspect=self.inspect, cowork_export=plan.cowork_export)
        if (plan.blockers or current.blockers or current.snapshots != plan.snapshots
                or current.versions != plan.versions or current.credentials != plan.credentials):
            raise SafetyError('План изменился или есть блокеры. Повторите предпросмотр.')
        from .cowork import verify_cleanup_exports
        verify_cleanup_exports(self.paths, plan.cowork_export)

    def apply(self, plan, *, confirmation, consent_id, server_step_complete=False):
        if confirmation != 'СТЕРЕТЬ' or consent_id != plan.id or not server_step_complete:
            raise SafetyError('Нужны слово СТЕРЕТЬ, текущий план и отметка серверного этапа.')
        with operation_lock(self.paths):
            self._fresh(plan)
            run = guarded(self.paths.state / 'runs' / plan.id, self.paths.state)
            if run.exists():
                raise SafetyError('План уже запускался. Проверьте отчёт и создайте новый.')
            run.mkdir(parents=True)
            report = {'run': plan.id, 'status': 'started', 'mode': plan.mode,
                      'accepted_unlisted_version': plan.accept_unlisted,
                      'credentials_removed': 0, 'credentials_verified_absent': False,
                      'cowork_export_verified': bool(plan.cowork_export),
                      'cowork_source_removed': False,
                      'memory': 'not_kept', 'ready_for_new_account': False}
            atomic_json(run / 'result.json', report, self.paths.state)
            try:
                bundle = None
                if plan.mode == 'wipe_memory':
                    bundle, _ = snapshot_memory(self.paths.home / '.claude')
                    validate_memory_bundle(bundle)
                    self.storage._write_private(run / 'memory.dpapi', bundle)
                    report['memory'] = 'encrypted_archive_verified'
                self._fresh(plan)
                for target in fixed_targets(self.paths):
                    if target.kind == 'contents' and target.path.exists():
                        for child in list(guarded(target.path, target.root).iterdir()):
                            remove_owned(child, target.root)
                    else:
                        remove_owned(target.path, target.root)
                from .cowork import profiles
                report['cowork_source_removed'] = not profiles(self.paths)[0].exists()
                for name in plan.credentials:
                    self.delete_credential(name)
                    report['credentials_removed'] += 1
                if self.inspect().get('credentials'):
                    raise SafetyError('Сохранённые пароли Claude остались после удаления')
                report['credentials_verified_absent'] = True
                report['audit_before_memory_restore'] = audit(self.paths)
                if not report['audit_before_memory_restore']['zero_file_remainder']:
                    raise SafetyError('После стирания обнаружены файловые остатки')
                if bundle is not None:
                    profile = self.paths.home / '.claude'
                    restore_memory(bundle, profile)
                    if any(guarded(profile / name, profile).read_bytes() != data
                           for name, data in validate_memory_bundle(bundle)):
                        raise SafetyError('Память не совпала с архивом')
                    report['memory'] = 'restored_verbatim'
                report['audit'] = audit(self.paths)
                report['status'] = 'fixed_locations_wiped'
            except Exception:
                report['status'] = 'failed_or_partial'
                atomic_json(run / 'result.json', report, self.paths.state)
                raise SafetyError('Стирание остановлено. Проверьте отчёт; созданный архив памяти сохранён.') from None
            atomic_json(run / 'result.json', report, self.paths.state)
            return report


MODES = {
    'reset_memory': 'Сброс, сохранив память',
    'wipe': 'Стереть всё',
    'wipe_memory': 'Стереть всё, сохранив память',
}
OUTSIDE_AUDIT = ['credentials', 'desktop_keys', 'vscode_database', 'browser_sites',
                 'projects_and_remote', 'server']


@dataclass(frozen=True)
class Target:
    label: str
    path: Path
    root: Path
    kind: str = 'tree'


def fixed_targets(paths):
    """The location list in wipe_claude.ps1, never a caller-supplied delete list."""
    paths.validate()
    from .native_worker import FAMILY
    targets = [
        Target('Desktop MSIX', paths.local / 'Packages/Claude_pzs8sxrjxfjjc', paths.local, 'contents'),
        Target('Desktop', paths.roaming / 'Claude', paths.roaming),
        Target('Desktop 3p', paths.roaming / 'Claude-3p', paths.roaming),
        Target('Claude Code', paths.home / '.claude', paths.home),
        Target('Конфигурация Code', paths.home / '.claude.json', paths.home, 'file'),
        Target('Хранилище расширения', paths.roaming / 'Code/User/globalStorage/anthropic.claude-code', paths.roaming),
    ]
    targets.append(Target('Desktop / Cowork данные', paths.local / 'Claude-Data' / FAMILY.lower(), paths.local))
    for item in sorted(paths.home.iterdir()):
        if item.name.startswith('.claude.json.'):
            targets.append(Target('Резервная конфигурация Code', item, paths.home, 'file'))
    for target in targets:
        if (paths.state == target.path or paths.state.is_relative_to(target.path)
                or target.path.is_relative_to(paths.state)):
            raise SafetyError('Cleanup target overlaps application state')
    return targets


def preview(paths, mode='wipe'):
    if mode not in MODES:
        raise SafetyError('Unknown cleanup mode')
    rows = []
    for target in fixed_targets(paths):
        row = {'label': target.label, 'kind': target.kind, 'status': 'absent',
               'files': 0, 'bytes': 0, 'objects': 0}
        try:
            entries = list(tree_entries(target.path, target.root))
            if target.kind == 'contents':
                entries = [(p, s) for p, s in entries if p != target.path]
            if entries:
                row['status'] = 'present'
            for _, info in entries:
                row['objects'] += 1
                if stat.S_ISREG(info.st_mode):
                    row['files'] += 1
                    row['bytes'] += info.st_size
        except (OSError, SafetyError):
            row['status'] = 'unavailable'
        rows.append(row)
    return {'mode': mode, 'rows': rows, 'bytes': sum(r['bytes'] for r in rows),
            'complete': all(r['status'] != 'unavailable' for r in rows),
            'scope': 'fixed_file_locations', 'outside_audit': list(OUTSIDE_AUDIT),
            'ready_for_new_account': False}


def audit(paths):
    """Fresh enumeration, independent of any earlier preview or deletion result."""
    result = preview(paths)
    result['zero_file_remainder'] = result['complete'] and all(
        r['status'] == 'absent' for r in result['rows'])
    result['zero_remainder'] = False  # External stores have not been measured.
    return result
