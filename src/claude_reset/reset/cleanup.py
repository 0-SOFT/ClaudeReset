"""Fixed-location cleanup inventory. Public results contain no user paths."""
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .. import layout
from ..errors import SafetyError
from ..model import clients
from ..model.confirmation import Confirmation
from ..model.ids import new_id
from ..model.status import Location, Reset
from ..safeio import atomic_json, fingerprint, guarded, remove_owned, tree_entries
from ..windows.cleanup_actions import delete_credential as native_delete
from ..windows.dpapi import DPAPI
from ..windows.inventory import inspect_windows
from ..windows.powershell import ps_json
from .cowork import verify_cleanup_exports
from .execution import Executor, operation_lock
from .memory import restore_memory, snapshot_memory, validate_memory_bundle

__all__ = ['MODES', 'WipeExecutor', 'WipePlan', 'audit', 'fixed_targets', 'inspect_cleanup', 'prepare_wipe', 'preview']


def inspect_cleanup(*, windows=inspect_windows, query=ps_json):
    """Processes, restore sources, credentials and the Cowork service; windows and query read this PC."""
    from ..windows.cleanup_actions import credential_names
    state = windows()
    state['credentials'] = credential_names()
    state['cowork_service'] = query("$s = Get-Service -Name CoworkVMService -ErrorAction SilentlyContinue; "
                                     "@{running=($null -ne $s -and $s.Status -ne 'Stopped')} | ConvertTo-Json")['running']
    return state


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
        raise SafetyError('Choose a wipe mode', code='wipe_mode')
    state = inspect()
    blockers = []
    if any(p.get('kind') in clients.owners('code', 'vscode', 'desktop') for p in state.get('processes', [])):
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
    code_present = layout.code_home(paths).exists() or layout.code_config(paths).exists()
    known_code = ((versions[0] in CLI_VERSIONS or bool(versions[1]))
                  and (versions[0] is None or versions[0] in CLI_VERSIONS)
                  and all(v in EXTENSION_VERSIONS for v in versions[1]))
    if not accept_unlisted and code_present and not known_code:
        blockers.append('unlisted_version')
    try:
        snapshots = _inventory(paths)
        profile = layout.code_home(paths)
        if profile.exists() and extra_entries(profile):
            blockers.append('extra_entries')
    except (OSError, SafetyError):
        snapshots = ()
        blockers.append('inventory')
    return WipePlan(new_id(), mode, snapshots, versions, bool(accept_unlisted), tuple(blockers),
                    tuple(state.get('credentials', ())), cowork_export)


class WipeExecutor:
    def __init__(self, paths, *, crypto=DPAPI(), inspect=inspect_cleanup, delete_credential=native_delete,
                 verify_exports=verify_cleanup_exports, restore=restore_memory):
        """verify_exports checks the Cowork exports the plan relies on (cowork.verify_cleanup_exports) and
        restore puts the kept memory back (memory.restore_memory)."""
        self.delete_credential = delete_credential
        self.verify_exports, self.restore = verify_exports, restore
        self.paths, self.inspect = paths, inspect
        self.storage = Executor(paths, crypto=crypto, inspect=inspect)

    def _fresh(self, plan):
        current = prepare_wipe(self.paths, plan.mode, accept_unlisted=plan.accept_unlisted,
                               inspect=self.inspect, cowork_export=plan.cowork_export)
        if (plan.blockers or current.blockers or current.snapshots != plan.snapshots
                or current.versions != plan.versions or current.credentials != plan.credentials):
            raise SafetyError('The plan changed or has blockers; preview again', code='wipe_plan_changed')
        self.verify_exports(self.paths, plan.cowork_export)

    def apply(self, plan, *, confirmation, consent_id, server_step_complete=False):
        if confirmation is not Confirmation.ERASE or consent_id != plan.id or not server_step_complete:
            raise SafetyError('Erasing requires a confirmation, the current plan and the server step')
        with operation_lock(self.paths):
            self._fresh(plan)
            run = layout.run_folder(self.paths, layout.RUNS, plan.id)
            if run.exists():
                raise SafetyError('This plan has already run; check its report and make a new one', code='wipe_plan_used')
            run.mkdir(parents=True)
            report = {'run': plan.id, 'status': Reset.STARTED, 'mode': plan.mode,
                      'accepted_unlisted_version': plan.accept_unlisted,
                      'credentials_removed': 0, 'credentials_verified_absent': False,
                      'cowork_export_verified': bool(plan.cowork_export),
                      'cowork_source_removed': False,
                      'memory': 'not_kept', 'ready_for_new_account': False}
            atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
            try:
                bundle = None
                if plan.mode == 'wipe_memory':
                    bundle, _ = snapshot_memory(layout.code_home(self.paths))
                    validate_memory_bundle(bundle)
                    self.storage.write_private(run / layout.MEMORY_FILE, bundle)
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
                    raise SafetyError('Saved Claude credentials remain after removal', code='credentials_remain')
                report['credentials_verified_absent'] = True
                report['audit_before_memory_restore'] = audit(self.paths)
                if not report['audit_before_memory_restore']['zero_file_remainder']:
                    raise SafetyError('Files remain after the wipe', code='files_remain')
                if bundle is not None:
                    profile = layout.code_home(self.paths)
                    self.restore(bundle, profile)
                    if any(guarded(profile / name, profile).read_bytes() != data
                           for name, data in validate_memory_bundle(bundle)):
                        raise SafetyError('Memory does not match its archive', code='memory_mismatch')
                    report['memory'] = 'restored_verbatim'
                report['audit'] = audit(self.paths)
                report['status'] = Reset.FIXED_LOCATIONS_WIPED
            except Exception:
                report['status'] = Reset.FAILED_OR_PARTIAL
                atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
                raise SafetyError('The wipe stopped; check the report, the memory archive it made is kept', code='wipe_stopped') from None
            atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
            return report


MODES = ('reset_memory', 'wipe', 'wipe_memory')
OUTSIDE_AUDIT = ('credentials', 'desktop_keys', 'vscode_database', 'browser_sites',
                 'projects_and_remote', 'server')


@dataclass(frozen=True)
class Target:
    label: str
    path: Path
    root: Path
    kind: str = 'tree'


def fixed_targets(paths):
    """The location list in maintainer/wipe_claude.ps1, never a caller-supplied delete list."""
    paths.validate()
    targets = [
        Target('Desktop MSIX', layout.desktop_package(paths), paths.local, 'contents'),
        Target('Desktop', paths.roaming / layout.DESKTOP_ROAMING, paths.roaming),
        Target('Desktop 3p', paths.roaming / layout.DESKTOP_3P, paths.roaming),
        Target('Claude Code', layout.code_home(paths), paths.home),
        Target('Code config', layout.code_config(paths), paths.home, 'file'),
        Target('Extension storage', paths.roaming / 'Code/User/globalStorage/anthropic.claude-code', paths.roaming),
    ]
    targets.append(Target('Desktop / Cowork data', layout.desktop_data(paths), paths.local))
    for item in sorted(paths.home.iterdir()):
        if item.name.startswith('.claude.json.'):
            targets.append(Target('Code config backup', item, paths.home, 'file'))
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
        row = {'label': target.label, 'kind': target.kind, 'status': Location.ABSENT,
               'files': 0, 'bytes': 0, 'objects': 0}
        try:
            entries = list(tree_entries(target.path, target.root))
            if target.kind == 'contents':
                entries = [(p, s) for p, s in entries if p != target.path]
            if entries:
                row['status'] = Location.PRESENT
            for _, info in entries:
                row['objects'] += 1
                if stat.S_ISREG(info.st_mode):
                    row['files'] += 1
                    row['bytes'] += info.st_size
        except (OSError, SafetyError):
            row['status'] = Location.UNAVAILABLE
        rows.append(row)
    return {'mode': mode, 'rows': rows, 'bytes': sum(r['bytes'] for r in rows),
            'complete': all(r['status'] != Location.UNAVAILABLE for r in rows),
            'scope': 'fixed_file_locations', 'outside_audit': list(OUTSIDE_AUDIT),
            'ready_for_new_account': False}


def audit(paths):
    """Fresh enumeration, independent of any earlier preview or deletion result."""
    result = preview(paths)
    result['zero_file_remainder'] = result['complete'] and all(
        r['status'] == Location.ABSENT for r in result['rows'])
    result['zero_remainder'] = False  # External stores have not been measured.
    return result
