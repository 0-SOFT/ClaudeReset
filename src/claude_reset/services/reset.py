"""One-button reset: check, resolve the blockers that are safe to resolve, wipe, verify.

Public results use fixed keys only: no paths, names or exception text. A step runner
`step(label, fn, uac=False)` lets the window show progress; by default steps run directly.
"""
from types import MappingProxyType

from ..reset import cleanup
from ..errors import SafetyError
from .. import layout
from ..model import clients
from ..model.confirmation import Confirmation
from ..model.status import Export, Location, Reset
from ..reset import browser_sites, customizations, desktop_keys
from collections.abc import Callable

__all__ = ['Actions', 'ResetSession']

# Who resolves each blocker: 'auto' ones the reset resolves itself, the rest need the person ('ask': a choice).
BLOCKER_KINDS = MappingProxyType({
    'processes': 'auto',
    'vscode': 'user',
    'claude_running': 'user',
    'cowork_service': 'auto',
    'cowork_export': 'auto',
    'extra_entries': 'auto',
    'unlisted_version': 'ask',
    'restore_sources': 'user',
    'inventory': 'user',
    'cowork_location': 'user',
})

def direct(_label: str, fn: Callable[[], object], uac: bool = False) -> object:
    return fn()


class ResetSession:
    """Private state between the window's steps; the window reads only public results."""

    def __init__(self, paths, *, keep_memory=True, inspect=None, actions=None, planner=None):
        # planner prepares the wipe plan and its preview (reset.cleanup unless given).
        self.paths, self.keep_memory = paths, keep_memory
        self.planner = planner or cleanup
        self.inspect = inspect or cleanup.inspect_cleanup
        self.actions = actions or Actions(paths)
        self.accept_unlisted = False
        self.cowork_export = None
        self.plan = None
        self.kinds = set()

    @property
    def mode(self) -> str:
        return 'wipe_memory' if self.keep_memory else 'wipe'

    def check(self, step: Callable = direct) -> dict:
        state = step('check', self.inspect)
        self.kinds = {p.get('kind') for p in state.get('processes', [])}
        self.plan = self.planner.prepare_wipe(self.paths, self.mode, accept_unlisted=self.accept_unlisted,
                                              inspect=lambda: state, cowork_export=self.cowork_export)
        found = self.planner.preview(self.paths, self.mode)
        rows = [{'label': r['label'], 'bytes': r['bytes'], 'status': r['status']}
                for r in found['rows'] if r['status'] != Location.ABSENT]
        return {'rows': rows, 'total_bytes': found['bytes'], 'credentials': len(self.plan.credentials),
                'blockers': self.blockers(), 'ready': not self.plan.blockers, 'nothing_found': not rows and not self.plan.credentials}

    def blockers(self) -> list[dict]:
        result = []
        for key in self.plan.blockers if self.plan else ():
            if key == 'processes':
                if self.kinds & clients.owners('vscode'):
                    result.append(self._blocker('vscode'))
                if self.kinds & clients.CLAUDE_PROCESSES or not self.kinds & clients.owners('vscode'):
                    result.append(self._blocker('processes'))
            else:
                result.append(self._blocker(key))
        return result

    @staticmethod
    def _blocker(key):
        return {'key': key, 'kind': BLOCKER_KINDS.get(key, 'user')}

    def resolve(self, step: Callable = direct) -> dict:
        """Resolve every 'auto' blocker once, then check again. Returns the new check result and what was done."""
        done, failed = [], []
        keys = {b['key'] for b in self.blockers() if b['kind'] == 'auto'}
        if clients.ProcessKind.COWORK_SERVICE in self.kinds and self.plan and 'processes' in self.plan.blockers:
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

    def wipe(self, confirmation: Confirmation, *, browsers: bool = False, step: Callable = direct) -> dict:
        """Desktop device keys first (they need the profile), then a fresh plan, the wipe and its audit."""
        if confirmation is not Confirmation.ERASE:
            raise SafetyError('Erasing requires an explicit confirmation')
        if self.plan is None or self.plan.blockers:
            raise SafetyError('Check the computer and resolve the blockers first', code='wipe_unchecked')
        keys = step('desktop_keys', self.actions.reset_desktop_keys)
        if keys == 'reset':
            self.check(step)
            if self.plan.blockers:
                raise SafetyError('Blockers appeared after the key reset; check the computer again', code='wipe_new_blockers')
        try:
            report = step('wipe', lambda: self.actions.wipe(self.plan, confirmation))
        except SafetyError:
            # The executor wrote its own report; the archived memory (if any) is kept.
            self.plan = None
            return {'status': Reset.FAILED, 'desktop_keys': keys}
        self.plan = None
        site = step('browsers', self.actions.clear_browsers) if browsers else 'not_requested'
        audit = report.get('audit') or {}
        return {'status': Reset.DONE if report.get('status') == Reset.FIXED_LOCATIONS_WIPED else Reset.PARTIAL,
                'memory': report.get('memory'), 'desktop_keys': keys, 'browsers': site,
                'passwords_removed': report.get('credentials_removed', 0),
                'no_files_left': bool(audit.get('zero_file_remainder')) if not self.keep_memory else bool(
                    (report.get('audit_before_memory_restore') or {}).get('zero_file_remainder'))}


class Actions:
    """The existing tested functions behind each automatic step."""
    # The reset areas the steps call, as attributes so that a test gives scripted ones.
    customizations = customizations
    desktop_keys = desktop_keys
    browser_sites = browser_sites

    def __init__(self, paths):
        self.paths = paths

    def close_claude(self) -> dict:
        from ..windows.cleanup_actions import resolve_processes
        return resolve_processes(clients.CLOSABLE_APPS)

    def stop_cowork(self) -> dict:
        from ..windows.cleanup_actions import resolve_service
        return resolve_service()

    def export_cowork(self) -> tuple | None:
        from ..reset.cowork import export_all
        result = export_all(self.paths)
        return tuple(result['runs']) if result.get('status') == Export.ENCRYPTED_EXPORT_VERIFIED else None

    def archive_extras(self) -> dict:
        """Archive every extra Code entry; entries that look like credentials are removed without a copy."""
        entries = self.customizations.extra_entries(layout.code_home(self.paths))
        try:
            report = self.customizations.create_plan(self.paths, entries)
        except SafetyError:
            report = self.customizations.create_plan(self.paths, [])
        return self.customizations.apply_plan(self.paths, report['run'], server_step_complete=True)

    def reset_desktop_keys(self) -> str:
        profile = layout.desktop_data(self.paths)
        if not profile.exists():
            return 'not_present'
        try:
            plan = self.desktop_keys.create_plan(self.paths, profile)
        except Exception:
            return 'not_supported'
        if not plan.get('keys'):
            return 'no_keys'
        try:
            self.desktop_keys.apply_plan(self.paths, plan['run'], server_step_complete=True)
        except Exception:
            return 'failed'
        return 'reset'

    def wipe(self, plan: cleanup.WipePlan, confirmation: Confirmation) -> dict:
        return cleanup.WipeExecutor(self.paths).apply(plan, confirmation=confirmation, consent_id=plan.id,
                                                      server_step_complete=True)

    def clear_browsers(self) -> str:
        try:
            self.browser_sites.site_data(self.paths, erase=True, confirmation=Confirmation.ERASE)
        except browser_sites.BrowsersOpenError:
            return 'browsers_open'
        except Exception:
            return 'failed'
        return 'cleared'
