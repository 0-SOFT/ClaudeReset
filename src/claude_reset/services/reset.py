"""One-button reset: check, resolve the blockers that are safe to resolve, wipe, verify.

Public results use fixed keys only: no paths, names or exception text. A step runner
`step(label, fn, uac=False)` lets the window show progress; by default steps run directly.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType

from .. import layout
from ..errors import SafetyError, error_kind
from ..model import clients
from ..model.confirmation import Confirmation
from ..model.status import BlockerKind, Browsers, DesktopKeys, Export, Location, Reset
from ..reset import browser_sites, cleanup, customizations, desktop_keys

__all__ = ['Actions', 'Blocker', 'CheckResult', 'Found', 'ResetSession', 'WipeResult']

# Who resolves each blocker: 'auto' ones the reset resolves itself, the rest need the person ('ask': a choice).
BLOCKER_KINDS = MappingProxyType({
    'processes': BlockerKind.AUTO,
    'vscode': BlockerKind.USER,
    'claude_running': BlockerKind.USER,
    'cowork_service': BlockerKind.AUTO,
    'cowork_export': BlockerKind.AUTO,
    'extra_entries': BlockerKind.AUTO,
    'unlisted_version': BlockerKind.ASK,
    'restore_sources': BlockerKind.USER,
    'inventory': BlockerKind.USER,
    'cowork_location': BlockerKind.USER,
})


@dataclass(frozen=True)
class Found:
    """A location that holds data, by its fixed label: its size, and its Location status as the preview gave it."""
    label: str
    bytes: int
    status: str

    def to_json(self) -> dict:
        return {'label': self.label, 'bytes': self.bytes, 'status': self.status}


@dataclass(frozen=True)
class Blocker:
    """What stops the wipe, by its key, and who resolves it."""
    key: str
    kind: BlockerKind

    def to_json(self) -> dict:
        return {'key': self.key, 'kind': self.kind}


@dataclass(frozen=True)
class CheckResult:
    """What a check found and what still stops the wipe.

    After a resolution it also names the blockers resolved, those that failed and the kind of each error; before
    one they are None."""
    rows: tuple[Found, ...]
    total_bytes: int
    credentials: int
    blockers: tuple[Blocker, ...]
    ready: bool
    nothing_found: bool
    resolved: tuple[str, ...] | None = None
    failed: tuple[str, ...] | None = None
    errors: Mapping[str, str] | None = None

    def to_json(self) -> dict:
        document = {'rows': [row.to_json() for row in self.rows], 'total_bytes': self.total_bytes,
                    'credentials': self.credentials, 'blockers': [blocker.to_json() for blocker in self.blockers],
                    'ready': self.ready, 'nothing_found': self.nothing_found}
        if self.resolved is not None:
            document.update(resolved=list(self.resolved), failed=list(self.failed or ()),
                            errors=dict(self.errors or {}))
        return document


@dataclass(frozen=True)
class WipeResult:
    """How the wipe ended, with the Desktop keys reset before it.

    A failed wipe reports only its status and the keys: its executor wrote its own report. A finished one also
    reports the memory copy, the browsers, the removed passwords, whether files are left and the kind of each
    error after the wipe."""
    status: Reset
    desktop_keys: DesktopKeys
    memory: str | None = None
    browsers: Browsers | None = None
    passwords_removed: int = 0
    no_files_left: bool = False
    errors: Mapping[str, str] = MappingProxyType({})

    def to_json(self) -> dict:
        if self.status == Reset.FAILED:
            return {'status': self.status, 'desktop_keys': self.desktop_keys}
        return {'status': self.status, 'memory': self.memory, 'desktop_keys': self.desktop_keys,
                'browsers': self.browsers, 'passwords_removed': self.passwords_removed,
                'no_files_left': self.no_files_left, 'errors': dict(self.errors)}


def direct(_label: str, fn: Callable[[], object], uac: bool = False) -> object:
    return fn()


class ResetSession:
    """Private state between the window's steps; the window reads only public results."""

    def __init__(self, paths, *, keep_memory=True, inspect=cleanup.inspect_cleanup,
                 actions=None,   # None: Actions(paths), the steps for this session's folders
                 planner=cleanup):
        # planner prepares the wipe plan and its preview.
        self.paths, self.keep_memory = paths, keep_memory
        self.planner = planner
        self.inspect = inspect
        self.actions = actions or Actions(paths)
        self.accept_unlisted = False
        self.cowork_export = None
        self.plan = None
        self.kinds = set()

    @property
    def mode(self) -> str:
        return 'wipe_memory' if self.keep_memory else 'wipe'

    def check(self, step: Callable = direct) -> CheckResult:
        state = step('check', self.inspect)
        self.kinds = {p.get('kind') for p in state.get('processes', [])}
        self.plan = self.planner.prepare_wipe(self.paths, self.mode, accept_unlisted=self.accept_unlisted,
                                              inspect=lambda: state, cowork_export=self.cowork_export)
        found = self.planner.preview(self.paths, self.mode)
        rows = tuple(Found(r['label'], r['bytes'], r['status'])
                     for r in found['rows'] if r['status'] != Location.ABSENT)
        return CheckResult(rows=rows, total_bytes=found['bytes'], credentials=len(self.plan.credentials),
                           blockers=tuple(self.blockers()), ready=not self.plan.blockers,
                           nothing_found=not rows and not self.plan.credentials)

    def blockers(self) -> list[Blocker]:
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
    def _blocker(key: str) -> Blocker:
        return Blocker(key, BLOCKER_KINDS.get(key, BlockerKind.USER))

    def resolve(self, step: Callable = direct) -> CheckResult:
        """Resolve every 'auto' blocker once, then check again. Returns the new check result and what was done."""
        done, failed, errors = [], [], {}
        keys = {b.key for b in self.blockers() if b.kind == BlockerKind.AUTO}
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
            except Exception as exc:
                failed.append(key)
                errors[key] = error_kind(exc)
                continue
            if key == 'cowork_export':
                if outcome:
                    self.cowork_export = outcome
                else:
                    failed.append(key)
                    continue
            done.append(key)
        result = self.check(step)
        blockers = result.blockers
        tried = 'processes' in done or 'processes' in failed
        if tried and any(b.key == 'processes' for b in blockers):
            # Closing was already attempted: what is left needs the person.
            blockers = tuple(self._blocker('claude_running') if b.key == 'processes' else b for b in blockers)
        return replace(result, blockers=blockers, resolved=tuple(done), failed=tuple(failed),
                       errors=MappingProxyType(errors))

    def wipe(self, confirmation: Confirmation, *, browsers: bool = False, step: Callable = direct) -> WipeResult:
        """Desktop device keys first (they need the profile), then a fresh plan, the wipe and its audit."""
        if confirmation is not Confirmation.ERASE:
            raise SafetyError('Erasing requires an explicit confirmation')
        if self.plan is None or self.plan.blockers:
            raise SafetyError('Check the computer and resolve the blockers first', code='wipe_unchecked')
        keys = step('desktop_keys', self.actions.reset_desktop_keys)
        if keys == DesktopKeys.RESET:
            self.check(step)
            if self.plan.blockers:
                raise SafetyError('Blockers appeared after the key reset; check the computer again', code='wipe_new_blockers')
        try:
            report = step('wipe', lambda: self.actions.wipe(self.plan, confirmation))
        except SafetyError:
            # The executor wrote its own report; the archived memory (if any) is kept.
            self.plan = None
            return WipeResult(Reset.FAILED, keys)
        self.plan = None
        errors = {}
        try:
            site = step('browsers', self.actions.clear_browsers) if browsers else Browsers.NOT_REQUESTED
        except Exception as exc:   # the wipe is done; its result must still reach the window
            site, errors['browsers'] = Browsers.FAILED, error_kind(exc)
        # With the memory kept, the audit before the memory went back says whether the wipe left files.
        audit = report.get('audit_before_memory_restore' if self.keep_memory else 'audit') or {}
        return WipeResult(Reset.DONE if report.get('status') == Reset.FIXED_LOCATIONS_WIPED else Reset.PARTIAL,
                          keys, memory=report.get('memory'), browsers=site,
                          passwords_removed=report.get('credentials_removed', 0),
                          no_files_left=bool(audit.get('zero_file_remainder')), errors=MappingProxyType(errors))


class Actions:
    """The steps the reset resolves and runs by itself: the port tests replace with scripted steps."""

    def __init__(self, paths, *, customizations=customizations, desktop_keys=desktop_keys,
                 browser_sites=browser_sites):
        # The reset areas the steps call.
        self.paths = paths
        self.customizations, self.desktop_keys, self.browser_sites = customizations, desktop_keys, browser_sites

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

    def reset_desktop_keys(self) -> DesktopKeys:
        profile = layout.desktop_data(self.paths)
        if not profile.exists():
            return DesktopKeys.NOT_PRESENT
        try:
            plan = self.desktop_keys.create_plan(self.paths, profile)
        except SafetyError:
            return DesktopKeys.NOT_SUPPORTED
        if not plan.get('keys'):
            return DesktopKeys.NO_KEYS
        try:
            self.desktop_keys.apply_plan(self.paths, plan['run'], server_step_complete=True)
        except SafetyError:
            return DesktopKeys.FAILED
        return DesktopKeys.RESET

    def wipe(self, plan: cleanup.WipePlan, confirmation: Confirmation) -> dict:
        return cleanup.WipeExecutor(self.paths).apply(plan, confirmation=confirmation, consent_id=plan.id,
                                                      server_step_complete=True)

    def clear_browsers(self) -> Browsers:
        try:
            self.browser_sites.site_data(self.paths, erase=True, confirmation=Confirmation.ERASE)
        except browser_sites.BrowsersOpenError:
            return Browsers.BROWSERS_OPEN
        except (SafetyError, OSError):
            return Browsers.FAILED
        return Browsers.CLEARED
