"""The protection as a whole: one state, the fix to suggest and what was found. The windows word it themselves."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .. import config
from ..errors import SafetyError, error_kind
from ..model.status import Check, Fix, Protection, ProtectionLevel, ProtectionState, ProxyKind
from ..network import controller_status, l1_check, l1_consent, l1_install, l1_remove, remote_backend

__all__ = ['CLIENTS', 'L1', 'STOP_FIXES', 'ActionResult', 'ClientFound', 'ProtectionDetails', 'ProtectionStatus',
           'details', 'open_boundaries', 'run_action', 'state']

# What the person can do about each reason the controller stopped; any other reason: restart.
STOP_FIXES = MappingProxyType({
    'exit_mismatch': Fix.ACCEPT_EXIT,
    'proxy_unreachable': Fix.RETRY,
    'exit_probe_failed': Fix.RETRY,
    'backend_changed': Fix.RETRY,
    'backend_config_failed': Fix.REENTER,
    'profile_changed': Fix.RESTART,
    'monitor_error': Fix.RESTART,
    'exception': Fix.RESTART,
})
# The readiness checks that find each Claude client.
CLIENTS = ('client_desktop', 'client_standalone_cli', 'client_vscode_extension')


@dataclass(frozen=True)
class ClientFound:
    """Whether the readiness check named by check found its Claude client."""
    check: str
    present: bool

    def to_json(self) -> dict:
        return {'check': self.check, 'present': self.present}


@dataclass(frozen=True)
class ProtectionStatus:
    """The protection in one state with one fix to suggest, the proxy it goes through and the clients found.

    stop_reason is the controller's reason when the state is a problem; error_type names an error that left the
    state unknown."""
    state: ProtectionState
    fix: Fix | None = None
    proxy: ProxyKind | None = None
    proxy_saved: bool = False
    clients: tuple[ClientFound, ...] = ()
    stop_reason: str | None = None
    error_type: str | None = None

    def to_json(self) -> dict:
        clients = [client.to_json() for client in self.clients]
        if self.error_type is not None:
            return {'state': self.state, 'fix': self.fix, 'proxy': self.proxy, 'proxy_saved': self.proxy_saved,
                    'clients': clients, 'error_type': self.error_type}
        document = {'proxy': self.proxy, 'proxy_saved': self.proxy_saved, 'clients': clients, 'state': self.state}
        if self.state is ProtectionState.PROBLEM:
            document['stop_reason'] = self.stop_reason
        document['fix'] = self.fix
        return document


@dataclass(frozen=True)
class ProtectionDetails:
    """The readiness check of each part, the controller's last report and whether an install can start."""
    parts: Mapping[str, str]
    last_report: Mapping[str, object]
    can_install: bool | None

    def to_json(self) -> dict:
        return {'parts': dict(self.parts), 'last_report': dict(self.last_report), 'can_install': self.can_install}


@dataclass(frozen=True)
class ActionResult:
    """How a protection action ended, with the details the windows word.

    report is the operation report of the L1 install, restart or removal; None when the scenario refused the action
    before any operation started."""
    status: str | None
    report: Mapping[str, object] | None = None
    extension_protection: str | None = None
    profile_saved: bool = False
    retry_blocked: bool = False
    seconds_without_relay: int | float | None = None

    @classmethod
    def of(cls, report: Mapping[str, object]) -> ActionResult:
        """The result that an operation report of the L1 install, restart or removal describes."""
        return cls(status=report.get('status'), report=MappingProxyType(dict(report)),
                   extension_protection=report.get('extension_protection'),
                   profile_saved=bool(report.get('profile_saved')), retry_blocked=bool(report.get('retry_blocked')),
                   seconds_without_relay=report.get('seconds_without_relay'))

    def to_json(self) -> dict:
        return dict(self.report) if self.report is not None else {'status': self.status}


def state(paths, *, collect=l1_check.collect, evaluate=l1_check.evaluate, status=controller_status.status,
          remote=remote_backend.load) -> ProtectionStatus:
    """Fresh read-only state: off, on, paused, problem, partial or unknown, with one suggested fix."""
    try:
        facts = collect(paths)
        report = evaluate(facts)
        parts = {c['id']: c['status'] for c in report.get('checks', [])}
        task = (facts.get('tasks') or {}).get(config.CONTROLLER_TASK)
    except Exception as exc:
        return ProtectionStatus(ProtectionState.UNKNOWN, error_type=error_kind(exc))
    try:
        last = status(paths).get('last_report') or {}
    except (SafetyError, OSError, ValueError):
        last = {}
    try:
        profile = remote(paths)
    except (SafetyError, OSError, ValueError):
        profile = None
    if profile is not None:
        proxy = ProxyKind.HTTP if profile.get('adapter') == remote_backend.HTTP_ADAPTER else ProxyKind.SOCKS5
    else:
        proxy = ProxyKind.VLESS if parts.get('backend_task') == Check.OK else None
    saved = parts.get('backend_task') == Check.OK and parts.get('connection_profile') == Check.OK
    controller = parts.get('controller_task') == Check.OK and parts.get('controller_files') == Check.OK
    found = {'proxy': proxy, 'proxy_saved': saved,
             'clients': tuple(ClientFound(key, parts.get(key) == Check.OK) for key in CLIENTS)}
    if report.get('protection') == ProtectionLevel.INSTALLED:
        return ProtectionStatus(ProtectionState.ON, **found)
    if controller and task == 'Disabled' and parts.get('relay_listening') != Check.OK:
        # The owner paused the protection: its task is switched off, Claude goes out directly.
        return ProtectionStatus(ProtectionState.PAUSED, fix=Fix.RESUME, **found)
    if controller:
        reason = last.get('stop_reason')
        return ProtectionStatus(ProtectionState.PROBLEM, fix=STOP_FIXES.get(reason, Fix.RESTART), stop_reason=reason,
                                **found)
    if report.get('protection') == ProtectionLevel.PARTIAL and any(
            parts.get(k) == Check.OK for k in ('isolation_package', 'consent', 'controller_files', 'controller_task')):
        return ProtectionStatus(ProtectionState.PARTIAL, fix=Fix.INSTALL, **found)
    return ProtectionStatus(ProtectionState.OFF, **found)


class L1:
    """The L1 reads and operations the windows reach through these scenarios: the port tests replace."""

    def check(self, paths) -> dict:
        return l1_check.check(paths)

    def report(self, paths) -> dict:
        return controller_status.status(paths)

    def boundaries(self) -> list[str]:
        return l1_consent.open_boundaries()

    def install(self, paths, **options: object) -> dict:
        return l1_install.run(paths, **options)

    def restart(self, paths, **options: object) -> dict:
        return l1_install.restart(paths, **options)

    def remove(self, paths) -> dict:
        return l1_remove.run(paths)


def open_boundaries(paths, *, l1: L1 = L1()) -> list[str]:
    """The L1 boundaries open right now, which the owner accepts by installing."""
    return l1.boundaries()


def details(paths, *, l1: L1 = L1()) -> ProtectionDetails:
    """The readiness check of each part, the controller's last report and whether an install can start."""
    fresh = l1.check(paths)
    last = l1.report(paths).get('last_report') or {}
    return ProtectionDetails(parts=MappingProxyType({c['id']: c['status'] for c in fresh.get('checks', [])}),
                             last_report=MappingProxyType(last), can_install=fresh.get('can_install'))


def run_action(paths, action, *, protect_extension=None, proxy_draft=None, l1: L1 = L1()) -> ActionResult:
    """One protection action of a window: install, reinstall, restart, change_proxy, extension or remove."""
    if action in ('install', 'reinstall'):
        return ActionResult.of(l1.install(paths, confirmed=True, protect_extension=protect_extension,
                                          reinstall_controller=action == 'reinstall'))
    if action == 'restart':
        return ActionResult.of(l1.restart(paths))
    if action == 'change_proxy':
        if proxy_draft is None or proxy_draft.expected is None:
            return ActionResult(Protection.PROXY_CONFIRMATION_REQUIRED)
        return ActionResult.of(l1.restart(paths, proxy_draft=proxy_draft))
    if action == 'extension':
        if protect_extension is None:
            return ActionResult(Protection.EXTENSION_CHOICE_REQUIRED)
        return ActionResult.of(l1.restart(paths, protect_extension=protect_extension))
    if action == 'remove':
        return ActionResult.of(l1.remove(paths))
    raise ValueError('Unknown protection action')
