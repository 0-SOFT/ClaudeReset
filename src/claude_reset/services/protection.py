"""The protection as a whole: one state, the fix to suggest and what was found. The windows word it themselves."""
from __future__ import annotations
from types import MappingProxyType

from ..network import controller_status, l1_check, l1_consent, l1_install, l1_remove, remote_backend
from .. import config
from ..model.status import Check, Protection, ProtectionLevel, ProtectionState

__all__ = ['CLIENTS', 'L1', 'STOP_FIXES', 'details', 'open_boundaries', 'run_action', 'state']

# What the person can do about each reason the controller stopped; any other reason: restart.
STOP_FIXES = MappingProxyType({
    'exit_mismatch': 'accept_exit',
    'proxy_unreachable': 'retry',
    'exit_probe_failed': 'retry',
    'backend_changed': 'retry',
    'backend_config_failed': 'reenter',
    'profile_changed': 'restart',
    'monitor_error': 'restart',
    'exception': 'restart',
})
# The readiness checks that find each Claude client.
CLIENTS = ('client_desktop', 'client_standalone_cli', 'client_vscode_extension')


def state(paths, *, collect=l1_check.collect, evaluate=l1_check.evaluate, status=controller_status.status,
          remote=remote_backend.load) -> dict:
    """Fresh read-only state: off, on, paused, problem, partial or unknown, with one suggested fix."""
    try:
        facts = collect(paths)
        report = evaluate(facts)
        parts = {c['id']: c['status'] for c in report.get('checks', [])}
        task = (facts.get('tasks') or {}).get(config.CONTROLLER_TASK)
    except Exception:
        return {'state': ProtectionState.UNKNOWN, 'fix': None, 'proxy': None, 'proxy_saved': False, 'clients': []}
    try:
        last = status(paths).get('last_report') or {}
    except Exception:
        last = {}
    try:
        profile = remote(paths)
    except Exception:
        profile = None
    if profile is not None:
        proxy = 'HTTP' if profile.get('adapter') == remote_backend.HTTP_ADAPTER else 'SOCKS5'
    else:
        proxy = 'VLESS' if parts.get('backend_task') == Check.OK else None
    saved = parts.get('backend_task') == Check.OK and parts.get('connection_profile') == Check.OK
    controller = parts.get('controller_task') == Check.OK and parts.get('controller_files') == Check.OK
    clients = [{'check': key, 'present': parts.get(key) == Check.OK} for key in CLIENTS]
    base = {'proxy': proxy, 'proxy_saved': saved, 'clients': clients}
    if report.get('protection') == ProtectionLevel.INSTALLED:
        return dict(base, state=ProtectionState.ON, fix=None)
    if controller and task == 'Disabled' and parts.get('relay_listening') != Check.OK:
        # The owner paused the protection: its task is switched off, Claude goes out directly.
        return dict(base, state=ProtectionState.PAUSED, fix='resume')
    if controller:
        reason = last.get('stop_reason')
        return dict(base, state=ProtectionState.PROBLEM, stop_reason=reason, fix=STOP_FIXES.get(reason, 'restart'))
    if report.get('protection') == ProtectionLevel.PARTIAL and any(
            parts.get(k) == Check.OK for k in ('isolation_package', 'consent', 'controller_files', 'controller_task')):
        return dict(base, state=ProtectionState.PARTIAL, fix='install')
    return dict(base, state=ProtectionState.OFF, fix=None)


class L1:
    """The L1 reads and operations the windows reach through these scenarios; a test passes scripted ones."""

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


def open_boundaries(paths, *, l1: L1 | None = None) -> list[str]:
    """The L1 boundaries open right now, which the owner accepts by installing."""
    return (l1 or L1()).boundaries()


def details(paths, *, l1: L1 | None = None) -> dict:
    """The readiness check of each part, the controller's last report and whether an install can start."""
    l1 = l1 or L1()
    fresh = l1.check(paths)
    last = l1.report(paths).get('last_report') or {}
    return {'parts': {c['id']: c['status'] for c in fresh.get('checks', [])}, 'last_report': last,
            'can_install': fresh.get('can_install')}


def run_action(paths, action, *, protect_extension=None, proxy_draft=None, l1: L1 | None = None) -> dict:
    """One protection action of a window: install, reinstall, restart, change_proxy, extension or remove."""
    l1 = l1 or L1()
    if action in ('install', 'reinstall'):
        return l1.install(paths, confirmed=True, protect_extension=protect_extension,
                          reinstall_controller=action == 'reinstall')
    if action == 'restart':
        return l1.restart(paths)
    if action == 'change_proxy':
        if proxy_draft is None or proxy_draft.expected is None:
            return {'status': Protection.PROXY_CONFIRMATION_REQUIRED}
        return l1.restart(paths, proxy_draft=proxy_draft)
    if action == 'extension':
        if protect_extension is None:
            return {'status': Protection.EXTENSION_CHOICE_REQUIRED}
        return l1.restart(paths, protect_extension=protect_extension)
    if action == 'remove':
        return l1.remove(paths)
    raise ValueError('Unknown protection action')
