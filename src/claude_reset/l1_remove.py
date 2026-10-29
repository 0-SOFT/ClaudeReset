"""One command that takes L1 protection off this PC again, in the reverse order of l1_install.

  close controller -> autostart off (UAC) -> remove filters and Desktop policy (UAC) -> backend -> package (UAC)
  -> consent and exclusion flag -> verify
Protected clients (Desktop, the standalone CLI) have no network from the moment the controller stops until the
filters are removed, which is why the three UAC prompts follow each other without other work in between.
An unresolved elevation blocks another run; only confirmed steps permit continuation.
"""
import time

from . import backend_install, remote_backend, connections, l1_check, l1_consent, package_isolation, strict_guard
from .l1_install import EXCLUDE_FLAG
from .uac_request import serialized


def wait_relay_gone(seconds=60, sleep=time.sleep, clock=time.monotonic):
    from . import l1_mechanism
    deadline = clock() + seconds
    while clock() < deadline:
        if l1_mechanism.connect('127.0.0.1', strict_guard.GATE_PORT, .3) != 'connected':
            return True
        sleep(1)
    return False


class Deps:
    @staticmethod
    def pending(paths):
        from .uac_request import blocked
        return blocked(paths)

    check = staticmethod(l1_check.check)
    wait_relay_gone = staticmethod(wait_relay_gone)

    @staticmethod
    def wait_controller_idle():
        from .l1_install import wait_task_idle
        return wait_task_idle()

    @staticmethod
    def request_close(paths):
        return strict_guard.request_close(paths)

    @staticmethod
    def autostart_off(paths):
        return strict_guard.elevated_autostart(paths, enable=False)

    @staticmethod
    def remove_filters(paths):
        return strict_guard.elevated_remove(paths)

    @staticmethod
    def remove_backend(paths):
        remote_backend.remove(paths)
        return backend_install.remove(paths)

    @staticmethod
    def remove_package(paths):
        return package_isolation.dispatch(paths, '--l1-package-remove-serve', 'package-remove-')

    @staticmethod
    def remove_connection_profile(paths):
        return connections.remove(paths)

    @staticmethod
    def revoke_consent(paths):
        return l1_consent.revoke(strict_guard.directory(paths))


@serialized('l1_remove', completed={'removed'})
def run(paths, *, deps=None, clock=time.time):
    d = deps or Deps()
    report = {'schema': 1, 'action': 'l1_remove', 'finished': False, 'steps': []}

    def stop(status, step, **extra):
        report['steps'].append({'step': step, 'status': 'stopped', **extra})
        report.update(status=status, finished=True)
        return report

    def ok(step, **extra):
        report['steps'].append({'step': step, 'status': 'ok', **extra})
    folder = strict_guard.directory(paths)
    try:
        if d.pending(paths):
            return stop('pending_elevation', 'pending')
        before = d.check(paths)
        checks = {c['id']: c['status'] for c in before.get('checks', [])}
        ok('check', protection=before.get('protection'))
        if any(checks.get(key) == 'ok' for key in ('relay_listening', 'controller_task', 'controller_files')):
            receipt = d.request_close(paths)
            if receipt.get('status') != 'strict_close_requested' or receipt.get('retry_blocked'):
                return stop('controller_not_stopped', 'close')
            if not d.wait_relay_gone():
                return stop('controller_not_stopped', 'close', next='Проверьте status.json контроллера; фильтры не удалялись')
        if not d.wait_controller_idle():
            return stop('controller_not_stopped', 'close')
        ok('controller_stopped')
        if checks.get('controller_task') == 'ok' or checks.get('controller_files') == 'ok':
            receipt = d.autostart_off(paths)
            if receipt.get('passed') is not True:
                return stop('autostart_not_removed', 'autostart', detail=receipt.get('status'))
        ok('autostart_off')
        receipt = d.remove_filters(paths)
        if receipt.get('passed') is not True:
            return stop('filters_not_removed', 'filters', detail=receipt.get('status'))
        ok('filters_removed')
        backend = d.remove_backend(paths)
        if backend.get('status') not in ('removed',):
            return stop('backend_not_removed', 'backend', detail=backend.get('status'), error=backend.get('error'))
        ok('backend_removed')
        if checks.get('isolation_package') == 'ok':
            package = d.remove_package(paths)
            if package.get('passed') is not True:
                return stop('package_not_removed', 'package', detail=package.get('status'), error=package.get('error'))
        ok('package_removed')
        d.revoke_consent(paths)
        (folder / EXCLUDE_FLAG).unlink(missing_ok=True)
        ok('consent_and_flag_removed')
        if not d.remove_connection_profile(paths):
            return stop('connection_profile_not_removed', 'connection_profile')
        ok('connection_profile_removed')
        after = d.check(paths)
        ok('verify', protection=after.get('protection'))
        report.update(status='removed' if after.get('protection') == 'not_installed' else 'removed_with_leftovers', finished=True)
    except BaseException as exc:
        report.update(status='failed', error=type(exc).__name__ + ': ' + str(exc)[:200], finished=True)
    return report
