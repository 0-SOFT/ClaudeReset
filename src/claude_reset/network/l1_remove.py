"""One command that takes L1 protection off this PC again, in the reverse order of l1_install.

  close controller -> autostart off (UAC) -> remove filters and Desktop policy (UAC) -> backend -> package (UAC)
  -> consent and exclusion flag -> verify
Protected clients (Desktop, the standalone CLI) have no network from the moment the controller stops until the
filters are removed, which is why the three UAC prompts follow each other without other work in between.
An unresolved elevation blocks another run; only confirmed steps permit continuation.
"""
import time

from ..backend import install as backend_install
from . import autostart, controller, remote_backend, connections, l1_check, l1_consent, package_isolation
from ..elevation.claims import serialized
from ..errors import error_info
from ..model.status import Backend, Check, Network, Protection, ProtectionLevel
from ..model.status import NextAction
from .l1_common import wait_relay_gone, wait_task_idle
from .. import layout
from ..model.report import OperationReport


class Deps:
    @staticmethod
    def pending(paths):
        from ..elevation.claims import blocked
        return blocked(paths)

    check = staticmethod(l1_check.check)
    wait_relay_gone = staticmethod(wait_relay_gone)

    @staticmethod
    def wait_controller_idle():
        return wait_task_idle()

    @staticmethod
    def request_close(paths):
        return controller.request_close(paths)

    @staticmethod
    def autostart_off(paths):
        return autostart.elevated(paths, enable=False)

    @staticmethod
    def remove_filters(paths):
        return controller.elevated_remove(paths)

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
        return l1_consent.revoke(layout.controller(paths))


@serialized('l1_remove', completed={Protection.REMOVED})
def run(paths, *, deps=None, clock=time.time):
    d = deps or Deps()
    report = OperationReport('l1_remove')
    folder = layout.controller(paths)
    try:
        if d.pending(paths):
            return report.stop(Protection.PENDING_ELEVATION, 'pending')
        before = d.check(paths)
        checks = {c['id']: c['status'] for c in before.get('checks', [])}
        report.ok('check', protection=before.get('protection'))
        if any(checks.get(key) == Check.OK for key in ('relay_listening', 'controller_task', 'controller_files')):
            receipt = d.request_close(paths)
            if receipt.get('status') != Network.STRICT_CLOSE_REQUESTED or receipt.get('retry_blocked'):
                return report.stop(Protection.CONTROLLER_NOT_STOPPED, 'close')
            if not d.wait_relay_gone():
                return report.stop(Protection.CONTROLLER_NOT_STOPPED, 'close', next=NextAction.CHECK_CONTROLLER_STATUS, filters_removed=False)
        if not d.wait_controller_idle():
            return report.stop(Protection.CONTROLLER_NOT_STOPPED, 'close')
        report.ok('controller_stopped')
        if checks.get('controller_task') == Check.OK or checks.get('controller_files') == Check.OK:
            receipt = d.autostart_off(paths)
            if receipt.get('passed') is not True:
                return report.stop(Protection.AUTOSTART_NOT_REMOVED, 'autostart', detail=receipt.get('status'))
        report.ok('autostart_off')
        receipt = d.remove_filters(paths)
        if receipt.get('passed') is not True:
            return report.stop(Protection.FILTERS_NOT_REMOVED, 'filters', detail=receipt.get('status'))
        report.ok('filters_removed')
        backend = d.remove_backend(paths)
        if backend.get('status') not in (Backend.REMOVED,):
            return report.stop(Protection.BACKEND_NOT_REMOVED, 'backend', detail=backend.get('status'), error=backend.get('error'))
        report.ok('backend_removed')
        if checks.get('isolation_package') == Check.OK:
            package = d.remove_package(paths)
            if package.get('passed') is not True:
                return report.stop(Protection.PACKAGE_NOT_REMOVED, 'package', detail=package.get('status'), error=package.get('error'))
        report.ok('package_removed')
        d.revoke_consent(paths)
        (folder / layout.EXTENSION_EXCLUDED_FLAG).unlink(missing_ok=True)
        report.ok('consent_and_flag_removed')
        if not d.remove_connection_profile(paths):
            return report.stop(Protection.CONNECTION_PROFILE_NOT_REMOVED, 'connection_profile')
        report.ok('connection_profile_removed')
        after = d.check(paths)
        report.ok('verify', protection=after.get('protection'))
        report.update(status=Protection.REMOVED if after.get('protection') == ProtectionLevel.NOT_INSTALLED else Protection.REMOVED_WITH_LEFTOVERS, finished=True)
    except Exception as exc:
        report.update(status=Protection.FAILED, error=error_info(exc), finished=True)
    return report
