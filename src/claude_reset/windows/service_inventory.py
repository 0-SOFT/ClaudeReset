"""Read-only inventory of fixed installation slots, never service control."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from .api import Library
from .gateway_service import Config, Status
from ..errors import SafetyError
from .folders import program_files
from .. import config

__all__ = ['fresh_install_blockers', 'inspect', 'registry_slots', 'services']



def registry_slots(*, api=None) -> list[dict]:
    """Inspect fixed key objects without reading values or following final links; api is advapi32."""
    api = api or Library('advapi32')
    rows = []
    for name in config.BUNDLE_SERVICES:
        handle = W.HANDLE()
        key = 'SYSTEM\\CurrentControlSet\\Services\\' + name
        # OPEN_LINK, READ_CONTROL | QUERY_VALUE | 64-bit registry view only.
        status = api.RegOpenKeyExW(W.HANDLE(-2147483646), key, 8, 0x20101, C.byref(handle))
        row = dict(name=name, exists=None, inspected=False)
        if status == 2:
            row.update(exists=False, inspected=True)
        elif status == 0 and handle.value:
            closed = api.RegCloseKey(handle)
            row.update(exists=True, inspected=closed == 0)
            if closed:
                row['winerror'] = closed
        else:
            row['winerror'] = status
        rows.append(row)
    return rows


def services() -> list[dict]:
    api = Library('advapi32')
    manager = api.OpenSCManagerW(None, None, 1)
    if not manager:
        raise SafetyError('Cannot inspect the local service manager')
    rows = []
    try:
        for name in config.BUNDLE_SERVICES:
            service = api.OpenServiceW(manager, name, 1 | 4)  # QUERY_CONFIG | QUERY_STATUS only
            if not service:
                error = C.get_last_error()
                if error != 1060:
                    raise SafetyError('Service inventory is incomplete: ' + name)
                rows.append({'name': name, 'exists': False})
                continue
            try:
                needed = W.DWORD()
                api.QueryServiceConfigW(service, None, 0, C.byref(needed))
                if not C.sizeof(Config) <= needed.value <= 65536:
                    raise SafetyError('Invalid service configuration size: ' + name)
                buf = C.create_string_buffer(needed.value)
                if not api.QueryServiceConfigW(service, buf, len(buf), C.byref(needed)):
                    raise SafetyError('Cannot inspect service configuration: ' + name)
                cfg = Config.from_buffer(buf)
                status = Status()
                if not api.QueryServiceStatusEx(service, 0, C.byref(status), C.sizeof(status), C.byref(needed)):
                    raise SafetyError('Cannot inspect service status: ' + name)
                rows.append({'name': name, 'exists': True, 'binary': cfg.binary,
                    'type': cfg.type, 'start': cfg.start, 'account': cfg.account,
                    'state': status.state, 'pid': status.pid})
            finally:
                if not api.CloseServiceHandle(service):
                    raise SafetyError('Cannot close service inventory handle')
    finally:
        if not api.CloseServiceHandle(manager):
            raise SafetyError('Cannot close service inventory manager')
    return rows


def fresh_install_blockers(rows: list[dict], root_exists: bool) -> list[str]:
    """An executable path alone never establishes ownership of an existing slot."""
    if (not isinstance(rows, list) or len(rows) != len(config.BUNDLE_SERVICES)
            or any(not isinstance(r, dict) for r in rows)
            or [r.get('name') for r in rows] != list(config.BUNDLE_SERVICES)
            or any(type(r.get('exists')) is not bool for r in rows)
            or type(root_exists) is not bool):
        raise SafetyError('Incomplete installation inventory')
    blockers = [{'code': 'service_slot_occupied', 'service': row['name'],
                 'action': 'Require verified ownership and a separate migration transaction; do not stop or replace.'}
                for row in rows if row['exists']]
    if root_exists:
        blockers.append({'code': 'installation_directory_occupied',
                         'action': 'Require a protected ownership manifest; do not adopt existing files.'})
    return blockers


def inspect(*, folder=None, list_services=services, api=None) -> dict:
    """folder is Program Files, list_services reads the service manager and api is the registry (advapi32)."""
    root = (folder or program_files()) / config.PRODUCT_NAME
    # lstat, not exists: a dangling final reparse point is still an occupied slot.
    try:
        root.lstat()
        occupied = True
    except FileNotFoundError:
        occupied = False
    rows = list_services()
    registry = registry_slots(api=api)
    blockers = fresh_install_blockers(rows, occupied)
    for row in registry:
        if row['inspected'] is not True or row['exists'] is not False:
            blockers.append(dict(code='service_registry_slot_occupied' if row['inspected'] else
                                 'service_registry_slot_unverified', service=row['name'],
                                 action='Do not adopt, delete or replace the registry key.'))
    return {'schema': 2, 'root': str(root), 'root_occupied': occupied,
            'services': rows, 'registry_slots': registry, 'fresh_install_blockers': blockers,
            'settings_changed': False, 'client_admission': False,
            'limits': ['Snapshot only; repeat under the protected installer lock.',
                       'Signature, ACL, driver use and client inventory acceptance are separate requirements.']}
