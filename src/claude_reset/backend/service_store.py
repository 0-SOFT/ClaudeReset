"""Read-only validation of the administrator-owned gateway installation.

Ordinary user file access is preserved. The service's executable/configuration
must already be protected by Windows ACLs before a reservation is installed.
"""
from __future__ import annotations
from pathlib import Path
from ..errors import SafetyError
from .. import config
from .. import layout
from ..windows.service_security import OWNERS
from ..windows.folders import program_files
from ..windows.folders import acl_rows

# Write data/append/EA/attributes, delete-child/delete, change DACL/owner and
# generic all/write. Deny ACEs do not grant authority and need no exclusion.
WRITE_MASK = 2 | 4 | 16 | 64 | 256 | 65536 | 262144 | 524288 | 0x10000000 | 0x40000000


def validate_acl(row, *, directory=False):
    if not isinstance(row, dict) or row.get('owner') not in OWNERS or row.get('reparse') is not False:
        raise SafetyError('Gateway files must have a trusted owner and no reparse points')
    if directory and row.get('protected') is not True:
        raise SafetyError('The gateway installation directory must have a protected DACL')
    rules = row.get('rules')
    if not isinstance(rules, list) or not rules:
        raise SafetyError('Gateway ACL could not be read')
    trusted_writers = set()
    for rule in rules:
        if not isinstance(rule, dict) or type(rule.get('rights')) is not int or rule.get('type') not in ('Allow','Deny') or not isinstance(rule.get('sid'),str):
            raise SafetyError('Unknown gateway ACL entry')
        if rule['type'] == 'Allow' and rule['rights'] & WRITE_MASK:
            if rule['sid'] not in OWNERS:
                raise SafetyError('An ordinary principal can change gateway files')
            trusted_writers.add(rule['sid'])
    if not OWNERS <= trusted_writers:
        raise SafetyError('The dedicated service and administrators must retain installation control')


def verify_image(executable, service):
    root=program_files()
    if service==config.GATEWAY_SERVICE:
        folder=root/layout.PRODUCT/'Gateway'
        directories=[root/layout.PRODUCT,folder]
        name='ClaudeResetGateway.exe'
        config_name='gateway.json'
    elif service==config.BACKEND_SERVICE:
        folder=root/layout.PRODUCT/'Engine'
        directories=[root/layout.PRODUCT,folder]
        name='engine.exe'
        config_name='engine.json'
    elif service==config.GATEWAY_FIXTURE_SERVICE:
        folder=root/service
        directories=[folder]
        name='ClaudeResetGateway.exe'
        config_name='gateway.json'
    elif service==config.BACKEND_FIXTURE_SERVICE:
        folder=root/service
        directories=[folder]
        name='engine.exe'
        config_name='engine.json'
    else:
        raise SafetyError('Unknown gateway service')
    executable=Path(executable)
    if executable != folder/name:
        raise SafetyError('Gateway image must reside in its dedicated Program Files directory')
    # Include the config if present; staging the port before writing the config
    # grants no file write rights and creates no client permit.
    paths=[*directories,executable]
    if (folder/config_name).exists():
        paths.append(folder/config_name)
    return verify_paths(paths, directories)


def verify_paths(paths, directories):
    """Inspect a caller's fixed local installation path set, without mutation."""
    from ..safeio import local_path
    from ..safeio import guarded, local_volume
    paths = [Path(path) for path in paths]
    directories = {Path(path) for path in directories}
    for path in paths:
        local_path(str(path))
        guarded(local_volume(path), path, allow_root=True)
    result=acl_rows(paths)
    rows=(result or {}).get('rows')
    if not isinstance(rows,list) or len(rows)!=len(paths):
        raise SafetyError('Incomplete gateway ACL inspection')
    for path,row in zip(paths,rows):
        if row.get('path')!=str(path):
            raise SafetyError('Gateway ACL target changed')
        validate_acl(row,directory=path in directories)
    return {'passed':True,'files_checked':len(paths),'settings_changed':False}
