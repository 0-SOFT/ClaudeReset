"""Read-only validation of the administrator-owned gateway installation.

Ordinary user file access is preserved. The service's executable/configuration
must already be protected by Windows ACLs before a reservation is installed.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
from .safeio import SafetyError
from .windows import ps_json
from .netguard import psq

OWNERS = {'S-1-5-18', 'S-1-5-32-544'}
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


def program_files():
    shell=C.WinDLL('shell32')
    shell.SHGetFolderPathW.argtypes=[W.HWND,C.c_int,W.HANDLE,W.DWORD,W.LPWSTR]
    shell.SHGetFolderPathW.restype=C.c_long
    value=C.create_unicode_buffer(260)
    if shell.SHGetFolderPathW(None,0x26,None,0,value)!=0 or not value.value:
        raise SafetyError('The Windows Program Files location is unavailable')
    return Path(value.value)


def verify_image(executable, service):
    root=program_files()
    if service=='ClaudeResetGateway':
        folder=root/'ClaudeReset'/'Gateway';directories=[root/'ClaudeReset',folder]
        name='ClaudeResetGateway.exe';config_name='gateway.json'
    elif service=='ClaudeResetBackend':
        folder=root/'ClaudeReset'/'Engine';directories=[root/'ClaudeReset',folder]
        name='engine.exe';config_name='engine.json'
    elif service=='ClaudeResetGatewayFixture':
        folder=root/service;directories=[folder]
        name='ClaudeResetGateway.exe';config_name='gateway.json'
    elif service=='ClaudeResetBackendFixture':
        folder=root/service;directories=[folder]
        name='engine.exe';config_name='engine.json'
    else:raise SafetyError('Unknown gateway service')
    executable=Path(executable)
    if executable != folder/name:
        raise SafetyError('Gateway image must reside in its dedicated Program Files directory')
    # Include the config if present; staging the port before writing the config
    # grants no file write rights and creates no client permit.
    paths=[*directories,executable]
    if (folder/config_name).exists():paths.append(folder/config_name)
    return verify_paths(paths, directories)


def verify_paths(paths, directories):
    """Inspect a caller's fixed local installation path set, without mutation."""
    from .gateway_profile import local_path
    from .safeio import guarded, local_volume
    paths = [Path(path) for path in paths]
    directories = {Path(path) for path in directories}
    for path in paths:
        local_path(str(path))
        guarded(local_volume(path), path, allow_root=True)
    values=','.join(psq(str(p)) for p in paths)
    result=ps_json("@{rows=@("+values+"|ForEach-Object {$p=$_;$a=Get-Acl -LiteralPath $p -ErrorAction Stop;$f=Get-Item -LiteralPath $p -Force -ErrorAction Stop;@{path=$p;owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value;protected=$a.AreAccessRulesProtected;reparse=[bool]($f.Attributes -band [IO.FileAttributes]::ReparsePoint);rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {@{sid=$_.IdentityReference.Value;rights=[long]$_.FileSystemRights;type=[string]$_.AccessControlType}})}})}|ConvertTo-Json -Depth 6 -Compress")
    rows=(result or {}).get('rows')
    if not isinstance(rows,list) or len(rows)!=len(paths):raise SafetyError('Incomplete gateway ACL inspection')
    for path,row in zip(paths,rows):
        if row.get('path')!=str(path):raise SafetyError('Gateway ACL target changed')
        validate_acl(row,directory=path in directories)
    return {'passed':True,'files_checked':len(paths),'settings_changed':False}
