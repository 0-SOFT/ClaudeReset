"""Read current process tokens and Cowork presence; never authorize from a snapshot."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
from . import netguard
from .windows import ps_json


LOCAL_METADATA_SCRIPT = r'''
$r=@{}
try {$r.family=[string][Windows.ApplicationModel.Package,Windows.ApplicationModel,ContentType=WindowsRuntime]::Current.Id.FamilyName} catch {$r.family='unavailable'}
try {
 $device=[Windows.Devices.Enumeration.DeviceAccessInformation,Windows.Devices.Enumeration,ContentType=WindowsRuntime]::CreateFromDeviceClass([Windows.Devices.Enumeration.DeviceClass,Windows.Devices.Enumeration,ContentType=WindowsRuntime]::Location)
 $r.location_status=[string]$device.CurrentStatus
} catch {$r.location_status='unavailable'}
try {
 $r.non_loopback_adapters=[string]@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {$_.NetworkInterfaceType -ne [Net.NetworkInformation.NetworkInterfaceType]::Loopback}).Count
} catch {$r.non_loopback_adapters='unavailable'}
$r | ConvertTo-Json -Compress
'''


def local_metadata_probe():
    rows = []
    for package in (netguard.DESKTOP_PACKAGE, netguard.OWNED_PACKAGE):
        try:
            value = netguard.in_package(package, LOCAL_METADATA_SCRIPT)
            count = value.get('non_loopback_adapters', '')
            rows.append({'identity_matches': value.get('family') == package[0],
                         'location_status': value.get('location_status', 'unavailable'),
                         'non_loopback_adapters_visible': int(count) if count.isdigit() else None})
        except Exception as exc:
            rows.append({'identity_matches': False, 'error_type': type(exc).__name__})
    return {'packages': rows, 'network_requests': 0, 'coordinates_requested': False,
            'ip_or_mac_addresses_read': False, 'permission_prompt_requested': False,
            'settings_changed': False,
            'limits': ['A Windows socket filter does not hide network-adapter metadata',
                       'Location permission state is not an IP geolocation measurement']}


def summarize(rows, hcs):
    scoped = [r for r in rows if r.get('scoped')]
    unreadable = sum(r.get('token_read_failed', False) for r in scoped)
    contained = sum(r.get('appcontainer') is True and r.get('capability_count') == 0 for r in scoped)
    escapes = sum(bool(r.get('descendant')) and not r.get('protected_identity') for r in scoped)
    return {'status': 'isolation_audit_completed', 'passed': False, 'full_tunnel_verified': False,
            'read_only': True, 'network_requests': 0, 'processes_changed': False,
            'protected_processes_observed': len(scoped), 'no_capability_appcontainer_processes': contained,
            'full_trust_or_unverified_processes': len(scoped) - contained,
            'unreadable_protected_tokens': unreadable, 'descendants_without_protected_identity': escapes,
            'claude_processes_outside_protected_scope': sum(not r.get('scoped') for r in rows),
            'cowork_service_observed': any(r.get('kind', '').lower() == 'cowork-svc.exe' for r in rows),
            'cowork_service_within_protected_scope': any(r.get('kind', '').lower() == 'cowork-svc.exe' for r in scoped),
            'cowork': hcs,
            'full_pc_file_access_required': True,
            'blockers': ['DNS and system-service delegation are not contained for current clients',
                         'Cowork guest coverage after the new boundary is not verified',
                         'Local network-adapter metadata remains visible or unverified'],
            'limits': ['This is a process snapshot, not proof of future children or all IPC',
                       'A missing or stopped Cowork VM is not a passing guest-network test']}


def process_token(pid):
    k = C.WinDLL('kernel32', use_last_error=True)
    a = C.WinDLL('advapi32', use_last_error=True)
    k.OpenProcess.argtypes, k.OpenProcess.restype = [W.DWORD, W.BOOL, W.DWORD], W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    k.GetPackageFamilyName.argtypes = [W.HANDLE, C.POINTER(W.UINT), W.LPWSTR]
    a.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)]
    a.GetTokenInformation.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    handle = k.OpenProcess(0x1000, False, pid)
    token = W.HANDLE()
    if not handle:
        return {'token_read_failed': True}
    try:
        n = W.UINT()
        result = {'package': None, 'token_read_failed': True}
        code = k.GetPackageFamilyName(handle, C.byref(n), None)
        if code == 122 and 0 < n.value <= 1024:
            value = C.create_unicode_buffer(n.value)
            if k.GetPackageFamilyName(handle, C.byref(n), value) == 0:
                result['package'] = value.value
        elif code != 15700:
            return result
        if not a.OpenProcessToken(handle, 8, C.byref(token)):
            return result
        needed, flag = W.DWORD(), W.DWORD()
        if not a.GetTokenInformation(token, 29, C.byref(flag), 4, C.byref(needed)):
            return result
        result['appcontainer'] = bool(flag.value)
        a.GetTokenInformation(token, 30, None, 0, C.byref(needed))
        if not 4 <= needed.value <= 65536:
            return result
        buffer = C.create_string_buffer(needed.value)
        if not a.GetTokenInformation(token, 30, buffer, len(buffer), C.byref(needed)):
            return result
        result.update(capability_count=W.DWORD.from_buffer(buffer).value, token_read_failed=False)
        return result
    finally:
        if token:
            k.CloseHandle(token)
        k.CloseHandle(handle)


def audit(paths):
    census = ps_json("@{rows=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)} | ConvertTo-Json -Depth 4 -Compress")
    records = {r['ProcessId']: r for r in (census or {}).get('rows', [])}
    tokens, protected = {}, set()
    families = (netguard.DESKTOP_PACKAGE[0], netguard.OWNED_PACKAGE[0])
    standalone = os.path.normcase(str(paths.home / '.local/bin/claude.exe'))
    for pid, record in records.items():
        if str(record.get('Name', '')).lower() not in ('claude.exe', 'claude-desktop.exe', 'cowork-svc.exe', 'code.exe', 'chrome.exe'):
            continue
        value = tokens[pid] = process_token(pid)
        if value.get('package') in families or os.path.normcase(record.get('ExecutablePath') or '') == standalone:
            protected.add(pid)
    descendants = set(protected)
    for _ in records:
        extra = {pid for pid, r in records.items() if r['ParentProcessId'] in descendants} - descendants
        if not extra:
            break
        descendants |= extra
    selected = descendants | {pid for pid, r in records.items() if str(r.get('Name', '')).lower() in ('claude.exe', 'claude-desktop.exe', 'cowork-svc.exe')}
    rows = []
    for pid in selected:
        value = tokens[pid] if pid in tokens else process_token(pid)
        rows.append(dict(value, kind=records[pid]['Name'], scoped=pid in descendants, descendant=pid not in protected,
                         protected_identity=value.get('package') in families or pid in protected))
    hcs = {'inventory_verified': False, 'guest_verified': False, 'running_guests': None}
    try:
        process = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/hcsdiag.exe'), 'list', '-raw'],
                                 capture_output=True, timeout=10, creationflags=0x08000000)
        if process.returncode == 0:
            systems = json.loads(process.stdout.decode('utf-8-sig'))
            if isinstance(systems, list) and all(isinstance(s, dict) for s in systems):
                guests = [s for s in systems if 'cowork' in str(s.get('Owner', '')).lower()]
                hcs.update(inventory_verified=True, running_guests=sum(s.get('State') == 'Running' for s in guests), observed_guests=len(guests))
        else:
            hcs['reason'] = 'elevated_inventory_required_or_unavailable'
    except (OSError, ValueError, subprocess.TimeoutExpired):
        hcs['reason'] = 'inventory_unavailable'
    result = summarize(rows, hcs)
    result['local_metadata'] = local_metadata_probe()
    return result
