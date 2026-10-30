"""Code run inside an app package (the Desktop package or the program's own isolation package), and the
package identity of this process."""
from __future__ import annotations
import base64
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import secrets
import tempfile
import time

from .api import Library
from ..errors import SafetyError
from ..safeio import guarded, remove_owned
from .powershell import executable, ps_json, quote
from collections.abc import Collection, Iterable
from typing import Any

__all__ = ['LOCAL_METADATA_PROBE', 'WORKER_KEYS', 'WORKER_PROBE', 'bootstrap', 'current_package', 'live_state', 'run_in_package',
           'split_command_line', 'worker_probe', 'dns_probe']


def current_package() -> str | None:
    kernel = Library('kernel32')
    length = wintypes.UINT()
    code = kernel.GetCurrentPackageFamilyName(ctypes.byref(length), None)
    if code == 15700:  # APPMODEL_ERROR_NO_PACKAGE
        return None
    if code != 122 or not 0 < length.value < 1024:
        raise SafetyError('Package identity of this process could not be read', code='package_identity_unread')
    buffer = ctypes.create_unicode_buffer(length.value)
    if kernel.GetCurrentPackageFamilyName(ctypes.byref(length), buffer):
        raise SafetyError('Package identity of this process could not be read', code='package_identity_unread')
    return buffer.value


def split_command_line(line: str) -> list[str]:
    """Windows argv rules, independent of the first-token special case."""
    shell32, kernel = Library('shell32'), Library('kernel32')
    count = ctypes.c_int()
    argv = shell32.CommandLineToArgvW('x ' + line, ctypes.byref(count))
    if not argv:
        raise SafetyError('Command line could not be parsed', code='command_line_unparsed')
    try:
        return [argv[i] for i in range(1, count.value)]
    finally:
        kernel.LocalFree(argv)


def live_state(pids: Iterable[int | None], *, ports: Iterable[int], owned_package: str, desktop_family: str) -> Any:
    """Processes by id, listeners on the given ports, proxy settings and both packages; read-only."""
    pids = [int(p) for p in pids if isinstance(p, int) and p > 0]
    process_filter = ' OR '.join(f'ProcessId={p}' for p in pids) or 'ProcessId=-1'
    return ps_json(f'''$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $processes = @(Get-CimInstance Win32_Process -Filter {quote(process_filter)} | ForEach-Object {{
      @{{pid=[int]$_.ProcessId; parent=[int]$_.ParentProcessId; path=[string]$_.ExecutablePath; command=[string]$_.CommandLine;
        created=$_.CreationDate.ToUniversalTime().ToString('o')}} }})
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort {','.join(str(port) for port in ports)} -ErrorAction SilentlyContinue | ForEach-Object {{
      @{{port=[int]$_.LocalPort; address=[string]$_.LocalAddress; pid=[int]$_.OwningProcess}} }})
    $inet = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
    $variables = @{{}}
    foreach ($scope in 'Machine','User') {{ foreach ($name in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY') {{
      $variables[$scope + ':' + $name] = -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, $scope)) }} }}
    $owned = Get-AppxPackage -Name {quote(owned_package)} | Select-Object -First 1
    $desktop = Get-AppxPackage -Name 'Claude' | Where-Object PackageFamilyName -eq {quote(desktop_family)} | Select-Object -First 1
    @{{boot=$boot; processes=$processes; listeners=$listeners;
      wininet=@{{proxy_enable=[int]$inet.ProxyEnable; auto_config=-not [string]::IsNullOrEmpty($inet.AutoConfigURL)}};
      proxy_variables=$variables; owned_package=[string]$owned.PackageFamilyName;
      desktop=@{{version=[string]$desktop.Version; location=[string]$desktop.InstallLocation}}}} | ConvertTo-Json -Depth 5 -Compress''')


WORKER_PROBE = r'''$ErrorActionPreference = 'Stop'
$r = [ordered]@{}
try { $r.family = [Windows.ApplicationModel.Package,Windows.ApplicationModel,ContentType=WindowsRuntime]::Current.Id.FamilyName } catch { $r.family = '' }
foreach ($t in @(@('v4','1.1.1.1','InterNetwork'), @('v6','2606:4700:4700::1111','InterNetworkV6'))) {
  $s = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]$t[2], [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
  try {
    $a = $s.BeginConnect([Net.IPAddress]::Parse($t[1]), 443, $null, $null)
    if ($a.AsyncWaitHandle.WaitOne(3000)) { $s.EndConnect($a); $v = 'connected' } else { $v = 'timeout' }
  } catch { $e = $_.Exception; while ($e -and -not ($e -is [Net.Sockets.SocketException])) { $e = $e.InnerException }; $v = if ($e) { [string]$e.ErrorCode } else { 'error' } }
  finally { $s.Dispose() }
  $r['tcp_' + $t[0]] = $v
}
foreach ($entry in __PORTS__) {
  $s = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
  try {
    $a=$s.BeginConnect([Net.IPAddress]::Loopback,[int]$entry[1],$null,$null)
    if($a.AsyncWaitHandle.WaitOne(2000)) {$s.EndConnect($a);$v='connected'} else {$v='timeout'}
  } catch {$e=$_.Exception;while($e -and -not($e -is [Net.Sockets.SocketException])){$e=$e.InnerException};$v=if($e){[string]$e.ErrorCode}else{'error'}}
  finally {$s.Dispose()}
  $r['tcp_'+$entry[0]]=$v
}
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $q = [Net.HttpWebRequest]::Create('https://example.com/'); $q.Method = 'HEAD'; $q.Timeout = 12000
  $q.Proxy = [Net.WebProxy]::new('__PROXY__')
  $p = $q.GetResponse(); $r.proxy_https = [string][int]$p.StatusCode; $p.Close()
} catch { $r.proxy_https = $_.Exception.GetType().Name }
__LAUNCH__
'{' + (($r.Keys | ForEach-Object { '"' + $_ + '":"' + (([string]$r[$_]) -replace '[^\w.:-]', '') + '"' }) -join ',') + '}'
'''


def worker_probe(proxy: str, ports: Iterable[tuple[str, int]], launch: str='') -> str:
    """WORKER_PROBE for one run: the proxy to test, (name, port) pairs to try on loopback, an optional launch."""
    ports = ','.join(f"@('{name}',{port})" for name, port in ports)
    return WORKER_PROBE.replace('__PROXY__', proxy).replace('__LAUNCH__', launch).replace('__PORTS__', f'@({ports})')


WORKER_KEYS = frozenset({'family', 'tcp_v4', 'tcp_v6', 'tcp_backend', 'tcp_controller', 'tcp_gate', 'proxy_https',
                         'launch', 'pid', 'location_status', 'non_loopback_adapters'})


def bootstrap(port: int, token: str) -> str:
    """Tiny in-package stub: proves the token, receives the script over loopback, returns one JSON line."""
    return ("$c=[Net.Sockets.TcpClient]::new('127.0.0.1'," + str(port) + ");$s=$c.GetStream();$e=[Text.UTF8Encoding]::new($false);"
            "$r=[IO.StreamReader]::new($s,$e);$w=[IO.StreamWriter]::new($s,$e);$w.AutoFlush=$true;$w.WriteLine('" + token + "');"
            "$t=$e.GetString([Convert]::FromBase64String($r.ReadLine()));$o=& ([scriptblock]::Create($t));"
            "$w.WriteLine([string]@($o)[-1]);$c.Close()")


def dns_probe(name: str, server: str) -> str:
    """A script for inside a package: its identity, and whether <name>.invalid resolves at server."""
    return ("$r=@{};try{$r.family=[Windows.ApplicationModel.Package,Windows.ApplicationModel,ContentType=WindowsRuntime]::Current.Id.FamilyName}catch{$r.family='ordinary'};"
            "try{Resolve-DnsName -Name '" + name + ".invalid' -Server " + server + " -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null;$r.proxy_https='resolved'}catch{$r.proxy_https='dns_error'};"
            "$r | ConvertTo-Json -Compress")


# Run inside a package: its identity, location access and how many non-loopback adapters it sees.
LOCAL_METADATA_PROBE = r'''
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


def _read_answer(path, root):
    path = guarded(path, root)
    if path.stat().st_size > 65536:
        raise SafetyError('Package worker answer is too large')
    return json.loads(path.read_text('utf-8-sig'))


def run_in_package(package: str, script: str, *, root: Path, keys: Collection[str], timeout: float=45.0) -> dict:
    """Run a script inside an app package and return its one JSON answer.

    Non-network IPC through files under root stays available while WFP denies all package sockets."""
    guarded(root, Path.home()).mkdir(exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='strict-', dir=root))
    response = folder / 'probe.json'
    token = secrets.token_hex(16)
    wrapper = ("$ErrorActionPreference='Stop'; $result=& {" + script + "}; "
               "$value=@{nonce='" + token + "'; result=([string]@($result)[-1] | ConvertFrom-Json)}; "
               "[IO.File]::WriteAllText(" + quote(response) + ",($value | ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))")
    encoded = base64.b64encode(wrapper.encode('utf-16-le')).decode()
    arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + encoded
    try:
        ps_json(f'Invoke-CommandInDesktopPackage -PackageFamilyName {quote(package[0])} -AppId {quote(package[1])} '
                f'-Command {quote(executable())} -Args {quote(arguments)} -PreventBreakaway')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if response.exists():
                try:
                    value = _read_answer(response, root)
                except json.JSONDecodeError:
                    time.sleep(.05)
                    continue
                result = value.get('result')
                if value.get('nonce') != token or not isinstance(result, dict) or set(result) - keys or not all(
                        isinstance(v, str) and len(v) <= 200 for v in result.values()):
                    raise SafetyError('Package worker returned an invalid result', code='package_worker_invalid')
                return result
            time.sleep(.05)
        raise SafetyError('Package worker did not report in time', code='package_worker_timeout')
    finally:
        remove_owned(folder, root)
