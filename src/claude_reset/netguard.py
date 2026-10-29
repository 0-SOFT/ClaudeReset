"""Local Claude-only snow guard: read-only checks, opt-in probes and guarded launch.

The guard itself (loopback snow proxy task, scoped WFP filters, owned package identity)
is installed outside the program. Nothing here changes filters, proxy settings, routes,
DNS, firewall profiles or the router, and ordinary applications are never targeted.
"""
from __future__ import annotations
import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from .safeio import SafetyError, guarded, reparse
from .windows import DPAPI, ps_json
from .compatibility import LEGACY_REVIEW

TASK_NAME = 'ClaudeReset-SnowProxy'
PROXY_HOST, PROXY_PORT, CONTROLLER_PORT = '127.0.0.1', 25080, 25081
PROXY_URL = f'http://{PROXY_HOST}:{PROXY_PORT}'
NO_PROXY = 'localhost,127.0.0.1,::1'
DESKTOP_PACKAGE = ('Claude_pzs8sxrjxfjjc', 'Claude')
OWNED_PACKAGE = ('ClaudeReset.NetworkIsolation_79st3xwgefr0c', 'IsolatedTools')
# Builds whose network and permission code was reviewed together with the guard.
REVIEWED_DESKTOP = LEGACY_REVIEW['desktop']
REVIEWED_LAUNCH = LEGACY_REVIEW['launch']
REVIEWED_STANDALONE_CLI = LEGACY_REVIEW['standalone_code']
DEDICATED_EXTENSION = LEGACY_REVIEW['dedicated_extension']
PATH_FILTERED_EXTENSION = 'anthropic.claude-code-' + DEDICATED_EXTENSION[0] + '-win32-x64'
PROFILE_ID = re.compile(r'[a-f0-9]{32}')
CHROME_MARK = '.claude-local-isolation.json'
BOUNDARIES = [
    'Claude в обычных VS Code и Chrome вне защищённой области по решению владельца',
    'Статические проверки не измеряют маршрут роутера и не доказывают отсутствие делегированных запросов системных служб',
    'WFP-фильтры читаются только с правами администратора: отдельная проверка',
]


@dataclass(frozen=True)
class Guard:
    base: Path
    python: Path
    task: dict

    @property
    def work(self) -> Path:
        return self.base.parent


def powershell() -> Path:
    return Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


def current_package() -> str | None:
    kernel = ctypes.WinDLL('kernel32')
    length = wintypes.UINT()
    code = kernel.GetCurrentPackageFamilyName(ctypes.byref(length), None)
    if code == 15700:  # APPMODEL_ERROR_NO_PACKAGE
        return None
    if code != 122 or not 0 < length.value < 1024:
        raise SafetyError('Package identity of this process could not be read')
    buffer = ctypes.create_unicode_buffer(length.value)
    if kernel.GetCurrentPackageFamilyName(ctypes.byref(length), buffer):
        raise SafetyError('Package identity of this process could not be read')
    return buffer.value


def psq(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def split_command_line(line: str) -> list[str]:
    """Windows argv rules, independent of the first-token special case."""
    shell32 = ctypes.WinDLL('shell32')
    kernel = ctypes.WinDLL('kernel32')
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    count = ctypes.c_int()
    argv = shell32.CommandLineToArgvW('x ' + line, ctypes.byref(count))
    if not argv:
        raise SafetyError('Command line could not be parsed')
    try:
        return [argv[i] for i in range(1, count.value)]
    finally:
        kernel.LocalFree(argv)


def sha256(path: Path) -> str:
    with open(path, 'rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def same_path(a, b) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def guard_from_task(task: dict) -> Guard:
    """The installed logon task is the only accepted pointer to the guard files."""
    actions = task.get('actions') or []
    if len(actions) != 1:
        raise SafetyError('Unexpected snow proxy task actions')
    python = Path(actions[0].get('execute') or '')
    arguments = split_command_line(actions[0].get('arguments') or '')
    if python.name.lower() != 'pythonw.exe' or len(arguments) != 1 or Path(arguments[0]).name.lower() != 'proxy_worker.py':
        raise SafetyError('Unexpected snow proxy task actions')
    script = Path(arguments[0])
    if not script.is_absolute():
        raise SafetyError('Unexpected snow proxy task actions')
    guarded(script, Path(script.anchor))
    return Guard(script.parent, python, {k: task.get(k) for k in ('state', 'enabled', 'run_level')})


def locate_guard() -> Guard | None:
    task = ps_json(f'''$t = Get-ScheduledTask -TaskName {psq(TASK_NAME)} -ErrorAction SilentlyContinue
    if ($t) {{ @{{state=[string]$t.State; enabled=[bool]$t.Settings.Enabled; run_level=[string]$t.Principal.RunLevel;
      actions=@($t.Actions | ForEach-Object {{ @{{execute=[string]$_.Execute; arguments=[string]$_.Arguments}} }})}} | ConvertTo-Json -Depth 4 -Compress }}
    exit 0''')  # an absent task is a normal answer; SilentlyContinue leaves $? false and PowerShell exits 1
    return guard_from_task(task) if task else None


def read_json(path: Path, root: Path, limit=1_000_000):
    path = guarded(path, root)
    if path.stat().st_size > limit:
        raise SafetyError('Guard metadata file is too large')
    return json.loads(path.read_text('utf-8-sig'))


def check_proxy_config(cfg: dict) -> dict:
    """Shape of the decrypted engine config. Server, credentials and keys are never returned."""
    outbounds = cfg.get('outbounds') or []
    api = (cfg.get('experimental') or {}).get('clash_api') or {}
    result = {
        'single_snow_outbound': [o.get('tag') for o in outbounds] == ['snow-only'],
        'no_direct_fallback': cfg.get('route') == {'final': 'snow-only'} and not any(o.get('type') in ('direct', 'block', 'selector', 'urltest') for o in outbounds),
        'loopback_inbound_only': cfg.get('inbounds') == [{'type': 'http', 'tag': 'claude-loopback', 'listen': PROXY_HOST, 'listen_port': PROXY_PORT}],
        'controller_loopback': api.get('external_controller') == f'{PROXY_HOST}:{CONTROLLER_PORT}' and bool(api.get('secret')),
        'engine_log_disabled': cfg.get('log') == {'disabled': True},
    }
    result['passed'] = all(result.values())
    return result


def check_listeners(listeners: list, engine_pid) -> dict:
    ports = {}
    for row in listeners:
        ports.setdefault(int(row['port']), []).append(row)
    exposed = [r for r in listeners if r.get('address') != PROXY_HOST]
    foreign = [r for r in listeners if r.get('pid') != engine_pid]
    return {'proxy_listening': PROXY_PORT in ports, 'controller_listening': CONTROLLER_PORT in ports,
            'loopback_only': not exposed, 'owned_by_engine': bool(listeners) and not foreign,
            'passed': PROXY_PORT in ports and CONTROLLER_PORT in ports and not exposed and not foreign}


def live_state(pids) -> dict:
    pids = [int(p) for p in pids if isinstance(p, int) and p > 0]
    process_filter = ' OR '.join(f'ProcessId={p}' for p in pids) or 'ProcessId=-1'
    return ps_json(f'''$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $processes = @(Get-CimInstance Win32_Process -Filter {psq(process_filter)} | ForEach-Object {{
      @{{pid=[int]$_.ProcessId; parent=[int]$_.ParentProcessId; path=[string]$_.ExecutablePath; command=[string]$_.CommandLine;
        created=$_.CreationDate.ToUniversalTime().ToString('o')}} }})
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort {PROXY_PORT},{CONTROLLER_PORT} -ErrorAction SilentlyContinue | ForEach-Object {{
      @{{port=[int]$_.LocalPort; address=[string]$_.LocalAddress; pid=[int]$_.OwningProcess}} }})
    $inet = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue
    $variables = @{{}}
    foreach ($scope in 'Machine','User') {{ foreach ($name in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY') {{
      $variables[$scope + ':' + $name] = -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, $scope)) }} }}
    $owned = Get-AppxPackage -Name 'ClaudeReset.NetworkIsolation' | Select-Object -First 1
    $desktop = Get-AppxPackage -Name 'Claude' | Where-Object PackageFamilyName -eq {psq(DESKTOP_PACKAGE[0])} | Select-Object -First 1
    @{{boot=$boot; processes=$processes; listeners=$listeners;
      wininet=@{{proxy_enable=[int]$inet.ProxyEnable; auto_config=-not [string]::IsNullOrEmpty($inet.AutoConfigURL)}};
      proxy_variables=$variables; owned_package=[string]$owned.PackageFamilyName;
      desktop=@{{version=[string]$desktop.Version; location=[string]$desktop.InstallLocation}}}} | ConvertTo-Json -Depth 5 -Compress''')


def check_worker(guard: Guard, state: dict, live: dict) -> dict:
    by_pid = {p['pid']: p for p in live.get('processes') or []}
    worker, engine = by_pid.get(state.get('worker_pid')), by_pid.get(state.get('engine_pid'))
    boot = live['boot']
    profile = read_json(guard.base / 'profile.json', guard.base)
    result = {
        'state_running': state.get('state') == 'running',
        'worker_alive': bool(worker) and str(guard.base / 'proxy_worker.py').casefold() in (worker.get('command') or '').casefold(),
        'engine_child_of_worker': bool(worker and engine) and engine.get('parent') == worker['pid'] and same_path(engine.get('path') or '', profile['engine_path']),
        'started_after_boot': bool(worker) and worker['created'] > boot,
    }
    result['passed'] = all(result.values())
    return result


def check_engine_and_config(guard: Guard, *, crypto=None) -> dict:
    profile = read_json(guard.base / 'profile.json', guard.base)
    engine = guarded(Path(profile['engine_path']), guard.base / 'engine')
    result = {'engine_reviewed': engine.is_file() and sha256(engine) == profile['engine_sha256'], 'proxy_url': profile.get('proxy_url') == PROXY_URL}
    sealed = guarded(guard.base / 'snow-config.dpapi', guard.base)
    plain = (crypto or DPAPI()).decrypt(sealed.read_bytes())
    try:
        result['config_reviewed'] = hashlib.sha256(plain).hexdigest() == profile['config_sha256']
        result.update(check_proxy_config(json.loads(plain)))
    finally:
        del plain
    result['passed'] = all(v for k, v in result.items() if k != 'passed')
    return result


def check_dedicated_chrome(guard: Guard) -> Path:
    base = guarded(guard.work / 'claude-only-chrome', guard.work)
    candidates = [d for d in base.iterdir() if PROFILE_ID.fullmatch(d.name) and (d / CHROME_MARK).is_file()] if base.is_dir() else []
    if len(candidates) != 1:
        raise SafetyError('Expected exactly one dedicated Claude Chrome profile')
    directory = guarded(candidates[0], base)
    meta = read_json(directory / CHROME_MARK, directory)
    if not (meta.get('run') == directory.name and meta.get('scope') == 'claude_only' and meta.get('source_was_closed') is True
            and sha256(guarded(directory / 'claude-reset-profile.json', directory)) == meta.get('source_marker_sha256')):
        raise SafetyError('Dedicated Claude Chrome profile marker is invalid')
    profile = read_json(directory / 'Default/Preferences', directory, limit=20_000_000).get('profile', {})
    exceptions = profile.get('content_settings', {}).get('exceptions', {}).get('geolocation', {})
    if profile.get('default_content_setting_values', {}).get('geolocation') != 2 or not isinstance(exceptions, dict) \
            or not all(isinstance(v, dict) and v.get('setting') == 2 for v in exceptions.values()):
        raise SafetyError('Review geolocation permissions of the dedicated Chrome profile')
    return directory


def check_dedicated_editor(guard: Guard) -> tuple[Path, Path]:
    from .jsonc import read as read_jsonc
    base = guarded(guard.work / 'claude-only-editor', guard.work)
    candidates = [d for d in base.iterdir() if PROFILE_ID.fullmatch(d.name) and (d / 'profile-manifest.json').is_file()] if base.is_dir() else []
    if len(candidates) != 1:
        raise SafetyError('Expected exactly one dedicated Claude editor profile')
    root = guarded(candidates[0], base)
    profile, extensions = root / 'user-data', root / 'extensions'
    manifest = read_json(root / 'profile-manifest.json', root, limit=5_000_000)
    version, native = DEDICATED_EXTENSION
    folder = guarded(extensions / str(manifest.get('extension_folder')), root)
    if manifest.get('scope') != 'claude_only' or manifest.get('ordinary_profile_copied') is not False \
            or folder.name != f'anthropic.claude-code-{version}-win32-x64' \
            or (manifest.get('extension_files') or {}).get('resources/native-binary/claude.exe') != native:
        raise SafetyError('Dedicated Claude editor manifest is invalid')
    if sorted(p.name for p in extensions.iterdir() if p.is_dir()) != [folder.name]:
        raise SafetyError('Unexpected extension in the dedicated Claude editor')
    files = {}
    for path in [folder, *sorted(folder.rglob('*'))]:
        if reparse(path):
            raise SafetyError('Reparse point or symbolic link in the target path')
        if path.is_file():
            files[path.relative_to(folder).as_posix()] = sha256(path)
    if files != manifest['extension_files']:
        raise SafetyError('Reviewed extension of the dedicated Claude editor changed')
    settings = read_jsonc(profile / 'User/settings.json', root)
    expected_env = [{'name': 'HTTP_PROXY', 'value': PROXY_URL}, {'name': 'HTTPS_PROXY', 'value': PROXY_URL}, {'name': 'NO_PROXY', 'value': NO_PROXY}]
    if settings.get('http.proxy') != PROXY_URL or settings.get('telemetry.telemetryLevel') != 'off' \
            or settings.get('extensions.autoUpdate') not in (False, 'off') or settings.get('claudeCode.environmentVariables') != expected_env:
        raise SafetyError('Dedicated Claude editor settings changed')
    return profile, extensions


def launch_executable(paths, target: str) -> Path:
    if target == 'chrome':
        from .services import chrome_executable
        return chrome_executable(paths.local)
    exe = paths.local / 'Programs/Microsoft VS Code/Code.exe'
    if not exe.is_file():
        raise SafetyError('VS Code was not found in the supported installation location')
    return exe


def drift(paths, live: dict, guard: Guard) -> list[dict]:
    rows = []
    desktop = live.get('desktop') or {}
    if desktop.get('version'):
        app = Path(desktop['location']) / 'app'
        try:
            current = {'version': desktop['version'], 'exe': sha256(app / 'Claude.exe'), 'asar': sha256(app / 'resources/app.asar')}
        except OSError:
            current = None
        rows.append({'component': 'desktop_msix', 'drift': current != REVIEWED_DESKTOP, 'current_version': desktop['version'],
                     'effect': 'Фильтры по SID пакета продолжают действовать; код сети и разрешений новой сборки нужно проверить'})
    for target, digest in REVIEWED_LAUNCH.items():
        try:
            changed = sha256(launch_executable(paths, target)) != digest
        except (OSError, SafetyError):
            changed = True
        rows.append({'component': target + '_executable', 'drift': changed,
                     'effect': 'Защищённый запуск отказывает до проверки нового бинарника'})
    try:
        check_dedicated_editor(guard)
        editor_changed = False
    except (OSError, SafetyError, ValueError, KeyError):
        editor_changed = True
    rows.append({'component': 'dedicated_editor_extension', 'drift': editor_changed,
                 'effect': 'Защищённый запуск редактора отказывает; нужен новый проверенный профиль'})
    ordinary = sorted(p.name for p in (paths.home / '.vscode/extensions').glob('anthropic.claude-code-*') if p.is_dir())
    rows.append({'component': 'ordinary_vscode_extension', 'drift': ordinary != [PATH_FILTERED_EXTENSION], 'current': ordinary,
                 'effect': 'Фильтр WFP по пути не покрывает CLI обычного редактора; обычный редактор вне защищённой области'})
    cli = paths.home / '.local/bin/claude.exe'
    rows.append({'component': 'standalone_cli', 'drift': not cli.is_file() or sha256(cli) != REVIEWED_STANDALONE_CLI,
                 'effect': 'Фильтр WFP по пути продолжает блокировать новый файл на том же месте; перенесённый файл не покрыт'})
    return rows


def status(paths) -> dict:
    """Read-only, no network requests: is the installed guard in its reviewed state?"""
    report = {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), 'scope': 'claude_only_local_guard',
              'network_requests': 0, 'settings_changed': False, 'router_contacted': False, 'boundaries': BOUNDARIES}
    guard = locate_guard()
    if not guard:
        return {**report, 'installed': False, 'status': 'not_installed', 'passed': False,
                'findings': ['Задача ClaudeReset-SnowProxy не найдена: локальная защита не установлена']}
    blocking, review = [], []

    def section(check):
        try:
            return check()
        except (OSError, SafetyError, ValueError, KeyError, TypeError) as exc:
            return {'passed': False, 'error_type': type(exc).__name__}
    try:
        state = read_json(guard.base / 'worker-status.json', guard.base)
    except (OSError, SafetyError, ValueError):
        state = {}
    live = live_state([state.get('worker_pid'), state.get('engine_pid')])
    report.update(installed=True, task=guard.task, program_package=current_package())
    if not guard.task.get('enabled'):
        blocking.append('Задача автозапуска прокси отключена')
    if guard.task.get('run_level') != 'Limited':
        review.append('Задача прокси запускается не с обычными правами')
    report['worker'] = section(lambda: check_worker(guard, state, live))
    if not report['worker']['passed']:
        blocking.append('Прокси snow не работает или процесс не совпадает с установленным')
    report['listener'] = check_listeners(live.get('listeners') or [], state.get('engine_pid'))
    if not report['listener']['passed']:
        blocking.append('Порт прокси не принадлежит движку или открыт не только на loopback')
    report['proxy_config'] = section(lambda: check_engine_and_config(guard))
    if not report['proxy_config']['passed']:
        blocking.append('Движок или конфигурация прокси отличаются от проверенных')
    report['packages'] = {'owned_registered': live.get('owned_package') == OWNED_PACKAGE[0],
                          'desktop_installed': bool((live.get('desktop') or {}).get('version'))}
    if not report['packages']['owned_registered']:
        blocking.append('Не зарегистрирован собственный пакет защищённых запусков')
    variables = live.get('proxy_variables') or {}
    report['ordinary_scope'] = {'wininet_proxy_enabled': bool((live.get('wininet') or {}).get('proxy_enable')),
                                'wininet_auto_config': bool((live.get('wininet') or {}).get('auto_config')),
                                'global_proxy_variables': sorted(k for k, v in variables.items() if v)}
    if any(report['ordinary_scope'].values()):
        review.append('Найден общий proxy Windows или глобальная переменная proxy: защита Claude не должна их использовать')
    report['drift'] = drift(paths, live, guard)
    review += ['Изменился компонент: ' + row['component'] for row in report['drift'] if row['drift']]
    report.update(findings=blocking + review, blocking=bool(blocking), passed=not blocking,
                  status='protection_degraded' if blocking else 'static_checks_passed_review_needed' if review else 'static_checks_passed')
    return report


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
foreach ($entry in @(@('backend',25080),@('controller',25081),@('gate',25082))) {
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

WORKER_KEYS = {'family', 'tcp_v4', 'tcp_v6', 'tcp_backend', 'tcp_controller', 'tcp_gate', 'proxy_https', 'launch', 'pid',
               'location_status', 'non_loopback_adapters'}


def bootstrap(port: int, token: str) -> str:
    """Tiny in-package stub: proves the token, receives the script over loopback, returns one JSON line."""
    return ("$c=[Net.Sockets.TcpClient]::new('127.0.0.1'," + str(port) + ");$s=$c.GetStream();$e=[Text.UTF8Encoding]::new($false);"
            "$r=[IO.StreamReader]::new($s,$e);$w=[IO.StreamWriter]::new($s,$e);$w.AutoFlush=$true;$w.WriteLine('" + token + "');"
            "$t=$e.GetString([Convert]::FromBase64String($r.ReadLine()));$o=& ([scriptblock]::Create($t));"
            "$w.WriteLine([string]@($o)[-1]);$c.Close()")


def exchange(start, script: str, timeout=45.0) -> dict:
    """Serve one worker over loopback. `start(port, token)` must start it; foreign peers are ignored."""
    token = secrets.token_hex(16)
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_HOST, 0))
        server.listen(4)
        start(server.getsockname()[1], token)
        while (remaining := deadline - time.monotonic()) > 0:
            server.settimeout(remaining)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                break
            with connection, connection.makefile('rwb') as stream:
                connection.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    if not hmac.compare_digest(stream.readline(64).strip(), token.encode()):
                        continue
                    stream.write(base64.b64encode(script.encode('utf-8')) + b'\n')
                    stream.flush()
                    line = stream.readline(65536)
                except OSError:
                    break
            try:
                result = json.loads(line)
            except ValueError:
                raise SafetyError('Package worker returned an invalid result') from None
            if not isinstance(result, dict) or set(result) - WORKER_KEYS or not all(isinstance(v, str) and len(v) <= 200 for v in result.values()):
                raise SafetyError('Package worker returned an invalid result')
            return result
    raise SafetyError('Package worker did not report in time')


def in_package(package: tuple[str, str], script: str, timeout=45.0) -> dict:
    """Non-network IPC remains available while WFP denies all package sockets."""
    import tempfile
    from .safeio import remove_owned
    root = Path.home() / '.claude-reset-ipc'
    guarded(root, Path.home()).mkdir(exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='strict-', dir=root))
    response = folder / 'probe.json'
    token = secrets.token_hex(16)
    wrapper = ("$ErrorActionPreference='Stop'; $result=& {" + script + "}; "
               "$value=@{nonce='" + token + "'; result=([string]@($result)[-1] | ConvertFrom-Json)}; "
               "[IO.File]::WriteAllText(" + psq(response) + ",($value | ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))")
    encoded = base64.b64encode(wrapper.encode('utf-16-le')).decode()
    arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + encoded
    try:
        ps_json(f'Invoke-CommandInDesktopPackage -PackageFamilyName {psq(package[0])} -AppId {psq(package[1])} '
                f'-Command {psq(powershell())} -Args {psq(arguments)} -PreventBreakaway')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if response.exists():
                try:
                    value = read_json(response, root, limit=65536)
                except json.JSONDecodeError:
                    time.sleep(.05)
                    continue
                result = value.get('result')
                if value.get('nonce') != token or not isinstance(result, dict) or set(result) - WORKER_KEYS or not all(
                        isinstance(v, str) and len(v) <= 200 for v in result.values()):
                    raise SafetyError('Package worker returned an invalid result')
                return result
            time.sleep(.05)
        raise SafetyError('Package worker did not report in time')
    finally:
        remove_owned(folder, root)


def in_package_loopback(package: tuple[str, str], script: str, timeout=45.0) -> dict:
    family, app = package

    def start(port, token):
        encoded = base64.b64encode(bootstrap(port, token).encode('utf-16-le')).decode()
        arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + encoded
        ps_json(f'Invoke-CommandInDesktopPackage -PackageFamilyName {psq(family)} -AppId {psq(app)} '
                f'-Command {psq(powershell())} -Args {psq(arguments)} -PreventBreakaway')
    return exchange(start, script, timeout)


def package_probe(package: tuple[str, str]) -> dict:
    row = {'package': package[0]}
    try:
        result = in_package(package, WORKER_PROBE.replace('__PROXY__', PROXY_URL).replace('__LAUNCH__', ''))
    except SafetyError as exc:
        return {**row, 'passed': False, 'error': str(exc)}
    row.update(identity_verified=result.get('family') == package[0],
               direct_tcp={'v4': result.get('tcp_v4'), 'v6': result.get('tcp_v6')}, proxy_https=result.get('proxy_https'))
    row['passed'] = row['identity_verified'] and row['direct_tcp'] == {'v4': '10013', 'v6': '10013'} and row['proxy_https'] == '200'
    return row


def https_status(url: str, proxy: str | None, timeout=12) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy} if proxy else {}))
    request = urllib.request.Request(url, headers={'User-Agent': 'ClaudeReset network-guard'})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096)
            return {'http_status': response.status, 'body': body}
    except urllib.error.HTTPError as exc:
        return {'http_status': exc.code}
    except Exception as exc:
        return {'error_type': type(exc).__name__}


def probe(paths, *, ordinary_control=False) -> dict:
    """Scoped probes only by default; an ordinary outbound control is separate."""
    if paths is not None:
        from .strict_guard import directory, probe as strict_probe
        if (directory(paths) / 'status.json').is_file():
            return strict_probe(paths)
    guard = locate_guard()
    if not guard:
        raise SafetyError('Local Claude network guard is not installed')
    preflight = status(paths)
    if not preflight.get('passed'):
        return {'status': 'guard_preflight_failed', 'passed': False, 'network_requests': 0,
                'settings_changed': False, 'full_tunnel_verified': False}
    trace = https_status('https://claude.ai/cdn-cgi/trace', PROXY_URL)
    fields = dict(x.split('=', 1) for x in trace.pop('body', b'').decode('ascii', 'replace').splitlines() if '=' in x)
    snow = {**trace, 'loc': fields.get('loc'), 'colo': fields.get('colo')}
    own = current_package()
    if own:
        # Inside a guarded package this process is itself denied direct egress.
        ordinary = {'status': 'not_applicable_program_runs_in_package', 'package': own}
    elif ordinary_control:
        ordinary = https_status('https://example.com/', None)
        ordinary.pop('body', None)
    else:
        ordinary = {'status': 'not_requested_only_scoped_probes'}
    packages = [package_probe(DESKTOP_PACKAGE), package_probe(OWNED_PACKAGE)]
    passed = all(p['passed'] for p in packages) and snow.get('http_status') == 200
    return {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), 'scope': 'claude_only_local_guard',
            'program_package': own, 'packages': packages, 'snow_exit': snow, 'ordinary_direct_control': ordinary,
            'raw_addresses_saved': False, 'settings_changed': False, 'router_contacted': False, 'passed': passed,
            'full_tunnel_verified': False,
            'status': 'direct_egress_denied_proxy_working' if passed else 'guard_probe_failed',
            'limits': ['Проба проверяет TCP IPv4/IPv6 и HTTPS через прокси из свежего процесса каждого пакета',
                       'UDP, DNS и WebRTC проверены отдельно ранее; эта проба их не повторяет'] + BOUNDARIES[:2]}


def uses_directory(args: list[str], directory: Path) -> bool:
    for i, arg in enumerate(args):
        value = arg.split('=', 1)[1] if arg.startswith('--user-data-dir=') else args[i + 1] if arg == '--user-data-dir' and i + 1 < len(args) else None
        if value and same_path(value, directory):
            return True
    return False


def running_instances(exe: Path, directory: Path) -> int:
    rows = ps_json(f'''@(Get-CimInstance Win32_Process -Filter {psq("Name='" + exe.name + "'")} | ForEach-Object {{
      @{{path=[string]$_.ExecutablePath; command=[string]$_.CommandLine}} }}) | ConvertTo-Json -Depth 3 -Compress''') or []
    count = 0
    for row in rows if isinstance(rows, list) else [rows]:
        if not row.get('command'):
            # An unreadable command line fails closed instead of assuming no instance.
            raise SafetyError('A running instance could not be inspected; launch refused')
        if same_path(row.get('path') or '', exe) and uses_directory(split_command_line(row['command']), directory):
            count += 1
    return count


def guarded_launch(paths, target: str) -> dict:
    """Keep the legacy entry point closed until installed release acceptance.

    Diagnostic probes and user-writable legacy status are not client admission
    authority. This compatibility command deliberately performs no launch or probe.
    """
    if target not in ('chrome', 'vscode'):
        raise SafetyError('Unknown guarded launch target')
    return {'target': target, 'scope': 'dedicated_claude_profile',
            'status': 'blocked_installed_acceptance_required', 'passed': False,
            'client_admission': False, 'process_started': False, 'network_requests': 0,
            'settings_changed': False, 'ordinary_profiles_targeted': False,
            'current_sessions_closed': False, 'router_changed': False,
            'functional_acceptance_pending': True,
            'reason': 'Working-client launch requires the installed boundary and full release acceptance; diagnostic probes cannot authorize it.'}


def filters() -> dict:
    """Administrative read of the ten owned WFP filters (run elevated)."""
    from .wfp import inspect_owned_filters
    return {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), **inspect_owned_filters()}


def filter_receipt(paths, request_id):
    """Read-only child result with exact identity, including inspection errors."""
    from .uac_request import admit_child, child_event
    identity = admit_child(paths, 'filters', request_id)
    try:
        result = filters()
    except Exception as exc:
        result = {'status': 'inspection_failed', 'error_type': type(exc).__name__, 'passed': False}
    child_event(paths, identity, 'finish')
    return {**result, **identity, 'schema': 1, 'finished': True,
            'read_only': True, 'filters_changed': False}


def elevated_filters(paths, timeout=120) -> dict:
    """Serialize UAC inspection and expose only a bounded public summary."""
    from . import strict_guard, uac_request
    requests = []
    def dispatch(request):
        requests.append(request)
        return strict_guard.dispatch_request(request)
    result = uac_request.execute(paths, 'filters', dispatch, wait_seconds=timeout)
    # Completion means the read finished, not that L1 is installed or accepted.
    result.update(passed=False, read_only=True, filters_changed=False)
    if result['status'] == 'inspection_finished':
        row = uac_request.read_receipt(requests[0])
        statuses = {'administrator_required', 'engine_unavailable', 'owned_filters_verified',
                    'owned_filters_incomplete', 'inspection_failed'}
        result['inspection_status'] = row.get('status') if row and row.get('status') in statuses else 'inspection_failed'
        result['filters_verified'] = bool(row and row.get('status') == 'owned_filters_verified'
                                          and row.get('passed') is True)
    return result
