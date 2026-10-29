"""Read-only readiness check for installing or running L1 on this PC.

Changes nothing, starts no client and makes no network request. `evaluate` is pure so every
verdict can be tested from a facts dictionary; `collect` gathers the facts from Windows.
Two separate answers: `can_install` (preconditions that no install step can create) and
`protection` (how much of L1 is already installed).
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import connections, l1_consent, netguard, remote_backend
from .safeio import SafetyError
from .windows import ps_json

MIN_BUILD = 22000          # Windows 11
MIN_FREE_GB = 2.0
BLOCKING_FREE_GB = 0.5
CONTROLLER_TASK = 'ClaudeReset L1 Controller'
PORTS = (25080, 25081, 25082)
PROGRAM_FILES = ('ClaudeReset.exe',)

FACTS_SCRIPT = r'''
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$unlock = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue
$desktop = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Where-Object PackageFamilyName -eq {family} | Select-Object -First 1
$owned = Get-AppxPackage -Name 'ClaudeReset.NetworkIsolation' -ErrorAction SilentlyContinue | Select-Object -First 1
$tasks = @{}
foreach ($n in @({backend_task}, {controller_task})) {
  $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
  $tasks[$n] = if ($t) { [string]$t.State } else { $null }
}
$listen = @{}
foreach ($p in {ports}) { $listen[[string]$p] = [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue) }
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$vars = @()
foreach ($scope in 'Machine','User') { foreach ($name in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY') {
  if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, $scope))) { $vars += ($scope + ':' + $name) } } }
$program = Join-Path $env:ProgramFiles 'ClaudeReset-L1'
$files = if (Test-Path $program) { @(Get-ChildItem $program -File | ForEach-Object { $_.Name }) } else { @() }
$drive = Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':')) -ErrorAction SilentlyContinue
$allowUnsigned = [bool](Get-Command Add-AppxPackage -ErrorAction SilentlyContinue).Parameters.ContainsKey('AllowUnsigned')
$bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
$cowork = Get-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
@{
  os_build = [int][Environment]::OSVersion.Version.Build; os_caption = [string]$os.Caption; cpu_architecture = [int]$cpu.Architecture
  elevated = [bool]$admin; allow_unsigned = $allowUnsigned
  dev_mode = @{ allow_development = $unlock.AllowDevelopmentWithoutDevLicense; allow_all_trusted = $unlock.AllowAllTrustedApps }
  bfe = if ($bfe) { [string]$bfe.Status } else { $null }
  desktop = if ($desktop) { @{ version = [string]$desktop.Version; family = [string]$desktop.PackageFamilyName } } else { $null }
  isolation_package = if ($owned) { [string]$owned.PackageFamilyName } else { $null }
  tasks = $tasks; listeners = $listen
  wininet_proxy = [bool]([int]$inet.ProxyEnable) -or -not [string]::IsNullOrEmpty($inet.AutoConfigURL)
  proxy_variables = $vars
  program_files = $files
  free_gb = if ($drive) { [math]::Round($drive.Free / 1GB, 1) } else { $null }
  cowork_service = if ($cowork) { [string]$cowork.Status } else { $null }
} | ConvertTo-Json -Depth 5 -Compress
exit 0
'''


def collect(paths) -> dict:
    """All I/O. Every failure becomes None/unknown, never an exception that hides the rest."""
    script = (FACTS_SCRIPT.replace('{family}', netguard.psq(netguard.DESKTOP_PACKAGE[0]))
              .replace('{backend_task}', netguard.psq(netguard.TASK_NAME))
              .replace('{controller_task}', netguard.psq(CONTROLLER_TASK))
              .replace('{ports}', ','.join(str(p) for p in PORTS)))
    try:
        facts = ps_json(script) or {}
    except SafetyError:
        facts = {'inspection_failed': True}
    home = paths.home
    cli = home / '.local/bin/claude.exe'
    try:
        facts['cli'] = {'present': cli.is_file(),
                        'reviewed_hash': cli.is_file() and netguard.sha256(cli) == netguard.REVIEWED_STANDALONE_CLI}
    except OSError:
        facts['cli'] = {'present': None, 'reviewed_hash': None}
    extensions = home / '.vscode/extensions'
    facts['extensions'] = sorted(p.parent.parent.parent.name.removeprefix('anthropic.claude-code-').removesuffix('-win32-x64')
                                 for p in extensions.glob('anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe')
                                 if p.is_file()) if extensions.is_dir() else []
    consent = paths.state / 'strict-guard' / l1_consent.FILE
    try:
        facts['consent'] = bool(consent.is_file() and l1_consent.load(paths.state / 'strict-guard'))
    except (OSError, SafetyError):
        facts['consent'] = None
    try:
        facts['connection_profile'] = connections.load(paths) is not None
    except (OSError, SafetyError):
        facts['connection_profile'] = None
    try:
        facts['remote_backend'] = remote_backend.load(paths) is not None
    except (OSError, SafetyError):
        facts['remote_backend'] = None
    facts['frozen'] = bool(getattr(sys, 'frozen', False))
    facts['python'] = '.'.join(str(v) for v in sys.version_info[:3])
    return facts


def row(identifier, status, detail, **extra):
    return {'id': identifier, 'status': status, 'detail': detail, **extra}


def evaluate(facts: dict) -> dict:
    """status: ok | info | warn | missing (an install step creates it) | blocked (no install step can fix it) | unknown."""
    if facts.get('inspection_failed'):
        rows = [row('windows_inspection', 'unknown', 'Windows PowerShell did not answer; nothing can be concluded')]
        return {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), 'status': 'unknown', 'can_install': None,
                'protection': 'unknown', 'checks': rows, 'blockers': [], 'next_steps': ['Повторите проверку; если ошибка повторяется, прикрепите отчёт'],
                'changes_system': False, 'network_requests': 0}
    rows = []
    build, arch = facts.get('os_build'), facts.get('cpu_architecture')
    rows.append(row('windows', 'ok' if isinstance(build, int) and build >= MIN_BUILD and arch == 9 else 'blocked',
                    f"{facts.get('os_caption') or 'Windows'}, build {build}, {'x64' if arch == 9 else 'architecture ' + str(arch)}; нужен Windows 11 x64",
                    needs='Windows 11 x64'))
    bfe = facts.get('bfe')
    rows.append(row('base_filtering_engine', 'ok' if bfe == 'Running' else 'blocked', f'служба BFE: {bfe}', needs='работающая служба Base Filtering Engine'))
    free = facts.get('free_gb')
    rows.append(row('disk_space', 'unknown' if free is None else 'blocked' if free < BLOCKING_FREE_GB else 'warn' if free < MIN_FREE_GB else 'ok',
                    f'свободно на системном диске: {free} ГБ'))
    desktop, cli, extensions = facts.get('desktop'), facts.get('cli') or {}, facts.get('extensions') or []
    clients = []
    if desktop:
        clients.append('desktop')
        rows.append(row('client_desktop', 'ok', f"Claude Desktop {desktop.get('version')} ({desktop.get('family')}): защита по идентичности пакета, версия не закрепляется"))
    if extensions:
        clients.append('extension')
        rows.append(row('client_vscode_extension', 'ok', 'Claude Code в VS Code: ' + ', '.join(extensions) + '; покрывается точным путём claude.exe каждой версии'))
    if cli.get('present'):
        clients.append('cli')
        rows.append(row('client_standalone_cli', 'ok' if cli.get('reviewed_hash') else 'warn',
                        'автономный CLI найден' + ('' if cli.get('reviewed_hash') else '; хеш не из проверенного списка: запрет ставится по пути, работа через реле не подтверждена')))
    elif cli.get('present') is False:
        rows.append(row('client_standalone_cli', 'info', 'автономного CLI нет: защищать нечего, это не препятствие'))
    rows.append(row('claude_client', 'ok' if clients else 'blocked', 'найдено: ' + (', '.join(clients) or 'ничего'), needs='хотя бы один клиент Claude'))
    proxies = (['Internet Settings'] if facts.get('wininet_proxy') else []) + list(facts.get('proxy_variables') or [])
    rows.append(row('ordinary_proxy', 'warn' if proxies else 'ok', 'общий proxy Windows или переменные: ' + (', '.join(proxies) or 'нет') + ' (продукт их не меняет и не использует)'))
    dev = facts.get('dev_mode') or {}
    rows.append(row('developer_mode', 'info', f"AllowDevelopmentWithoutDevLicense={dev.get('allow_development')}, AllowAllTrustedApps={dev.get('allow_all_trusted')} (None: значения нет); понадобится ли, решает шаг регистрации пакета"))
    rows.append(row('elevation', 'info', 'сеанс повышен' if facts.get('elevated') else 'сеанс без повышения прав: установка запросит UAC у владельца'))
    rows.append(row('cowork', 'info', f"служба Cowork: {facts.get('cowork_service')}; Cowork вне границ L1"))
    if not facts.get('isolation_package'):
        unsigned = facts.get('allow_unsigned')
        rows.append(row('unsigned_package_registration', 'ok' if unsigned else 'unknown' if unsigned is None else 'blocked',
                        'Add-AppxPackage -AllowUnsigned ' + ('доступен' if unsigned else 'недоступен' if unsigned is False else 'не определён'),
                        needs='Windows 11 с Add-AppxPackage -AllowUnsigned (без него пакет изоляции не зарегистрировать)'))
    blockers = [r for r in rows if r['status'] == 'blocked']
    tasks, listeners = facts.get('tasks') or {}, facts.get('listeners') or {}
    from . import netguard as n
    parts = {
        'isolation_package': bool(facts.get('isolation_package')),
        # A remote SOCKS5 profile needs no engine task or loopback listener: the controller's relay does the work.
        'backend_task': facts.get('remote_backend') is True or tasks.get(n.TASK_NAME) is not None,
        'backend_listening': facts.get('remote_backend') is True or bool(listeners.get(str(PORTS[0]))),
        'controller_files': all(name in (facts.get('program_files') or []) for name in PROGRAM_FILES),
        'controller_task': tasks.get(CONTROLLER_TASK) is not None,
        'connection_profile': facts.get('connection_profile') is True,
        'consent': facts.get('consent') is True,
        'relay_listening': bool(listeners.get(str(PORTS[2]))),
    }
    for name, present in parts.items():
        rows.append(row(name, 'ok' if present else 'missing', 'установлено' if present else 'не установлено'))
    if all(parts.values()):
        protection = 'installed'
    elif not any(parts[k] for k in ('isolation_package', 'backend_task', 'controller_files', 'controller_task', 'consent', 'connection_profile')):
        protection = 'not_installed'
    else:
        protection = 'partial'
    steps = []
    if blockers:
        steps += [f"Устраните: {b['id']} ({b.get('needs') or b['detail']})" for b in blockers]
    elif protection != 'installed':
        steps.append('Предусловия выполнены. Установка идёт шагами плана v3: N1 пакет изоляции, N2 backend, N3 контроллер; каждый шаг заранее описывается владельцу (UAC).')
    status = 'blocked' if blockers else protection if protection != 'not_installed' else 'ready_to_install'
    return {'schema': 1, 'utc': datetime.now(timezone.utc).isoformat(), 'status': status, 'can_install': not blockers,
            'protection': protection, 'checks': rows, 'blockers': [b['id'] for b in blockers], 'next_steps': steps,
            'client_versions': {'desktop': (desktop or {}).get('version'), 'vscode_extensions': extensions,
                                'standalone_cli_present': cli.get('present')},
            'environment': {'python': facts.get('python'), 'frozen': facts.get('frozen')},
            'changes_system': False, 'network_requests': 0}


def check(paths) -> dict:
    report = evaluate(collect(paths))
    # Exit code 0 means "can be installed or already is"; blockers make the CLI exit 2.
    report['passed'] = report['can_install'] is True
    return report
