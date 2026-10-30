"""One read-only snapshot of the Windows facts the L1 readiness check needs; it changes nothing."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .powershell import ps_json, quote

__all__ = ['system_facts']

FACTS = r'''
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$unlock = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -ErrorAction SilentlyContinue
$desktop = Get-AppxPackage -Name 'Claude' -ErrorAction SilentlyContinue | Where-Object PackageFamilyName -eq {family} | Select-Object -First 1
$owned = Get-AppxPackage -Name {owned_name} -ErrorAction SilentlyContinue | Select-Object -First 1
$tasks = @{}
foreach ($n in @({tasks})) {
  $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
  $tasks[$n] = if ($t) { [string]$t.State } else { $null }
}
$listen = @{}
foreach ($p in {ports}) { $listen[[string]$p] = [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue) }
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$vars = @()
foreach ($scope in 'Machine','User') { foreach ($name in 'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY') {
  if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, $scope))) { $vars += ($scope + ':' + $name) } } }
$program = Join-Path $env:ProgramFiles {l1_program}
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


def system_facts(*, desktop_family: str, owned_package: str, tasks: Iterable[str], ports: Iterable[int], program_folder: Path | str) -> Any:
    """OS build, packages, task states, listeners, proxy settings, program files and free space.

    A failed inspection raises; every value inside is read-only."""
    script = (FACTS.replace('{family}', quote(desktop_family))
              .replace('{tasks}', ', '.join(quote(name) for name in tasks))
              .replace('{owned_name}', quote(owned_package))
              .replace('{l1_program}', quote(program_folder))
              .replace('{ports}', ','.join(str(port) for port in ports)))
    return ps_json(script)
