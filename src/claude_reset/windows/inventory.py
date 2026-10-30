"""Read-only snapshots of this PC for the reset: Claude processes, launch settings, startup and task entries,
packages, time zone and locale. The scripts recognise the program's own tasks and package by their config names.
"""
from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any

from .. import config
from .powershell import ps_json, quote

__all__ = ['OWNED_NAMES', 'inspect_runtime', 'inspect_windows', 'with_owned_names']


# The program's own names the scripts below must recognise; each @TOKEN@ becomes a quoted PowerShell literal.
OWNED_NAMES = MappingProxyType({
    '@CONTROLLER_TASK@': quote(config.CONTROLLER_TASK),
    '@CONTROLLER_EXE@': quote(config.L1_PROGRAM + '\\' + config.CONTROLLER_EXE),
    '@BACKEND_TASK@': quote(config.BACKEND_TASK),
    '@BACKEND_WORKER@': quote('(?i)' + re.escape(config.BACKEND_WORKER) + '"?$'),
    '@RECOVERY_TASK@': quote(config.RECOVERY_TASK),
    '@RECOVERY_WATCH@': quote('(?i)' + re.escape(config.RECOVERY_WATCH) + '"?$'),
    '@OWNED_PACKAGE@': quote(config.OWNED_PACKAGE_NAME),
    '@MANAGED_CHROME@': quote(config.PRODUCT_NAME + r'[\\/]' + config.CHROME_PROFILES),
})


def with_owned_names(script: str) -> str:
    """script with every @TOKEN@ of OWNED_NAMES replaced by its literal."""
    for token, literal in OWNED_NAMES.items():
        script = script.replace(token, literal)
    return script


# Claude processes, launch settings, startup and task entries, packages, time zone and locale, as JSON.
INSPECT_SCRIPT = with_owned_names(r'''
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
    $allProcesses = @(Get-CimInstance Win32_Process);
    $processes = @($allProcesses | Where-Object {
        $_.Name -match '^(Claude|claude-desktop|claude|Code|Code - Insiders|chrome|cowork-svc|wsl|wslhost|vmmemWSL|docker|com.docker.backend|node)\.exe$'
    } | ForEach-Object {
        $kind = if ($_.Name -eq 'node.exe') {
            if ($_.CommandLine -match '(?i)([\\/](\.claude|@anthropic-ai|claude-code)[\\/])|\bclaude-mcp\b|\bclaude\.(mjs|cjs|js)\b') {'claude-child'} else {'unclassified-node'}
        } elseif ($_.Name -eq 'chrome.exe' -and $_.CommandLine -match @MANAGED_CHROME@) {'chrome-managed'} else {$_.Name};
        @{kind=$kind; pid=$_.ProcessId}
    });
    $vars = @{}; $directoryEnv = @{};
    foreach ($scope in @('Machine','User')) {
        foreach ($entry in [Environment]::GetEnvironmentVariables($scope).GetEnumerator()) {
            if ($entry.Key -match '^(CLAUDE|ANTHROPIC|OTEL|DISABLE_TELEMETRY|DISABLE_ERROR_REPORTING|DO_NOT_TRACK)') {
                $vars[$scope + ':' + $entry.Key] = -not [string]::IsNullOrEmpty($entry.Value)
                if ($entry.Key -in @('CLAUDE_CONFIG_DIR','CLAUDE_USER_DATA_DIR','ANTHROPIC_CONFIG_DIR')) {
                    $directoryEnv[$entry.Key] = [Environment]::ExpandEnvironmentVariables($entry.Value)
                }
            }
        }
    }
    $tz = [TimeZoneInfo]::Local;
    $candidate = [TimeZoneInfo]::FindSystemTimeZoneById('Turkey Standard Time');
    $now = [DateTimeOffset]::UtcNow;
    $cliPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\\bin\\claude.exe';
    $cliVersion = if (Test-Path -LiteralPath $cliPath) {(Get-Item -LiteralPath $cliPath).VersionInfo.FileVersion} else {$null};
    if (-not $cliVersion) {
        $cliCommand = Get-Command claude.exe -ErrorAction SilentlyContinue;
        if ($cliCommand) {$cliVersion = (Get-Item -LiteralPath $cliCommand.Source).VersionInfo.FileVersion}
    }
    $extPath = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.vscode\\extensions';
    $extVersions = @();
    $extensionRoots = @($extPath, (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.vscode-insiders\extensions'));
    $customRoots = @(); $remote = @(); $restoreSources = @();
    $launches = @($allProcesses | Select-Object Name,ExecutablePath,CommandLine);
    $shell = New-Object -ComObject WScript.Shell;
    foreach ($folder in @([Environment]::GetFolderPath('StartMenu'), [Environment]::GetFolderPath('Desktop'))) {
        if (Test-Path -LiteralPath $folder) {
            foreach ($lnk in @(Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -Depth 3 -ErrorAction SilentlyContinue | Where-Object {$_.BaseName -match '(?i)claude|chrome|visual studio code|^code( |$)'} | Select-Object -First 512)) {
                $shortcut = $shell.CreateShortcut($lnk.FullName);
                $launches += [pscustomobject]@{Name=[IO.Path]::GetFileName($shortcut.TargetPath);ExecutablePath=$shortcut.TargetPath;CommandLine=$shortcut.Arguments};
            }
        }
    }
    foreach ($launch in $launches) {
        $component = if ($launch.Name -match '^chrome\.exe$') {'chrome'} elseif ($launch.Name -match '^Code( - Insiders)?\.exe$') {'vscode'} else {$null};
        if ($component -and $launch.CommandLine -match '--user-data-dir(?:=|\s+)(?:"([^"]+)"|([^\s"]+))') {
            $directory = if ($Matches[1]) {$Matches[1]} else {$Matches[2]};
            if ($component -eq 'vscode') {$directory = Join-Path $directory 'User'};
            $customRoots += @{component=$component;path=$directory};
        }
        if ($component -eq 'vscode' -and $launch.ExecutablePath) {
            $portable = Join-Path ([IO.Path]::GetDirectoryName($launch.ExecutablePath)) 'data';
            if (Test-Path -LiteralPath (Join-Path $portable 'user-data\User')) {
                $customRoots += @{component='vscode';path=(Join-Path $portable 'user-data\User')};
                $extensionRoots += (Join-Path $portable 'extensions');
            }
        }
        if ($launch.CommandLine -match '(?i)ssh-remote\+') {$remote += 'ssh'};
        if ($launch.CommandLine -match '(?i)dev-container|devcontainer') {$remote += 'devcontainer'};
        if ($launch.CommandLine -match '(?i)wsl\+') {$remote += 'wsl'};
    }
    if (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss') {$remote += 'wsl'};
    if ($allProcesses.Name -match '^com\.docker\.backend\.exe$') {$remote += 'docker'};
    foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path $key) {
            foreach ($property in (Get-ItemProperty $key).PSObject.Properties) {
                if ($property.Name -notmatch '^PS' -and [string]$property.Value -match '(?i)claude|anthropic|0-code') {$restoreSources += 'startup'}
            }
        }
    }
    $taskInspection = 'complete';
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.State -ne 'Disabled'})) {
            foreach ($action in $task.Actions) {
                # Exactly this program's own L1 tasks (controller in Program Files, backend worker) are not restore sources.
                $ownController = $task.TaskName -ceq @CONTROLLER_TASK@ -and $action.Execute -ieq (Join-Path $env:ProgramFiles @CONTROLLER_EXE@);
                $ownBackend = $task.TaskName -ceq @BACKEND_TASK@ -and $action.Execute -match '(?i)\\pythonw\.exe$' -and $action.Arguments -match @BACKEND_WORKER@;
                $ownRecovery = $task.TaskName -ceq @RECOVERY_TASK@ -and $action.Execute -match '(?i)\\pythonw\.exe$' -and $action.Arguments -match @RECOVERY_WATCH@;
                if ($ownController -or $ownBackend -or $ownRecovery) {continue};
                if (($action.Execute + ' ' + $action.Arguments) -match '(?i)claude|anthropic|0-code') {$restoreSources += 'scheduled_task'}
            }
        }
    } catch {$taskInspection = 'unavailable'};
    foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if (Test-Path -LiteralPath $folder) {
            foreach ($item in @(Get-ChildItem -LiteralPath $folder -File)) {
                if ($item.Extension -eq '.lnk') {
                    $shortcut = $shell.CreateShortcut($item.FullName);
                    if (($shortcut.TargetPath + ' ' + $shortcut.Arguments) -match '(?i)claude|anthropic|0-code') {$restoreSources += 'startup_shortcut'}
                } elseif ($item.Extension -in @('.cmd','.bat','.ps1')) {
                    if ($item.Length -lt 1048576 -and (Get-Content -Raw -LiteralPath $item.FullName) -match '(?i)claude|anthropic|0-code') {$restoreSources += 'startup_script'}
                }
            }
        }
    }
    foreach ($root in ($extensionRoots | Select-Object -Unique)) {
      if (Test-Path -LiteralPath $root) {
        $extVersions += @(Get-ChildItem -LiteralPath $root -Directory | Where-Object {$_.Name -like 'anthropic.claude-code-*'} | ForEach-Object {
            $manifest = Join-Path $_.FullName 'package.json';
            if (Test-Path -LiteralPath $manifest) {(Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json).version}
        });
      }
    }
    # This program's own identity package matches the wildcard but is not a Claude client.
    $packages = @(Get-AppxPackage -Name '*Claude*' | Where-Object {$_.Name -ne @OWNED_PACKAGE@} | Select-Object Name,Version,InstallLocation,PackageFamilyName);
    $desktopVersions = @($packages | ForEach-Object {[string]$_.Version});
    foreach ($exe in @((Join-Path $env:LOCALAPPDATA 'AnthropicClaude\Claude.exe'),(Join-Path $env:LOCALAPPDATA 'Programs\Claude\Claude.exe'))) {
        if (Test-Path -LiteralPath $exe) {$desktopVersions += (Get-Item -LiteralPath $exe).VersionInfo.FileVersion}
    }
    $managedSettings = @();
    $managed = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json';
    if (Test-Path -LiteralPath $managed) {$managedSettings += $managed};
    $locationPermission = 'unavailable';
    $locationKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location';
    if (Test-Path $locationKey) {$locationPermission = (Get-ItemProperty $locationKey).Value};
    @{processes=$processes; environment_presence=$vars;
      directory_environment=$directoryEnv; custom_roots=$customRoots; remote_environments=@($remote|Select-Object -Unique);
      restore_sources=@($restoreSources|Select-Object -Unique); task_inspection=$taskInspection;
      managed_settings=$managedSettings; desktop_versions=@($desktopVersions|Select-Object -Unique);
      account_manager_active=[bool]($allProcesses | Where-Object {$_.Name -match '^0-?code(\.exe)?$' -or $_.CommandLine -match '(?i)[\\/]0-code[\\/]'});
      locale=(Get-Culture).Name; ui_locale=(Get-UICulture).Name; windows_location_permission=$locationPermission;
      cli_version=$cliVersion; extension_versions=@($extVersions|Select-Object -Unique);
      timezone=@{id=$tz.Id; offset_minutes=$tz.GetUtcOffset($now).TotalMinutes;
      candidate='Turkey Standard Time'; candidate_offset_minutes=$candidate.GetUtcOffset($now).TotalMinutes};
      packages=$packages
    } | ConvertTo-Json -Depth 6 -Compress
    ''')


# Running Claude processes by kind, for the owner check between mutations.
RUNTIME_SCRIPT = with_owned_names(r'''
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new();
    $items = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -match '^(Claude|claude-desktop|claude|Code|Code - Insiders|chrome|cowork-svc|node)\.exe$'
    } | ForEach-Object {
        $kind = if ($_.Name -eq 'node.exe') {
            if ($_.CommandLine -match '(?i)([\\/](\.claude|@anthropic-ai|claude-code)[\\/])|\bclaude-mcp\b|\bclaude\.(mjs|cjs|js)\b') {'claude-child'} else {'unclassified-node'}
        } elseif ($_.Name -eq 'chrome.exe' -and $_.CommandLine -match @MANAGED_CHROME@) {'chrome-managed'} else {$_.Name};
        @{kind=$kind;pid=$_.ProcessId}
    });
    @{processes=$items} | ConvertTo-Json -Depth 4 -Compress
    ''')


def inspect_windows() -> dict:
    return ps_json(INSPECT_SCRIPT)


def inspect_runtime() -> Any:
    """Fast owner check used between mutations; full discovery surrounds the run."""
    return ps_json(RUNTIME_SCRIPT)
