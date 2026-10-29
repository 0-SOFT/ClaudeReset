# Full local wipe of Claude data for the current Windows user: Desktop (+ Cowork VM data), Claude Code state,
# the Claude Code extension's own VS Code storage and matching saved Windows credentials. NOTHING is kept.
#
# Scope is a fixed list of Claude locations (shown before anything is deleted). Not touched: the installed
# programs, browsers and their profiles, VS Code settings and projects, other applications, the router, the
# network settings, the L1 protection. Preview first, then you type the confirmation word.
# Windows account keys that Desktop registered (CNG) are NOT removed by this script.
param(
    [switch]$PreviewOnly,
    [switch]$Apply            # internal: set by the elevated relaunch after the confirmation
)
$ErrorActionPreference = 'Continue'
$home_ = $env:USERPROFILE
$local = $env:LOCALAPPDATA
$roaming = $env:APPDATA
$package = Join-Path $local 'Packages\Claude_pzs8sxrjxfjjc'

# Kind: contents = delete everything inside, keep the folder; tree = delete the folder; file = delete the file
$targets = @(
    [pscustomobject]@{ Group = 'Claude Desktop'; Kind = 'contents'; Path = $package }
    [pscustomobject]@{ Group = 'Claude Desktop'; Kind = 'tree'; Path = (Join-Path $roaming 'Claude') }
    [pscustomobject]@{ Group = 'Claude Desktop'; Kind = 'tree'; Path = (Join-Path $roaming 'Claude-3p') }
    [pscustomobject]@{ Group = 'Claude Code'; Kind = 'tree'; Path = (Join-Path $home_ '.claude') }
    [pscustomobject]@{ Group = 'Claude Code'; Kind = 'file'; Path = (Join-Path $home_ '.claude.json') }
    [pscustomobject]@{ Group = 'Расширение Claude Code в VS Code'; Kind = 'tree'; Path = (Join-Path $roaming 'Code\User\globalStorage\anthropic.claude-code') }
)
Get-ChildItem -LiteralPath $home_ -Force -Filter '.claude.json.*' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne '.claude.json' } | ForEach-Object {
    $targets += [pscustomobject]@{ Group = 'Claude Code'; Kind = 'file'; Path = $_.FullName }
}

function Test-Reparse($item) { return [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint) }
function Get-Size($path) {
    $sum = 0
    Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $sum += $_.Length }
    return $sum
}
function Format-Size($bytes) {
    if ($bytes -ge 1GB) { return ('{0:N1} ГБ' -f ($bytes / 1GB)) }
    if ($bytes -ge 1MB) { return ('{0:N1} МБ' -f ($bytes / 1MB)) }
    return ('{0:N0} КБ' -f ($bytes / 1KB))
}
# A junction or symlink is removed as a link and never followed, so nothing outside the list can be deleted through it.
function Remove-Tree($path) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    if (Test-Reparse $item) {
        try { if ($item.PSIsContainer) { [IO.Directory]::Delete($path) } else { [IO.File]::Delete($path) } } catch { }
        return
    }
    if ($item.PSIsContainer) {
        foreach ($child in Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue) { Remove-Tree $child.FullName }
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    } else {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}
function Test-Allowed($path) {
    $full = [IO.Path]::GetFullPath($path)
    foreach ($root in @($home_, $local, $roaming)) {
        $rootFull = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if ($full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase) -and $full.TrimEnd('\').Length -gt $rootFull.TrimEnd('\').Length) { return $true }
    }
    return $false
}
function Get-ClaudeCredentials {
    $found = @()
    $text = (cmdkey /list 2>$null) | Out-String
    foreach ($m in [regex]::Matches($text, '(?im)^\s*(?:Target|Цель):\s*(.+?)\s*$')) {
        $name = $m.Groups[1].Value
        if ($name -match '(?i)(^|[:=/\\ ._-])(claude|anthropic)([:=/\\ ._-]|$)') { $found += $name }
    }
    return $found
}

Write-Host ''
Write-Host '=== Что будет стёрто (предпросмотр, пока ничего не удалено) ===' -ForegroundColor Cyan
$present = @()
foreach ($t in $targets) {
    if (-not (Test-Path -LiteralPath $t.Path)) { continue }
    if (-not (Test-Allowed $t.Path)) { Write-Host ('ПРОПУЩЕНО (вне разрешённой области): ' + $t.Path) -ForegroundColor Yellow; continue }
    $size = if ($t.Kind -eq 'file') { (Get-Item -LiteralPath $t.Path -Force).Length } else { Get-Size $t.Path }
    $present += [pscustomobject]@{ Group = $t.Group; Kind = $t.Kind; Path = $t.Path; Size = $size }
    Write-Host ('{0,-34} {1,10}  {2}' -f $t.Group, (Format-Size $size), $t.Path)
}
$credentials = @(Get-ClaudeCredentials)
foreach ($c in $credentials) { Write-Host ('{0,-34} {1,10}  {2}' -f 'Сохранённые пароли Windows', '', $c) }
if ($present.Count -eq 0 -and $credentials.Count -eq 0) {
    Write-Host 'Ничего не найдено: данные Claude на этом ПК уже стёрты.' -ForegroundColor Green
    if (-not $Apply) { Read-Host 'Нажмите Enter, чтобы закрыть окно' }
    exit 0
}
Write-Host ''
Write-Host 'НЕ затрагивается: установленные программы, браузеры и их профили, настройки и проекты VS Code, чужие программы, сеть, защита L1.'
Write-Host 'Ключи устройства Desktop в учётной записи Windows этим скриптом не удаляются.'
if ($PreviewOnly) { exit 0 }

if (-not $Apply) {
    Write-Host ''
    Write-Host 'Это необратимо: вход, сессии, память, проекты Claude Code и данные Cowork пропадут.' -ForegroundColor Yellow
    $answer = Read-Host 'Чтобы стереть всё перечисленное, напишите слово СТЕРЕТЬ'
    if ($answer -cne 'СТЕРЕТЬ') { Write-Host 'Отменено, ничего не удалено.'; Read-Host 'Нажмите Enter, чтобы закрыть окно'; exit 0 }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host 'Для остановки службы Cowork нужны права администратора: сейчас появится запрос Windows, нажмите «Да».'
        Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-Apply')
        exit 0
    }
}

Write-Host ''
Write-Host '=== Стираю ===' -ForegroundColor Cyan
# Programs that hold these files open
$vscode = Get-Process -Name 'Code' -ErrorAction SilentlyContinue
if ($vscode) {
    Write-Host 'VS Code открыт. Закройте его полностью (в нём могут быть ваши несохранённые файлы) и запустите скрипт снова.' -ForegroundColor Red
    Read-Host 'Нажмите Enter, чтобы закрыть окно'; exit 1
}
foreach ($name in @('Claude', 'claude')) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object { Write-Host ('Закрываю ' + $_.ProcessName + ' (' + $_.Id + ')'); Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
}
$service = Get-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue
$serviceWasRunning = $false
if ($service -and $service.Status -eq 'Running') {
    $serviceWasRunning = $true
    Write-Host 'Останавливаю службу Cowork'
    Stop-Service -Name 'CoworkVMService' -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
Get-Process -Name 'cowork-svc' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

foreach ($t in $present) {
    if (-not (Test-Allowed $t.Path)) { continue }
    if ($t.Kind -eq 'contents') {
        foreach ($child in Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue) { Remove-Tree $child.FullName }
    } else {
        Remove-Tree $t.Path
    }
}
foreach ($c in $credentials) { cmdkey /delete:"$c" | Out-Null }
if ($serviceWasRunning) { Start-Service -Name 'CoworkVMService' -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host '=== Проверка ===' -ForegroundColor Cyan
$left = @()
foreach ($t in $present) {
    if ($t.Kind -eq 'contents') {
        $rest = @(Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue)
        if ($rest.Count) { $left += $t.Path + ' (осталось объектов: ' + $rest.Count + ')' }
    } elseif (Test-Path -LiteralPath $t.Path) { $left += $t.Path }
}
foreach ($c in @(Get-ClaudeCredentials)) { $left += 'пароль Windows: ' + $c }
if ($left.Count -eq 0) {
    Write-Host 'ГОТОВО. Данные Claude стёрты, остатков нет.' -ForegroundColor Green
} else {
    Write-Host 'Остались (чаще всего их держит запущенная программа; закройте её и запустите скрипт ещё раз):' -ForegroundColor Yellow
    $left | ForEach-Object { Write-Host (' - ' + $_) }
}
Read-Host 'Нажмите Enter, чтобы закрыть окно'
