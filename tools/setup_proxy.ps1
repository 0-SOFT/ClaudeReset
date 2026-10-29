# Guided, one-run setup of the L1 protection with the owner's SOCKS5 proxy.
# Double-click Setup-Proxy.cmd in the repository root (or run this file in PowerShell).
# Every step stops the run on a problem and says what to do; nothing is hidden.
param(
    [string]$Secrets = (Join-Path $env:USERPROFILE 'claude-reset-secrets'),
    [string]$Venv = 'C:\claude-reset-venv'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($text) { Write-Host ''; Write-Host ('=== ' + $text) -ForegroundColor Cyan }
function Fail($text) {
    Write-Host ''
    Write-Host ('СТОП: ' + $text) -ForegroundColor Red
    Write-Host 'Скопируйте всё, что выведено выше, и отправьте. Ничего страшного не произошло: каждый шаг можно повторить.'
    Read-Host 'Нажмите Enter, чтобы закрыть окно'
    exit 1
}
function Ask($question) {
    $answer = Read-Host ($question + ' [да/нет]')
    return ($answer -match '^(да|д|y|yes)$')
}
function Run($arguments) {
    $text = (& $script:py src\launcher.py @arguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
    Write-Host $text
    $json = $null
    try { $json = $text | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ Code = $code; Text = $text; Json = $json }
}

Step '0. Проверка окружения'
$script:py = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $script:py)) {
    Write-Host 'Окружение Python не найдено, создаю его (нужен установленный Python 3.12).'
    $system = Get-Command python -ErrorAction SilentlyContinue
    if (-not $system) { Fail 'Python не найден. Установите Python 3.12 с python.org (галочка Add python.exe to PATH) и запустите снова.' }
    & $system.Source -m venv $Venv
    & (Join-Path $Venv 'Scripts\pip.exe') install -r requirements-dev.txt
    if (-not (Test-Path $script:py)) { Fail 'Не удалось создать окружение Python.' }
}
$socks = Join-Path $Secrets 'socks5.json'
$connection = Join-Path $Secrets 'connection-socks5.json'
foreach ($file in @($socks, $connection)) {
    if (-not (Test-Path $file)) { Fail ('Нет файла ' + $file + '. Перенесите socks5.json и connection-socks5.json в папку ' + $Secrets + ' и запустите снова.') }
}
Write-Host 'Python и оба файла прокси на месте.'

Step '1. Готовность ПК'
$r = Run @('--l1-check')
if ($r.Code -ne 0 -or -not $r.Json) { Fail 'Проверка готовности не пройдена (см. blockers выше).' }
$state = $r.Json.protection
Write-Host ('Состояние защиты: ' + $state)
if ($state -ne 'not_installed') {
    Write-Host 'На ПК уже есть части прежней защиты. Их нужно снять перед новой установкой.'
    if (-not (Ask 'Снять прежнюю защиту сейчас? Появятся три запроса Windows (UAC), нажимайте «Да» сразу')) { Fail 'Без снятия прежней защиты установка невозможна.' }
    $r = Run @('--l1-remove')
    if ($r.Code -ne 0) {
        Write-Host 'Если статус removed_with_leftovers, это профиль выхода от старой версии: он удалится при следующей попытке.'
        Fail 'Снятие прежней защиты не завершилось чисто.'
    }
    Write-Host 'Перезапустите Claude Desktop (закройте полностью, в том числе значок у часов), затем вернитесь сюда.'
    Read-Host 'Когда перезапустили, нажмите Enter'
}

Step '2. Профиль прокси (проверка адреса, входа и подключения)'
$r = Run @('--l1-backend-install', $socks)
if ($r.Code -ne 0) { Fail 'Прокси не принят. peer_unreachable: прокси не отвечает с этого ПК. authentication failed: неверный логин или пароль.' }

Step '3. Ожидаемый выход прокси'
$r = Run @('--connection-save', $connection)
if ($r.Code -ne 0) { Fail 'Не удалось сохранить ожидаемый выход.' }
$r = Run @('--connection-check')
if ($r.Code -ne 0) { Fail 'Выход прокси не совпал с ожидаемым. Дальше идти нельзя: защита закрыла бы Claude.' }

Step '4. Согласие с границами защиты'
Write-Host 'Эта защита (уровень L1) НЕ закрывает следующее, и вы принимаете это:'
Write-Host ' - имена сайтов могут уходить мимо прокси через DNS Windows;'
Write-Host ' - защиты от программ, умеющих обойти её через внутренние механизмы Windows, нет;'
Write-Host ' - Cowork (виртуальная машина Claude) не защищён;'
Write-Host ' - общие Chrome и сам VS Code не затрагиваются;'
Write-Host ' - SOCKS5 не шифруется между ПК и прокси: прокси видит имена сайтов, содержимое остаётся под TLS;'
Write-Host ' - если прокси перестанет отвечать, Claude останется без сети (так задумано).'
if (-not (Ask 'Принимаете эти границы?')) { Fail 'Вы не приняли границы. Ничего не установлено.' }

Step '5. Установка защиты (будут запросы Windows, нажимайте «Да» сразу)'
Write-Host 'Сейчас: регистрация пакета, сборка программы на этом ПК (1-2 минуты), автозапуск, запуск. Не закрывайте окно.'
$r = Run @('--l1-install', '--confirm-l1-limits')
if ($r.Code -ne 0) { Fail 'Установка остановилась. Смотрите status и next выше.' }

Step '6. Проверка'
Write-Host 'Теперь полностью перезапустите Claude Desktop: закройте (в том числе значок у часов) и откройте снова.'
Read-Host 'Когда перезапустили, нажмите Enter'
$r = Run @('--strict-guard-probe')
if ($r.Code -ne 0) { Fail 'Проверка границы не пройдена.' }
$r = Run @('--l1-check')
Write-Host ''
Write-Host 'ГОТОВО. Защита установлена. Напишите что-нибудь в Claude Desktop: он должен ответить.' -ForegroundColor Green
Write-Host ('Папку ' + $Secrets + ' с паролем прокси теперь можно удалить.')
Read-Host 'Нажмите Enter, чтобы закрыть окно'
