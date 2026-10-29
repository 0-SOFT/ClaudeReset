# Replace the installed L1 program with the build in -Dist: stop the controller, install (one UAC), start it again.
# Protected clients are offline between the stop and the new relay_open, so this is one unattended script with a log.
# The install is attempted only after the controller is really gone (relay port closed, no ClaudeReset process);
# if any step fails the controller is started again with whatever is installed, so the outage ends either way.
param([Parameter(Mandatory)][string]$Dist, [Parameter(Mandatory)][string]$Log, [Parameter(Mandatory)][string]$Guard, [int]$UacSeconds = 240)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $Dist 'ClaudeReset.exe'
$installed = Join-Path (Join-Path $env:ProgramFiles 'ClaudeReset-L1') 'ClaudeReset.exe'
$task = 'ClaudeReset L1 Controller'
function Say($message) { Add-Content -Path $Log -Value ('{0} {1}' -f (Get-Date -Format o), $message) }
# ClaudeReset.exe is a windowed program: run it with Start-Process -Wait, its output is not available.
function Run-Exe($argument) { Start-Process -FilePath $exe -ArgumentList $argument -WindowStyle Hidden -Wait }
# The controller is elevated, so its Path is not readable here: judge by the relay port and the process name.
function Relay-Listening { [bool](Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort 25082 -ErrorAction SilentlyContinue) }
function Controller-Gone { (-not (Relay-Listening)) -and (-not (Get-Process ClaudeReset -ErrorAction SilentlyContinue)) }
function Wait-For($seconds, $test) { $end = (Get-Date).AddSeconds($seconds); while ((Get-Date) -lt $end) { if (& $test) { return $true }; Start-Sleep -Seconds 2 }; return $false }
try {
    Say ('start dist=' + $Dist)
    Say ('dist sha256 ' + (Get-FileHash $exe -Algorithm SHA256).Hash)
    Run-Exe '--strict-guard-close'
    $gone = Wait-For 90 { Controller-Gone }
    Say ('close requested; controller gone=' + $gone)
    if (-not $gone) { throw 'controller did not stop; install skipped' }
    $since = Get-Date
    Run-Exe '--strict-guard-autostart'
    Say 'install dispatched, waiting for UAC and receipt'
    $receipt = $null
    $done = Wait-For $UacSeconds {
        $found = Get-ChildItem $Guard -Filter 'autostart-*.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'autostart-report.json' -and $_.LastWriteTime -gt $since } | Select-Object -First 1
        if ($found) { $script:receipt = $found.FullName; $true } else { $false }
    }
    if ($done) { Say ('receipt ' + ((Get-Content $receipt -Raw) -replace '\s+', ' ')) } else { Say 'no receipt (UAC declined or timed out)' }
    if (Test-Path $installed) { Say ('installed sha256 ' + (Get-FileHash $installed -Algorithm SHA256).Hash) }
} catch {
    Say ('error ' + $_.Exception.Message)
} finally {
    if (-not (Relay-Listening)) { schtasks.exe /Run /TN $task | Out-Null; Say 'task run requested' }
    Say ('relay_open=' + (Wait-For 150 { Relay-Listening }))
    Say 'finished'
}
