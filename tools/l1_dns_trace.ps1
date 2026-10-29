# Attribute local DNS queries to processes for the L1 privacy measurement.
# Elevated, fixed operations only: start a temporary ETW session for the DNS-Client provider,
# wait, stop it, convert the trace, and record the process list at both ends.
# Nothing persistent changes: no event-log enablement, no DNS settings, no firewall/WFP, no routes.
param([Parameter(Mandatory)][string]$Out, [int]$Seconds = 180, [int]$SnapshotEvery = 10)
$ErrorActionPreference = 'Stop'
$session = 'ClaudeResetDnsTrace'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$etl = Join-Path $Out 'dns.etl'
function Snapshot($name) {
    Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath |
        ConvertTo-Json -Compress | Set-Content -Encoding UTF8 (Join-Path $Out $name)
}
$log = Join-Path $Out 'trace.log'
try {
    Snapshot 'processes-start.json'
    & logman.exe start $session -p 'Microsoft-Windows-DNS-Client' 0xFFFFFFFFFFFFFFFF 0xFF -o $etl -ets | Out-File $log
    for ($i = 0; $i -lt $Seconds; $i += $SnapshotEvery) { Snapshot ("processes-{0:D6}.json" -f $i); Start-Sleep -Seconds $SnapshotEvery }
} finally {
    & logman.exe stop $session -ets | Out-File $log -Append
    & tracerpt.exe $etl -o (Join-Path $Out 'dns.xml') -of XML -y | Out-File $log -Append
    Set-Content -Path (Join-Path $Out 'done.flag') -Value (Get-Date).ToString('o')
}
