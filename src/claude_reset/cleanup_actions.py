"""Bounded cleanup actions; no elevation or client/network startup."""
import re
from .windows import ps_json
from .safeio import SafetyError


def credential_names():
    result = ps_json(r'''
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
    $text = (cmdkey /list | Out-String);
    if ($LASTEXITCODE -ne 0) { throw 'Credential inventory failed' }
    @{text=$text} | ConvertTo-Json -Compress
    ''')
    return parse_credentials(result['text'])


def parse_credentials(text):
    names = re.findall(r'^\s*(?:Target|Цель):\s*(.+?)\s*$', text, re.M | re.I)
    return tuple(sorted(set(n for n in names if re.search(
        r'(^|[:=/\\ ._-])(claude|anthropic)([:=/\\ ._-]|$)', n, re.I))))


def delete_credential(name):
    if parse_credentials('Target: ' + name) != (name,):
        raise SafetyError('Запись не относится к Claude')
    quoted = "'" + name.replace("'", "''") + "'"
    ps_json("$target = " + quoted + "; cmdkey ('/delete:' + $target) | Out-Null; "
            "if ($LASTEXITCODE -ne 0) { throw 'Credential deletion failed' }; @{ok=$true} | ConvertTo-Json")


def resolve_processes(*, run=ps_json):
    # Preserve this worker and every ancestor, including a hosting Claude session.
    return run(r'''
    $all = @(Get-CimInstance Win32_Process);
    $keep = @(); $current = $PID;
    while ($current -and $current -notin $keep) {
        $keep += $current;
        $parent = $all | Where-Object ProcessId -eq $current | Select-Object -First 1;
        $current = $parent.ParentProcessId;
    }
    $targets = @($all | Where-Object {
        $_.Name -in @('Claude.exe','claude.exe','claude-desktop.exe') -and $_.ProcessId -notin $keep
    });
    foreach ($p in $targets) {
        $live = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.ProcessId);
        if ($live -and $live.CreationDate -eq $p.CreationDate -and $live.Name -eq $p.Name) {
            Stop-Process -Id $p.ProcessId -ErrorAction Stop
        }
    }
    @{status='process_stop_requested'; shared_editor_preserved=$true} | ConvertTo-Json
    ''')


def resolve_service(*, run=ps_json):
    return run(r'''
    $s = Get-Service -Name CoworkVMService -ErrorAction SilentlyContinue;
    if ($s -and $s.Status -ne 'Stopped') {
        Stop-Service -Name CoworkVMService -ErrorAction Stop;
        $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15));
    }
    @{status='cowork_service_stopped'} | ConvertTo-Json
    ''')
