"""Bounded cleanup actions; no elevation or client/network startup."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any

from ..errors import SafetyError
from .powershell import ps_json

__all__ = ['credential_names', 'delete_credential', 'resolve_processes', 'resolve_service']


def credential_names() -> tuple[str, ...]:
    result = ps_json(r'''
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
    $text = (cmdkey /list | Out-String);
    if ($LASTEXITCODE -ne 0) { throw 'Credential inventory failed' }
    @{text=$text} | ConvertTo-Json -Compress
    ''')
    return parse_credentials(result['text'])


def parse_credentials(text: str) -> tuple[str, ...]:
    names = re.findall(r'^\s*(?:Target|Цель):\s*(.+?)\s*$', text, re.M | re.I)
    return tuple(sorted(set(n for n in names if re.search(
        r'(^|[:=/\\ ._-])(claude|anthropic)([:=/\\ ._-]|$)', n, re.I))))


def delete_credential(name: str) -> None:
    if parse_credentials('Target: ' + name) != (name,):
        raise SafetyError('The entry does not belong to Claude', code='not_claude_entry')
    quoted = "'" + name.replace("'", "''") + "'"
    ps_json("$target = " + quoted + "; cmdkey ('/delete:' + $target) | Out-Null; "
            "if ($LASTEXITCODE -ne 0) { throw 'Credential deletion failed' }; @{ok=$true} | ConvertTo-Json")


def resolve_processes(names: Iterable[str], *, run: Callable[[str], Any]=ps_json) -> Any:
    # Preserve this worker and every ancestor, including a hosting Claude session.
    return run(CLOSE_CLAUDE.replace('__CLOSABLE__', ','.join(f"'{name}'" for name in names)))


CLOSE_CLAUDE = r'''
    $all = @(Get-CimInstance Win32_Process);
    $keep = @(); $current = $PID;
    while ($current -and $current -notin $keep) {
        $keep += $current;
        $parent = $all | Where-Object ProcessId -eq $current | Select-Object -First 1;
        $current = $parent.ParentProcessId;
    }
    $targets = @($all | Where-Object {
        $_.Name -in @(__CLOSABLE__) -and $_.ProcessId -notin $keep
    });
    foreach ($p in $targets) {
        $live = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.ProcessId);
        if ($live -and $live.CreationDate -eq $p.CreationDate -and $live.Name -eq $p.Name) {
            Stop-Process -Id $p.ProcessId -ErrorAction Stop
        }
    }
    @{status='process_stop_requested'; shared_editor_preserved=$true} | ConvertTo-Json
    '''


def resolve_service(*, run: Callable[[str], Any]=ps_json) -> Any:
    return run(r'''
    $s = Get-Service -Name CoworkVMService -ErrorAction SilentlyContinue;
    if ($s -and $s.Status -ne 'Stopped') {
        Stop-Service -Name CoworkVMService -ErrorAction Stop;
        $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15));
    }
    @{status='cowork_service_stopped'} | ConvertTo-Json
    ''')
