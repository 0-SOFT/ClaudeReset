"""Windows Task Scheduler: lookup, registration, start and removal of one named task.

Callers pass the task name; which tasks the program owns is decided above this layer (config).
"""
from __future__ import annotations
from pathlib import Path
import subprocess
import tempfile

from ..errors import SafetyError
from .powershell import NO_WINDOW, ps_json, quote, run
from collections.abc import Callable

__all__ = ['Scheduler', 'create_from_xml', 'delete', 'describe', 'exists', 'lookup', 'register_logon_task', 'run_now',
           'start', 'state', 'unregister', 'xml']

# One COM connection to the scheduler's root folder; the task object is read by exact name.
_ROOT_FOLDER = r'''
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
$service = New-Object -ComObject 'Schedule.Service';
$service.Connect();
$folder = $service.GetFolder('\');
'''


def exists(name: str, runner: Callable[..., subprocess.CompletedProcess] | None=None) -> bool:
    code, out, _ = run(f"if (Get-ScheduledTask -TaskName {quote(name)} -ErrorAction SilentlyContinue) {{ 'yes' }}; exit 0", runner)
    return code == 0 and out == 'yes'


def register_logon_task(name: str, executable: Path | str, argument: str, working_directory: Path | str, description: str, runner: Callable[..., subprocess.CompletedProcess] | None=None) -> None:
    """A task that starts the program at the current user's logon with limited rights; never overwrites one."""
    script = f'''
$name = {quote(name)}
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {{ throw 'Task already exists; no overwrite' }}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute {quote(executable)} -Argument {quote(argument)} -WorkingDirectory {quote(working_directory)}
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description {quote(description)} | Out-Null
exit 0'''
    code, _, error = run(script, runner)
    if code:
        raise SafetyError('Task registration was refused: ' + (error or 'no details'))


def start(name: str, runner: Callable[..., subprocess.CompletedProcess] | None=None) -> None:
    code, _, error = run(f"Start-ScheduledTask -TaskName {quote(name)}; exit 0", runner)
    if code:
        raise SafetyError('Task start was refused: ' + error)


def unregister(name: str, runner: Callable[..., subprocess.CompletedProcess] | None=None) -> None:
    code, _, error = run(f"Unregister-ScheduledTask -TaskName {quote(name)} -Confirm:$false; exit 0", runner)
    if code:
        raise SafetyError('Task removal was refused: ' + error)


def state(name: str, runner: Callable[..., subprocess.CompletedProcess] | None=None) -> str | None:
    """'Missing', the task's state name, or None when the scheduler could not answer."""
    code, out, _ = run(
        f"$ErrorActionPreference='Stop'; try {{ $t=@(Get-ScheduledTask -ErrorAction Stop | "
        f"Where-Object {{ $_.TaskName -eq {quote(name)} }}); "
        "if ($t.Count -eq 0) { 'Missing' } elseif ($t.Count -eq 1) { [string]$t[0].State } "
        "else { exit 1 }; exit 0 } catch { exit 1 }", runner)
    return out.strip() if code == 0 else None


def run_now(name: str, run_process: Callable[..., subprocess.CompletedProcess] | None=None) -> subprocess.CompletedProcess:
    """Ask the scheduler to start the task now; the completed schtasks process is returned."""
    return (run_process or subprocess.run)(['schtasks', '/Run', '/TN', name], capture_output=True, text=True,
                                           timeout=60, creationflags=NO_WINDOW)


def describe(name: str) -> dict | None:
    """State, enablement, run level and actions of the task, or None when it does not exist."""
    return ps_json(f'''$t = Get-ScheduledTask -TaskName {quote(name)} -ErrorAction SilentlyContinue
    if ($t) {{ @{{state=[string]$t.State; enabled=[bool]$t.Settings.Enabled; run_level=[string]$t.Principal.RunLevel;
      actions=@($t.Actions | ForEach-Object {{ @{{execute=[string]$_.Execute; arguments=[string]$_.Arguments}} }})}} | ConvertTo-Json -Depth 4 -Compress }}
    exit 0''')  # an absent task is a normal answer; SilentlyContinue leaves $? false and PowerShell exits 1


def xml(name: str, *, query: Callable[[str], object] = ps_json) -> str | None:
    """The registered task definition as XML text, or None when the scheduler gave none.

    query runs the PowerShell lookup and parses its JSON answer."""
    row = query(_ROOT_FOLDER + f'''
$task = $folder.GetTask({quote(name)});
@{{xml=$task.Xml}} | ConvertTo-Json -Compress
''')
    return row.get('xml') if isinstance(row, dict) else None


def lookup(name: str, *, query: Callable[[str], object] = ps_json) -> str:
    """'present', 'absent' or 'unknown': a failed or localized answer never proves absence.

    query runs the PowerShell lookup and parses its JSON answer."""
    try:
        row = query(_ROOT_FOLDER + f'''
try {{
    $task = $folder.GetTask({quote(name)});
    if ($null -eq $task) {{ $state = 'unknown' }}
    else {{ $state = 'present' }}
}} catch {{
    $failure = $_.Exception;
    while ($null -ne $failure.InnerException) {{ $failure = $failure.InnerException }}
    $state = 'unknown';
    if (($failure -is [System.Runtime.InteropServices.COMException]) -and
        ($failure.ErrorCode -eq -2147024894)) {{ $state = 'absent' }}
}}
@{{state=$state}} | ConvertTo-Json -Compress
''')
        if isinstance(row, dict) and row.get('state') in ('present', 'absent', 'unknown'):
            return row['state']
    except (OSError, ValueError, TypeError, SafetyError):
        pass
    return 'unknown'


def create_from_xml(name: str, definition: str) -> None:
    """Register (or replace) the task from an XML definition; a refusal raises."""
    with tempfile.TemporaryDirectory() as folder:
        file = Path(folder) / 'task.xml'
        file.write_text(definition, encoding='utf-16')
        created = subprocess.run(['schtasks', '/Create', '/TN', name, '/XML', str(file), '/F'],
                                 capture_output=True, text=True, creationflags=NO_WINDOW)
    if created.returncode != 0:
        raise SafetyError('Task registration failed')


def delete(name: str) -> None:
    subprocess.run(['schtasks', '/Delete', '/TN', name, '/F'], capture_output=True, text=True, creationflags=NO_WINDOW)


class Scheduler:
    """The scheduler calls of a task the program registers from XML; a test gives a fake scheduler."""

    def xml(self, name: str) -> str | None:
        return xml(name)

    def lookup(self, name: str) -> str:
        return lookup(name)

    def create(self, name: str, definition: str) -> None:
        create_from_xml(name, definition)

    def delete(self, name: str) -> None:
        delete(name)
