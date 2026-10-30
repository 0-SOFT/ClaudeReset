"""Run once per minute as the owner, without elevation or direct WFP access.

The only recovery action is running the existing, verified L1 controller task.
It must perform all its normal admission checks again. A matching explicit
close request or missing L1 consent disarms recovery until a manual start.
"""
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from claude_reset import config, layout
from claude_reset.layout import Paths
from claude_reset.network.l1_recovery import backoff, decide
from claude_reset.safeio import SafetyError, atomic_json, guarded
from claude_reset.windows.powershell import ps_json, quote

TASK = config.CONTROLLER_TASK


def read(path, default=None):
    guarded(path, path.parent)
    try:
        with path.open('rb') as stream:
            data = stream.read(262145)
    except FileNotFoundError:
        if default is not None:
            return default
        raise
    if len(data) > 262144:
        raise SafetyError('Recovery input exceeds size limit')
    result = json.loads(data.decode('utf-8'))
    if not isinstance(result, dict):
        raise SafetyError('Recovery input must be an object')
    return result


# The controller task and whether its relay listens; @TASK@, @LOOPBACK@ and @PORT@ come from config.
METADATA_SCRIPT = r'''$ErrorActionPreference='Stop';
      $t=Get-ScheduledTask -TaskName @TASK@;
      @{task_state=$t.State.ToString(); executable=[string]$t.Actions.Execute;
        arguments=[string]$t.Actions.Arguments;
        relay_listening=@(Get-NetTCPConnection -State Listen -LocalAddress @LOOPBACK@ -LocalPort @PORT@ -ErrorAction SilentlyContinue).Count -gt 0
      } | ConvertTo-Json -Compress'''


def metadata():
    script = METADATA_SCRIPT.replace('@TASK@', quote(TASK)).replace('@LOOPBACK@', quote(config.LOOPBACK))
    return ps_json(script.replace('@PORT@', str(config.RELAY_PORT)))


def verify_task(meta, folder):
    expected = layout.l1_program() / config.CONTROLLER_EXE
    arguments = '--strict-guard-serve --report "' + str(folder / 'autostart-report.json') + '"'
    if (meta.get('executable') != str(expected) or meta.get('arguments') != arguments
            or meta.get('task_state') not in ('Ready', 'Running', 'Queued')):
        raise SafetyError('Recovery refuses an unexpected or disabled controller task')
    guarded(expected, expected.parent)
    with expected.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    for receipt in folder.glob('autostart-*.json'):
        value = read(receipt)
        if value.get('registered') is True and value.get('executable_sha256') == digest:
            return digest
    raise SafetyError('Installed controller has no matching installation receipt')


def run_once():
    paths = Paths.current()
    folder = guarded(paths.state / 'strict-guard', paths.state)
    # Task Scheduler uses IgnoreNew. This extra lock also covers manual runs.
    import msvcrt
    with (folder / 'recovery.lock').open('a+b') as lock:
        lock.seek(0)
        lock.write(b'0')
        lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return dict(reason='another_recovery_check_running', restart=False)
        try:
            state = read(folder / 'status.json')
            close = read(folder / 'close.request', {})
            saved = read(folder / 'recovery-state.json', {})
            pending = read(folder / 'recovery-pending-stop.json', {})
            if pending:
                if state.get('instance') != pending.get('previous_instance'):
                    close = dict(pending['request'], instance=state['instance'])
                    atomic_json(folder / 'close.request', close, folder)
                    (folder / 'recovery-pending-stop.json').unlink()
                saved['armed'] = False
            meta = metadata()
            digest = verify_task(meta, folder)
            plan = decide(state, close, armed=saved.get('armed') is True,
                          task_running=meta['task_state'] in ('Running', 'Queued'),
                          relay_listening=meta['relay_listening'] is True,
                          consent_present=(folder / 'l1-consent.dpapi').is_file())
            now = time.time()
            attempts = saved.get('attempts', 0)
            if type(attempts) is not int or not 0 <= attempts <= 1000000:
                attempts = 0
            next_attempt = saved.get('next_attempt', 0)
            if type(next_attempt) not in (int, float) or not 0 <= next_attempt <= now + 300:
                next_attempt = 0
            if plan['reason'] == 'relay_available' or not plan['armed']:
                attempts = next_attempt = 0
            result = dict(schema=1, utc=now, **plan, instance=state.get('instance'),
                          controller_sha256=digest, started=False, wfp_changed=False,
                          elevation_requested=False)
            if plan['restart'] and now >= next_attempt:
                # Re-read stop/consent immediately before running the fixed task.
                current = read(folder / 'status.json')
                current_close = read(folder / 'close.request', {})
                fresh = decide(current, current_close, armed=plan['armed'],
                               task_running=False, relay_listening=False,
                               consent_present=(folder / 'l1-consent.dpapi').is_file())
                if current.get('instance') != state.get('instance') or not fresh['restart']:
                    result.update(reason='recovery_context_changed', restart=False)
                    if not fresh['armed']:
                        result['armed'] = False
                else:
                    executable = Path(os.environ['SystemRoot']) / 'System32/schtasks.exe'
                    run = subprocess.run([str(executable), '/Run', '/TN', TASK],
                                         capture_output=True, timeout=15, creationflags=0x08000000)
                    attempts += 1
                    next_attempt = now + backoff(attempts)
                    result.update(started=run.returncode == 0, task_run_exit=run.returncode)
                    if run.returncode == 0:
                        # A Stop command can have read the old status just
                        # before Task Scheduler starts the replacement. Carry
                        # that request forward instead of silently ignoring it.
                        stopped = follow_start(folder, state['instance'], current_close)
                        if stopped:
                            result.update(armed=False, reason='explicit_close_during_restart')
            elif plan['restart']:
                result['reason'] = 'retry_backoff'
            atomic_json(folder / 'recovery-state.json', dict(schema=1, armed=result['armed'],
                        attempts=attempts, next_attempt=next_attempt), folder)
            atomic_json(folder / 'recovery-report.json', result, folder)
            return result
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def follow_start(folder, previous_instance, previous_close):
    deadline = time.monotonic() + 20
    explicit_close = None
    while time.monotonic() < deadline:
        close = read(folder / 'close.request', {})
        if close != previous_close:
            explicit_close = close
        state = read(folder / 'status.json')
        instance = state.get('instance')
        if instance != previous_instance:
            if explicit_close is not None:
                # The controller still handles its usual, scoped close request.
                # No process termination or service stop is performed here.
                atomic_json(folder / 'close.request', dict(explicit_close, instance=instance), folder)
                return True
            return False
        time.sleep(.25)
    # Never keep retrying a request whose startup outcome is unknown.
    if explicit_close is not None:
        atomic_json(folder / 'recovery-pending-stop.json',
                    dict(previous_instance=previous_instance, request=explicit_close), folder)
        return True
    return False


if __name__ == '__main__':
    try:
        result = run_once()
        if sys.stdout is not None:
            print(json.dumps(result))
    except Exception as error:
        if sys.stdout is not None:
            print(json.dumps(dict(reason='recovery_refused', error_type=type(error).__name__)))
        raise SystemExit(2)
