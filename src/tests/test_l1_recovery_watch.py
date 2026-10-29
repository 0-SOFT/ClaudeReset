import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

spec = importlib.util.spec_from_file_location('recovery_watch', Path(__file__).resolve().parents[2] / 'tools/l1_recovery_watch.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)
INSTANCE = 'a' * 32


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    state_root = tmp_path / 'state'
    folder = state_root / 'strict-guard'; folder.mkdir(parents=True)
    program_files = tmp_path / 'Program Files'
    executable = program_files / 'ClaudeReset-L1/ClaudeReset.exe'
    executable.parent.mkdir(parents=True); executable.write_bytes(b'modeled installed controller')
    monkeypatch.setenv('ProgramFiles', str(program_files))
    monkeypatch.setattr(watch.Paths, 'current', lambda: SimpleNamespace(state=state_root))
    def save(name, value):
        (folder / name).write_text(json.dumps(value), encoding='utf-8')
    save('status.json', dict(instance=INSTANCE, state='blocked_controller_stopped', live_permit_session=False))
    save('recovery-state.json', dict(armed=True, attempts=0, next_attempt=0))
    save('autostart-model.json', dict(registered=True, executable_sha256=watch.hashlib.sha256(executable.read_bytes()).hexdigest()))
    (folder / 'l1-consent.dpapi').write_bytes(b'opaque consent, never decrypted by watchdog')
    meta = dict(executable=str(executable), arguments='--strict-guard-serve --report "' + str(folder / 'autostart-report.json') + '"',
                task_state='Ready', relay_listening=False)
    monkeypatch.setattr(watch, 'metadata', lambda: dict(meta))
    calls = []
    def run(args, **kw):
        calls.append(args); return SimpleNamespace(returncode=0)
    monkeypatch.setattr(watch.subprocess, 'run', run)
    monkeypatch.setattr(watch, 'follow_start', lambda *args: False)
    return folder, meta, calls, save


def test_restart_runs_only_existing_fixed_task_and_no_elevation(fixture):
    folder, meta, calls, save = fixture
    result = watch.run_once()
    assert calls == [[str(Path(watch.os.environ['SystemRoot']) / 'System32/schtasks.exe'), '/Run', '/TN', 'ClaudeReset L1 Controller']]
    assert result['started'] is True and result['wfp_changed'] is False
    assert result['elevation_requested'] is False
    assert json.loads((folder / 'recovery-state.json').read_text())['attempts'] == 1


@pytest.mark.parametrize('fault', ['explicit_stop', 'missing_consent', 'unarmed', 'task_running', 'listener_present'])
def test_normal_stop_or_unverified_conditions_never_launch_task(fixture, fault):
    folder, meta, calls, save = fixture
    if fault == 'explicit_stop': save('close.request', dict(instance=INSTANCE, requested='owner'))
    if fault == 'missing_consent': (folder / 'l1-consent.dpapi').unlink()
    if fault == 'unarmed': save('recovery-state.json', dict(armed=False))
    if fault == 'task_running': meta['task_state'] = 'Running'
    if fault == 'listener_present': meta['relay_listening'] = True
    assert watch.run_once()['started'] is False
    assert not calls


@pytest.mark.parametrize('fault', ['image', 'arguments', 'disabled', 'binary'])
def test_changed_controller_task_or_image_is_refused(fixture, fault):
    folder, meta, calls, save = fixture
    if fault == 'image': meta['executable'] = 'C:\\foreign.exe'
    if fault == 'arguments': meta['arguments'] += ' --arbitrary-command'
    if fault == 'disabled': meta['task_state'] = 'Disabled'
    if fault == 'binary': Path(meta['executable']).write_bytes(b'changed')
    with pytest.raises(watch.SafetyError): watch.run_once()
    assert not calls


def test_live_relay_arms_recovery_but_does_not_start_anything(fixture):
    folder, meta, calls, save = fixture
    save('recovery-state.json', dict(armed=False))
    save('status.json', dict(instance=INSTANCE, state='relay_open', live_permit_session=True))
    meta.update(task_state='Running', relay_listening=True)
    result = watch.run_once()
    assert result['armed'] and result['reason'] == 'relay_available'
    assert not calls


def test_stop_between_inspection_and_launch_is_respected(fixture, monkeypatch):
    folder, meta, calls, save = fixture
    original = watch.verify_task
    def stop(*args):
        digest = original(*args)
        save('close.request', dict(instance=INSTANCE, requested='owner'))
        return digest
    monkeypatch.setattr(watch, 'verify_task', stop)
    result = watch.run_once()
    assert not result['started'] and not result['armed'] and not calls


def test_unknown_start_with_pending_stop_is_forwarded_to_new_instance(fixture):
    folder, meta, calls, save = fixture
    save('recovery-pending-stop.json', dict(previous_instance='b' * 32, request=dict(requested='owner')))
    result = watch.run_once()
    assert not result['armed'] and not calls
    assert json.loads((folder / 'close.request').read_text()) == dict(instance=INSTANCE, requested='owner')
    assert not (folder / 'recovery-pending-stop.json').exists()


def test_retry_backoff_does_not_launch_again(fixture):
    folder, meta, calls, save = fixture
    save('recovery-state.json', dict(armed=True, attempts=1, next_attempt=watch.time.time() + 60))
    assert watch.run_once()['reason'] == 'retry_backoff'
    assert not calls


def test_follow_start_carries_concurrent_stop_forward(tmp_path, monkeypatch):
    # Use the real follow_start implementation (fixture does not patch it).
    folder = tmp_path
    (folder / 'status.json').write_text(json.dumps(dict(instance='b' * 32)), encoding='utf-8')
    (folder / 'close.request').write_text(json.dumps(dict(instance=INSTANCE, requested='owner')), encoding='utf-8')
    assert watch.follow_start(folder, INSTANCE, {}) is True
    assert json.loads((folder / 'close.request').read_text()) == dict(instance='b' * 32, requested='owner')
