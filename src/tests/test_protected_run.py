import io
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from multiprocessing.connection import AuthenticationError, Client, Listener

import pytest

from claude_reset import protected_run as run
from claude_reset.safeio import SafetyError


@pytest.fixture
def home(tmp_path):
    folder = tmp_path / 'user'
    (folder / '.local/bin').mkdir(parents=True)
    # A stand-in with the reviewed name and path; cmd.exe has no side files to lose.
    shutil.copyfile(r'C:\Windows\System32\cmd.exe', folder / '.local/bin/claude.exe')
    return folder


def pipe():
    return r'\\.\pipe\clauderesettest-' + secrets.token_hex(8), secrets.token_bytes(16)


def run_job(job, home, stdin=b''):
    name, key = pipe()
    listener = Listener(name, family='AF_PIPE', authkey=key)
    result = {}

    def pump():
        conn = Client(name, family='AF_PIPE', authkey=key)
        result['code'] = run.pump_job(conn, json.loads(conn.recv_bytes()), home)
    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    conn = listener.accept()
    out, err = io.BytesIO(), io.BytesIO()
    code = run.drive(conn, job, io.BytesIO(stdin), out, err)
    thread.join(10)
    listener.close()
    return code, out.getvalue(), err.getvalue()


def test_stdio_and_exit_code_cross_the_pipe(home):
    exe = str(home / '.local/bin/claude.exe')
    code, out, err = run_job({'argv': [exe, '/c', 'echo OUT& echo ERR 1>&2& exit 7'], 'env': {}, 'cwd': str(home)}, home)
    assert code == 7 and b'OUT' in out and b'ERR' in err


def test_stdin_reaches_the_binary_and_eof_ends_it(home):
    exe = str(home / '.local/bin/claude.exe')
    code, out, _ = run_job({'argv': [exe, '/c', 'findstr /r .'], 'env': dict(os.environ), 'cwd': str(home)}, home, stdin=b'line-one\r\nline-two\r\n')
    assert code == 0 and b'line-one' in out and b'line-two' in out


def test_proxy_environment_is_forced_to_the_relay(home):
    exe = str(home / '.local/bin/claude.exe')
    code, out, _ = run_job({'argv': [exe, '/c', 'echo %HTTPS_PROXY% %NO_PROXY%'], 'cwd': str(home),
                            'env': {'HTTPS_PROXY': 'http://elsewhere:1', 'SystemRoot': r'C:\Windows'}}, home)
    assert b'http://127.0.0.1:25082' in out and b'elsewhere' not in out


def test_unreviewed_binary_is_refused_before_starting(home, tmp_path):
    other = tmp_path / 'claude.exe'
    shutil.copyfile(r'C:\Windows\System32\cmd.exe', other)
    code, _, err = run_job({'argv': [str(other), '/c', 'echo SHOULD-NOT-RUN'], 'env': {}, 'cwd': str(tmp_path)}, home)
    assert code == 126 and b'not a reviewed' in err
    assert not run.is_reviewed_binary(r'C:\Windows\System32\cmd.exe', home)


def test_reviewed_paths_match_only_the_named_images(home):
    extension = home / '.vscode/extensions/anthropic.claude-code-2.1.310-win32-x64/resources/native-binary'
    extension.mkdir(parents=True)
    shutil.copyfile(r'C:\Windows\System32\cmd.exe', extension / 'claude.exe')
    assert run.is_reviewed_binary(extension / 'claude.exe', home)
    assert run.is_reviewed_binary(home / '.local/bin/claude.exe', home)
    sibling = home / '.vscode/extensions/other.claude-code-1-win32-x64/resources/native-binary'
    sibling.mkdir(parents=True)
    shutil.copyfile(r'C:\Windows\System32\cmd.exe', sibling / 'claude.exe')
    assert not run.is_reviewed_binary(sibling / 'claude.exe', home)
    assert not run.is_reviewed_binary(home / 'missing/claude.exe', home)


def test_wrong_key_never_receives_a_job():
    name, key = pipe()
    listener = Listener(name, family='AF_PIPE', authkey=key)
    seen = {}

    def accept():
        try:
            listener.accept()
        except (AuthenticationError, OSError, EOFError) as exc:
            seen['error'] = exc
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    with pytest.raises((AuthenticationError, OSError, EOFError)):
        Client(name, family='AF_PIPE', authkey=secrets.token_bytes(16))
    thread.join(5)
    listener.close()
    assert 'error' in seen


def test_breaking_the_pipe_ends_the_binary_and_its_children(home):
    exe = str(home / '.local/bin/claude.exe')
    name, key = pipe()
    listener = Listener(name, family='AF_PIPE', authkey=key)
    result = {}

    def pump():
        conn = Client(name, family='AF_PIPE', authkey=key)
        result['code'] = run.pump_job(conn, json.loads(conn.recv_bytes()), home)
    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    conn = listener.accept()
    marker = f'127.0.0.{secrets.randbelow(200) + 20}'
    conn.send_bytes(json.dumps({'argv': [exe, '/c', f'ping -n 60 {marker} >nul'], 'env': dict(os.environ), 'cwd': str(home)}).encode())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not find_ping(marker):
        time.sleep(.2)
    assert find_ping(marker), 'child of the binary did not start'
    conn.close()
    thread.join(15)
    listener.close()
    assert not thread.is_alive() and not find_ping(marker)


def find_ping(marker):
    out = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                          "(Get-CimInstance Win32_Process -Filter \"Name='PING.EXE'\").CommandLine"],
                         capture_output=True, text=True, creationflags=0x08000000).stdout
    return marker in out


def test_disable_flag_runs_the_binary_directly(home, monkeypatch):
    monkeypatch.setattr(run, 'state_folder', lambda: home / '.claude-reset')
    (home / '.claude-reset').mkdir()
    (home / '.claude-reset' / 'disable-wrapper.flag').write_text('')
    monkeypatch.setattr(run.Path, 'home', classmethod(lambda cls: home))
    called = []
    monkeypatch.setattr(run, 'run_direct', lambda argv: called.append(argv) or 0)
    never = lambda *a, **k: pytest.fail('package launch must not be attempted')
    assert run.wrapper_main([str(home / '.local/bin/claude.exe'), '-p'], connector=never) == 0
    assert called and called[0][1] == '-p'


def test_pump_failure_falls_back_visibly_and_is_logged(home, monkeypatch, capfd):
    monkeypatch.setattr(run, 'state_folder', lambda: home / '.claude-reset')
    monkeypatch.setattr(run.Path, 'home', classmethod(lambda cls: home))
    monkeypatch.setattr(run, 'run_direct', lambda argv: 5)

    def refuse(executable):
        raise SafetyError('Package launch refused')
    assert run.wrapper_main([str(home / '.local/bin/claude.exe')], connector=refuse) == 5
    assert 'without coverage of child processes' in capfd.readouterr().err
    row = json.loads((home / '.claude-reset' / 'protected-run.log').read_text('ascii').splitlines()[-1])
    assert row['mode'] == 'direct' and row['reason'] == 'SafetyError' and set(row) == {'utc', 'mode', 'reason'}


def test_wrapper_refuses_an_unreviewed_binary(home, tmp_path, monkeypatch):
    monkeypatch.setattr(run, 'state_folder', lambda: home / '.claude-reset')
    monkeypatch.setattr(run.Path, 'home', classmethod(lambda cls: home))
    other = tmp_path / 'claude.exe'
    shutil.copyfile(r'C:\Windows\System32\cmd.exe', other)
    never = lambda *a, **k: pytest.fail('must not connect for an unreviewed binary')
    assert run.wrapper_main([str(other)], connector=never) == 126
