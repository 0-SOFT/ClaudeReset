"""Real Windows ownership, temporary files and synthetic controller effects only."""
import json
import queue
import subprocess
import sys
import threading
import uuid
from types import SimpleNamespace

import pytest

from claude_reset.elevation import admission as gate
from claude_reset.network import controller as guard
from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.safeio import SafetyError
from test_uac_request import paths


CHILD = r'''
import ctypes
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from claude_reset.network import controller as guard
from claude_reset.safeio import SafetyError

# Use the production file lock and real Windows APIs, but a unique mutex name
# so this test cannot acquire or interfere with the installed controller.
native = ctypes.WinDLL
class Kernel:
    def __init__(self, *args, **kwargs):
        self.api = native(*args, **kwargs)
        create = self.api.CreateMutexW
        create.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        create.restype = ctypes.c_void_p
        self.CreateMutexW = lambda security, owner, name: create(security, owner, sys.argv[3])
    def __getattr__(self, name):
        return getattr(self.api, name)
ctypes.WinDLL = Kernel
p = SimpleNamespace(local=Path(sys.argv[1]), state=Path(sys.argv[2]))
def synthetic(paths, report, folder, state, **kw):
    print(json.dumps(state), flush=True)
    if sys.argv[5] == 'hold':
        command = sys.stdin.readline().strip()
        if command == 'close':
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    row = json.loads((folder / 'close.request').read_text('utf-8'))
                    if row.get('instance') == state['instance']:
                        return state
                except (OSError, ValueError):
                    pass
                time.sleep(.01)
            raise RuntimeError('No exact close request')
    return state
guard.run_admitted = synthetic
try:
    guard.serve(p, p.state / 'report.json', request_id=sys.argv[4] or None)
except SafetyError:
    sys.exit(7)
'''


@pytest.fixture
def children(paths):
    processes = []
    mutex = 'Local\\ClaudeReset.Test.' + uuid.uuid4().hex

    def launch(request_id='', *, hold=False, state=None):
        # Bypass the Windows venv launcher: Popen owns the interpreter itself.
        process = subprocess.Popen(
            [sys._base_executable, '-c', CHILD, str(paths.local), str(state or paths.state),
             mutex, request_id, 'hold' if hold else 'once'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, creationflags=0x08000000)
        processes.append(process)
        return process

    yield launch
    for process in processes:
        if process.poll() is None:
            process.kill()  # Only synthetic processes created by this fixture.
        process.communicate(timeout=10)


def admitted(process):
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    return json.loads(lines.get(timeout=10))


def refused(process):
    out, err = process.communicate(timeout=10)
    assert process.returncode == 7, err
    assert out == ''  # The first synthetic effect was never reached.


def old_controller(paths, children):
    request = uac.prepare(paths, 'start')
    process = children(request.request_id, hold=True)
    state = admitted(process)
    assert state['pid'] == process.pid and state['process_created'] > 0
    uac.release(paths, request)
    return process, state


def test_preexisting_controller_is_stopped_before_change_and_exact_handoff(paths, children):
    old, initial = old_controller(paths, children)
    status = paths.state / 'strict-guard/status.json'
    before = status.read_bytes()
    for root in (paths.state, paths.state.parent / 'other'):
        target = SimpleNamespace(local=paths.local, state=root)
        request = uac.prepare(target, 'start')
        # A valid permit cannot bypass either lifetime lock: the other root
        # has its own file lock, leaving the real named mutex as the barrier.
        refused(children(request.request_id, state=root))
        assert json.loads(gate.permit_path(target).read_text())['consumed'] is False
        assert old.poll() is None and status.read_bytes() == before
        uac.release(target, request)

    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        claim = claims.pending_path(p).read_bytes()
        before = status.read_bytes()
        refused(children())
        # Another root bypasses controller.lock but not the real named mutex.
        refused(children(state=p.state.parent / 'other'))
        assert old.poll() is None and status.read_bytes() == before
        old.stdin.write('close\n')
        old.stdin.flush()
        result = guard.request_close(p)
        assert result['process_exited'] is True
        assert old.wait(timeout=10) == 0
        assert json.loads((status.parent / 'close.request').read_text())['instance'] == initial['instance']
        for phase in ('after_stop', 'change', 'before_start'):
            refused(children())
            assert claims.pending_path(p).read_bytes() == claim, phase
            assert status.read_bytes() == before
        request = uac.schedule(status.parent)
        replacement = children(hold=True)
        fresh = admitted(replacement)
        assert fresh['request_id'] == request.request_id
        assert fresh['instance'] != initial['instance']
        assert fresh['pid'] != initial['pid']
        refused(children())
        replacement.stdin.write('exit\n')
        replacement.stdin.flush()
        assert replacement.wait(timeout=10) == 0
        refused(children())  # Consumed permit, even after lifetime lock release.
        return {'status': 'completed'}

    assert replace(paths)['status'] == 'completed'
    assert not claims.blocked(paths)
    refused(children())  # Late scheduler after successful claim release.


def test_bare_scheduler_denial_is_recorded_without_inferred_identity(paths, children):
    refused(children())
    files = list((paths.state / 'strict-guard').glob('denied-unknown-*.json'))
    assert len(files) == 1
    assert json.loads(files[0].read_text()) == {
        'schema': 2, 'event': 'admission-denied', 'identity': None,
        'attempt_id': files[0].stem.removeprefix('denied-unknown-')}
    assert not (paths.state / 'strict-guard' / 'status.json').exists()
