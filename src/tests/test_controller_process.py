"""No installed controller, task, elevation or network is used."""
import json
import subprocess
import sys

import pytest

from claude_reset import controller_process as cp
from claude_reset.safeio import SafetyError


def exercise(folder, *, created=123, exited=True, replace=None):
    calls = []
    class Process:
        def __init__(self, pid):
            assert pid == 42
            self.created = created
        def __enter__(self): return self
        def __exit__(self, *args): calls.append('closed')
        def wait(self, milliseconds):
            calls.append('wait')
            if replace:
                row = json.loads((folder / 'status.json').read_text())
                row.update(replace)
                (folder / 'status.json').write_text(json.dumps(row))
            return exited
    def read(path, root): return json.loads(path.read_text())
    def write(path, value, root):
        calls.append('request')
        path.write_text(json.dumps(value))
    result = cp.close_and_wait(folder, read, write, 'fixture', process_factory=Process)
    return result, calls


@pytest.fixture
def status(tmp_path):
    (tmp_path / 'status.json').write_text(json.dumps(
        {'schema': 1, 'operation': 'start', 'request_id': 'a' * 32,
         'state_root': str(tmp_path.parent),
         'instance': 'old', 'pid': 42, 'process_created': 123}))
    return tmp_path


def test_closed_relay_and_idle_task_cannot_replace_process_exit(status):
    result, calls = exercise(status, exited=False)
    assert result is False
    assert calls == ['request', 'wait', 'closed']


def test_exact_handle_exit_is_required(status):
    assert exercise(status) == (True, ['request', 'wait', 'closed'])


def test_reused_pid_cannot_receive_close_request(status):
    with pytest.raises(SafetyError, match='generation changed'):
        exercise(status, created=456)
    assert not (status / 'close.request').exists()


def test_new_controller_status_invalidates_completed_wait(status):
    result, _ = exercise(status, replace={'instance': 'new', 'pid': 43, 'process_created': 456})
    assert result is False


@pytest.mark.parametrize('data', [None, 'broken', '{}', '{"instance":"legacy","pid":42}'])
def test_missing_corrupt_or_legacy_status_never_permits_stop(tmp_path, data):
    if data is not None:
        (tmp_path / 'status.json').write_text(data)
    with pytest.raises((OSError, ValueError, SafetyError)):
        exercise(tmp_path)
    assert not (tmp_path / 'close.request').exists()


@pytest.mark.parametrize('field,value', [
    ('schema', None), ('schema', True), ('schema', 2),
    ('operation', 'remove'), ('state_root', 'foreign'),
    ('request_id', None), ('request_id', 'legacy'), ('request_id', 'G' * 32),
    ('pid', True), ('pid', 0), ('pid', 2**32), ('process_created', True),
])
def test_unsupported_identity_refused_before_open_or_write(status, field, value):
    row = json.loads((status / 'status.json').read_text())
    row[field] = value
    (status / 'status.json').write_text(json.dumps(row))
    def forbidden(*args):
        pytest.fail('Unsupported identity reached process or close request')
    with pytest.raises(SafetyError, match='identity unavailable'):
        cp.close_and_wait(status, lambda *a: row, forbidden, 'fixture',
                          process_factory=forbidden)
    assert not (status / 'close.request').exists()


@pytest.mark.parametrize('phase', ['open', 'wait'])
@pytest.mark.parametrize('field,value', [('request_id', 'b' * 32),
                                        ('schema', 2), ('operation', 'remove'),
                                        ('state_root', 'foreign')])
def test_protocol_change_with_same_process_never_confirms_stop(status, phase, field, value):
    row = json.loads((status / 'status.json').read_text())
    calls = []
    class Process:
        created = 123
        def __init__(self, pid):
            if phase == 'open':
                row[field] = value
        def __enter__(self): return self
        def __exit__(self, *args): calls.append('closed')
        def wait(self, milliseconds):
            row[field] = value
            return True
    try:
        result = cp.close_and_wait(status, lambda *a: row,
                                  lambda *a: calls.append('write'), 'fixture',
                                  process_factory=Process)
        assert result is False
    except SafetyError:
        pass
    assert calls == (['closed'] if phase == 'open' else ['write', 'closed'])


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows process handle')
def test_native_handle_waits_for_only_the_test_child():
    with subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.readline()'],
                          stdin=subprocess.PIPE, creationflags=0x08000000) as child:
        try:
            with cp.Process(child.pid) as witness:
                assert witness.created == cp.generation(child.pid)
                assert not witness.wait(0)
                child.communicate(b'finish\n', timeout=10)
                assert witness.wait(1000)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
