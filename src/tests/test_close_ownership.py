"""Close submission uses temporary state only; no controller is started."""
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from claude_reset.network import controller as guard
from claude_reset import layout
from claude_reset.elevation import request as uac
from claude_reset.elevation import claims
from test_reset import paths


class FixtureProcess:
    created = 123
    def __init__(self, pid):
        assert pid == 42
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def wait(self, milliseconds): return True


@pytest.fixture(autouse=True)
def process_witness(monkeypatch):
    from claude_reset.network import controller_process
    monkeypatch.setattr(controller_process, 'RetainedProcess', FixtureProcess)


def seed(paths):
    folder = layout.controller(paths)
    folder.mkdir(parents=True)
    (folder / 'status.json').write_text(json.dumps({'schema': 1, 'operation': 'start', 'request_id': 'a' * 32, 'state_root': str(paths.state), 'instance': 'fixture', 'pid': 42, 'process_created': 123}))
    return folder / 'close.request'


def test_standalone_submission_retains_claim_and_prevents_replay(paths):
    target = seed(paths)
    result = guard.request_close(paths)
    assert result['status'] == 'strict_close_requested'
    assert result['retry_blocked'] is True
    before = target.read_bytes()
    claim = claims.pending_path(paths).read_bytes()
    assert guard.request_close(paths)['status'] == 'pending_elevation'
    assert target.read_bytes() == before
    assert claims.pending_path(paths).read_bytes() == claim


def test_busy_close_does_not_even_read_controller_status(paths, monkeypatch):
    uac.prepare(paths, 'filters')
    monkeypatch.setattr(guard, 'read_json', lambda *a: pytest.fail('status read'))
    assert guard.request_close(paths)['retry_blocked'] is True


def test_unfinished_process_retains_outer_claim(paths, monkeypatch):
    seed(paths)
    monkeypatch.setattr(FixtureProcess, 'wait', lambda *a: False)
    @claims.serialized('outer', completed={'done'})
    def chain(paths):
        result = guard.request_close(paths)
        assert result['status'] == 'controller_not_stopped'
        assert result['process_exited'] is False
        return {'status': 'done'}
    assert chain(paths)['retry_blocked'] is True
    assert claims.blocked(paths)


@pytest.mark.parametrize('finished', [False, True])
def test_outer_chain_owns_submission_until_its_final_verdict(paths, finished):
    seed(paths)

    @claims.serialized('outer', completed={'done'})
    def chain(paths):
        claim = claims.pending_path(paths).read_bytes()
        assert 'retry_blocked' not in guard.request_close(paths)
        assert claims.pending_path(paths).read_bytes() == claim
        other = SimpleNamespace(local=paths.local, state=paths.state / 'other')
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(guard.request_close, other).result()['retry_blocked']
        return {'status': 'done' if finished else 'not_stopped'}

    result = chain(paths)
    assert claims.blocked(paths) is not finished
    assert result.get('retry_blocked', False) is not finished


def test_partial_close_write_poisoning_survives_caught_exception(paths, monkeypatch):
    target = seed(paths)

    def fail(path, value, root):
        path.write_bytes(b'partial')
        raise OSError('synthetic')

    monkeypatch.setattr(guard, 'atomic_json', fail)

    @claims.serialized('outer', completed={'done'})
    def chain(paths):
        with pytest.raises(OSError):
            guard.request_close(paths)
        with pytest.raises(uac.SafetyError):
            guard.request_close(paths)
        return {'status': 'done'}

    assert chain(paths)['retry_blocked'] is True
    assert target.read_bytes() == b'partial'
    assert claims.blocked(paths)


@pytest.mark.parametrize('field', ['schema', 'operation', 'request_id', 'state_root'])
def test_legacy_status_with_valid_process_identity_retains_claim(paths, field):
    target = seed(paths)
    status = target.parent / 'status.json'
    row = json.loads(status.read_text())
    del row[field]
    status.write_text(json.dumps(row))

    @claims.serialized('outer', completed={'done'})
    def chain(p):
        with pytest.raises(uac.SafetyError):
            guard.request_close(p)
        return {'status': 'done'}

    assert chain(paths)['retry_blocked'] is True
    assert claims.blocked(paths)
    assert not target.exists()
