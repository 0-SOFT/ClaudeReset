"""Temporary journals and fake process handles; no installed-state changes."""
import json
from contextlib import contextmanager
from dataclasses import asdict

import pytest

from claude_reset import admission_recovery as recovery, controller_process as cp
from claude_reset import uac_request as uac
from claude_reset.controller_boundary import Boundary
from test_uac_request import paths


@pytest.fixture(autouse=True)
def isolate_boundary(monkeypatch):
    monkeypatch.setattr(recovery, 'hold_boundary', fake_boundary)


@contextmanager
def fake_boundary():
    yield Boundary()


def status(request, **changes):
    row = {**asdict(request), 'instance': 'fixture', 'pid': 42, 'process_created': 123}
    row.update(changes)
    path = uac.Path(request.state_root) / 'strict-guard' / 'status.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row), encoding='utf-8')
    return path


def factory(*, created=123, exited=False, on_wait=lambda: None, calls=None):
    class Process:
        def __init__(self, pid):
            assert pid == 42
            self.created = created
        def __enter__(self): return self
        def __exit__(self, *args):
            if calls is not None: calls.append('closed')
        def wait(self, milliseconds):
            assert milliseconds == 0
            on_wait()
            return exited
    return Process


@pytest.mark.parametrize('exited', [False, True])
def test_exact_controller_observed_without_stop(paths, exited):
    request = uac.prepare(paths, 'start')
    file = status(request, state='blocked_controller_stopped', finished=True)
    calls = []
    assert cp.observe_request(request, process_factory=factory(exited=exited, calls=calls)) == (
        'exited' if exited else 'running')
    assert calls == ['closed']
    assert not (file.parent / 'close.request').exists()
    assert uac.blocked(paths)


@pytest.mark.parametrize('data', [None, '{', '{}', '[]', '{"pid":42}',
                                  '[' * 2000 + '0' + ']' * 2000, ' ' * 65537],
                         ids=['missing', 'torn', 'empty', 'list', 'legacy', 'deep', 'oversized'])
def test_missing_corrupt_legacy_status_is_unknown(paths, data):
    request = uac.prepare(paths, 'start')
    file = status(request)
    if data is None: file.unlink()
    else: file.write_text(data)
    def forbidden(pid): pytest.fail('invalid status opened a process')
    assert cp.observe_request(request, process_factory=forbidden) == 'unknown'


@pytest.mark.parametrize('changes', [{'request_id': 'f' * 32}, {'operation': 'remove'},
                                   {'state_root': 'foreign'}, {'pid': True},
                                   {'schema': True}, {'process_created': True}])
def test_foreign_or_invalid_identity_never_opens_handle(paths, changes):
    request = uac.prepare(paths, 'start')
    status(request, **changes)
    def forbidden(pid): pytest.fail('foreign status opened a process')
    assert cp.observe_request(request, process_factory=forbidden) == 'unknown'


def test_pid_reuse_and_replacement_during_wait(paths):
    request = uac.prepare(paths, 'start')
    status(request)
    assert cp.observe_request(request, process_factory=factory(created=456)) == 'unknown'
    assert cp.observe_request(request, process_factory=factory(
        exited=True, on_wait=lambda: status(request, instance='new'))) == 'unknown'


@pytest.mark.parametrize('missing_inventory', [False, True])
def test_recovery_closes_before_observing_and_never_releases(paths, monkeypatch, missing_inventory):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        uac.prepare(p, 'start')
        return {'status': 'incomplete'}
    chain(paths)
    claim = json.loads(uac.pending_path(paths).read_text())
    if missing_inventory: uac._inventory_path(claim).unlink()
    calls = []
    def observe(request):
        assert uac._generation_marker(claim).exists()
        calls.append(request)
        return 'exited'
    monkeypatch.setattr(recovery, 'observe_request', observe)
    result = recovery.prepare_recovery(paths, claim)
    assert result['admission'] == 'closed'
    assert result['inventory'] == ('unknown' if missing_inventory else 'recorded')
    assert result['controllers'] == ([] if missing_inventory else ['exited'])
    assert bool(calls) is not missing_inventory
    for field in ('resources', 'child_exit', 'controller_ownership'):
        assert result[field] == 'unknown'
    assert result['retry_blocked'] and result['requires_live_verification']
    assert json.loads(uac.pending_path(paths).read_text()) == claim


def test_snapshot_change_during_observation_discards_results(paths, monkeypatch):
    request = uac.prepare(paths, 'start')
    claim = asdict(request)
    def observe(request):
        uac.pending_path(paths).write_text('{}')
        return 'exited'
    monkeypatch.setattr(recovery, 'observe_request', observe)
    result = recovery.prepare_recovery(paths, claim)
    assert result['inventory'] == 'unknown' and result['controllers'] == []
    assert result['retry_blocked'] and uac.blocked(paths)


def test_failed_fence_does_not_observe(paths, monkeypatch):
    request = uac.prepare(paths, 'start')
    claim = asdict(request)
    def fail(*args): raise OSError('private fixture')
    monkeypatch.setattr(uac, 'close_admission', fail)
    monkeypatch.setattr(recovery, 'observe_request', lambda r: pytest.fail('unfenced observation'))
    monkeypatch.setattr(recovery, 'hold_boundary', lambda: pytest.fail('unfenced boundary'))
    result = recovery.prepare_recovery(paths, claim)
    assert result['admission'] == 'unknown' and result['retry_blocked']
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize('witness', ['busy', 'acquired', 'abandoned', 'unknown'])
@pytest.mark.parametrize('missing_inventory', [False, True])
def test_boundary_observed_without_status_or_inventory(paths, monkeypatch, witness, missing_inventory):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        uac.prepare(p, 'start')
        return {'status': 'incomplete'}
    chain(paths)
    claim = json.loads(uac.pending_path(paths).read_text())
    if missing_inventory:
        uac._inventory_path(claim).unlink()
    calls = []
    @contextmanager
    def observe():
        assert uac._generation_marker(claim).exists()
        calls.append(True)
        yield Boundary(witness, witness in ('acquired', 'abandoned'))
        calls.append(False)
    monkeypatch.setattr(recovery, 'hold_boundary', observe)
    result = recovery.prepare_recovery(paths, claim)
    assert calls == [True, False]
    assert result['controller_boundary'] == witness
    assert result['controllers'] == ([] if missing_inventory else ['unknown'])
    assert result['controller_ownership'] == result['resources'] == result['child_exit'] == 'unknown'
    assert result['retry_blocked'] and json.loads(uac.pending_path(paths).read_text()) == claim


@pytest.mark.parametrize('changed', [False, True])
def test_scope_held_through_process_and_final_snapshot(paths, monkeypatch, changed):
    request = uac.prepare(paths, 'start')
    claim = asdict(request)
    active = []
    @contextmanager
    def hold():
        active.append(True)
        try:
            yield Boundary('acquired', True)
        finally:
            active.clear()
    monkeypatch.setattr(recovery, 'hold_boundary', hold)
    inspections = []
    inspect = uac.inspect_pending
    def check(p):
        assert active
        inspections.append(True)
        return inspect(p)
    monkeypatch.setattr(uac, 'inspect_pending', check)
    def observe(r):
        assert active
        if changed:
            raise OSError('private observation error')
        return 'exited'
    monkeypatch.setattr(recovery, 'observe_request', observe)
    result = recovery.prepare_recovery(paths, claim)
    assert not active
    assert len(inspections) == (1 if changed else 2)
    assert result['inventory'] == ('unknown' if changed else 'recorded')
    assert result['controller_ownership'] == 'unknown'
    assert result['retry_blocked'] and uac.blocked(paths)
    assert 'private' not in json.dumps(result)


def test_cleanup_failure_is_not_reported_as_acquired(paths, monkeypatch):
    request = uac.prepare(paths, 'start')
    @contextmanager
    def hold():
        witness = Boundary('acquired', True)
        yield witness
        witness.held = False
        witness.observation = 'unknown'
    monkeypatch.setattr(recovery, 'hold_boundary', hold)
    result = recovery.prepare_recovery(paths, asdict(request))
    assert result['controller_boundary'] == 'unknown'
    assert result['controller_ownership'] == 'unknown'
    assert result['retry_blocked'] and uac.blocked(paths)


def test_native_recovery_holds_private_mutex_across_observation(paths, monkeypatch):
    import ctypes as C
    import os
    import uuid
    from concurrent.futures import ThreadPoolExecutor
    from claude_reset import controller_boundary as boundary
    if os.name != 'nt':
        pytest.skip('Windows mutex')
    monkeypatch.setattr(boundary, 'NAME', 'Local\\ClaudeReset.Test.' + uuid.uuid4().hex)
    monkeypatch.setattr(recovery, 'hold_boundary', boundary.hold)
    api = boundary._kernel()
    api.CreateMutexW.argtypes = [C.c_void_p, C.c_int, C.c_wchar_p]
    api.CreateMutexW.restype = C.c_void_p
    handle = api.CreateMutexW(None, False, boundary.NAME)
    assert handle
    try:
        request = uac.prepare(paths, 'start')
        with ThreadPoolExecutor(1) as pool:
            def observe(r):
                assert pool.submit(boundary.observe).result(timeout=5) == 'busy'
                return 'unknown'  # No status exists; no exit evidence invented.
            monkeypatch.setattr(recovery, 'observe_request', observe)
            result = recovery.prepare_recovery(paths, asdict(request))
            assert pool.submit(boundary.observe).result(timeout=5) == 'acquired'
        assert result['controllers'] == ['unknown']
        assert result['controller_boundary'] == 'acquired'
        assert result['controller_ownership'] == 'unknown'
        assert result['retry_blocked'] and uac.blocked(paths)
    finally:
        api.CloseHandle(handle)
