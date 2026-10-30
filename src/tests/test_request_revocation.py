"""Temporary files and synthetic effects only; no elevation."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from test_uac_request import paths

from claude_reset.elevation import admission as gate
from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.elevation.locks import locked


def consume(paths, request):
    if request.operation == 'start':
        with locked(paths):
            return gate.consume(paths, request.request_id)
    return uac.admit_child(paths, request.operation, request.request_id)


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS))
def test_revoked_cannot_begin_effect(paths, operation):
    request = uac.prepare(paths, operation)
    uac.revoke(paths, request)
    uac.revoke(paths, request)
    with pytest.raises(uac.SafetyError):
        consume(paths, request)
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', ['remove', 'start'])
def test_consumed_cannot_be_revoked(paths, operation):
    request = uac.prepare(paths, operation)
    consume(paths, request)
    with pytest.raises(uac.SafetyError):
        uac.revoke(paths, request)
    assert not claims.request_marker(request, 'revoked').exists()
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', ['remove', 'start'])
def test_torn_revocation_blocks_admission(paths, monkeypatch, operation):
    request = uac.prepare(paths, operation)
    original = claims.save_exclusive
    def torn(path, data):
        if path.name.startswith('revoked-'):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{')
            raise OSError('synthetic torn write')
        original(path, data)
    monkeypatch.setattr(claims, 'save_exclusive', torn)
    with pytest.raises(OSError):
        uac.revoke(paths, request)
    for action in (consume, uac.revoke):
        with pytest.raises(uac.SafetyError):
            action(paths, request)
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', ['remove', 'start'])
@pytest.mark.parametrize('repeat', range(10))
def test_concurrent_revoke_admit_never_both_win(paths, operation, repeat):
    request = uac.prepare(paths, operation)
    barrier = Barrier(2)
    def contender(action):
        barrier.wait(timeout=5)
        try:
            action(paths, request)
            return True
        except uac.SafetyError:
            return False
    with ThreadPoolExecutor(2) as pool:
        revoked = pool.submit(contender, uac.revoke)
        admitted = pool.submit(contender, consume)
        results = revoked.result(), admitted.result()
    assert sum(results) == 1
    assert claims.blocked(paths)
    with pytest.raises(uac.SafetyError):
        (consume if results[0] else uac.revoke)(paths, request)


@pytest.mark.parametrize('operation', ['remove', 'start'])
def test_nested_denial_fences_late_helper(paths, operation):
    saved = []
    @claims.serialized('test', completed={'done'})
    def chain(p):
        assert uac.execute(p, operation, lambda r: saved.append(r) or 5)['status'] == 'denied'
        with pytest.raises(uac.SafetyError):
            consume(p, saved[0])
        return {'status': 'incomplete'}
    assert chain(paths)['retry_blocked']
    for kind in ('dispatch', 'revoked', 'denial'):
        assert claims.request_marker(saved[0], kind).exists()


def test_denial_after_consumption_retains_claim(paths):
    def dispatch(r):
        consume(paths, r)
        return 5
    assert uac.execute(paths, 'remove', dispatch)['status'] == 'unknown'
    assert claims.blocked(paths)


@pytest.mark.parametrize('event', ['denial', 'receipt-observed'])
def test_failed_final_event_preserves_claim(paths, monkeypatch, event):
    from test_uac_request import write
    original = claims.save_exclusive
    def fail(path, data):
        if path.name.startswith(event + '-'):
            raise OSError('synthetic failure')
        original(path, data)
    monkeypatch.setattr(claims, 'save_exclusive', fail)
    def dispatch(request):
        if event == 'denial':
            return 5
        write(request)
        return 42
    assert uac.execute(paths, 'autostart', dispatch)['status'] == 'unknown'
    assert claims.blocked(paths)


def test_failed_dispatch_journal_prevents_launch(paths, monkeypatch):
    original = claims.save_exclusive
    def fail(path, data):
        if path.name.startswith('dispatch-'):
            raise OSError('synthetic failure')
        original(path, data)
    monkeypatch.setattr(claims, 'save_exclusive', fail)
    assert uac.execute(paths, 'remove', lambda r: pytest.fail('dispatch'))['status'] == 'unknown'
    assert claims.blocked(paths)
