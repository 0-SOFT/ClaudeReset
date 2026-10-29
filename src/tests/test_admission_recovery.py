"""Recovery fencing on temporary profiles; no UAC or installed state."""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from claude_reset import uac_request as uac, controller_admission as gate
from claude_reset.admission import locked
from test_uac_request import paths
from test_request_revocation import consume


def snapshot(paths):
    return json.loads(uac.pending_path(paths).read_text('utf-8'))


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS))
@pytest.mark.parametrize('nested', [False, True])
def test_reopened_recovery_fences_all_children(paths, operation, nested):
    requests = []
    @uac.serialized('test', completed={'done'})
    def chain(p):
        requests.append(uac.prepare(p, operation))
        return {'status': 'incomplete'}
    if nested:
        chain(paths)
    else:
        requests.append(uac.prepare(paths, operation))
    claim = snapshot(paths)
    assert uac._chain.get() is None
    for _ in range(2):
        assert uac.close_admission(paths, claim)['status'] == 'admission_closed'
    with pytest.raises(uac.SafetyError):
        consume(paths, requests[0])
    with pytest.raises(uac.SafetyError):
        uac._release(paths, requests[0])
    assert snapshot(paths) == claim


def test_failed_prepare_after_permit_closed_without_inventory(paths, monkeypatch):
    grant = gate.grant
    saved = []
    def fail(p, request, **kw):
        grant(p, request, **kw)
        saved.append(request)
        raise OSError('synthetic')
    monkeypatch.setattr(gate, 'grant', fail)
    @uac.serialized('test', completed={'done'})
    def chain(p):
        with pytest.raises(OSError):
            uac.prepare(p, 'start', scheduler=True)
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    claim = snapshot(paths)
    uac._inventory_path(claim).unlink()
    uac.close_admission(paths, claim)
    with locked(paths), pytest.raises(uac.SafetyError):
        gate.consume(paths, None)
    assert json.loads(gate.permit_path(paths).read_text())['consumed'] is False
    assert uac.blocked(paths)


@pytest.mark.parametrize('operation', ['start', 'remove'])
def test_already_admitted_remains_uncertain(paths, operation):
    request = uac.prepare(paths, operation)
    identity = consume(paths, request)
    claim = snapshot(paths)
    result = uac.close_admission(paths, claim)
    uac.child_event(paths, identity, 'finish')
    assert result['requires_live_verification'] and result['retry_blocked']
    assert snapshot(paths) == claim


@pytest.mark.parametrize('torn', [False, True])
def test_closure_write_failure_is_not_success(paths, monkeypatch, torn):
    request = uac.prepare(paths, 'remove')
    claim = snapshot(paths)
    original = uac._save_exclusive
    def fail(path, record):
        if path.name.startswith('closed-generation-'):
            if torn:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{')
            raise OSError('synthetic')
        original(path, record)
    monkeypatch.setattr(uac, '_save_exclusive', fail)
    with pytest.raises(OSError):
        uac.close_admission(paths, claim)
    assert snapshot(paths) == claim
    if torn:
        with pytest.raises(uac.SafetyError):
            consume(paths, request)
        with pytest.raises(uac.SafetyError):
            uac.close_admission(paths, claim)
    else:
        assert consume(paths, request)  # No false claim that the failed fence exists.


def test_recovery_serializes_with_admission_and_stale_owner(paths):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        request = uac.prepare(p, 'start')
        claim = snapshot(p)
        with locked(p), ThreadPoolExecutor(1) as pool:
            with pytest.raises(uac.SafetyError):
                pool.submit(uac.close_admission, p, claim).result()
        assert not uac._generation_marker(claim).exists()
        with ThreadPoolExecutor(1) as pool:
            pool.submit(uac.close_admission, p, claim).result()
        # The old owner's ContextVar was not changed by the recovery thread.
        assert not uac._chain.get().uncertain
        with pytest.raises(uac.SafetyError):
            uac._event(p, request, 'scheduler-1-dispatch')
        with pytest.raises(uac.SafetyError):
            uac.prepare(p, 'remove')
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    assert uac.blocked(paths)


def test_recovery_refuses_stale_snapshot(paths):
    request = uac.prepare(paths, 'remove')
    claim = snapshot(paths)
    foreign = {**claim, 'request_id': 'f' * 32}
    with pytest.raises(uac.SafetyError):
        uac.close_admission(paths, foreign)
    assert consume(paths, request)


def test_stale_owner_cannot_release_after_external_closure(paths):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        with ThreadPoolExecutor(1) as pool:
            pool.submit(uac.close_admission, p, snapshot(p)).result()
        return {'status': 'done'}
    with pytest.raises(uac.SafetyError):
        chain(paths)
    assert uac.blocked(paths)
