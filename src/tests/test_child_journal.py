"""Only temporary journals and synthetic scheduler calls."""
import json
from types import SimpleNamespace

import pytest
from test_uac_request import paths

from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.network import l1_install


def records(paths):
    return [json.loads(p.read_text()) for p in
            (paths.state / 'strict-guard').glob('child-*.json')]


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_valid_looking_foreign_id_never_gets_bound_denial(paths, operation):
    request = uac.prepare(paths, operation)
    foreign = 'f' * 32
    assert foreign != request.request_id
    for _ in range(2):
        with pytest.raises(claims.ChildAdmissionRefused):
            uac.admit_child(paths, operation, foreign)
    assert records(paths) == []
    rows = [json.loads(p.read_text()) for p in
            (paths.state / 'strict-guard').glob('denied-unknown-*.json')]
    assert len(rows) == 2 and all(r['identity'] is None for r in rows)
    assert len({r['attempt_id'] for r in rows}) == 2
    assert foreign not in json.dumps(rows)
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_verified_refusals_have_distinct_attempts(paths, operation):
    request = uac.prepare(paths, operation)
    uac.revoke(paths, request)
    for _ in range(2):
        with pytest.raises(claims.ChildAdmissionRefused):
            uac.admit_child(paths, operation, request.request_id)
    rows = records(paths)
    assert len(rows) == 2
    assert all(r['identity'] == claims.receipt_identity(paths, operation, request.request_id)
               and r['schema'] == 2 for r in rows)
    assert len({r['attempt_id'] for r in rows}) == 2
    assert claims.blocked(paths)


def test_denial_keeps_verified_snapshot_after_claim_changes(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    uac.revoke(paths, request)
    original = uac.admission_denied
    def changed(p, operation, request_id, **kwargs):
        claims.pending_path(p).write_text('{}')
        return original(p, operation, request_id, **kwargs)
    monkeypatch.setattr(uac, 'admission_denied', changed)
    with pytest.raises(claims.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert records(paths)[0]['identity'] == claims.receipt_identity(paths, 'remove', request.request_id)
    assert claims.blocked(paths)


def test_denial_write_failure_preserves_claim(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    uac.revoke(paths, request)
    before = claims.pending_path(paths).read_bytes()
    def fail(*args):
        raise OSError('synthetic private error')
    monkeypatch.setattr(claims, 'save_exclusive', fail)
    with pytest.raises(claims.ChildAdmissionRefused, match='Elevation admission unavailable'):
        uac.admit_child(paths, 'remove', request.request_id)
    assert claims.pending_path(paths).read_bytes() == before
    assert records(paths) == []


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_finish_and_replay_denial_are_distinct(paths, operation):
    request = uac.prepare(paths, operation)
    identity = uac.admit_child(paths, operation, request.request_id)
    uac.child_event(paths, identity, 'finish')
    with pytest.raises(claims.ChildAdmissionRefused):
        uac.admit_child(paths, operation, request.request_id)
    assert {r['event'] for r in records(paths)} == {'finish', 'admission-denied'}
    assert all(r['identity'] == identity for r in records(paths))
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_revoked_request_logs_refusal_without_finish(paths, operation):
    request = uac.prepare(paths, operation)
    uac.revoke(paths, request)
    with pytest.raises(claims.ChildAdmissionRefused):
        uac.admit_child(paths, operation, request.request_id)
    assert [r['event'] for r in records(paths)] == ['admission-denied']
    assert claims.blocked(paths)


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS))
def test_torn_child_event_never_releases_claim(paths, monkeypatch, operation):
    request = uac.prepare(paths, operation)
    identity = claims.receipt_identity(paths, operation, request.request_id)
    def torn(path, record):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{')
        raise OSError('synthetic private error')
    monkeypatch.setattr(claims, 'save_exclusive', torn)
    with pytest.raises(OSError):
        uac.child_event(paths, identity, 'finish')
    assert claims.blocked(paths)
    assert [p.read_text() for p in (paths.state / 'strict-guard').glob('child-*.json')] == ['{']


@pytest.mark.parametrize('failure', ['dispatch-write', 'run-error', 'run-failed', 'unobserved'])
def test_scheduler_uncertainty_survives_ignored_failure(paths, monkeypatch, failure):
    effects = []
    def run(*args, **kwargs):
        effects.append('run')
        if failure == 'run-error':
            raise OSError('synthetic')
        return SimpleNamespace(returncode=1 if failure == 'run-failed' else 0)
    if failure == 'dispatch-write':
        monkeypatch.setattr(uac, 'record_event', lambda *a: (_ for _ in ()).throw(OSError('journal')))
    @claims.serialized('test', completed={'done'})
    def chain(p):
        try:
            assert not l1_install.start_controller(p.state / 'strict-guard', run=run,
                                                  attempts=1, wait_each=0, sleep=lambda _: None)
        except OSError:
            pass
        with pytest.raises(uac.SafetyError):
            uac.prepare(p, 'start')
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    assert claims.blocked(paths)
    assert bool(effects) == (failure != 'dispatch-write')


def test_finish_write_failure_prevents_package_success_receipt(paths, monkeypatch):
    from test_package_isolation import FAMILY, FULL, Windows

    from claude_reset.network import package_isolation as package
    request = uac.prepare(paths, 'package-register')
    monkeypatch.setattr(uac, 'child_event', lambda *a: (_ for _ in ()).throw(OSError('disk')))
    with pytest.raises(OSError):   # the package is already registered: register only reports it
        package.register(paths.state / 'report.json', paths=paths, request_id=request.request_id,
                         folder=package.source_directory(), runner=Windows((FAMILY, FULL, package.PUBLISHER)))
    assert not (paths.state / 'report.json').exists()
    assert claims.blocked(paths)

@pytest.mark.parametrize('request_id', [None, '', '../private-password', 'f' * 31])
def test_unidentifiable_denial_has_no_untrusted_data(paths, request_id):
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request_id)
    files = list((paths.state / 'strict-guard').glob('denied-unknown-*.json'))
    assert len(files) == 1
    assert json.loads(files[0].read_text()) == {
        'schema': 2, 'event': 'admission-denied', 'identity': None,
        'attempt_id': files[0].stem.removeprefix('denied-unknown-')}


def test_scheduler_inventory_rejects_gap_without_changing_count(paths):
    request = uac.prepare(paths, 'start')
    uac.record_event(paths, request, 'scheduler-1-dispatch')
    with pytest.raises(uac.SafetyError):
        uac.record_event(paths, request, 'scheduler-3-dispatch')
    assert uac.scheduler_count(request) == 1
    assert not claims.request_marker(request, 'scheduler-3-dispatch').exists()


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS))
@pytest.mark.parametrize('damage', ['missing', 'torn', 'omitted'])
def test_inventory_damage_forbids_late_child(paths, operation, damage):
    @claims.serialized('test', completed={'done'})
    def chain(p):
        request = uac.prepare(p, operation)
        claim = claims.chain.get().claim
        marker = claims.inventory_path(claim)
        if damage == 'missing':
            marker.unlink()
        elif damage == 'torn':
            marker.write_text('{')
        else:
            row = claims.inventory(claim)
            row['requests'] = []
            marker.write_text(json.dumps(row))
        with pytest.raises((OSError, uac.SafetyError)):
            uac.record_event(p, request, 'dispatch')
        with pytest.raises(uac.SafetyError):
            if operation == 'start':
                from claude_reset.elevation.admission import consume
                from claude_reset.elevation.locks import locked
                with locked(p):
                    consume(p, request.request_id)
            else:
                uac.admit_child(p, operation, request.request_id)
        return {'status': 'incomplete'}

    chain(paths)
    assert claims.blocked(paths)


@pytest.mark.parametrize('after_replace', [False, True])
def test_second_request_inventory_failure_prevents_permit(paths, monkeypatch, after_replace):
    from claude_reset import safeio
    from claude_reset.elevation import admission as controller_admission
    save = safeio.atomic_json

    def fail(path, row, root):
        if path.name.startswith('expected-requests-') and len(row['requests']) == 2:
            if after_replace:
                save(path, row, root)
            raise OSError('synthetic')
        save(path, row, root)

    monkeypatch.setattr(safeio, 'atomic_json', fail)

    @claims.serialized('test', completed={'done'})
    def chain(p):
        uac.prepare(p, 'remove')
        with pytest.raises(OSError):
            uac.prepare(p, 'start')
        assert not controller_admission.permit_path(p).exists()
        assert len(list((p.state / 'strict-guard').glob('request-*.json'))) == 1
        assert len(claims.inventory(claims.chain.get().claim)['requests']) == (2 if after_replace else 1)
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert claims.blocked(paths)
