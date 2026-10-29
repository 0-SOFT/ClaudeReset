"""Only temporary journals and synthetic scheduler calls."""
import json
from types import SimpleNamespace

import pytest

from claude_reset import uac_request as uac, l1_install
from test_uac_request import paths


def records(paths):
    return [json.loads(p.read_text()) for p in
            (paths.state / 'strict-guard').glob('child-*.json')]


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_valid_looking_foreign_id_never_gets_bound_denial(paths, operation):
    request = uac.prepare(paths, operation)
    foreign = 'f' * 32
    assert foreign != request.request_id
    for _ in range(2):
        with pytest.raises(uac.ChildAdmissionRefused):
            uac.admit_child(paths, operation, foreign)
    assert records(paths) == []
    rows = [json.loads(p.read_text()) for p in
            (paths.state / 'strict-guard').glob('denied-unknown-*.json')]
    assert len(rows) == 2 and all(r['identity'] is None for r in rows)
    assert len({r['attempt_id'] for r in rows}) == 2
    assert foreign not in json.dumps(rows)
    assert uac.blocked(paths)


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_verified_refusals_have_distinct_attempts(paths, operation):
    request = uac.prepare(paths, operation)
    uac.revoke(paths, request)
    for _ in range(2):
        with pytest.raises(uac.ChildAdmissionRefused):
            uac.admit_child(paths, operation, request.request_id)
    rows = records(paths)
    assert len(rows) == 2
    assert all(r['identity'] == uac.receipt_identity(paths, operation, request.request_id)
               and r['schema'] == 2 for r in rows)
    assert len({r['attempt_id'] for r in rows}) == 2
    assert uac.blocked(paths)


def test_denial_keeps_verified_snapshot_after_claim_changes(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    uac.revoke(paths, request)
    original = uac.admission_denied
    def changed(p, operation, request_id, **kwargs):
        uac.pending_path(p).write_text('{}')
        return original(p, operation, request_id, **kwargs)
    monkeypatch.setattr(uac, 'admission_denied', changed)
    with pytest.raises(uac.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert records(paths)[0]['identity'] == uac.receipt_identity(paths, 'remove', request.request_id)
    assert uac.blocked(paths)


def test_denial_write_failure_preserves_claim(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    uac.revoke(paths, request)
    before = uac.pending_path(paths).read_bytes()
    def fail(*args):
        raise OSError('synthetic private error')
    monkeypatch.setattr(uac, '_save_exclusive', fail)
    with pytest.raises(uac.ChildAdmissionRefused, match='Elevation admission unavailable'):
        uac.admit_child(paths, 'remove', request.request_id)
    assert uac.pending_path(paths).read_bytes() == before
    assert records(paths) == []


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_finish_and_replay_denial_are_distinct(paths, operation):
    request = uac.prepare(paths, operation)
    identity = uac.admit_child(paths, operation, request.request_id)
    uac.child_event(paths, identity, 'finish')
    with pytest.raises(uac.ChildAdmissionRefused):
        uac.admit_child(paths, operation, request.request_id)
    assert {r['event'] for r in records(paths)} == {'finish', 'admission-denied'}
    assert all(r['identity'] == identity for r in records(paths))
    assert uac.blocked(paths)


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_revoked_request_logs_refusal_without_finish(paths, operation):
    request = uac.prepare(paths, operation)
    uac.revoke(paths, request)
    with pytest.raises(uac.ChildAdmissionRefused):
        uac.admit_child(paths, operation, request.request_id)
    assert [r['event'] for r in records(paths)] == ['admission-denied']
    assert uac.blocked(paths)


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS))
def test_torn_child_event_never_releases_claim(paths, monkeypatch, operation):
    request = uac.prepare(paths, operation)
    identity = uac.receipt_identity(paths, operation, request.request_id)
    def torn(path, record):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{')
        raise OSError('synthetic private error')
    monkeypatch.setattr(uac, '_save_exclusive', torn)
    with pytest.raises(OSError):
        uac.child_event(paths, identity, 'finish')
    assert uac.blocked(paths)
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
        monkeypatch.setattr(uac, '_event', lambda *a: (_ for _ in ()).throw(OSError('journal')))
    @uac.serialized('test', completed={'done'})
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
    assert uac.blocked(paths)
    assert bool(effects) == (failure != 'dispatch-write')


@pytest.mark.parametrize('failed', [False, True])
def test_filter_handler_records_finish_for_both_outcomes(paths, monkeypatch, failed):
    from claude_reset import netguard
    request = uac.prepare(paths, 'filters')
    def inspect():
        if failed:
            raise OSError('private synthetic detail')
        return {'passed': True}
    monkeypatch.setattr(netguard, 'filters', inspect)
    result = netguard.filter_receipt(paths, request.request_id)
    assert result['finished'] is True
    assert [r['event'] for r in records(paths)] == ['finish']
    assert 'private synthetic detail' not in json.dumps(records(paths))
    assert uac.blocked(paths)


def test_finish_write_failure_prevents_package_success_receipt(paths, monkeypatch):
    from claude_reset import package_isolation as package
    request = uac.prepare(paths, 'package-register')
    monkeypatch.setattr(package, 'source_directory', lambda: paths.state)
    monkeypatch.setattr(package, 'verify_sources', lambda _: None)
    monkeypatch.setattr(package, 'installed', lambda _: ('family', 'name', 'publisher'))
    monkeypatch.setattr(package, 'accepted', lambda _: True)
    monkeypatch.setattr(uac, 'child_event', lambda *a: (_ for _ in ()).throw(OSError('disk')))
    with pytest.raises(OSError):
        package.register(paths.state / 'report.json', paths=paths, request_id=request.request_id)
    assert not (paths.state / 'report.json').exists()
    assert uac.blocked(paths)

@pytest.mark.parametrize('request_id', [None, '', '../private-password', 'f' * 31])
def test_unidentifiable_denial_has_no_untrusted_data(paths, request_id):
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request_id)
    files = list((paths.state / 'strict-guard').glob('denied-unknown-*.json'))
    assert len(files) == 1
    assert json.loads(files[0].read_text()) == {
        'schema': 2, 'event': 'admission-denied', 'identity': None,
        'attempt_id': files[0].stem.removeprefix('denied-unknown-')}


@pytest.mark.parametrize('damage', ['none', 'missing', 'torn', 'wrong', 'gap', 'conflict'])
def test_scheduler_history_requires_each_exact_attempt(paths, damage):
    request = uac.prepare(paths, 'start')
    assert uac.inspect_scheduler_history(request) == 'incomplete'
    for kind in ['scheduler-1-dispatch', 'scheduler-1-nonzero',
                 'scheduler-2-dispatch', 'scheduler-2-accepted', 'scheduler-2-observed']:
        uac._event(paths, request, kind)
    target = uac._request_marker(request, 'scheduler-1-nonzero')
    if damage == 'missing':
        target.unlink()
    elif damage == 'torn':
        target.write_text('{')
    elif damage == 'wrong':
        target.write_text('{}')
    elif damage == 'gap':
        uac._save_exclusive(uac._request_marker(request, 'scheduler-4-dispatch'),
                            {'schema': 1, 'request': uac.asdict(request),
                             'event': 'scheduler-4-dispatch'})
        uac._event(paths, request, 'scheduler-4-error')
    elif damage == 'conflict':
        uac._event(paths, request, 'scheduler-1-error')
    assert uac.inspect_scheduler_history(request) == ('recorded' if damage == 'none' else 'incomplete')
    assert uac.blocked(paths)


def test_each_scheduler_retry_is_durable_before_effect(paths):
    calls = []
    @uac.serialized('test', completed={'done'})
    def chain(p):
        def run(*args, **kwargs):
            request = uac._chain.get().start_request
            number = len(calls) + 1
            assert uac._request_marker(request, f'scheduler-{number}-dispatch').is_file()
            assert uac._scheduler_count(request) == number
            calls.append(number)
            return SimpleNamespace(returncode=1)
        assert not l1_install.start_controller(p.state / 'strict-guard', run=run,
                                               attempts=3, sleep=lambda _: None)
        assert uac.inspect_scheduler_history(uac._chain.get().start_request) == 'recorded'
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    assert calls == [1, 2, 3]


def test_missing_whole_scheduler_tail_cannot_release_uncertain_chain(paths):
    calls = []

    @uac.serialized('test', completed={'done'})
    def chain(p):
        def run(*args, **kwargs):
            calls.append('run')
            return SimpleNamespace(returncode=1)

        assert not l1_install.start_controller(
            p.state / 'strict-guard', run=run, attempts=2, sleep=lambda _: None)
        request = uac._chain.get().start_request
        assert len(calls) == 2
        # Lose a whole trailing attempt, leaving a syntactically valid prefix.
        # These are synthetic journal files under the pytest temporary profile.
        for kind in ('scheduler-2-dispatch', 'scheduler-2-nonzero'):
            uac._request_marker(request, kind).unlink()
        assert uac.inspect_scheduler_history(request) == 'incomplete'
        with pytest.raises(uac.SafetyError):
            uac.prepare(p, 'start')
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert uac.blocked(paths)


@pytest.mark.parametrize('damage', ['missing', 'torn', 'foreign', 'boolean', 'extra'])
def test_scheduler_inventory_damage_is_incomplete(paths, damage):
    request = uac.prepare(paths, 'start')
    uac._event(paths, request, 'scheduler-1-dispatch')
    uac._event(paths, request, 'scheduler-1-nonzero')
    marker = uac._request_marker(request, 'expected-scheduler')
    row = json.loads(marker.read_text())
    if damage == 'missing':
        marker.unlink()
    elif damage == 'torn':
        marker.write_text('{')
    else:
        if damage == 'foreign':
            row['request']['request_id'] = 'f' * 32
        elif damage == 'boolean':
            row['attempts'] = True
        else:
            row['extra'] = 1
        marker.write_text(json.dumps(row))
    assert uac.inspect_scheduler_history(request) == 'incomplete'
    assert uac.blocked(paths)


@pytest.mark.parametrize('failure', ['inventory', 'dispatch'])
def test_scheduler_inventory_write_failure_prevents_effect(paths, monkeypatch, failure):
    save = uac._save_exclusive
    calls = []

    def fail(path, row):
        if path.name.startswith('expected-scheduler' if failure == 'inventory' else 'scheduler-1-dispatch'):
            raise OSError('synthetic')
        save(path, row)

    monkeypatch.setattr(uac, '_save_exclusive', fail)

    @uac.serialized('test', completed={'done'})
    def chain(p):
        with pytest.raises(OSError):
            l1_install.start_controller(p.state / 'strict-guard',
                                       run=lambda *a, **k: calls.append('effect'))
        request = uac._chain.get().start_request
        assert uac.inspect_scheduler_history(request) == 'incomplete'
        assert uac._request_marker(request, 'expected-scheduler').exists() == (failure == 'dispatch')
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert not calls
    assert uac.blocked(paths)


def test_scheduler_inventory_rejects_gap_without_changing_count(paths):
    request = uac.prepare(paths, 'start')
    uac._event(paths, request, 'scheduler-1-dispatch')
    with pytest.raises(uac.SafetyError):
        uac._event(paths, request, 'scheduler-3-dispatch')
    assert uac._scheduler_count(request) == 1
    assert not uac._request_marker(request, 'scheduler-3-dispatch').exists()


@pytest.mark.parametrize('after_replace', [False, True])
def test_scheduler_second_index_failure_prevents_second_dispatch(paths, monkeypatch, after_replace):
    from claude_reset import safeio
    save = safeio.atomic_json
    calls = []

    def fail(path, row, root):
        if path.name.startswith('expected-scheduler-'):
            if after_replace:
                save(path, row, root)
            raise OSError('synthetic')
        save(path, row, root)

    monkeypatch.setattr(safeio, 'atomic_json', fail)

    @uac.serialized('test', completed={'done'})
    def chain(p):
        def run(*a, **k):
            calls.append('run')
            return SimpleNamespace(returncode=1)
        with pytest.raises(OSError):
            l1_install.start_controller(p.state / 'strict-guard', run=run,
                                       attempts=2, sleep=lambda _: None)
        request = uac._chain.get().start_request
        assert uac.inspect_scheduler_history(request) == ('incomplete' if after_replace else 'recorded')
        assert not uac._request_marker(request, 'scheduler-2-dispatch').exists()
        with pytest.raises(uac.SafetyError):
            uac.prepare(p, 'remove')
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert calls == ['run'] and uac.blocked(paths)


def test_missing_whole_request_is_detected_after_reopening(paths):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        first = uac.prepare(p, 'remove')
        second = uac.prepare(p, 'filters')
        claim = uac._chain.get().claim
        assert uac._inventory(claim)['requests'] == [uac.asdict(first), uac.asdict(second)]
        uac._request_marker(second, 'request').unlink()
        return {'status': 'incomplete'}

    chain(paths)
    assert uac.inspect_pending(paths)['status'] == 'claim_unavailable'
    assert uac.blocked(paths)


def test_request_write_failure_keeps_inventory_intent_and_claim(paths, monkeypatch):
    save = uac._save_exclusive

    def fail(path, row):
        if path.name.startswith('request-'):
            raise OSError('synthetic')
        save(path, row)

    monkeypatch.setattr(uac, '_save_exclusive', fail)

    @uac.serialized('test', completed={'done'})
    def chain(p):
        with pytest.raises(OSError):
            uac.prepare(p, 'start')
        assert len(uac._inventory(uac._chain.get().claim)['requests']) == 1
        from claude_reset.controller_admission import permit_path
        assert not permit_path(p).exists()
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert uac.inspect_pending(paths)['status'] == 'claim_unavailable'


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS))
@pytest.mark.parametrize('damage', ['missing', 'torn', 'omitted'])
def test_inventory_damage_forbids_late_child(paths, operation, damage):
    @uac.serialized('test', completed={'done'})
    def chain(p):
        request = uac.prepare(p, operation)
        claim = uac._chain.get().claim
        marker = uac._inventory_path(claim)
        if damage == 'missing':
            marker.unlink()
        elif damage == 'torn':
            marker.write_text('{')
        else:
            row = uac._inventory(claim)
            row['requests'] = []
            marker.write_text(json.dumps(row))
        with pytest.raises((OSError, uac.SafetyError)):
            uac._event(p, request, 'dispatch')
        with pytest.raises(uac.SafetyError):
            if operation == 'start':
                from claude_reset.controller_admission import consume
                from claude_reset.admission import locked
                with locked(p):
                    consume(p, request.request_id)
            else:
                uac.admit_child(p, operation, request.request_id)
        return {'status': 'incomplete'}

    chain(paths)
    assert uac.blocked(paths)


@pytest.mark.parametrize('after_replace', [False, True])
def test_second_request_inventory_failure_prevents_permit(paths, monkeypatch, after_replace):
    from claude_reset import safeio, controller_admission
    save = safeio.atomic_json

    def fail(path, row, root):
        if path.name.startswith('expected-requests-') and len(row['requests']) == 2:
            if after_replace:
                save(path, row, root)
            raise OSError('synthetic')
        save(path, row, root)

    monkeypatch.setattr(safeio, 'atomic_json', fail)

    @uac.serialized('test', completed={'done'})
    def chain(p):
        uac.prepare(p, 'filters')
        with pytest.raises(OSError):
            uac.prepare(p, 'start')
        assert not controller_admission.permit_path(p).exists()
        assert len(list((p.state / 'strict-guard').glob('request-*.json'))) == 1
        assert len(uac._inventory(uac._chain.get().claim)['requests']) == (2 if after_replace else 1)
        return {'status': 'done'}

    assert chain(paths)['retry_blocked']
    assert uac.blocked(paths)


def test_initial_inventory_failure_never_enters_chain(paths, monkeypatch):
    save = uac._save_exclusive

    def fail(path, row):
        if path.name.startswith('expected-requests-'):
            raise OSError('synthetic')
        save(path, row)

    monkeypatch.setattr(uac, '_save_exclusive', fail)

    @uac.serialized('test', completed={'done'})
    def chain(p):
        pytest.fail('effect before inventory')

    with pytest.raises(OSError):
        chain(paths)
    assert uac.blocked(paths)
    assert uac.inspect_pending(paths)['status'] == 'claim_unavailable'


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS))
@pytest.mark.parametrize('damage', ['schema', 'claim', 'requests', 'item', 'duplicate',
    'request_schema', 'owner', 'root', 'operation', 'id', 'receipt', 'extra', 'deep'])
def test_invalid_inventory_fields_block_dispatch_admission_and_inspection(paths, operation, damage):
    from claude_reset import controller_admission
    from claude_reset.admission import locked

    @uac.serialized('test', completed={'done'})
    def chain(p):
        request = uac.prepare(p, operation)
        claim = uac._chain.get().claim
        marker = uac._inventory_path(claim)
        row = uac._inventory(claim)
        item = row['requests'][0]
        if damage == 'schema':
            row['schema'] = True
        elif damage == 'claim':
            row['claim']['owner_id'] = 'f' * 32
        elif damage == 'requests':
            row['requests'] = {}
        elif damage == 'item':
            row['requests'] = [None]
        elif damage == 'duplicate':
            row['requests'].append(dict(item))
        elif damage == 'extra':
            item['private'] = 'PRIVATE-INVENTORY'
        elif damage != 'deep':
            field, value = {
                'request_schema': ('schema', True), 'owner': ('owner_id', 'f' * 32),
                'root': ('state_root', 'PRIVATE-INVENTORY'),
                'operation': ('operation', []), 'id': ('request_id', '../private'),
                'receipt': ('receipt', 'PRIVATE-INVENTORY'),
            }[damage]
            item[field] = value
        marker.write_text('[' * 50000 + '0' + ']' * 50000 if damage == 'deep' else json.dumps(row))
        before = marker.read_bytes()
        with pytest.raises(uac.SafetyError):
            uac._event(p, request, 'dispatch')
        assert not uac._request_marker(request, 'dispatch').exists()
        with pytest.raises(uac.SafetyError):
            if operation == 'start':
                with locked(p):
                    controller_admission.consume(p, request.request_id)
            else:
                uac.admit_child(p, operation, request.request_id)
        if operation == 'start':
            assert json.loads(controller_admission.permit_path(p).read_text())['consumed'] is False
        assert not uac._request_marker(request, 'admitted').exists()
        result = uac.inspect_pending(p)
        assert result['status'] == 'claim_unavailable' and result['requests'] == []
        assert 'PRIVATE-INVENTORY' not in str(result)
        assert marker.read_bytes() == before
        return {'status': 'incomplete'}

    chain(paths)
    assert uac.blocked(paths)
