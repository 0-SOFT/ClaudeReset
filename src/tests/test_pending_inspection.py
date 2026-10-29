"""Persisted request inspection never dispatches or releases ownership."""
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from claude_reset import uac_request as uac


@pytest.fixture
def paths(tmp_path):
    return SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')


def receipt(request, **changes):
    row = dict(schema=1, request_id=request.request_id, operation=request.operation,
               state_root=request.state_root, finished=True, registered=True)
    row.update(changes)
    target = Path(request.receipt)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(row), encoding='utf-8')


def retained_chain(paths):
    requests = []
    @uac.serialized('l1_install', completed={'installed'})
    def run(paths):
        uac.execute(paths, 'autostart', lambda r: requests.append(r) or 42, wait_seconds=0)
        return {'status': 'failed'}
    run(paths)
    return requests[0]


@pytest.mark.parametrize('change', ['missing', 'torn', 'omit', 'append'])
def test_inventory_change_during_receipt_read_discards_all_evidence(paths, monkeypatch, change):
    request = retained_chain(paths)
    receipt(request)
    pending = uac.pending_path(paths)
    before = pending.read_bytes()
    marker = uac._inventory_path(json.loads(before))
    original = uac.read_receipt

    def changing(request):
        result = original(request)
        row = json.loads(marker.read_text())
        if change == 'missing':
            marker.unlink()
        elif change == 'torn':
            marker.write_text('{')
        else:
            if change == 'omit':
                row['requests'] = []
            else:
                extra = dict(row['requests'][0], request_id='e' * 32,
                             receipt=str(paths.state / 'strict-guard' / ('uac-' + 'e' * 32 + '.json')))
                row['requests'].append(extra)
            marker.write_text(json.dumps(row))
        return result

    monkeypatch.setattr(uac, 'read_receipt', changing)
    result = uac.inspect_pending(paths)
    assert result['status'] == 'claim_unavailable' and result['requests'] == []
    assert result['retry_blocked'] and result['requires_live_verification']
    assert pending.read_bytes() == before and uac.blocked(paths)


@pytest.mark.parametrize('nested', [False, True])
@pytest.mark.parametrize('status', [None, 'broken', '{}', '{"instance":"old"}'])
def test_late_success_is_evidence_only_even_without_controller_status(paths, nested, status):
    request = retained_chain(paths) if nested else uac.prepare(paths, 'autostart')
    receipt(request)
    if status is not None:
        (paths.state / 'strict-guard' / 'status.json').write_text(status)
    before = uac.pending_path(paths).read_bytes()
    reopened = SimpleNamespace(state=paths.state, local=paths.local)
    result = uac.inspect_pending(reopened)
    assert result['status'] == 'reconcile_required'
    assert result['requests'] == ['completed']
    assert result['retry_blocked'] and result['requires_live_verification']
    assert uac.pending_path(paths).read_bytes() == before
    with pytest.raises(FileExistsError):
        uac.prepare(reopened, 'remove')


@pytest.mark.parametrize('change', [{}, {'request_id': 'f' * 32}, {'error': 'PRIVATE'}, {'finished': False}])
def test_receipt_classification_does_not_expose_contents(paths, change):
    request = retained_chain(paths)
    receipt(request, **change)
    result = uac.inspect_pending(paths)
    expected = ('completed' if not change else 'reconcile_required' if 'error' in change else None)
    assert result['requests'] == [expected]
    assert 'PRIVATE' not in str(result) and str(paths.state) not in str(result)
    assert uac.blocked(paths)


@pytest.mark.parametrize('raw', ['broken', '[]', '{"schema":true}', '{"schema":3}', 'null'])
def test_corrupt_or_legacy_claim_is_retained(paths, raw):
    pending = uac.pending_path(paths)
    pending.parent.mkdir(parents=True)
    pending.write_text(raw)
    assert uac.inspect_pending(paths)['status'] == 'claim_unavailable'
    assert pending.read_text() == raw and uac.blocked(paths)


def test_foreign_root_is_not_followed(paths, monkeypatch):
    retained_chain(paths)
    other = SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    monkeypatch.setattr(uac, 'read_receipt', lambda _: pytest.fail('foreign receipt read'))
    assert uac.inspect_pending(other)['status'] == 'claim_unavailable'


@pytest.mark.parametrize('changes', [dict(request_id='../private'), dict(operation='foreign'),
    dict(receipt='private'), dict(schema=True), dict(owner_id='f' * 32)])
def test_invalid_standalone_request_never_reads_receipt(paths, monkeypatch, changes):
    request = uac.prepare(paths, 'autostart')
    row = asdict(request)
    row.update(changes)
    uac.pending_path(paths).write_text(json.dumps(row))
    monkeypatch.setattr(uac, 'read_receipt', lambda _: pytest.fail('invalid receipt read'))
    assert uac.inspect_pending(paths)['status'] == 'claim_unavailable'


@pytest.mark.parametrize('target', ['claim', 'request'])
def test_change_during_inspection_discards_evidence(paths, monkeypatch, target):
    request = retained_chain(paths)
    receipt(request)
    original = uac.read_receipt
    def changing(request):
        row = original(request)
        path = (uac.pending_path(paths) if target == 'claim' else
                paths.state / 'strict-guard' / ('request-' + request.request_id + '.json'))
        path.write_text('{}')
        return row
    monkeypatch.setattr(uac, 'read_receipt', changing)
    result = uac.inspect_pending(paths)
    assert result['status'] == 'claim_unavailable' and result['requests'] == []
    assert uac.blocked(paths)


def test_missing_claim_has_no_completion_assertion(paths):
    result = uac.inspect_pending(paths)
    assert result['status'] == 'no_claim' and not result['retry_blocked']
    assert result['requires_live_verification'] and result['requests'] == []
    assert not paths.local.exists()
