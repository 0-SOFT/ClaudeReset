"""Temporary admission records only; no elevation or client effects."""
from dataclasses import asdict
import json
from types import SimpleNamespace

import pytest

from claude_reset import child_process as child, uac_request as uac
from claude_reset import admission_recovery as recovery
from test_uac_request import paths
from test_recovery_observation import factory, fake_boundary


def recorded(paths, monkeypatch):
    monkeypatch.setattr(child, 'os', SimpleNamespace(getpid=lambda: 42))
    monkeypatch.setattr(child.controller_process, 'generation', lambda pid: 123)
    request = uac.prepare(paths, 'remove')
    identity = uac.admit_child(paths, 'remove', request.request_id)
    return request, identity


@pytest.mark.parametrize('exited', [False, True])
def test_finish_does_not_replace_process_wait(paths, monkeypatch, exited):
    request, identity = recorded(paths, monkeypatch)
    uac.child_event(paths, identity, 'finish')
    calls = []
    assert child.observe(request, process_factory=factory(exited=exited, calls=calls)) == (
        'exited' if exited else 'running')
    assert calls == ['closed']
    assert uac.blocked(paths)


@pytest.mark.parametrize('data', [None, '{', '{}', '[]', ' ' * 65537],
                         ids=['missing', 'torn', 'empty', 'list', 'oversized'])
def test_missing_legacy_corrupt_is_unknown(paths, monkeypatch, data):
    request, _ = recorded(paths, monkeypatch)
    file = child._path(request)
    if data is None: file.unlink()
    else: file.write_text(data)
    assert child.observe(request, process_factory=lambda pid: pytest.fail('opened')) == 'unknown'


@pytest.mark.parametrize('field,value', [('pid', True), ('pid', 0), ('process_created', True),
                                        ('schema', True), ('request', {})])
def test_invalid_identity_not_opened(paths, monkeypatch, field, value):
    request, _ = recorded(paths, monkeypatch)
    file = child._path(request)
    row = json.loads(file.read_text())
    row[field] = value
    file.write_text(json.dumps(row))
    assert child.observe(request, process_factory=lambda pid: pytest.fail('opened')) == 'unknown'


def test_pid_reuse_and_record_loss_during_wait(paths, monkeypatch):
    request, _ = recorded(paths, monkeypatch)
    assert child.observe(request, process_factory=factory(created=456)) == 'unknown'
    assert child.observe(request, process_factory=factory(
        exited=True, on_wait=child._path(request).unlink)) == 'unknown'


@pytest.mark.parametrize('failure', ['generation', 'before-write', 'torn-write'])
def test_record_failure_refuses_handler_and_keeps_consumption(paths, monkeypatch, failure):
    request = uac.prepare(paths, 'remove')
    save = uac._save_exclusive
    def fail(path, row):
        if path.name.startswith('process-'):
            if failure == 'torn-write': path.write_text('{')
            raise OSError('private error')
        save(path, row)
    if failure == 'generation':
        monkeypatch.setattr(child.controller_process, 'generation',
                            lambda pid: (_ for _ in ()).throw(OSError('private error')))
    else:
        monkeypatch.setattr(uac, '_save_exclusive', fail)
    with pytest.raises(uac.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert (paths.state / 'strict-guard' / ('admitted-' + request.request_id + '.json')).exists()
    with pytest.raises(uac.ChildAdmissionRefused):
        uac.admit_child(paths, 'remove', request.request_id)
    assert uac.blocked(paths)


def test_recovery_observes_children_without_claim_release(paths, monkeypatch):
    request, _ = recorded(paths, monkeypatch)
    monkeypatch.setattr(recovery, 'hold_boundary', fake_boundary)
    monkeypatch.setattr(recovery, 'observe_child', lambda r: child.observe(
        r, process_factory=factory(exited=True)))
    result = recovery.prepare_recovery(paths, asdict(request))
    assert result['children'] == ['exited']
    assert result['child_exit'] == result['resources'] == result['controller_ownership'] == 'unknown'
    assert result['retry_blocked'] and uac.blocked(paths)


def test_inaccessible_process_is_unknown(paths, monkeypatch):
    request, _ = recorded(paths, monkeypatch)
    def denied(pid): raise OSError('private process detail')
    assert child.observe(request, process_factory=denied) == 'unknown'


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_all_noncontroller_admissions_record_current_process(paths, operation):
    import os
    request = uac.prepare(paths, operation)
    uac.admit_child(paths, operation, request.request_id)
    row = json.loads(child._path(request).read_text())
    assert row['request'] == asdict(request) and row['pid'] == os.getpid()
    assert child.observe(request) == 'running'


def test_changed_journal_discards_child_observations(paths, monkeypatch):
    request, _ = recorded(paths, monkeypatch)
    monkeypatch.setattr(recovery, 'hold_boundary', fake_boundary)
    def observe(r):
        uac.pending_path(paths).write_text('{}')
        return 'exited'
    monkeypatch.setattr(recovery, 'observe_child', observe)
    result = recovery.prepare_recovery(paths, asdict(request))
    assert result['inventory'] == 'unknown' and result['children'] == []
    assert result['retry_blocked']
