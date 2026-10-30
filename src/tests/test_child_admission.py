"""Late helpers use synthetic effects only; no UAC or system changes."""
import json
import subprocess
from types import SimpleNamespace

import pytest
from cli_env import folders
from scripted import Scripted

from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.network import autostart, controller, package_isolation


@pytest.fixture
def paths(tmp_path):
    return SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_exact_child_is_consumed_once_before_effect(paths, operation):
    request = uac.prepare(paths, operation)
    identity = uac.admit_child(paths, operation, request.request_id)
    assert identity['request_id'] == request.request_id
    record = paths.state / 'strict-guard' / ('admitted-' + request.request_id + '.json')
    assert json.loads(record.read_text())['request']['operation'] == operation
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, operation, request.request_id)
    assert claims.blocked(paths)


@pytest.mark.parametrize('damage', ['missing', 'corrupt', 'replaced', 'request_missing'])
def test_nested_late_child_requires_both_exact_records(paths, damage):
    @claims.serialized('test', completed={'done'})
    def chain(paths):
        request = uac.prepare(paths, 'remove')
        if damage == 'request_missing':
            (paths.state / 'strict-guard' / ('request-' + request.request_id + '.json')).unlink()
        elif damage == 'missing':
            claims.pending_path(paths).unlink()
        else:
            claims.pending_path(paths).write_text('broken' if damage == 'corrupt' else '{}')
        with pytest.raises(uac.SafetyError):
            uac.admit_child(paths, 'remove', request.request_id)
        assert not list((paths.state / 'strict-guard').glob('admitted-*'))
        return {'status': 'incomplete'}
    assert chain(paths)['retry_blocked']


def test_nested_child_survives_parent_timeout_but_cannot_replay(paths):
    requests = []
    @claims.serialized('test', completed={'done'})
    def chain(paths):
        uac.execute(paths, 'remove', lambda r: requests.append(r) or 42, wait_seconds=0)
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    request = requests[0]
    uac.admit_child(paths, 'remove', request.request_id)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request.request_id)
    assert claims.blocked(paths)


def test_torn_consumption_never_admits_or_retries(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    with monkeypatch.context() as patch:
        patch.setattr(uac.os, 'fsync', lambda _: (_ for _ in ()).throw(OSError()))
        with pytest.raises(uac.SafetyError):
            uac.admit_child(paths, 'remove', request.request_id)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request.request_id)
    assert claims.blocked(paths)


@pytest.mark.parametrize('mismatch', ['root', 'operation', 'request'])
def test_foreign_child_cannot_consume_valid_request(paths, mismatch):
    request = uac.prepare(paths, 'remove')
    other = SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(other if mismatch == 'root' else paths,
                        'start' if mismatch == 'operation' else 'remove',
                        'f' * 32 if mismatch == 'request' else request.request_id)
    assert uac.admit_child(paths, 'remove', request.request_id)['request_id'] == request.request_id


def tripwire(effect):
    """A scheduler or program folder whose every use is a domain effect: effect decides what happens."""
    double = Scripted()
    double.unscripted = effect
    return double


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
def test_real_child_entry_refuses_late_request_before_body(paths, monkeypatch, operation):
    request = uac.prepare(paths, operation)
    claims.pending_path(paths).unlink()
    fail = lambda *a, **k: pytest.fail('first domain effect')
    monkeypatch.setattr(subprocess, 'run', fail)
    report = paths.state / 'receipt.json'
    domain = dict(scheduler=tripwire(fail), folder=tripwire(fail))
    entries = {
        'remove': lambda: controller.remove(paths, report, request_id=request.request_id, engine=fail),
        'autostart': lambda: autostart.install(paths, report, request_id=request.request_id, **domain),
        'autostart-off': lambda: autostart.remove(paths, report, request_id=request.request_id, **domain),
        'package-register': lambda: package_isolation.register(report, paths=paths, request_id=request.request_id,
                                                               runner=fail),
        'package-remove': lambda: package_isolation.remove(report, paths=paths, request_id=request.request_id,
                                                           runner=fail),
    }
    with pytest.raises(uac.SafetyError):
        entries[operation]()
    assert not report.exists()


@pytest.mark.parametrize('operation', sorted(claims.OPERATIONS - {'start'}))
@pytest.mark.parametrize('identity', ['omitted', None, '', 123, 'bad'])
@pytest.mark.parametrize('claim', ['absent', 'pending', 'corrupt'])
def test_mutating_legacy_entry_never_reaches_effect_or_overwrites_receipt(
        paths, monkeypatch, operation, identity, claim):
    if claim != 'absent':
        uac.prepare(paths, operation)
        if claim == 'corrupt':
            claims.pending_path(paths).write_text('broken')
    pending = claims.pending_path(paths)
    before = pending.read_bytes() if pending.exists() else None
    effects = []
    def effect(*args, **kwargs):
        effects.append(True)
        raise AssertionError('Domain effect reached')
    monkeypatch.setattr(subprocess, 'run', effect)
    report = paths.state / 'receipt.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(b'previous receipt')
    kwargs = {} if identity == 'omitted' else {'request_id': identity}
    domain = dict(scheduler=tripwire(effect), folder=tripwire(effect))
    entries = {
        'remove': lambda: controller.remove(paths, report, engine=effect, **kwargs),
        'autostart': lambda: autostart.install(paths, report, **domain, **kwargs),
        'autostart-off': lambda: autostart.remove(paths, report, **domain, **kwargs),
        'package-register': lambda: package_isolation.register(report, paths=paths, runner=effect, **kwargs),
        'package-remove': lambda: package_isolation.remove(report, paths=paths, runner=effect, **kwargs),
    }
    with pytest.raises(uac.SafetyError, match='Invalid elevation identity'):
        entries[operation]()
    assert effects == []
    assert report.read_bytes() == b'previous receipt'
    assert (pending.read_bytes() if pending.exists() else None) == before
    assert not list(paths.state.rglob('admitted-*.json'))


@pytest.mark.parametrize('flag,operation', [
    ('--strict-guard-remove-serve', 'remove'),
    ('--strict-guard-autostart-serve', 'autostart'),
    ('--strict-guard-autostart-off-serve', 'autostart-off'),
    ('--l1-package-register-serve', 'package-register'),
    ('--l1-package-remove-serve', 'package-remove'),
])
@pytest.mark.parametrize('identity', ['omitted', 'foreign', 'replayed'])
def test_cli_refusal_preserves_existing_receipt(paths, monkeypatch, flag, operation, identity):
    from claude_reset import cli
    root = folders(monkeypatch, paths)
    request = uac.prepare(paths, operation)
    if identity == 'replayed':
        uac.admit_child(paths, operation, request.request_id)
    report = paths.state / 'receipt.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(b'previous receipt')
    before = claims.pending_path(paths).read_bytes()
    args = [flag, '--report', str(report)] + root
    if identity != 'omitted':
        args += ['--uac-request-id', request.request_id if identity == 'replayed' else 'f' * 32]
    assert cli.main(args) == 1
    assert report.read_bytes() == b'previous receipt'
    assert claims.pending_path(paths).read_bytes() == before
