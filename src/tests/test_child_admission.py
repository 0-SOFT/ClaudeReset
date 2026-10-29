"""Late helpers use synthetic effects only; no UAC or system changes."""
import json
from types import SimpleNamespace

import pytest

from claude_reset import uac_request as uac
from claude_reset import strict_guard, package_isolation, netguard


@pytest.fixture
def paths(tmp_path):
    return SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_exact_child_is_consumed_once_before_effect(paths, operation):
    request = uac.prepare(paths, operation)
    identity = uac.admit_child(paths, operation, request.request_id)
    assert identity['request_id'] == request.request_id
    record = paths.state / 'strict-guard' / ('admitted-' + request.request_id + '.json')
    assert json.loads(record.read_text())['request']['operation'] == operation
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, operation, request.request_id)
    assert uac.blocked(paths)


@pytest.mark.parametrize('damage', ['missing', 'corrupt', 'replaced', 'request_missing'])
def test_nested_late_child_requires_both_exact_records(paths, damage):
    @uac.serialized('test', completed={'done'})
    def chain(paths):
        request = uac.prepare(paths, 'remove')
        if damage == 'request_missing':
            (paths.state / 'strict-guard' / ('request-' + request.request_id + '.json')).unlink()
        elif damage == 'missing':
            uac.pending_path(paths).unlink()
        else:
            uac.pending_path(paths).write_text('broken' if damage == 'corrupt' else '{}')
        with pytest.raises(uac.SafetyError):
            uac.admit_child(paths, 'remove', request.request_id)
        assert not list((paths.state / 'strict-guard').glob('admitted-*'))
        return {'status': 'incomplete'}
    assert chain(paths)['retry_blocked']


def test_nested_child_survives_parent_timeout_but_cannot_replay(paths):
    requests = []
    @uac.serialized('test', completed={'done'})
    def chain(paths):
        uac.execute(paths, 'remove', lambda r: requests.append(r) or 42, wait_seconds=0)
        return {'status': 'done'}
    assert chain(paths)['retry_blocked']
    request = requests[0]
    uac.admit_child(paths, 'remove', request.request_id)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request.request_id)
    assert uac.blocked(paths)


def test_torn_consumption_never_admits_or_retries(paths, monkeypatch):
    request = uac.prepare(paths, 'remove')
    with monkeypatch.context() as patch:
        patch.setattr(uac.os, 'fsync', lambda _: (_ for _ in ()).throw(OSError()))
        with pytest.raises(uac.SafetyError):
            uac.admit_child(paths, 'remove', request.request_id)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(paths, 'remove', request.request_id)
    assert uac.blocked(paths)


@pytest.mark.parametrize('mismatch', ['root', 'operation', 'request'])
def test_foreign_child_cannot_consume_valid_request(paths, mismatch):
    request = uac.prepare(paths, 'remove')
    other = SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    with pytest.raises(uac.SafetyError):
        uac.admit_child(other if mismatch == 'root' else paths,
                        'filters' if mismatch == 'operation' else 'remove',
                        'f' * 32 if mismatch == 'request' else request.request_id)
    assert uac.admit_child(paths, 'remove', request.request_id)['request_id'] == request.request_id


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start'}))
def test_real_child_entry_refuses_late_request_before_body(paths, monkeypatch, operation):
    request = uac.prepare(paths, operation)
    uac.pending_path(paths).unlink()
    fail = lambda *a, **k: pytest.fail('first domain effect')
    monkeypatch.setattr(strict_guard, 'Engine', fail)
    monkeypatch.setattr(strict_guard, 'autostart_directory', fail)
    monkeypatch.setattr(strict_guard.subprocess, 'run', fail)
    monkeypatch.setattr(package_isolation, 'source_directory', fail)
    monkeypatch.setattr(package_isolation, 'installed', fail)
    monkeypatch.setattr(netguard, 'filters', fail)
    report = paths.state / 'receipt.json'
    entries = {
        'remove': lambda: strict_guard.remove(paths, report, request_id=request.request_id),
        'autostart': lambda: strict_guard.autostart_install(paths, report, request_id=request.request_id),
        'autostart-off': lambda: strict_guard.autostart_remove(paths, report, request_id=request.request_id),
        'package-register': lambda: package_isolation.register(report, paths=paths, request_id=request.request_id),
        'package-remove': lambda: package_isolation.remove(report, paths=paths, request_id=request.request_id),
        'filters': lambda: netguard.filter_receipt(paths, request.request_id),
    }
    with pytest.raises(uac.SafetyError):
        entries[operation]()
    assert not report.exists()


@pytest.mark.parametrize('operation', sorted(uac.OPERATIONS - {'start', 'filters'}))
@pytest.mark.parametrize('identity', ['omitted', None, '', 123, 'bad'])
@pytest.mark.parametrize('claim', ['absent', 'pending', 'corrupt'])
def test_mutating_legacy_entry_never_reaches_effect_or_overwrites_receipt(
        paths, monkeypatch, operation, identity, claim):
    if claim != 'absent':
        uac.prepare(paths, operation)
        if claim == 'corrupt':
            uac.pending_path(paths).write_text('broken')
    pending = uac.pending_path(paths)
    before = pending.read_bytes() if pending.exists() else None
    effects = []
    def effect(*args, **kwargs):
        effects.append(True)
        raise AssertionError('Domain effect reached')
    monkeypatch.setattr(strict_guard, 'Engine', effect)
    monkeypatch.setattr(strict_guard, 'autostart_directory', effect)
    monkeypatch.setattr(strict_guard.subprocess, 'run', effect)
    monkeypatch.setattr(package_isolation, 'source_directory', effect)
    monkeypatch.setattr(package_isolation, 'installed', effect)
    report = paths.state / 'receipt.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(b'previous receipt')
    kwargs = {} if identity == 'omitted' else {'request_id': identity}
    entries = {
        'remove': lambda: strict_guard.remove(paths, report, **kwargs),
        'autostart': lambda: strict_guard.autostart_install(paths, report, **kwargs),
        'autostart-off': lambda: strict_guard.autostart_remove(paths, report, **kwargs),
        'package-register': lambda: package_isolation.register(report, paths=paths, **kwargs),
        'package-remove': lambda: package_isolation.remove(report, paths=paths, **kwargs),
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
    from claude_reset import app
    monkeypatch.setattr(app.Paths, 'current', lambda *a: paths)
    request = uac.prepare(paths, operation)
    if identity == 'replayed':
        uac.admit_child(paths, operation, request.request_id)
    report = paths.state / 'receipt.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(b'previous receipt')
    before = uac.pending_path(paths).read_bytes()
    args = [flag, '--report', str(report)]
    if identity != 'omitted':
        args += ['--uac-request-id', request.request_id if identity == 'replayed' else 'f' * 32]
    assert app.main(args) == 1
    assert report.read_bytes() == b'previous receipt'
    assert uac.pending_path(paths).read_bytes() == before
