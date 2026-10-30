"""Synthetic receipts and dispatch only: never request elevation."""
import ctypes
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import sys
import threading

import pytest

from claude_reset.elevation import request as uac
from claude_reset.elevation import claims
from claude_reset.elevation import launch
from claude_reset.network import autostart, controller
from dialog_fakes import script
from cli_env import folders


@pytest.fixture
def paths(tmp_path):
    return SimpleNamespace(state=tmp_path / 'archive', local=tmp_path / 'local', home=tmp_path / 'home')


def plannable(paths):
    """A saved remote proxy, so the start entry's strict plan reads only these folders, never this PC's backend."""
    from claude_reset.network import remote_backend
    from claude_reset.services.proxy import ProxyDraft
    remote_backend.save(paths, ProxyDraft('8.8.8.8', 1080).profile)
    return paths


def write(request, **values):
    row = {k: v for k, v in asdict(request).items() if k != 'receipt'}
    row.update(finished=True, registered=True)
    row.update(values)
    file = Path(request.receipt)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(row), encoding='utf-8')


def test_pending_is_durable_before_dispatch_and_root_is_pinned(paths):
    original = paths.state
    def dispatch(request):
        assert json.loads(claims.pending_path(paths).read_text()) == asdict(request)
        paths.state = original.parent / 'new-selection'
        assert request.state_root == str(original)
        write(request)
        return 42
    assert uac.execute(paths, 'autostart', dispatch)['status'] == 'completed'
    assert not claims.blocked(paths)


def test_failed_save_never_dispatches_and_torn_claim_blocks(paths, monkeypatch):
    def fail(_):
        raise OSError('private secret')
    monkeypatch.setattr(uac.os, 'fsync', fail)
    with pytest.raises(OSError):
        uac.execute(paths, 'autostart', lambda _: pytest.fail('dispatch'))
    assert claims.blocked(paths)
    with pytest.raises(FileExistsError):
        uac.prepare(paths, 'autostart')


@pytest.mark.parametrize('code', [0, 5, 31, 32])
def test_definitive_denial_releases_claim(paths, code):
    assert uac.execute(paths, 'autostart', lambda _: code)['status'] == 'denied'
    assert not claims.blocked(paths)


def test_unknown_nested_child_cannot_be_ignored_by_outer_success(paths):
    @claims.serialized('test-chain', completed={'done'})
    def chain(paths):
        assert uac.execute(paths, 'remove', lambda _: 42, wait_seconds=0)['status'] == 'unknown'
        with pytest.raises(Exception, match='Mutation ownership mismatch'):
            uac.execute(paths, 'remove', lambda _: pytest.fail('second dispatch'))
        return {'status': 'done'}
    assert chain(paths)['retry_blocked'] is True
    assert claims.blocked(paths)


def test_nested_request_rejects_another_state_root(paths):
    @claims.serialized('test-chain', completed={'done'})
    def chain(paths):
        other = SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
        with pytest.raises(Exception, match='Mutation ownership mismatch'):
            uac.execute(other, 'remove', lambda _: pytest.fail('foreign dispatch'))
        return {'status': 'done'}
    chain(paths)


def test_mutation_claim_write_failure_prevents_first_effect(paths, monkeypatch):
    @claims.serialized('test-chain', completed={'done'})
    def chain(paths):
        pytest.fail('effect before durable claim')
    monkeypatch.setattr(uac.os, 'fsync', lambda _: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        chain(paths)
    assert claims.blocked(paths)


def test_exception_after_dispatch_retains_claim_across_instances(paths):
    def dispatch(_):
        raise RuntimeError('secret')
    assert uac.execute(paths, 'autostart', dispatch)['status'] == 'unknown'
    reopened = SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    assert claims.blocked(reopened)
    with pytest.raises(FileExistsError):
        uac.execute(reopened, 'remove', lambda _: pytest.fail('replay'))


@pytest.mark.parametrize('bad', [None, [], {'schema': 1}, 'broken'])
def test_malformed_receipt_does_not_authorize_replay(paths, bad):
    def dispatch(request):
        write(request)
        Path(request.receipt).write_text(json.dumps(bad), encoding='utf-8')
        return 42
    result = uac.execute(paths, 'autostart', dispatch, wait_seconds=0)
    assert result['status'] == 'unknown' and result['retry_blocked']
    assert claims.blocked(paths)


@pytest.mark.parametrize('changes', [dict(request_id='foreign'), dict(operation='remove'),
                                    dict(state_root='elsewhere'), dict(schema=True)])
def test_foreign_receipt_is_ignored(paths, changes):
    def dispatch(request):
        write(request, **changes)
        return 42
    assert uac.execute(paths, 'autostart', dispatch, wait_seconds=0)['status'] == 'unknown'
    assert claims.blocked(paths)


def test_delayed_exact_receipt_and_missing_file_use_monotonic_deadline(paths):
    requests, now = [], [0]
    def dispatch(request):
        requests.append(request)
        return 42
    def sleep(_):
        now[0] += 1
        if now[0] == 3:
            write(requests[0])
    result = uac.execute(paths, 'autostart', dispatch, sleep=sleep, clock=lambda: now[0], wait_seconds=4)
    assert result['status'] == 'completed' and now[0] == 3


@pytest.mark.parametrize('operation,values', [('autostart', {'registered': False}),
    ('autostart', {'error': 'private secret'}), ('remove', {'removed': False}),
    ('autostart-off', {'task_present_after': False, 'program_removed': False}),
    ('start', {'state': 'blocked_error'})])
def test_finished_partial_failure_never_means_success_or_releases_claim(paths, operation, values):
    def dispatch(request):
        write(request, **values)
        return 42
    result = uac.execute(paths, operation, dispatch)
    assert result['status'] == 'reconcile_required' and not result['passed']
    assert 'private secret' not in repr(result) and claims.blocked(paths)


def test_start_readiness_is_not_finished_or_live_attestation(paths):
    def dispatch(request):
        write(request, finished=False, state='relay_open', passed=True,
              persistent_boundary=True, live_permit_session=True)
        return 42
    result = uac.execute(paths, 'start', dispatch)
    assert result['status'] == 'observed_ready' and not result['passed']
    assert result['requires_live_verification'] and claims.blocked(paths)
    assert result['retry_blocked'] is True
    with pytest.raises(FileExistsError):
        uac.execute(paths, 'start', lambda _: pytest.fail('repeat dispatch'))


def test_observed_start_cannot_release_or_continue_outer_chain(paths):
    requests = []

    def dispatch(request):
        requests.append(request)
        write(request, finished=False, state='relay_open', passed=True,
              persistent_boundary=True, live_permit_session=True)
        return 42

    @claims.serialized('test-chain', completed={'done'})
    def chain(paths):
        result = uac.execute(paths, 'start', dispatch, wait_seconds=0)
        assert result['status'] == 'observed_ready' and result['retry_blocked']
        # A later receipt rewrite cannot make the outer success authoritative.
        write(requests[0], finished=True)
        with pytest.raises(uac.SafetyError, match='ownership mismatch'):
            uac.execute(paths, 'remove', lambda _: pytest.fail('second dispatch'))
        return {'status': 'done'}

    assert chain(paths)['retry_blocked'] is True
    assert len(requests) == 1 and claims.blocked(paths)


def test_two_windows_with_different_state_roots_dispatch_only_once(paths):
    barrier = threading.Barrier(2)
    calls = []
    def run(root):
        other = SimpleNamespace(state=root, local=paths.local)
        barrier.wait(timeout=3)
        try:
            return uac.execute(other, 'autostart', lambda request: calls.append(request) or 42, wait_seconds=0)
        except (FileExistsError, uac.SafetyError):
            return 'blocked'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [paths.state, paths.state.parent / 'second']))
    assert len(calls) == 1 and 'blocked' in results and claims.blocked(paths)


def test_dispatch_arguments_include_exact_identity_and_root(paths, monkeypatch):
    request = uac.prepare(paths, 'autostart')
    calls = []
    class ShellCall:
        def __call__(self, *args):
            calls.append(args)
            return 42
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **kw: SimpleNamespace(ShellExecuteW=ShellCall()))
    assert launch.dispatch_request(request) == 42
    command = calls[0][3]
    for part in [request.state_root, request.receipt, request.request_id, '--state-root', '--uac-request-id']:
        assert part in command
    assert calls[0][-1] == 0


@pytest.mark.parametrize('consent', [False, True])
def test_close_unknown_warns_and_preserves_replay_block(paths, consent):
    from claude_reset.ui import expert_window as app
    from claude_reset import cli
    uac.prepare(paths, 'start')
    ui = app.App.__new__(app.App)
    ui.paths = paths
    ui.worker = SimpleNamespace(busy=False)
    destroyed, messages = [], []
    ui.root = SimpleNamespace(destroy=lambda: destroyed.append(True))
    script(ui, askyesno=lambda *args: messages.append(args) or consent)
    ui.close()
    assert bool(destroyed) == consent and len(messages) == 1
    assert claims.blocked(paths)


def test_child_receipt_echoes_identity_even_after_partial_failure(paths, monkeypatch):
    request = uac.prepare(paths, 'autostart')
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    row = autostart.install(paths, Path(request.receipt), request_id=request.request_id)
    assert row['finished'] and 'error' in row
    assert uac.read_receipt(request) == row
    assert uac.verdict(request, row) == 'reconcile_required'


def test_built_program_dispatch_uses_serve_without_source_launcher(paths, monkeypatch):
    request = uac.prepare(paths, 'autostart')
    calls = []
    class ShellCall:
        def __call__(self, *args):
            calls.append(args)
            return 42
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **kw: SimpleNamespace(ShellExecuteW=ShellCall()))
    exe = paths.state / 'build with spaces' / 'ClaudeReset.exe'
    assert launch.dispatch_request(request, executable=exe) == 42
    args = calls[0]
    assert args[1] == 'runas' and args[2] == str(exe) and args[-1] == 0
    assert args[3].startswith('--strict-guard-autostart-serve ')
    assert 'launcher.py' not in args[3]
    for value in (request.request_id, request.receipt, request.state_root):
        assert value in args[3]


@pytest.mark.parametrize('entry,operation', [
    (controller.elevated_start, 'start'),
    (controller.elevated_remove, 'remove'),
    (autostart.elevated, 'autostart'),
    (lambda paths, **kw: autostart.elevated(paths, enable=False, **kw), 'autostart-off'),
])
def test_legacy_strict_entries_share_durable_request(paths, entry, operation):
    calls = []
    def dispatch(request):
        calls.append(request)
        assert claims.blocked(paths)
        return 5
    assert entry(plannable(paths), dispatch=dispatch)['status'] == 'denied'
    assert len(calls) == 1 and calls[0].operation == operation
    assert not claims.blocked(paths)


@pytest.mark.parametrize('entry', [controller.elevated_start, controller.elevated_remove,
                                  autostart.elevated])
def test_legacy_strict_entries_cannot_bypass_existing_claim(paths, entry):
    plannable(paths)
    uac.prepare(paths, 'remove')
    with pytest.raises(FileExistsError):
        entry(paths, dispatch=lambda _: pytest.fail('repeat dispatch'))
    assert claims.blocked(paths)

@pytest.mark.parametrize('operation,values', [
    ('package-register', {'status': 'registered'}),
    ('package-register', {'status': 'already_registered'}),
    ('package-remove', {'status': 'removed', 'registered_after': False}),
])
def test_package_nested_claim(paths, operation, values):
    from claude_reset.network import package_isolation as pkg
    def dispatch(request):
        assert request.operation == operation and request.owner_id
        write(request, **values)
        return 42
    @claims.serialized('package-chain', completed={'done'})
    def chain(paths):
        assert pkg.dispatch(paths, '--l1-' + operation + '-serve', '', prompt=dispatch)['passed'] is True
        assert claims.pending_path(paths).exists()
        return {'status': 'done'}
    assert chain(paths)['status'] == 'done'
    assert not claims.blocked(paths)


def test_package_foreign_receipt_blocks_repeat(paths):
    from claude_reset.network import package_isolation as pkg
    calls = []
    def dispatch(request):
        calls.append(request)
        write(request, status='registered', request_id='f' * 32)
        return 42
    assert pkg.dispatch(paths, '--l1-package-register-serve', '', wait_seconds=0, prompt=dispatch)['status'] == 'unknown'
    with pytest.raises(FileExistsError):
        pkg.dispatch(paths, '--l1-package-remove-serve', '', wait_seconds=0, prompt=dispatch)
    assert len(calls) == 1


@pytest.mark.parametrize('values', [
    {'status': 'removed'}, {'status': 'removed', 'registered_after': 0},
    {'status': 'registered', 'registered_after': False},
    {'status': 'removed', 'registered_after': False, 'error': 'failure'},
])
def test_package_partial_keeps_claim(paths, values):
    def dispatch(request):
        write(request, **values)
        return 42
    assert uac.execute(paths, 'package-remove', dispatch)['status'] == 'reconcile_required'
    assert claims.blocked(paths)

@pytest.mark.parametrize('values', [
    {'status': 'owned_filters_verified', 'passed': True},
    {'status': 'owned_filters_incomplete', 'passed': False},
    {'status': 'inspection_failed', 'error_type': 'OSError', 'passed': False},
])
def test_filter_inspection_retains_claim_after_exact_finished_read(paths, values):
    from claude_reset.network import legacy_guard as netguard
    def dispatch(request):
        assert request.operation == 'filters' and claims.blocked(paths)
        write(request, read_only=True, filters_changed=False, private='secret 203.0.113.7', **values)
        return 42
    result = netguard.elevated_filters(paths, timeout=0, dispatch=dispatch)
    assert result['status'] == 'inspection_finished' and result['passed'] is False
    assert result['filters_verified'] is (values['status'] == 'owned_filters_verified')
    assert 'secret' not in repr(result) and '203.0.113.7' not in repr(result)
    assert result['retry_blocked'] is True
    assert claims.blocked(paths)


@pytest.mark.parametrize('changes', [{'request_id': 'f' * 32}, {'read_only': False},
                                     {'finished': False}, {'filters_changed': True}])
def test_filter_bad_receipt_retains_claim(paths, changes):
    from claude_reset.network import legacy_guard as netguard
    def dispatch(request):
        values = dict(read_only=True, filters_changed=False, status='owned_filters_verified')
        values.update(changes)
        write(request, **values)
        return 42
    assert netguard.elevated_filters(paths, timeout=0, dispatch=dispatch)['status'] == 'unknown'
    assert claims.blocked(paths)
    with pytest.raises(FileExistsError):
        netguard.elevated_filters(paths, timeout=0, dispatch=dispatch)


def test_filter_timeout_keeps_late_receipt_and_denial_releases(paths):
    from claude_reset.network import legacy_guard as netguard
    assert netguard.elevated_filters(paths, timeout=0, dispatch=lambda _: 5)['status'] == 'denied'
    assert not claims.blocked(paths)
    requests = []
    assert netguard.elevated_filters(paths, timeout=0, dispatch=lambda r: requests.append(r) or 42)['status'] == 'unknown'
    write(requests[0], read_only=True, filters_changed=False)
    assert uac.read_receipt(requests[0]) is not None and claims.blocked(paths)


def test_filter_child_echoes_identity_on_failure(paths):
    from claude_reset.network import legacy_guard as netguard
    request = uac.prepare(paths, 'filters')
    result = netguard.filter_receipt(paths, request.request_id,
                                     inspect=lambda: (_ for _ in ()).throw(OSError('private secret')))
    assert result['request_id'] == request.request_id and result['state_root'] == str(paths.state)
    assert result['finished'] and result['read_only'] and result['filters_changed'] is False
    assert 'private secret' not in repr(result)
    assert uac.verdict(request, result) == 'inspection_finished'


def test_finished_filter_child_cannot_release_outer_chain(paths):
    def dispatch(request):
        write(request, read_only=True, filters_changed=False)
        return 42

    @claims.serialized('test-chain', completed={'done'})
    def chain(paths):
        result = uac.execute(paths, 'filters', dispatch, wait_seconds=0)
        assert result['status'] == 'inspection_finished'
        assert result['retry_blocked'] is True
        with pytest.raises(uac.SafetyError, match='ownership mismatch'):
            uac.execute(paths, 'remove', lambda _: pytest.fail('second dispatch'))
        return {'status': 'done'}

    assert chain(paths)['retry_blocked'] is True
    assert claims.blocked(paths)


def test_finished_start_receipt_cannot_claim_live_readiness(paths):
    def dispatch(request):
        write(request, state='relay_open', passed=True,
              persistent_boundary=True, live_permit_session=True)
        return 42

    result = uac.execute(paths, 'start', dispatch, wait_seconds=0)
    assert result['status'] == 'reconcile_required'
    assert result['retry_blocked'] is True
    assert claims.blocked(paths)


def test_filter_cli_writes_exact_receipt(paths, monkeypatch):
    from claude_reset import cli
    from claude_reset.network import legacy_guard as netguard
    request = uac.prepare(paths, 'filters')
    monkeypatch.setattr(netguard, 'filters', lambda: {'status': 'owned_filters_incomplete', 'passed': False})
    assert cli.main(['--network-guard-filters', *folders(monkeypatch, paths),
                     '--report', request.receipt, '--uac-request-id', request.request_id]) == 2
    row = uac.read_receipt(request)
    assert row and uac.verdict(request, row) == 'inspection_finished'


def test_filter_gui_passes_selected_paths(monkeypatch):
    from claude_reset.ui import expert_window as app
    from claude_reset.network import legacy_guard as netguard
    ui = app.App.__new__(app.App)
    ui.paths = object()
    calls = []
    monkeypatch.setattr(netguard, 'elevated_filters', lambda paths: calls.append(paths))
    ui.run = lambda action, callback, **kw: (calls.append(kw), action())
    ui.guard_filters()
    assert calls == [{'waiting_uac': True}, ui.paths]


@pytest.mark.parametrize('entry', ['install', 'remove', 'remote'])
def test_backend_entries_block_before_effects(paths, monkeypatch, entry):
    from claude_reset.backend import install as bi
    from claude_reset.network import remote_backend as rb
    uac.prepare(paths, 'filters')
    monkeypatch.setattr(bi, 'preconditions', lambda *a, **k: pytest.fail('backend effect'))
    monkeypatch.setattr(rb, 'path_of', lambda *a: pytest.fail('profile access'))
    result = (bi.remove(paths) if entry == 'remove' else
              (rb.install if entry == 'remote' else bi.install)(paths, 'must-not-read.json'))
    assert result['status'] == 'pending_elevation' and result['retry_blocked']


@pytest.mark.parametrize('failure', ['result', 'exception', 'replacement'])
def test_nested_mutation_failure_cannot_be_hidden_by_outer_success(paths, failure):
    @claims.serialized('inner', completed={'done'}, nested=True)
    def inner(paths):
        if failure == 'exception':
            raise RuntimeError('synthetic')
        if failure == 'replacement':
            claims.pending_path(paths).write_text('{}')
        return {'status': 'failed' if failure == 'result' else 'done'}

    @claims.serialized('outer', completed={'done'})
    def outer(paths):
        try:
            inner(paths)
        except (RuntimeError, uac.SafetyError):
            pass
        with pytest.raises(uac.SafetyError, match='Mutation ownership mismatch'):
            inner(paths)
        return {'status': 'done'}

    assert outer(paths)['retry_blocked'] is True
    assert claims.blocked(paths)


@pytest.mark.parametrize('different', ['state', 'local'])
def test_nested_mutation_rejects_foreign_paths_before_effect(paths, different):
    @claims.serialized('inner', completed={'done'}, nested=True)
    def inner(paths):
        pytest.fail('foreign effect')

    @claims.serialized('outer', completed={'done'})
    def outer(paths):
        other = SimpleNamespace(state=paths.state, local=paths.local)
        setattr(other, different, getattr(paths, different).parent / 'foreign')
        with pytest.raises(uac.SafetyError, match='Mutation ownership mismatch'):
            inner(other)
        return {'status': 'done'}

    assert outer(paths)['status'] == 'done'
    assert not claims.blocked(paths)


@pytest.mark.parametrize('damage', ['missing', 'corrupt', 'foreign'])
@pytest.mark.parametrize('code', [5, 42])
def test_late_nested_request_damage_cannot_be_hidden_by_success(paths, damage, code):
    def dispatch(request):
        record = Path(request.state_root) / 'strict-guard' / ('request-' + request.request_id + '.json')
        if damage == 'missing':
            record.unlink()
        else:
            record.write_text('broken' if damage == 'corrupt' else '{}')
        write(request, removed=True)
        return code

    @claims.serialized('outer', completed={'done'})
    def outer(paths):
        result = uac.execute(paths, 'remove', dispatch, wait_seconds=0)
        assert result['status'] == 'unknown' and result['retry_blocked']
        with pytest.raises(uac.SafetyError, match='ownership mismatch'):
            uac.execute(paths, 'filters', lambda request: pytest.fail('second dispatch'))
        return {'status': 'done'}

    assert outer(paths)['retry_blocked'] is True
    assert claims.blocked(paths)
