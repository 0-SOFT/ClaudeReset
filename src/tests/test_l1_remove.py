import types
from pathlib import Path

import pytest

from claude_reset import layout
from claude_reset.elevation import claims
from claude_reset.network import l1_remove as rem


def state(**changes):
    ids = {'relay_listening': 'ok', 'controller_task': 'ok', 'controller_files': 'ok', 'isolation_package': 'ok'}
    ids.update(changes)
    return {'protection': 'installed', 'checks': [{'id': k, 'status': v} for k, v in ids.items()]}


class Fake:
    def pending(self, paths):
        return self.fail.get('pending', False)

    def __init__(self, initial=None, **fail):
        self.calls, self.fail, self.initial, self.n = [], fail, initial or state(), 0

    def check(self, paths):
        self.calls.append('check')
        self.n += 1
        return self.initial if self.n == 1 else {'protection': 'partial' if self.fail.get('leftover') else 'not_installed', 'checks': []}

    def request_close(self, paths):
        self.calls.append('close')
        return {'status': 'strict_close_requested'}

    def wait_relay_gone(self):
        self.calls.append('wait_gone')
        return not self.fail.get('close')

    def wait_controller_idle(self):
        self.calls.append('wait_idle')
        return not self.fail.get('controller_busy')

    def autostart_off(self, paths):
        self.calls.append('autostart_off')
        return {'passed': not (self.fail.get('task_left') or self.fail.get('receipt') == 'autostart-off-')}

    def remove_filters(self, paths):
        self.calls.append('remove_filters')
        return {'passed': not (self.fail.get('filters') or self.fail.get('receipt') == 'remove-')}

    def remove_backend(self, paths):
        self.calls.append('backend')
        return {'status': 'failed' if self.fail.get('backend') else 'removed', 'error': 'x'}

    def remove_package(self, paths):
        self.calls.append('package')
        return {'passed': not self.fail.get('package'), 'status': 'failed'}

    def revoke_consent(self, paths):
        self.calls.append('consent')

    def remove_connection_profile(self, paths):
        self.calls.append('connection_profile')
        return not self.fail.get('profile')


@pytest.fixture
def paths(tmp_path):
    return types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local')


def run(paths, fake):
    return rem.run(paths, deps=fake, clock=lambda: 0)


def test_full_removal_runs_in_the_reverse_order_and_clears_the_flag(paths):
    flag = paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG
    flag.parent.mkdir(parents=True)
    flag.write_text('x')
    fake = Fake()
    report = run(paths, fake)
    assert report['status'] == 'removed' and not flag.exists()
    assert fake.calls == ['check', 'close', 'wait_gone', 'wait_idle', 'autostart_off', 'remove_filters', 'backend', 'package', 'consent', 'connection_profile', 'check']


def test_a_pc_without_protection_is_a_clean_no_op(paths):
    fake = Fake(initial=state(relay_listening='missing', controller_task='missing', controller_files='missing', isolation_package='missing'))
    report = run(paths, fake)
    assert report['status'] == 'removed'
    assert not any(c in fake.calls for c in ('close', 'autostart_off', 'package'))


@pytest.mark.parametrize('failure, status, last', [
    ({'close': True}, 'controller_not_stopped', 'wait_gone'),
    ({'receipt': 'autostart-off-'}, 'autostart_not_removed', 'autostart_off'),
    ({'task_left': True}, 'autostart_not_removed', 'autostart_off'),
    ({'receipt': 'remove-'}, 'filters_not_removed', 'remove_filters'),
    ({'filters': True}, 'filters_not_removed', 'remove_filters'),
    ({'backend': True}, 'backend_not_removed', 'backend'),
    ({'package': True}, 'package_not_removed', 'package'),
])
def test_a_failed_step_stops_the_rest(paths, failure, status, last):
    fake = Fake(**failure)
    report = run(paths, fake)
    assert report['status'] == status and fake.calls[-1] == last and report['finished']


def test_a_saved_exit_profile_that_cannot_be_deleted_stops_the_run(paths):
    fake = Fake(profile=True)
    report = run(paths, fake)
    assert report['status'] == 'connection_profile_not_removed' and fake.calls[-1] == 'connection_profile'


def test_leftovers_are_reported_not_hidden(paths):
    assert run(paths, Fake(leftover=True))['status'] == 'removed_with_leftovers'


def test_connections_remove_deletes_only_the_saved_profile(tmp_path):
    """Regression (second PC, F2): --l1-remove left connection.dpapi, so it reported removed_with_leftovers."""
    from claude_reset.network import connections
    state = tmp_path / 'state'
    state.mkdir()
    (state / layout.CONNECTION_PROFILE).write_bytes(b'x')
    (tmp_path / 'my-connection.json').write_text('{"keep": true}')
    paths = types.SimpleNamespace(home=tmp_path, state=state, local=tmp_path / 'local')
    assert connections.remove(paths) is True and not (state / layout.CONNECTION_PROFILE).exists()
    assert (tmp_path / 'my-connection.json').exists()
    assert connections.remove(paths) is True                       # already gone is fine


@pytest.mark.parametrize('step', ['autostart_off', 'remove_filters'])
@pytest.mark.parametrize('receipt', [
    {'status': 'unknown', 'retry_blocked': True},
    {'status': 'denied', 'passed': False},
    {'status': 'reconcile_required', 'passed': False},
    {'status': 'completed', 'passed': 1},
    {'finished': True, 'removed': True, 'task_present_after': False},
])
def test_removal_requires_exact_protocol_success(paths, step, receipt):
    fake = Fake()
    def result(_):
        fake.calls.append(step)
        return receipt
    setattr(fake, step, result)
    report = run(paths, fake)
    assert report['status'] == ('autostart_not_removed' if step == 'autostart_off' else 'filters_not_removed')
    assert fake.calls[-1] == step
    assert 'backend' not in fake.calls


def test_pending_request_blocks_removal_before_controller_close(paths):
    fake = Fake(pending=True)
    assert run(paths, fake)['status'] == 'pending_elevation'
    assert fake.calls == []


def test_competing_restart_cannot_stop_between_nested_receipts(paths):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from dataclasses import asdict

    from claude_reset.elevation import request as uac
    from claude_reset.network import l1_install

    fake = Fake()
    competitor = Fake()
    other = types.SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    pending_bytes = []

    def receipt(operation, **values):
        def dispatch(request):
            pending_bytes.append(claims.pending_path(paths).read_bytes())
            row = dict(asdict(request), finished=True, **values)
            Path(request.receipt).write_text(json.dumps(row), encoding='utf-8')
            return 42
        return uac.execute(paths, operation, dispatch, wait_seconds=0)

    def autostart(_):
        fake.calls.append('autostart_off')
        result = receipt('autostart-off', task_present_after=False, program_removed=True)
        assert result['passed'] is True
        # Independent execution context, different state root, same arbiter.
        with ThreadPoolExecutor() as pool:
            rejected = pool.submit(l1_install.restart, other, deps=competitor).result()
        assert rejected['status'] == 'pending_elevation'
        assert competitor.calls == []
        assert claims.pending_path(paths).read_bytes() == pending_bytes[0]
        return result

    fake.autostart_off = autostart
    fake.remove_filters = lambda _: receipt('remove', removed=True)
    assert run(paths, fake)['status'] == 'removed'
    assert pending_bytes[0] == pending_bytes[1]
    assert not claims.blocked(paths)


def test_denial_after_stop_retains_outer_claim_and_prevents_reopen(paths):
    from claude_reset.elevation import request as uac
    fake = Fake()
    fake.autostart_off = lambda _: uac.execute(paths, 'autostart-off', lambda request: 5)
    assert run(paths, fake)['status'] == 'autostart_not_removed'
    assert 'close' in fake.calls and claims.blocked(paths)
    second = Fake()
    assert run(paths, second)['status'] == 'pending_elevation'
    assert second.calls == []


def test_old_pending_blocks_before_any_effect(paths):
    from claude_reset.elevation import request as uac
    uac.prepare(paths, 'remove')
    fake = Fake()
    assert run(paths, fake)['status'] == 'pending_elevation'
    assert fake.calls == []


def test_simultaneous_instances_only_one_reaches_first_stop(paths):
    import threading
    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
    barrier = threading.Barrier(2)
    release = threading.Event()
    first, second = Fake(), Fake()
    other = types.SimpleNamespace(state=paths.state.parent / 'other', local=paths.local)
    for fake in (first, second):
        def close(_, fake=fake):
            fake.calls.append('close')
            assert release.wait(5)
            return {'status': 'strict_close_requested'}
        fake.request_close = close

    def launch(selected, fake):
        barrier.wait(timeout=5)
        return run(selected, fake)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(launch, paths, first), pool.submit(launch, other, second)]
        try:
            done, _ = wait(futures, timeout=5, return_when=FIRST_COMPLETED)
            assert len(done) == 1
            assert next(iter(done)).result()['status'] == 'pending_elevation'
            assert sum('close' in fake.calls for fake in (first, second)) <= 1
        finally:
            release.set()
        results = [future.result() for future in futures]
    assert sorted(row['status'] for row in results) == ['pending_elevation', 'removed']
    assert sum('close' in fake.calls for fake in (first, second)) == 1


def test_closed_relay_with_busy_controller_blocks_removal(paths):
    from claude_reset.elevation import request as uac
    fake = Fake(initial=state(relay_listening='missing'), controller_busy=True)
    result = run(paths, fake)
    assert result['status'] == 'controller_not_stopped'
    assert fake.calls == ['check', 'close', 'wait_gone', 'wait_idle']
    assert claims.blocked(paths)


def test_close_refusal_does_not_continue_removal(paths):
    fake = Fake()
    fake.request_close = lambda _: {'status': 'pending_elevation', 'retry_blocked': True}
    assert run(paths, fake)['status'] == 'controller_not_stopped'
    assert fake.calls == ['check']
