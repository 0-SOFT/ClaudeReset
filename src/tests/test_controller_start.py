import json
import types
import pytest

from claude_reset import l1_install as inst


@pytest.fixture(autouse=True)
def scheduler_identity(monkeypatch, tmp_path):
    from claude_reset import controller_admission, uac_request as uac
    paths = types.SimpleNamespace(state=tmp_path, local=tmp_path / 'local')
    claim = {'schema': 2, 'operation': 'test', 'owner_id': 'a' * 32,
             'state_root': str(tmp_path)}
    owner = uac.Owner(claim, uac.pending_path(paths))
    token = None
    def schedule(folder):
        nonlocal token
        uac._save_exclusive(owner.pending, claim)
        uac._save_exclusive(uac._inventory_path(claim),
                            {'schema': 1, 'claim': claim, 'requests': []})
        token = uac._chain.set(owner)
        request = uac.prepare(paths, 'start', scheduler=True)
        owner.start_request = request
        return request
    monkeypatch.setattr(controller_admission, 'schedule', schedule)
    try:
        yield
    finally:
        if token is not None:
            uac._chain.reset(token)


def clock_and_sleep():
    now = {'t': 0.0}
    return (lambda: now['t']), (lambda seconds: now.__setitem__('t', now['t'] + seconds)), now


def status(folder, **values):
    from claude_reset.uac_request import _chain
    owner = _chain.get()
    request = owner.start_request if owner else None
    values.setdefault('request_id', request.request_id if request else 'fixture-request')
    values.setdefault('state_root', request.state_root if request else 'fixture-root')
    values.setdefault('operation', 'start')
    (folder / 'status.json').write_text(json.dumps(values))


def test_an_unrelated_new_instance_does_not_prove_our_start(tmp_path):
    clock, sleep, _ = clock_and_sleep()
    run, calls = run_factory([0], on_run=lambda n: status(tmp_path, instance='new', request_id='other'))
    assert not inst.start_controller(tmp_path, 'old', attempts=1, run=run, sleep=sleep, clock=clock)


def run_factory(codes, on_run=None):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if on_run:
            on_run(len(calls))
        return types.SimpleNamespace(returncode=codes[min(len(calls), len(codes)) - 1])
    return run, calls


def test_a_new_instance_in_the_status_file_proves_the_start(tmp_path):
    clock, sleep, _ = clock_and_sleep()
    status(tmp_path, instance='old', state='blocked_controller_stopped')
    run, calls = run_factory([0], on_run=lambda n: status(tmp_path, instance='new', state='direct_sockets_blocked'))
    assert inst.start_controller(tmp_path, 'old', run=run, sleep=sleep, clock=clock) is True and len(calls) == 1


def test_an_ignored_run_request_is_retried(tmp_path):
    """MultipleInstancesPolicy IgnoreNew: the first request does nothing, the second starts the controller."""
    clock, sleep, _ = clock_and_sleep()
    status(tmp_path, instance='old', state='blocked_controller_stopped')
    run, calls = run_factory([0, 0], on_run=lambda n: status(tmp_path, instance='new') if n == 2 else None)
    assert inst.start_controller(tmp_path, 'old', run=run, sleep=sleep, clock=clock) is True and len(calls) == 2


def test_gives_up_after_the_attempts_and_says_so(tmp_path):
    clock, sleep, _ = clock_and_sleep()
    status(tmp_path, instance='old')
    run, calls = run_factory([0])
    assert inst.start_controller(tmp_path, 'old', attempts=3, run=run, sleep=sleep, clock=clock) is False and len(calls) == 3


def test_a_refused_request_is_retried_too(tmp_path):
    clock, sleep, _ = clock_and_sleep()
    run, calls = run_factory([1, 0], on_run=lambda n: status(tmp_path, instance='new') if n == 2 else None)
    assert inst.start_controller(tmp_path, None, run=run, sleep=sleep, clock=clock) is True and len(calls) == 2


def test_wait_for_relay_ignores_the_stopped_controllers_status(tmp_path, monkeypatch):
    """Regression: the stale 'blocked_controller_stopped' of the replaced controller ended the wait after 14 s."""
    from claude_reset import l1_mechanism
    clock, sleep, now = clock_and_sleep()
    status(tmp_path, instance='old', state='blocked_controller_stopped', stop_reason='close_requested')

    def tick(seconds):
        sleep(seconds)
        if now['t'] > 20:
            status(tmp_path, instance='new', state='relay_open', level='L1_owner_accepted_limits')
    monkeypatch.setattr(l1_mechanism, 'connect', lambda host, port, timeout=2.0: 'connected')
    up, state = inst.wait_for_relay(tmp_path, 'old', sleep=tick, clock=clock)
    assert up is True and state['instance'] == 'new'


def test_a_real_failure_of_the_new_controller_is_still_reported(tmp_path, monkeypatch):
    from claude_reset import l1_mechanism
    clock, sleep, now = clock_and_sleep()
    status(tmp_path, instance='old', state='blocked_controller_stopped')

    def tick(seconds):
        sleep(seconds)
        if now['t'] > 6:
            status(tmp_path, instance='new', state='blocked_error', error_reason='x')
    monkeypatch.setattr(l1_mechanism, 'connect', lambda host, port, timeout=2.0: 'refused')
    up, state = inst.wait_for_relay(tmp_path, 'old', sleep=tick, clock=clock)
    assert up is False and state['instance'] == 'new' and state['state'] == 'blocked_error'


def test_wait_task_idle_waits_for_the_process_tree_to_finish():
    clock, sleep, now = clock_and_sleep()
    states = iter(['Running', 'Running', 'Running', 'Ready'])
    assert inst.wait_task_idle(30, state=lambda: next(states), sleep=sleep, clock=clock) is True
    assert inst.wait_task_idle(5, state=lambda: 'Running', sleep=sleep, clock=clock) is False


class RestartDeps:
    def __init__(self, running=True, stop=True, start=True, up=True, installed=True):
        self.running, self.stop, self.start_ok, self.up, self.installed, self.calls = running, stop, start, up, installed, []

    def current_instance(self, folder):
        return 'old'

    def check(self, paths):
        ids = {'controller_task': 'ok' if self.installed else 'missing', 'controller_files': 'ok' if self.installed else 'missing',
               'relay_listening': 'ok' if self.running else 'missing'}
        return {'checks': [{'id': k, 'status': v} for k, v in ids.items()]}

    def stop_controller(self, paths):
        self.calls.append('stop')
        return self.stop

    def start(self, folder, stale, attempts=3):
        self.calls.append(('start', stale, attempts))
        return self.start_ok

    def wait_relay(self, folder, stale=None):
        self.calls.append(('wait', stale))
        return self.up, {'state': 'relay_open' if self.up else 'blocked_error', 'level': 'L1_owner_accepted_limits'}


def restart(tmp_path, deps):
    paths = types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local')
    ticks = iter(range(0, 1000, 3))
    return inst.restart(paths, deps=deps, clock=lambda: next(ticks))


def test_restart_stops_starts_and_waits_for_a_new_instance(tmp_path):
    deps = RestartDeps()
    report = restart(tmp_path, deps)
    assert report['status'] == 'restarted' and report['seconds_without_relay'] > 0
    assert deps.calls == ['stop', ('start', 'old', 8), ('wait', 'old')]


def test_restart_with_closed_port_still_checks_controller_stop(tmp_path):
    deps = RestartDeps(running=False)
    assert restart(tmp_path, deps)['status'] == 'restarted' and deps.calls[0] == 'stop'


def test_restart_reports_a_failed_start_with_the_manual_command(tmp_path):
    report = restart(tmp_path, RestartDeps(start=False))
    assert report['status'] == 'start_failed' and report['clients_without_network'] is True and 'schtasks /Run' in report['next']


def test_restart_that_never_opens_the_relay_says_so(tmp_path):
    report = restart(tmp_path, RestartDeps(up=False))
    assert report['status'] == 'relay_not_open' and report['clients_without_network'] is True


def test_restart_refuses_when_nothing_is_installed_and_when_the_controller_will_not_stop(tmp_path):
    assert restart(tmp_path, RestartDeps(installed=False))['status'] == 'not_installed'
    deps = RestartDeps(stop=False)
    assert restart(tmp_path, deps)['status'] == 'controller_not_stopped' and not any(isinstance(c, tuple) for c in deps.calls)


def test_current_instance_handles_a_missing_or_broken_status_file(tmp_path):
    assert inst.current_instance(tmp_path) is None
    (tmp_path / 'status.json').write_text('not json')
    assert inst.current_instance(tmp_path) is None
    status(tmp_path, instance='abc')
    assert inst.current_instance(tmp_path) == 'abc'


def test_unknown_task_states_never_prove_idle():
    for value in (None, '', 'Unknown', 'Queued', 'Running', 'Ready\nRunning'):
        clock, sleep, _ = clock_and_sleep()
        assert not inst.wait_task_idle(3, state=lambda: value, sleep=sleep, clock=clock)


def test_failed_task_query_cannot_report_missing(monkeypatch):
    from claude_reset import backend_install
    monkeypatch.setattr(backend_install, 'powershell', lambda script: (1, 'Missing', 'error'))
    assert inst.task_state() is None


def test_restart_closed_port_busy_controller_retains_claim(tmp_path):
    deps = RestartDeps(running=False, stop=False)
    result = restart(tmp_path, deps)
    assert result['status'] == 'controller_not_stopped'
    assert result['retry_blocked'] is True
    assert deps.calls == ['stop']
