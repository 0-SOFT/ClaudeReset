"""Actual GUI dispatch without a display or Windows mutations."""
import threading
from types import SimpleNamespace

import pytest

from claude_reset.ui import expert_window as app
from claude_reset.ui.worker import Event, Worker
from claude_reset.ui.text import gui_message
from claude_reset.safeio import SafetyError
from dialog_fakes import script
from scripted import Strict


@pytest.fixture
def window():
    ui = app.App.__new__(app.App)
    ui.worker = Worker()
    ui.events = ui.worker.events
    ui.operation = ui.result_callback = None
    ui.cancel_button = SimpleNamespace(configure=lambda **_: None)
    ui.messages, ui.scheduled, ui.statuses = [], [], []
    ui.status = SimpleNamespace(set=ui.statuses.append)
    ui.root = SimpleNamespace(after=lambda *args: ui.scheduled.append(args))
    script(ui, showerror=lambda *args: ui.messages.append(args))
    return ui


def fail():
    raise SafetyError('secret-password test-user 192.0.2.9 2001:db8::9')


def finish(window):
    events = []
    while True:
        event = window.events.get(timeout=3)
        events.append(event)
        if event.state in ('completed', 'operation_failed', 'worker_start_failed', 'cancelled'):
            break
    for event in events:
        window.events.put(event)
    window.poll()
    return events


def test_callback_failure_keeps_polling_and_accepts_next_result(window):
    window.run(lambda: None, lambda _: fail())
    finish(window)
    assert not window.busy
    assert window.messages[-1][1] == gui_message('callback_failed')
    received = []
    window.run(lambda: 42, received.append)
    finish(window)
    assert received == [42]
    assert len(window.scheduled) == 2


def test_slow_worker_does_not_block_poll_or_allow_second_action(window):
    entered, release = threading.Event(), threading.Event()
    received, second = [], []

    def action():
        entered.set()
        assert release.wait(3)
        return 42

    window.run(action, received.append)
    try:
        assert entered.wait(3)
        window.poll()
        assert window.busy and window.scheduled
        window.run(lambda: second.append(True), received.append)
        assert not second
        assert not window.worker.cancel()
    finally:
        release.set()
    finish(window)
    assert received == [42] and not window.busy


def test_worker_failure_queue_contains_no_raw_error(window):
    window.run(fail, lambda _: pytest.fail('must not call success callback'))
    events = finish(window)
    assert events[-1].state == 'operation_failed'
    assert 'secret-password' not in repr(events)
    assert window.messages[-1][1] == gui_message('operation_failed')
    assert not window.busy


def test_safe_and_tk_errors_do_not_stringify_exception(window):
    class PrivateError(Exception):
        def __str__(self):
            pytest.fail('exception text must not be inspected')

    def action():
        raise PrivateError()

    window.safe(action)
    window.callback_exception(PrivateError, PrivateError(), None)
    assert [m[1] for m in window.messages] == [gui_message('operation_failed'), gui_message('callback_failed')]


def test_thread_start_failure_releases_busy(window):
    window.worker = Worker(thread_factory=lambda **_: SimpleNamespace(start=fail))
    window.events = window.worker.events
    window.run(lambda: pytest.fail('not started'), lambda _: None)
    finish(window)
    assert not window.busy and window.events.empty()
    assert window.messages[-1][1] == gui_message('worker_start_failed')


def test_poll_reschedules_even_when_error_dialog_fails(window):
    script(window, showerror=lambda *args: fail())
    window.run(fail, lambda _: None)
    with pytest.raises(SafetyError):
        finish(window)
    assert len(window.scheduled) == 1


def test_unknown_public_message_is_not_echoed():
    assert gui_message('secret-password 192.0.2.9') == gui_message('operation_failed')


def test_completion_callback_can_start_next_job_and_stale_events_are_ignored(window):
    received = []
    window.run(lambda: 1, lambda value: window.run(lambda: value + 1, received.append))
    first = window.operation
    # Wait without consuming in the UI; the terminal slot must remain reserved.
    events = []
    while not events or events[-1].state != 'completed':
        events.append(window.events.get(timeout=3))
    for event in events:
        window.events.put(event)
    window.events.put(Event(first - 1, 'operation_failed'))
    window.poll()
    if window.busy:
        finish(window)
    assert received == [2] and not window.messages
    assert not window.busy


def test_safe_action_does_not_bypass_active_worker(window):
    targets = []
    window.worker = Worker(thread_factory=lambda **kw: SimpleNamespace(start=lambda: targets.append(kw['target'])))
    window.events = window.worker.events
    window.run(lambda: 1, lambda _: None)
    window.safe(lambda: pytest.fail('parallel synchronous action'))
    assert window.worker.cancel()
    targets.pop()()
    finish(window)
    assert not window.busy


@pytest.mark.parametrize('action', ['apply', 'save_policy'])
@pytest.mark.parametrize('change', ['replace', 'invalidate', 'edit', 'invalidate_restore', 'busy'])
def test_confirmation_cannot_authorize_changed_plan(window, action, change, tmp_path):
    original = SimpleNamespace(id='reviewed', blockers=[], actions=['reviewed-target'])
    window.plan = original
    window.server_done = SimpleNamespace(get=lambda: True)
    window.paths = SimpleNamespace(state=tmp_path)
    script(window, asksaveasfilename=lambda **_: str(tmp_path / 'policy.dpapi'))
    window.executor = lambda *_: pytest.fail('must not execute')
    window.policy = Strict()   # saving a policy fails the test

    def confirm(*_):
        if change == 'replace':
            window.plan = SimpleNamespace(id='other', blockers=[], actions=['other-target'])
        elif change == 'invalidate':
            window.invalidate()
        elif change == 'edit':
            original.actions.append('unreviewed-target')
        elif change == 'invalidate_restore':
            window.invalidate()
            window.plan = original
        else:
            window.worker = SimpleNamespace(busy=True)
        return True

    script(window, askyesno=confirm)
    getattr(window, action)()
    assert window.messages[-1][1] == gui_message('plan_changed')
    assert window.operation is None
    assert not (tmp_path / 'policy.dpapi').exists()


def test_policy_file_dialog_invalidates_plan_before_consent(window, tmp_path):
    window.plan = SimpleNamespace(id='reviewed', blockers=[])
    def choose(**_):
        window.invalidate()
        return str(tmp_path / 'policy.dpapi')
    script(window, asksaveasfilename=choose, askyesno=lambda *_: pytest.fail('stale confirmation'))
    window.save_policy()
    assert window.messages[-1][1] == gui_message('plan_changed')


@pytest.mark.parametrize('action', ['apply', 'save_policy'])
def test_unchanged_confirmation_uses_private_snapshot(window, action, tmp_path):
    script(window, askstring='СБРОСИТЬ')
    original = SimpleNamespace(id='reviewed', blockers=[], actions=['reviewed-target'])
    window.plan = original
    window.paths = SimpleNamespace(state=tmp_path)
    window.server_done = SimpleNamespace(get=lambda: True)
    received = []
    script(window, askyesno=True, asksaveasfilename=lambda **_: str(tmp_path / 'policy.dpapi'))
    window.policy = Strict(save_policy=lambda _file, plan, **kw: received.append((plan, kw)))
    window.executor = lambda *_: SimpleNamespace(apply=lambda plan, **kw: received.append((plan, kw)))
    window.run = lambda work, _callback: work()
    getattr(window, action)()
    original.actions.append('later-change')
    assert received[0][0].actions == ['reviewed-target']
    assert received[0][0] is not original
    assert received[0][1]['consent_id'] == 'reviewed'
    assert not window.messages
