import threading
from types import SimpleNamespace

import pytest

from claude_reset.gui_worker import Worker


def terminal(worker):
    events = []
    while True:
        event = worker.events.get(timeout=3)
        events.append(event)
        if event.state in ('completed', 'cancelled', 'operation_failed', 'worker_start_failed'):
            return event, events


def test_queued_cancel_never_enters_action_and_result_requires_acknowledgement():
    targets, calls = [], []
    worker = Worker(thread_factory=lambda **kw: SimpleNamespace(start=lambda: targets.append(kw['target'])))
    operation = worker.start(lambda context: context.step(lambda: calls.append(True)))
    assert worker.cancel()
    targets.pop()()
    event, _ = terminal(worker)
    assert event.state == 'cancelled' and not calls
    assert worker.start(lambda _: None) is None
    with pytest.raises(RuntimeError):
        worker.take_result(operation + 1)
    assert worker.busy
    worker.take_result(operation)
    assert not worker.busy


def test_cancel_between_steps_preserves_completed_step():
    ready, release = threading.Event(), threading.Event()
    calls = []
    worker = Worker()

    def action(context):
        context.step(lambda: calls.append('first'))
        context.checkpoint()
        ready.set()
        assert release.wait(3)
        context.step(lambda: calls.append('second'))

    operation = worker.start(action)
    try:
        assert ready.wait(3)
        assert worker.cancel()
    finally:
        release.set()
    event, _ = terminal(worker)
    assert event.state == 'cancelled' and calls == ['first']
    worker.take_result(operation)


def test_uac_is_noninterruptible_and_secret_result_not_on_public_bus():
    ready, release = threading.Event(), threading.Event()
    secret = {'password': 'test-secret', 'ip': '2001:db8::12', 'user': 'test-user'}
    worker = Worker()

    def receipt():
        ready.set()
        assert release.wait(3)
        return secret

    operation = worker.start(lambda context: context.step(receipt, waiting_uac=True))
    try:
        assert ready.wait(3)
        assert not worker.cancel()
        assert worker.start(lambda _: None) is None
    finally:
        release.set()
    event, events = terminal(worker)
    assert any(row.state == 'waiting_uac' for row in events)
    assert event.state == 'completed'
    assert all(value not in repr(events) for value in secret.values())
    assert worker.take_result(operation) is secret
    assert worker._result is None
