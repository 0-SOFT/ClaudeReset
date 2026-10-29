"""Serialized GUI jobs. Public events never carry domain data or exceptions.

Results stay in a private slot until the UI acknowledges the terminal event.
Cancellation is cooperative and may only take effect at declared checkpoints.
Legacy functions run as one indivisible step; never interrupt an issued mutation.
"""
from dataclasses import dataclass
import queue
import threading


@dataclass(frozen=True)
class Event:
    operation: int
    state: str
    cancellable: bool = False
    step: int = 0


class Cancelled(Exception):
    pass


class Context:
    def __init__(self, executor, operation):
        self._executor = executor
        self.operation = operation
        self._step = 0

    def checkpoint(self):
        """Call only before changes or at a recoverable boundary between steps."""
        with self._executor._lock:
            if self._executor._cancel:
                raise Cancelled()
            self._executor._cancellable = True
            self._executor.events.put(Event(self.operation, 'running', True, self._step))

    def step(self, action, *, waiting_uac=False):
        """Atomically leave the cancellation boundary, then run without interruption."""
        with self._executor._lock:
            if self._executor._cancel:
                raise Cancelled()
            self._executor._cancellable = False
            self._step += 1
            self._executor.events.put(Event(
                self.operation, 'waiting_uac' if waiting_uac else 'running', False, self._step))
        return action()


class Worker:
    def __init__(self, *, thread_factory=threading.Thread):
        self.events = queue.Queue()
        self._lock = threading.Lock()
        self._thread_factory = thread_factory
        self._serial = 0
        self._active = None
        self._terminal = False
        self._cancel = False
        self._cancellable = False
        self._result = None

    @property
    def busy(self):
        with self._lock:
            return self._active is not None

    def start(self, action):
        """Accept a function(Context); return its id, or None if already busy."""
        with self._lock:
            if self._active is not None:
                return None
            self._serial += 1
            operation = self._active = self._serial
            self._terminal = self._cancel = False
            self._cancellable = True
            self._result = None
            self.events.put(Event(operation, 'queued', True))

        def run():
            result = None
            try:
                context = Context(self, operation)
                context.checkpoint()
                result = action(context)
                state = 'completed'
            except Cancelled:
                state = 'cancelled'
            except BaseException:
                # No exception objects, type names, repr or traceback cross the bus.
                state = 'operation_failed'
            with self._lock:
                self._result = result
                self._terminal = True
                self._cancellable = False
                self.events.put(Event(operation, state))

        try:
            self._thread_factory(target=run, daemon=False).start()
        except Exception:
            with self._lock:
                self._terminal = True
                self._cancellable = False
                self.events.put(Event(operation, 'worker_start_failed'))
        return operation

    def cancel(self):
        with self._lock:
            if self._active is None or self._terminal or not self._cancellable:
                return False
            self._cancel = True
            self.events.put(Event(self._active, 'cancel_requested'))
            return True

    def take_result(self, operation):
        """UI-only acknowledgement; even finished jobs hold the serialization slot."""
        with self._lock:
            if operation != self._active or not self._terminal:
                raise RuntimeError('No terminal result for this operation')
            result, self._result = self._result, None
            self._active = None
            return result
