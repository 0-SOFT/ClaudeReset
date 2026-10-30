"""Serialized GUI jobs. Public events never carry domain data or exceptions.

Results stay in a private slot until the UI acknowledges the terminal event.
Cancellation is cooperative and may only take effect at declared checkpoints.
Legacy functions run as one indivisible step; never interrupt an issued mutation.
"""
from dataclasses import dataclass
from enum import StrEnum
import queue
import threading


class Phase(StrEnum):
    """Where an operation of the window is. The last four end it."""
    CANCELLED = 'cancelled'
    CANCEL_REQUESTED = 'cancel_requested'
    COMPLETED = 'completed'
    OPERATION_FAILED = 'operation_failed'
    QUEUED = 'queued'
    RUNNING = 'running'
    WAITING_UAC = 'waiting_uac'
    WORKER_START_FAILED = 'worker_start_failed'


FINISHED = frozenset({Phase.COMPLETED, Phase.CANCELLED, Phase.OPERATION_FAILED, Phase.WORKER_START_FAILED})


@dataclass(frozen=True)
class Event:
    operation: int
    state: Phase
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
        self._executor.boundary(self.operation, self._step)

    def step(self, action, *, waiting_uac=False):
        """Atomically leave the cancellation boundary, then run without interruption."""
        self._executor.begin_step(self.operation, self._step + 1, waiting_uac=waiting_uac)
        self._step += 1
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

    def boundary(self, operation, step):
        """A cancellation boundary of the running operation; raises Cancelled when cancellation was asked for."""
        with self._lock:
            if self._cancel:
                raise Cancelled()
            self._cancellable = True
            self.events.put(Event(operation, Phase.RUNNING, True, step))

    def begin_step(self, operation, step, *, waiting_uac=False):
        """Leave the cancellation boundary for one step that must run to its end."""
        with self._lock:
            if self._cancel:
                raise Cancelled()
            self._cancellable = False
            self.events.put(Event(operation, Phase.WAITING_UAC if waiting_uac else Phase.RUNNING, False, step))

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
            self.events.put(Event(operation, Phase.QUEUED, True))

        def run():
            result = None
            try:
                context = Context(self, operation)
                context.checkpoint()
                result = action(context)
                state = Phase.COMPLETED
            except Cancelled:
                state = Phase.CANCELLED
            except BaseException:
                # No exception objects, type names, repr or traceback cross the bus.
                state = Phase.OPERATION_FAILED
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
                self.events.put(Event(operation, Phase.WORKER_START_FAILED))
        return operation

    def cancel(self):
        with self._lock:
            if self._active is None or self._terminal or not self._cancellable:
                return False
            self._cancel = True
            self.events.put(Event(self._active, Phase.CANCEL_REQUESTED))
            return True

    def take_result(self, operation):
        """UI-only acknowledgement; even finished jobs hold the serialization slot."""
        with self._lock:
            if operation != self._active or not self._terminal:
                raise RuntimeError('No terminal result for this operation')
            result, self._result = self._result, None
            self._active = None
            return result
