"""What L1 install, restart, removal and the extension protection share: the controller's status file,
the controller task's state, and waiting for the task to go idle and the relay to close."""
import time

from .. import config
from . import l1_mechanism
from ..windows import tasks

__all__ = ['task_state', 'wait_relay_gone', 'wait_task_idle']


def task_state():
    return tasks.state(config.CONTROLLER_TASK)


def wait_task_idle(seconds=90, *, state=task_state, sleep=time.sleep, clock=time.monotonic):
    """The task ignores a run request while its previous process tree is still alive (MultipleInstancesPolicy
    IgnoreNew), and a closed relay port does not mean that process has exited. Wait until it is idle."""
    deadline = clock() + seconds
    while clock() < deadline:
        if state() in ('Ready', 'Disabled', 'Missing'):
            return True
        sleep(1)
    return False


def wait_relay_gone(seconds=60, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + seconds
    while clock() < deadline:
        if l1_mechanism.connect(config.LOOPBACK, config.RELAY_PORT, .3) != 'connected':
            return True
        sleep(1)
    return False
