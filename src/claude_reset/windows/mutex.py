"""Named Windows mutexes: one holder for the whole computer, taken without waiting."""
from __future__ import annotations

from .api import Library

__all__ = ['Mutex', 'hold']

WAIT_OBJECT_0 = 0
WAIT_ABANDONED = 0x80   # the previous holder died without releasing; the mutex is ours now


class Mutex:
    """A named mutex this process holds until release()."""

    def __init__(self, kernel, handle) -> None:
        self.kernel, self.handle = kernel, handle

    def release(self) -> None:
        self.kernel.ReleaseMutex(self.handle)
        self.kernel.CloseHandle(self.handle)


def hold(name: str) -> Mutex | None:
    """Take the named mutex now, or None when another process holds it or it cannot be created."""
    kernel = Library('kernel32')
    handle = kernel.CreateMutexW(None, False, name)
    if not handle:
        return None
    if kernel.WaitForSingleObject(handle, 0) not in (WAIT_OBJECT_0, WAIT_ABANDONED):
        kernel.CloseHandle(handle)
        return None
    return Mutex(kernel, handle)
