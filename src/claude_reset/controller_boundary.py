"""Nonblocking observation of the existing controller mutex, not recovery authority."""
import ctypes as C
from ctypes import wintypes as W
from contextlib import contextmanager
from dataclasses import dataclass


NAME = 'Global\\ClaudeReset.StrictGate.v1'


def _kernel():
    api = C.WinDLL('kernel32', use_last_error=True)
    for name, args, result in (
        ('OpenMutexW', [W.DWORD, W.BOOL, W.LPCWSTR], W.HANDLE),
        ('WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD),
        ('ReleaseMutex', [W.HANDLE], W.BOOL),
        ('CloseHandle', [W.HANDLE], W.BOOL),
    ):
        function = getattr(api, name)
        function.argtypes, function.restype = args, result
    return api


@dataclass
class Boundary:
    observation: str = 'unknown'
    held: bool = False


@contextmanager
def hold(*, api=None):
    """Hold an existing mutex on this thread for the whole synchronous scope.

    Never create a mutex or infer absence from OpenMutex failure. Acquisition
    can be recursive on the owner's thread and does not prove process exit,
    resource cleanup or legacy participation. Do not transfer across threads.
    The witness is invalidated on cleanup failure; held ends on scope exit.
    """
    handle = None
    acquired = False
    witness = Boundary()
    try:
        try:
            api = api if api is not None else _kernel()
            handle = api.OpenMutexW(0x100000 | 0x0001, False, NAME)
            if handle:
                waited = api.WaitForSingleObject(handle, 0)
                acquired = waited in (0, 0x80)
                witness.held = acquired
                witness.observation = {0: 'acquired', 0x80: 'abandoned', 258: 'busy'}.get(waited, 'unknown')
        except OSError:
            witness.observation = 'unknown'
        yield witness
    finally:
        witness.held = False
        if handle:
            # Close still runs if release fails. Neither failure is a clean witness.
            try:
                if acquired and not api.ReleaseMutex(handle):
                    witness.observation = 'unknown'
            except OSError:
                witness.observation = 'unknown'
            finally:
                try:
                    if not api.CloseHandle(handle):
                        witness.observation = 'unknown'
                except OSError:
                    witness.observation = 'unknown'


def observe(*, api=None):
    """Return a snapshot only; ownership is released before returning."""
    with hold(api=api) as witness:
        pass
    return witness.observation
