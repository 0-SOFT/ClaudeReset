"""Short OS admission lock, shared across state roots and integrity levels.

The permanent file must never be replaced or removed. Failure to acquire it
refuses admission; callers must not wait for a controller or UAC while holding it.
"""
import os
from contextlib import contextmanager

from .. import layout
from ..errors import SafetyError

__all__ = ['AdmissionUnavailable', 'locked']


class AdmissionUnavailable(SafetyError):
    pass


@contextmanager
def locked(paths):
    path = layout.app_local(paths, 'admission.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    # No initialization write: Windows permits byte locks beyond EOF. Writing
    # a sentinel before locking would collide with another process's lock.
    with path.open('a+b') as stream:
        try:
            if os.name == 'nt':
                import msvcrt
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AdmissionUnavailable('Admission unavailable') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
