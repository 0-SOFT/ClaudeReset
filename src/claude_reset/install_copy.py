"""Copy a held payload into a new file; no authorization or directory creation.

The privileged adapter must first authenticate the package, protect and lock
the destination parent, and persist an intent for this exact path. Failed
partial files are left for ownership-aware recovery, never silently deleted.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import os
from pathlib import Path
from .safeio import SafetyError, guarded, local_volume
from .windows_pin import PinnedFile


def _copy_pinned(source, destination, *, on_created=None):
    """Low-level primitive; caller establishes parent ACL and transaction ownership."""
    if not isinstance(source,PinnedFile) or not source.handle:
        raise SafetyError('An open payload pin is required')
    destination=Path(destination)
    guarded(local_volume(destination),destination.parent,allow_root=True)
    size=C.c_int64()
    if not source.api.GetFileSizeEx(source.handle,C.byref(size)) or not 0<=size.value<=268435456:
        raise SafetyError('Invalid pinned payload size')
    seek=source.api.SetFilePointerEx
    seek.argtypes=[W.HANDLE,C.c_int64,C.POINTER(C.c_int64),W.DWORD]
    seek.restype=W.BOOL
    if not seek(source.handle,0,None,0):raise SafetyError('Cannot rewind pinned payload')
    digest=hashlib.sha256();total=0
    buffer=C.create_string_buffer(65536)
    # Exclusive creation never truncates a previous or substituted resource.
    with destination.open('xb') as stream:
        if on_created is not None:
            # Persist ownership before the first byte, while this exact newly
            # created file is still open. A failed receipt leaves an unknown
            # resource for manual recovery, never a guessed deletion target.
            import msvcrt
            on_created(msvcrt.get_osfhandle(stream.fileno()))
        while True:
            count=W.DWORD()
            if not source.api.ReadFile(source.handle,buffer,len(buffer),C.byref(count),None):
                raise SafetyError('Cannot copy pinned payload')
            if not count.value:break
            total+=count.value
            if total>size.value:raise SafetyError('Pinned input size changed during copy')
            chunk=buffer.raw[:count.value]
            if stream.write(chunk)!=len(chunk):raise SafetyError('Incomplete staged write')
            digest.update(chunk)
        if total!=size.value or digest.hexdigest()!=source.sha256:
            raise SafetyError('Pinned input changed during copy')
        stream.flush();os.fsync(stream.fileno())
    # Re-open with no write/delete sharing and hash the actual destination.
    return PinnedFile(destination,expected_sha256=source.sha256,limit=max(1,size.value))
