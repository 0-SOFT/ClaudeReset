"""Copy a held payload into a new file; no authorization or directory creation.

The privileged adapter must first authenticate the package, protect and lock
the destination parent, and persist an intent for this exact path. Failed
partial files are left for ownership-aware recovery, never silently deleted.
"""
import hashlib
import os
from pathlib import Path
from ..errors import SafetyError
from ..safeio import guarded, local_volume
from ..windows.pin import PinnedFile

__all__ = ['copy_pinned']


def copy_pinned(source, destination, *, on_created=None):
    """Low-level primitive; caller establishes parent ACL and transaction ownership."""
    if not isinstance(source,PinnedFile) or not source.handle:
        raise SafetyError('An open payload pin is required')
    destination=Path(destination)
    guarded(local_volume(destination),destination.parent,allow_root=True)
    size=source.size()
    if size is None or not 0<=size<=268435456:
        raise SafetyError('Invalid pinned payload size')
    if not source.rewind():
        raise SafetyError('Cannot rewind pinned payload')
    digest=hashlib.sha256()
    total=0
    # Exclusive creation never truncates a previous or substituted resource.
    with destination.open('xb') as stream:
        if on_created is not None:
            # Persist ownership before the first byte, while this exact newly
            # created file is still open. A failed receipt leaves an unknown
            # resource for manual recovery, never a guessed deletion target.
            import msvcrt
            on_created(msvcrt.get_osfhandle(stream.fileno()))
        for chunk in source.chunks('Cannot copy pinned payload'):
            total+=len(chunk)
            if total>size:
                raise SafetyError('Pinned input size changed during copy')
            if stream.write(chunk)!=len(chunk):
                raise SafetyError('Incomplete staged write')
            digest.update(chunk)
        if total!=size or digest.hexdigest()!=source.sha256:
            raise SafetyError('Pinned input changed during copy')
        stream.flush()
        os.fsync(stream.fileno())
    # Re-open with no write/delete sharing and hash the actual destination.
    return PinnedFile(destination,expected_sha256=source.sha256,limit=max(1,size))
