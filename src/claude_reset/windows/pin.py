"""File handles that deny others: pinned inputs of a service generation, guarded reads, an exclusive lock."""
from __future__ import annotations
from collections.abc import Iterator
from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
import hashlib
import os
from pathlib import Path
from typing import BinaryIO
from ..safeio import local_path
from ..errors import SafetyError
from ..safeio import guarded, local_volume
from .api import Library

__all__ = ['ExclusiveFile', 'PinnedFile', 'locked_reader']


class PinnedFile:
    def __init__(self, path: Path, *, expected_sha256: str | None=None, limit: int=268435456) -> None:
        self.handle = None
        self.path = Path(local_path(str(path)))
        guarded(local_volume(self.path), self.path.parent)
        self.api = Library('kernel32')
        try:
            # GENERIC_READ, FILE_SHARE_READ only, OPEN_EXISTING; never follow a
            # final reparse point. Ancestors were checked before opening.
            self.handle = self.api.CreateFileW(str(self.path), 0x80000000, 1, None, 3, 0x00200000, None)
            if self.handle in (None, C.c_void_p(-1).value):
                self.handle = None
                raise SafetyError('Cannot pin the protected input file')
            final = C.create_unicode_buffer(32768)
            count = self.api.GetFinalPathNameByHandleW(self.handle, final, len(final), 0)
            if not count or count >= len(final) or final.value.casefold() != ('\\\\?\\' + str(self.path)).casefold():
                raise SafetyError('Pinned input path changed')
            size = self.size()
            if size is None or not 0 <= size <= limit:
                raise SafetyError('Pinned input exceeds its size limit')
            digest = hashlib.sha256()
            chunks = []
            total = 0
            for chunk in self.chunks('Cannot read pinned input'):
                total += len(chunk)
                if total > limit:
                    raise SafetyError('Pinned input exceeds its size limit')
                digest.update(chunk)
                if limit <= 65536:
                    chunks.append(chunk)
            if total != size:
                raise SafetyError('Pinned input size changed')
            self.sha256 = digest.hexdigest()
            self.data = b''.join(chunks) if limit <= 65536 else None
            if expected_sha256 is not None and self.sha256 != expected_sha256:
                raise SafetyError('Pinned input hash mismatch')
        except BaseException:
            self.close()
            raise

    def size(self) -> int | None:
        """The held file's size now, or None when Windows cannot tell."""
        size = C.c_int64()
        return size.value if self.api.GetFileSizeEx(self.handle, C.byref(size)) else None

    def rewind(self) -> bool:
        """Read from the start again; False when Windows refuses."""
        return bool(self.api.SetFilePointerEx(self.handle, 0, None, 0))

    def chunks(self, failure: str) -> Iterator[bytes]:
        """The held file from the current position, in pieces of up to 64 KiB; a failed read raises failure."""
        buffer = C.create_string_buffer(65536)
        while True:
            count = W.DWORD()
            if not self.api.ReadFile(self.handle, buffer, len(buffer), C.byref(count), None):
                raise SafetyError(failure)
            if not count.value:
                return
            yield buffer.raw[:count.value]

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


@contextmanager
def locked_reader(path: Path, busy: str) -> Iterator[BinaryIO]:
    """Keep a Windows handle denying concurrent writes/deletion until all reads finish; busy is the refusal."""
    if os.name != 'nt':
        with path.open('rb') as stream:
            yield stream
        return
    import msvcrt
    kernel = Library('kernel32')
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
    if handle == C.c_void_p(-1).value:
        raise SafetyError(busy)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, 'rb') as stream:
        yield stream


class ExclusiveFile:
    """A file opened (created when missing) with no sharing: while it is held, nobody else can open it."""

    def __init__(self, path: Path, busy: str) -> None:
        self.api = Library('kernel32')
        # GENERIC_READ | GENERIC_WRITE, no sharing, OPEN_ALWAYS, the reparse point itself.
        self.handle = self.api.CreateFileW(str(path), 0xC0000000, 0, None, 4, 0x00200000, None)
        if self.handle in (None, C.c_void_p(-1).value):
            self.handle = None
            raise SafetyError(busy)

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None
