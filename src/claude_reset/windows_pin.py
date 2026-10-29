"""Hold local immutable-by-sharing file handles for one service generation."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
from pathlib import Path
from .gateway_profile import local_path
from .safeio import SafetyError, guarded, local_volume


class PinnedFile:
    def __init__(self, path, *, expected_sha256=None, limit=268435456):
        self.handle = None
        self.path = Path(local_path(str(path)))
        guarded(local_volume(self.path), self.path.parent)
        self.api = C.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'CreateFileW': ([W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE], W.HANDLE),
            'ReadFile': ([W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p], W.BOOL),
            'GetFileSizeEx': ([W.HANDLE,C.POINTER(C.c_int64)], W.BOOL),
            'GetFinalPathNameByHandleW': ([W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD], W.DWORD),
            'CloseHandle': ([W.HANDLE], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name); function.argtypes, function.restype = args, result
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
            size = C.c_int64()
            if not self.api.GetFileSizeEx(self.handle, C.byref(size)) or not 0 <= size.value <= limit:
                raise SafetyError('Pinned input exceeds its size limit')
            digest = hashlib.sha256(); chunks = []; total = 0
            buffer = C.create_string_buffer(65536)
            while True:
                count = W.DWORD()
                if not self.api.ReadFile(self.handle, buffer, len(buffer), C.byref(count), None):
                    raise SafetyError('Cannot read pinned input')
                if not count.value: break
                total += count.value
                if total > limit: raise SafetyError('Pinned input exceeds its size limit')
                chunk = buffer.raw[:count.value]; digest.update(chunk)
                if limit <= 65536: chunks.append(chunk)
            if total != size.value: raise SafetyError('Pinned input size changed')
            self.sha256 = digest.hexdigest()
            self.data = b''.join(chunks) if limit <= 65536 else None
            if expected_sha256 is not None and self.sha256 != expected_sha256:
                raise SafetyError('Pinned input hash mismatch')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle); self.handle = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
