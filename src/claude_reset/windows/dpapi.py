"""Current-user DPAPI: archives, profiles and settings copies are sealed with the key of the signed-in user."""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from types import MappingProxyType

from ..errors import SafetyError
from .api import Library

__all__ = ['DPAPI', 'PROTOTYPES']


class Blob(ctypes.Structure):
    _fields_ = [('length', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


_BLOB, _PVOID = ctypes.POINTER(Blob), ctypes.c_void_p


# The DPAPI functions of crypt32 (windows/api.py has the shared table).
PROTOTYPES = MappingProxyType({'crypt32': MappingProxyType({
    'CryptProtectData': (wintypes.BOOL, [_BLOB, wintypes.LPCWSTR, _PVOID, _PVOID, _PVOID, wintypes.DWORD, _BLOB]),
    'CryptUnprotectData': (wintypes.BOOL, [_BLOB, _PVOID, _PVOID, _PVOID, _PVOID, wintypes.DWORD, _BLOB]),
})})


class DPAPI:
    """Current-user DPAPI; no machine scope, export of OS keys or plaintext fallback."""
    def _transform(self, payload: bytes, protect: bool) -> bytes:
        if os.name != 'nt':
            raise SafetyError('DPAPI memory archive requires Windows')
        crypt = Library('crypt32', PROTOTYPES)
        kernel = Library('kernel32')
        raw = ctypes.create_string_buffer(payload)
        source = Blob(len(payload), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte)))
        target = Blob()
        if protect:
            ok = crypt.CryptProtectData(ctypes.byref(source), 'Claude Reset memory', None, None, None, 1,
                                        ctypes.byref(target))
        else:
            ok = crypt.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
        if not ok:
            raise SafetyError('DPAPI operation failed; no plaintext archive created')
        try:
            return ctypes.string_at(target.data, target.length)
        finally:
            kernel.LocalFree(target.data)

    def encrypt(self, data: bytes) -> bytes:
        return b'CRMEM01\0' + self._transform(data, True)

    def decrypt(self, data: bytes) -> bytes:
        if not data.startswith(b'CRMEM01\0'):
            raise SafetyError('Unknown memory archive format')
        return self._transform(data[8:], False)
