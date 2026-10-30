"""Bind a held process handle to its generation and dedicated service token."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
import struct
from .api import Library
from ..errors import SafetyError
from .. import config
from pathlib import Path

__all__ = ['Process', 'service_descriptor', 'service_sid']


class SidAttributes(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('attributes', W.DWORD)]


def service_sid(name: str) -> str:
    if name not in (config.BACKEND_SERVICE, config.GATEWAY_SERVICE):
        raise SafetyError('Unknown runtime service identity')
    digest = hashlib.sha1(name.upper().encode('utf-16le')).digest()
    return 'S-1-5-80-' + '-'.join(str(value) for value in struct.unpack('<5I', digest))


class Process:
    def __init__(self, pid: int, *, image: Path, service: str) -> None:
        self.handle = None
        self.api, self.security = Library('kernel32'), Library('advapi32')
        self.pid = pid
        try:
            if type(pid) is not int or pid <= 0:
                raise SafetyError('Invalid service process ID')
            self.handle = self.api.OpenProcess(0x1000 | 0x100000, False, pid)
            if not self.handle:
                raise SafetyError('Service process handle unavailable')
            path = C.create_unicode_buffer(32768)
            length = W.DWORD(len(path))
            if (not self.api.QueryFullProcessImageNameW(self.handle, 0, path, C.byref(length))
                    or path.value.casefold() != str(image).casefold()):
                raise SafetyError('Service process image differs')
            times = [C.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(C.byref(value) for value in times)):
                raise SafetyError('Service process generation unavailable')
            self.start_utc_ticks = times[0].value + 504911232000000000
            self.require_token(service)
            if not self.running():
                raise SafetyError('Service process has exited')
        except BaseException:
            self.close()
            raise

    def sid_text(self, pointer: C.c_void_p) -> str:
        value = W.LPWSTR()
        if not self.security.ConvertSidToStringSidW(pointer, C.byref(value)):
            raise SafetyError('Invalid service token SID')
        try:
            return value.value
        finally:
            self.api.LocalFree(value)

    def require_token(self, service: str) -> None:
        token = W.HANDLE()
        if not self.security.OpenProcessToken(self.handle, 8, C.byref(token)):
            raise SafetyError('Service token unavailable')
        try:
            def info(kind: int) -> C.Array:
                needed = W.DWORD()
                self.security.GetTokenInformation(token, kind, None, 0, C.byref(needed))
                if not 8 <= needed.value <= 65536:
                    raise SafetyError('Invalid service token information size')
                buffer = C.create_string_buffer(needed.value)
                if not self.security.GetTokenInformation(token, kind, buffer, len(buffer), C.byref(needed)):
                    raise SafetyError('Cannot inspect service token')
                return buffer
            user = info(1)
            if self.sid_text(SidAttributes.from_buffer(user).sid) != 'S-1-5-18':
                raise SafetyError('Backend requires the LocalSystem service token')
            groups = info(2)
            count = W.DWORD.from_buffer(groups).value
            offset = C.alignment(SidAttributes)
            if offset + count*C.sizeof(SidAttributes) > len(groups):
                raise SafetyError('Invalid service token groups')
            expected = service_sid(service)
            for index in range(count):
                group = SidAttributes.from_buffer(groups, offset + index*C.sizeof(SidAttributes))
                if group.attributes & 4 and not group.attributes & 16 and self.sid_text(group.sid) == expected:
                    return
            raise SafetyError('Dedicated enabled service SID is absent')
        finally:
            self.api.CloseHandle(token)

    def running(self) -> bool:
        if not self.handle:
            return False
        result = self.api.WaitForSingleObject(self.handle, 0)
        if result not in (0, 258):
            raise SafetyError('Service process state unavailable')
        return result == 258

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


def service_descriptor(name: str) -> bytes:
    if name not in (config.GATEWAY_SERVICE, config.GATEWAY_FIXTURE_SERVICE, config.BACKEND_SERVICE, config.BACKEND_FIXTURE_SERVICE):
        raise SafetyError('Only the owned gateway service can reserve a port')
    a, k = Library('advapi32'), Library('kernel32')
    n, dn, use = W.DWORD(), W.DWORD(), W.DWORD()
    a.LookupAccountNameW(None,'NT SERVICE\\'+name,None,C.byref(n),None,C.byref(dn),C.byref(use))
    if C.get_last_error()!=122 or not 8<=n.value<=68 or not 1<=dn.value<=256:
        raise SafetyError('Gateway service SID is unavailable')
    sid, domain = C.create_string_buffer(n.value), C.create_unicode_buffer(dn.value)
    if not a.LookupAccountNameW(None,'NT SERVICE\\'+name,sid,C.byref(n),domain,C.byref(dn),C.byref(use)):
        raise SafetyError('Gateway service SID lookup failed')
    value, sd, length = W.LPWSTR(), C.c_void_p(), W.DWORD()
    if not a.ConvertSidToStringSidW(sid,C.byref(value)):
        raise SafetyError('Cannot encode service SID')
    try:
        if domain.value.casefold()!='nt service' or not value.value.startswith('S-1-5-80-'):
            raise SafetyError('Gateway service identity is not service-specific')
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:SYG:SYD:(A;;CC;;;'+value.value+')',1,C.byref(sd),C.byref(length)):
            raise SafetyError('Cannot construct service match descriptor')
        return C.string_at(sd,length.value)
    finally:
        if sd:
            k.LocalFree(sd)
        k.LocalFree(value)
