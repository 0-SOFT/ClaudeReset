"""Bind a held process handle to its generation and dedicated service token."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import struct
from .safeio import SafetyError


class SidAttributes(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('attributes', W.DWORD)]


def service_sid(name):
    if name not in ('ClaudeResetBackend', 'ClaudeResetGateway'):
        raise SafetyError('Unknown runtime service identity')
    digest = hashlib.sha1(name.upper().encode('utf-16le')).digest()
    return 'S-1-5-80-' + '-'.join(str(value) for value in struct.unpack('<5I', digest))


class Process:
    def __init__(self, pid, *, image, service):
        self.handle = None
        self.api = C.WinDLL('kernel32', use_last_error=True)
        self.security = C.WinDLL('advapi32', use_last_error=True)
        for name, args, result in [
            ('OpenProcess', [W.DWORD,W.BOOL,W.DWORD], W.HANDLE),
            ('CloseHandle', [W.HANDLE], W.BOOL),
            ('WaitForSingleObject', [W.HANDLE,W.DWORD], W.DWORD),
            ('QueryFullProcessImageNameW', [W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)], W.BOOL),
            ('GetProcessTimes', [W.HANDLE,*([C.POINTER(C.c_uint64)]*4)], W.BOOL),
            ('LocalFree', [C.c_void_p], C.c_void_p),
        ]:
            function = getattr(self.api, name); function.argtypes, function.restype = args, result
        for name, args in [
            ('OpenProcessToken', [W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)]),
            ('GetTokenInformation', [W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]),
            ('ConvertSidToStringSidW', [C.c_void_p,C.POINTER(W.LPWSTR)]),
        ]:
            function = getattr(self.security, name); function.argtypes, function.restype = args, W.BOOL
        self.pid = pid
        try:
            if type(pid) is not int or pid <= 0: raise SafetyError('Invalid service process ID')
            self.handle = self.api.OpenProcess(0x1000 | 0x100000, False, pid)
            if not self.handle: raise SafetyError('Service process handle unavailable')
            path = C.create_unicode_buffer(32768); length = W.DWORD(len(path))
            if (not self.api.QueryFullProcessImageNameW(self.handle, 0, path, C.byref(length))
                    or path.value.casefold() != str(image).casefold()):
                raise SafetyError('Service process image differs')
            times = [C.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(C.byref(value) for value in times)):
                raise SafetyError('Service process generation unavailable')
            self.start_utc_ticks = times[0].value + 504911232000000000
            self.require_token(service)
            if not self.running(): raise SafetyError('Service process has exited')
        except BaseException:
            self.close(); raise

    def sid_text(self, pointer):
        value = W.LPWSTR()
        if not self.security.ConvertSidToStringSidW(pointer, C.byref(value)):
            raise SafetyError('Invalid service token SID')
        try: return value.value
        finally: self.api.LocalFree(value)

    def require_token(self, service):
        token = W.HANDLE()
        if not self.security.OpenProcessToken(self.handle, 8, C.byref(token)):
            raise SafetyError('Service token unavailable')
        try:
            def info(kind):
                needed = W.DWORD()
                self.security.GetTokenInformation(token, kind, None, 0, C.byref(needed))
                if not 8 <= needed.value <= 65536: raise SafetyError('Invalid service token information size')
                buffer = C.create_string_buffer(needed.value)
                if not self.security.GetTokenInformation(token, kind, buffer, len(buffer), C.byref(needed)):
                    raise SafetyError('Cannot inspect service token')
                return buffer
            user = info(1)
            if self.sid_text(SidAttributes.from_buffer(user).sid) != 'S-1-5-18':
                raise SafetyError('Backend requires the LocalSystem service token')
            groups = info(2); count = W.DWORD.from_buffer(groups).value
            offset = C.alignment(SidAttributes)
            if offset + count*C.sizeof(SidAttributes) > len(groups):
                raise SafetyError('Invalid service token groups')
            expected = service_sid(service)
            for index in range(count):
                group = SidAttributes.from_buffer(groups, offset + index*C.sizeof(SidAttributes))
                if group.attributes & 4 and not group.attributes & 16 and self.sid_text(group.sid) == expected:
                    return
            raise SafetyError('Dedicated enabled service SID is absent')
        finally: self.api.CloseHandle(token)

    def running(self):
        if not self.handle: return False
        result = self.api.WaitForSingleObject(self.handle, 0)
        if result not in (0, 258): raise SafetyError('Service process state unavailable')
        return result == 258

    def close(self):
        if self.handle: self.api.CloseHandle(self.handle); self.handle = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
