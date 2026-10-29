"""Disposable AppContainer boundary for compatibility/containment verification.

This is NOT the production client launcher. Existing full-trust clients cannot
be converted in place. No credentials, real profiles, capabilities or inherited
handles enter the fixture. Only files inside the freshly created profile run.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import uuid
from .safeio import SafetyError, guarded


class STARTUPINFO(C.Structure):
    _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR), ('title', W.LPWSTR),
                *[(n, W.DWORD) for n in ('x', 'y', 'xs', 'ys', 'xc', 'yc', 'fill', 'flags')],
                ('show', W.WORD), ('cb2', W.WORD), ('reserved2', C.c_void_p),
                ('stdin', W.HANDLE), ('stdout', W.HANDLE), ('stderr', W.HANDLE)]


class STARTUPINFOEX(C.Structure):
    _fields_ = [('si', STARTUPINFO), ('attrs', C.c_void_p)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('process', W.HANDLE), ('thread', W.HANDLE), ('pid', W.DWORD), ('tid', W.DWORD)]


class CAPABILITIES(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('capabilities', C.c_void_p), ('count', W.DWORD), ('reserved', W.DWORD)]


class JOB_BASIC(C.Structure):
    _fields_ = [('process_time', C.c_int64), ('job_time', C.c_int64), ('flags', W.DWORD),
                ('min_working_set', C.c_size_t), ('max_working_set', C.c_size_t), ('active_limit', W.DWORD),
                ('affinity', C.c_size_t), ('priority', W.DWORD), ('scheduling', W.DWORD)]


class JOB_EXTENDED(C.Structure):
    _fields_ = [('basic', JOB_BASIC), ('io', C.c_uint64 * 6),
                *[(n, C.c_size_t) for n in ('process_memory', 'job_memory', 'peak_process', 'peak_job')]]


def environment(folder: Path, system_root: str) -> dict[str, str]:
    """Explicit whitelist: never propagate account tokens, proxy bypass or user PATH."""
    return {'SystemRoot': system_root, 'WINDIR': system_root,
            'SystemDrive': Path(system_root).drive,
            'PATH': str(Path(system_root) / 'System32'),
            'USERPROFILE': str(folder), 'HOME': str(folder),
            'APPDATA': str(folder / 'AppData/Roaming'), 'LOCALAPPDATA': str(folder / 'AppData/Local'),
            'TEMP': str(folder / 'Temp'), 'TMP': str(folder / 'Temp'),
            'CLAUDE_CONFIG_DIR': str(folder / 'ClaudeConfig')}


def fixture_executable(folder: Path, executable: Path) -> Path:
    target = guarded(executable, folder)
    if target.suffix.lower() != '.exe' or not target.is_file():
        raise SafetyError('The sandbox fixture requires a copied executable inside its own profile')
    return target


class Sandbox:
    """Fresh no-capability profile; suspended launch, token verification, owned job."""
    def __init__(self):
        if os.name != 'nt':
            raise SafetyError('AppContainer requires Windows')
        self.name = 'ClaudeReset.Probe.' + uuid.uuid4().hex
        self.sid, self._sid_text, self._path = C.c_void_p(), C.c_void_p(), C.c_void_p()
        self.created = False
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.userenv = C.WinDLL('userenv', use_last_error=True)
        self.advapi = C.WinDLL('advapi32', use_last_error=True)
        self.ole = C.WinDLL('ole32')
        self._bind()

    def _bind(self):
        def bind(dll, name, arguments, result=W.BOOL):
            fn = getattr(dll, name); fn.argtypes, fn.restype = arguments, result
        k, u, a = self.kernel, self.userenv, self.advapi
        bind(u, 'CreateAppContainerProfile', [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_void_p, W.DWORD, C.POINTER(C.c_void_p)], C.c_long)
        bind(u, 'DeleteAppContainerProfile', [W.LPCWSTR], C.c_long)
        bind(u, 'GetAppContainerFolderPath', [W.LPCWSTR, C.POINTER(C.c_void_p)], C.c_long)
        bind(a, 'ConvertSidToStringSidW', [C.c_void_p, C.POINTER(C.c_void_p)])
        bind(a, 'FreeSid', [C.c_void_p], C.c_void_p)
        bind(a, 'EqualSid', [C.c_void_p, C.c_void_p])
        bind(a, 'OpenProcessToken', [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)])
        bind(a, 'GetTokenInformation', [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)])
        bind(k, 'LocalFree', [C.c_void_p], C.c_void_p)
        bind(k, 'InitializeProcThreadAttributeList', [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)])
        bind(k, 'UpdateProcThreadAttribute', [C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p])
        bind(k, 'DeleteProcThreadAttributeList', [C.c_void_p], None)
        bind(k, 'CreateProcessW', [W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD, C.c_void_p, W.LPCWSTR, C.POINTER(STARTUPINFOEX), C.POINTER(PROCESS_INFORMATION)])
        bind(k, 'WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD)
        bind(k, 'ResumeThread', [W.HANDLE], W.DWORD)
        bind(k, 'GetExitCodeProcess', [W.HANDLE, C.POINTER(W.DWORD)])
        bind(k, 'TerminateProcess', [W.HANDLE, W.UINT])
        bind(k, 'CloseHandle', [W.HANDLE])
        bind(k, 'CreateJobObjectW', [C.c_void_p, W.LPCWSTR], W.HANDLE)
        bind(k, 'SetInformationJobObject', [W.HANDLE, C.c_int, C.c_void_p, W.DWORD])
        bind(k, 'AssignProcessToJobObject', [W.HANDLE, W.HANDLE])
        bind(self.ole, 'CoTaskMemFree', [C.c_void_p], None)

    @staticmethod
    def _check(value):
        if not value:
            raise SafetyError(f'Windows sandbox operation failed: {C.get_last_error()}')

    def __enter__(self):
        try:
            code = self.userenv.CreateAppContainerProfile(self.name, self.name, 'ClaudeReset disposable isolation verification', None, 0, C.byref(self.sid))
            if code:
                raise SafetyError(f'Cannot create sandbox profile: 0x{code & 0xffffffff:08x}')
            self.created = True
            self._check(self.advapi.ConvertSidToStringSidW(self.sid, C.byref(self._sid_text)))
            if self.userenv.GetAppContainerFolderPath(C.wstring_at(self._sid_text), C.byref(self._path)):
                raise SafetyError('Cannot resolve sandbox profile folder')
            self.folder = Path(C.wstring_at(self._path))
            if (not self.folder.is_absolute() or self.folder.name.casefold() != 'ac'
                    or self.folder.parent.name.casefold() != self.name.casefold()):
                raise SafetyError('Unexpected sandbox profile location')
            guarded(self.folder, self.folder.parent)
            self.env = environment(self.folder, os.environ['SystemRoot'])
            for key in ('APPDATA', 'LOCALAPPDATA', 'TEMP', 'CLAUDE_CONFIG_DIR'):
                guarded(Path(self.env[key]), self.folder).mkdir(parents=True, exist_ok=True)
            return self
        except BaseException:
            self.close()
            raise

    def token_verified(self, process):
        token = W.HANDLE()
        self._check(self.advapi.OpenProcessToken(process, 8, C.byref(token)))
        try:
            def query(kind):
                needed = W.DWORD()
                self.advapi.GetTokenInformation(token, kind, None, 0, C.byref(needed))
                if not 0 < needed.value <= 65536:
                    raise SafetyError('Invalid sandbox token information length')
                buffer = C.create_string_buffer(needed.value)
                self._check(self.advapi.GetTokenInformation(token, kind, buffer, len(buffer), C.byref(needed)))
                return buffer
            is_container, capabilities, identity = query(29), query(30), query(31)
            actual_sid = C.cast(identity, C.POINTER(C.c_void_p)).contents
            if (W.DWORD.from_buffer(is_container).value != 1 or W.DWORD.from_buffer(capabilities).value != 0
                    or not self.advapi.EqualSid(actual_sid, self.sid)):
                raise SafetyError('Child token is not the expected no-capability AppContainer')
            return True
        finally:
            self.kernel.CloseHandle(token)

    def run(self, executable: Path, arguments: list[str], *, timeout_ms=30000):
        if not self.created or type(timeout_ms) is not int or not 1 <= timeout_ms <= 60000:
            raise SafetyError('Invalid sandbox execution state or bounded timeout')
        executable = fixture_executable(self.folder, executable)
        if any(not isinstance(a, str) or '\0' in a for a in arguments):
            raise SafetyError('Invalid fixture arguments')
        k = self.kernel
        size = C.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        if not 0 < size.value < 65536:
            raise SafetyError('Invalid Windows startup attribute length')
        attrs = C.create_string_buffer(size.value)
        self._check(k.InitializeProcThreadAttributeList(attrs, 1, 0, C.byref(size)))
        process, job = PROCESS_INFORMATION(), None
        try:
            capabilities = CAPABILITIES(self.sid, None, 0, 0)
            self._check(k.UpdateProcThreadAttribute(attrs, 0, 0x20009, C.byref(capabilities), C.sizeof(capabilities), None, None))
            job = k.CreateJobObjectW(None, None)
            self._check(job)
            limits = JOB_EXTENDED(); limits.basic.flags = 0x2000  # Kill on job close; no breakaway flags.
            self._check(k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)))
            startup = STARTUPINFOEX(); startup.si.cb = C.sizeof(startup); startup.attrs = C.cast(attrs, C.c_void_p)
            command = C.create_unicode_buffer(subprocess.list2cmdline([str(executable)] + arguments))
            block = C.create_unicode_buffer('\0'.join(f'{key}={value}' for key, value in sorted(self.env.items(), key=lambda kv: kv[0].upper())) + '\0\0')
            self._check(k.CreateProcessW(str(executable), command, None, None, False,
                                        0x80000 | 0x08000000 | 4 | 0x400, block, str(self.folder), C.byref(startup), C.byref(process)))
            self._check(k.AssignProcessToJobObject(job, process.process))
            self.token_verified(process.process)  # Before executing even one instruction in the child.
            if k.ResumeThread(process.thread) == 0xffffffff:
                raise SafetyError('Cannot resume sandbox fixture')
            wait = k.WaitForSingleObject(process.process, timeout_ms)
            if wait != 0:
                raise SafetyError('Sandbox fixture did not complete within its timeout')
            code = W.DWORD(); self._check(k.GetExitCodeProcess(process.process, C.byref(code)))
            return {'exit_code': code.value, 'appcontainer_verified_before_resume': True,
                    'network_capabilities': 0, 'inherited_handles': False, 'owned_job': True}
        finally:
            # If assignment failed, the still-suspended child must not survive.
            if process.process and k.WaitForSingleObject(process.process, 0) != 0:
                k.TerminateProcess(process.process, 99)
            if job:
                k.CloseHandle(job)
            if process.process:
                k.WaitForSingleObject(process.process, 5000)
            for handle in (process.thread, process.process):
                if handle:
                    k.CloseHandle(handle)
            k.DeleteProcThreadAttributeList(attrs)

    def close(self):
        error = None
        if self.created:
            if self.userenv.DeleteAppContainerProfile(self.name):
                error = SafetyError('Could not remove this disposable sandbox profile')
            else:
                self.created = False
        for value, function in ((self._path, self.ole.CoTaskMemFree), (self._sid_text, self.kernel.LocalFree), (self.sid, self.advapi.FreeSid)):
            if value:
                function(value)
                value.value = None
        if error:
            raise error

    def __exit__(self, *args):
        self.close()
