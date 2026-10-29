"""SCM access restricted to the dedicated gateway and its held generation."""
import ctypes as C
from ctypes import wintypes as W
import time
from .safeio import SafetyError
from .service_identity import Process


class Status(C.Structure):
    _fields_ = [(name, W.DWORD) for name in ('type','state','controls','win32_exit','service_exit','checkpoint','wait_hint','pid','flags')]


class Config(C.Structure):
    _fields_ = [('type', W.DWORD), ('start', W.DWORD), ('error', W.DWORD),
                ('binary', W.LPWSTR), ('group', W.LPWSTR), ('tag', W.DWORD),
                ('dependencies', W.LPWSTR), ('account', W.LPWSTR), ('display', W.LPWSTR)]


class Gateway:
    def __init__(self, image):
        self.image = image; self.manager = self.service = None; self.process = None
        self.started = False
        self.cleanup_unconfirmed = False
        self.api = C.WinDLL('advapi32', use_last_error=True)
        signatures = {
            'OpenSCManagerW': ([W.LPCWSTR,W.LPCWSTR,W.DWORD], W.HANDLE),
            'OpenServiceW': ([W.HANDLE,W.LPCWSTR,W.DWORD], W.HANDLE),
            'CloseServiceHandle': ([W.HANDLE], W.BOOL),
            'QueryServiceStatusEx': ([W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)], W.BOOL),
            'QueryServiceConfigW': ([W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)], W.BOOL),
            'QueryServiceConfig2W': ([W.HANDLE,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)], W.BOOL),
            'StartServiceW': ([W.HANDLE,W.DWORD,C.c_void_p], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name); function.argtypes, function.restype = args, result
        try:
            self.manager = self.api.OpenSCManagerW(None, None, 1)
            if not self.manager: raise SafetyError('Cannot open the local service manager')
            self.service = self.api.OpenServiceW(self.manager, 'ClaudeResetGateway', 1|4|16)
            if not self.service: raise SafetyError('Dedicated gateway service is not installed')
            self.verify_config()
            if self.status().state != 1: raise SafetyError('Gateway must be stopped before a new generation')
        except BaseException:
            self.close(); raise

    def status(self):
        value = Status(); needed = W.DWORD()
        if not self.api.QueryServiceStatusEx(self.service, 0, C.byref(value), C.sizeof(value), C.byref(needed)):
            raise SafetyError('Gateway service state unavailable')
        return value

    def verify_config(self):
        needed = W.DWORD()
        self.api.QueryServiceConfigW(self.service, None, 0, C.byref(needed))
        if not C.sizeof(Config) <= needed.value <= 65536:
            raise SafetyError('Invalid gateway service configuration size')
        buffer = C.create_string_buffer(needed.value)
        if not self.api.QueryServiceConfigW(self.service, buffer, len(buffer), C.byref(needed)):
            raise SafetyError('Cannot inspect gateway service configuration')
        value = Config.from_buffer(buffer)
        if (value.type != 16 or value.start != 3 or value.account != 'LocalSystem'
                or value.binary != '"' + str(self.image) + '" --service'):
            raise SafetyError('Gateway service launch configuration differs')
        sid_type = W.DWORD()
        if (not self.api.QueryServiceConfig2W(self.service, 5, C.byref(sid_type), 4, C.byref(needed))
                or sid_type.value != 1):
            raise SafetyError('Gateway requires its unrestricted dedicated service SID')

    def start(self, timeout=15):
        if self.started or self.process or self.cleanup_unconfirmed or not self.service or not self.manager:
            raise SafetyError('Gateway instance cannot be reused')
        self.verify_config()
        if self.status().state != 1: raise SafetyError('Gateway state changed before start')
        try:
            if not self.api.StartServiceW(self.service, 0, None): raise SafetyError('Gateway service start failed')
            self.started = True
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                value = self.status()
                if value.state == 4:
                    self.process = Process(int(value.pid), image=self.image, service='ClaudeResetGateway')
                    self.verify(); return self
                if value.state != 2: raise SafetyError('Gateway failed to enter running state')
                time.sleep(.05)
            raise SafetyError('Gateway start timed out')
        except BaseException:
            if not self.started:
                # A failed start request can still have created a service process.
                # Release our handles without stopping an unbound generation.
                try:
                    self.close()
                finally:
                    self.cleanup_unconfirmed = True
            else:
                self.close()
            raise

    def verify(self):
        self.verify_config()
        value = self.status()
        if (not self.process or not self.process.running() or value.state != 4
                or value.pid != self.process.pid):
            raise SafetyError('Gateway process generation changed or exited')

    def close(self, timeout=15):
        if self.cleanup_unconfirmed:
            raise SafetyError('Gateway cleanup remains unconfirmed; separate recovery is required')
        error = None
        try:
            if self.started:
                self.verify_config()
                deadline = time.monotonic() + timeout
                while True:
                    value = self.status()
                    alive = self.process is not None and self.process.running()
                    if value.state == 1 and not alive:
                        break
                    # The owner closes its engine first. The gateway's held-engine
                    # health check then stops itself. SCM STOP cannot be bound to
                    # a process generation, even after a matching status snapshot.
                    if (not self.process or value.state not in (1,3,4)
                            or value.state != 1 and value.pid not in (0,self.process.pid)):
                        raise SafetyError('Gateway cleanup observes an unverified or replacement generation')
                    if time.monotonic() >= deadline:
                        raise SafetyError('Gateway cooperative exit was not confirmed')
                    time.sleep(.05)
        except BaseException as exc: error = exc
        finally:
            if self.process: self.process.close(); self.process = None
            for name in ('service','manager'):
                handle = getattr(self, name)
                if handle: self.api.CloseServiceHandle(handle); setattr(self, name, None)
            self.started = False
        if error:
            self.cleanup_unconfirmed = True
            raise error
