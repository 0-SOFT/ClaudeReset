"""Own one suspended child in a kill-on-close Windows job before executing it.

Only handles returned by this object's CreateProcess call are stopped. No PID
enumeration, external process termination, shell or inherited handles are used.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
from ..errors import SafetyError
from ..safeio import guarded, local_volume
from .api import Library, ProcessInfo, Startup
from .wfp import Identity
from collections.abc import Sequence

__all__ = ['KillOnClose', 'OwnedJob', 'environment']


class BasicLimits(C.Structure):
    _fields_ = [('process_time', C.c_int64), ('job_time', C.c_int64), ('flags', W.DWORD),
                ('min_working', C.c_size_t), ('max_working', C.c_size_t), ('active', W.DWORD),
                ('affinity', C.c_size_t), ('priority', W.DWORD), ('scheduling', W.DWORD)]


class IoCounters(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]


class ExtendedLimits(C.Structure):
    _fields_ = [('basic', BasicLimits), ('io', IoCounters), ('process_memory', C.c_size_t),
                ('job_memory', C.c_size_t), ('peak_process', C.c_size_t), ('peak_job', C.c_size_t)]


def environment(temp: Path) -> dict[str, str]:
    temp = guarded(local_volume(Path(temp)), Path(temp), allow_root=True)
    system = local_volume(Path(os.environ['SystemRoot']))
    return {'SystemRoot': str(system), 'WINDIR': str(system), 'SystemDrive': system.drive,
            'PATH': str(system / 'System32') + ';' + str(system), 'TEMP': str(temp), 'TMP': str(temp)}


class OwnedJob:
    def __init__(self, executable: Path | str, arguments: Sequence[str], *, temp: Path) -> None:
        executable = Path(executable)
        Identity('app', str(executable)).validate()
        if not isinstance(arguments, (list, tuple)) or any(not isinstance(a, str) or '\0' in a for a in arguments):
            raise SafetyError('Invalid owned-child arguments')
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or C.sizeof(ExtendedLimits) != 144 or C.sizeof(Startup) != 104:
            raise SafetyError('A supported Windows x64 process layout is required')
        self.api = Library('kernel32')
        self.job = None
        self.info = ProcessInfo()
        self.resumed = False
        self.closed = False
        self.exit_confirmed = False
        try:
            self.job = self.api.CreateJobObjectW(None, None)
            if not self.job:
                raise SafetyError('Cannot create owned process job')
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000 | 8
            limits.basic.active = 1
            if not self.api.SetInformationJobObject(self.job, 9, C.byref(limits), C.sizeof(limits)):
                raise SafetyError('Cannot enforce kill-on-close and single-process job limits')
            env = environment(temp)
            block = C.create_unicode_buffer('\0'.join(k+'='+v for k,v in sorted(env.items()))+'\0\0')
            command = C.create_unicode_buffer(subprocess.list2cmdline([str(executable), *arguments]))
            startup = Startup(cb=C.sizeof(Startup))
            # CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW.
            if not self.api.CreateProcessW(str(executable), command, None, None, False, 4|0x400|0x08000000,
                                          block, str(executable.parent), C.byref(startup), C.byref(self.info)):
                raise SafetyError('Cannot create the owned suspended process')
            if not self.api.AssignProcessToJobObject(self.job, self.info.process):
                raise SafetyError('Cannot assign the suspended process to its owner job')
            times = [C.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.info.process, *(C.byref(t) for t in times)):
                raise SafetyError('Cannot bind the process generation')
            self.start_utc_ticks = times[0].value + 504911232000000000
        except BaseException:
            self.close()
            raise

    @property
    def pid(self) -> int:
        return self.info.pid

    def running(self) -> bool:
        if self.closed or not self.info.process:
            return False
        result = self.api.WaitForSingleObject(self.info.process, 0)
        if result not in (0, 258):
            raise SafetyError('Owned process state is unavailable')
        return result == 258

    def resume(self) -> None:
        if self.closed or self.resumed or not self.running():
            raise SafetyError('Owned process cannot be resumed in this state')
        if self.api.ResumeThread(self.info.thread) != 1:
            self.close()
            raise SafetyError('Unexpected owned-thread suspension state')
        self.resumed = True
        self.api.CloseHandle(self.info.thread)
        self.info.thread = None

    def close(self) -> None:
        if self.closed:
            return
        try:
            if self.job:
                self.api.CloseHandle(self.job)
                self.job = None
            if self.info.process:
                # Also handles failure before assignment, when job closure did
                # not cover this still-suspended child. No PID lookup is used.
                if self.api.WaitForSingleObject(self.info.process, 1000) != 0:
                    self.api.TerminateProcess(self.info.process, 1)
                self.exit_confirmed = self.api.WaitForSingleObject(self.info.process, 5000) == 0
                if not self.exit_confirmed:
                    raise SafetyError('Owned child termination could not be confirmed')
        finally:
            for name in ('thread', 'process'):
                handle = getattr(self.info, name)
                if handle:
                    self.api.CloseHandle(handle)
                    setattr(self.info, name, None)
            self.closed = True

    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class KillOnClose:
    """A job object that ends every adopted process when the job's last handle closes (the pump dies or exits)."""
    def __init__(self) -> None:
        self.api = Library('kernel32')
        self.handle = self.api.CreateJobObjectW(None, None)
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000   # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.handle or not self.api.SetInformationJobObject(self.handle, 9, C.byref(limits), C.sizeof(limits)):
            self.handle = None

    def adopt(self, process: subprocess.Popen) -> None:
        if self.handle:
            # Popen keeps its own handle to the child open, so this pid still names that child.
            child = self.api.OpenProcess(0x0101, False, process.pid)   # PROCESS_SET_QUOTA | PROCESS_TERMINATE
            if child:
                try:
                    self.api.AssignProcessToJobObject(self.handle, child)
                finally:
                    self.api.CloseHandle(child)
