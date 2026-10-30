"""Own one suspended child in a kill-on-close Windows job before executing it.

Only handles returned by this object's CreateProcess call are stopped. No PID
enumeration, external process termination, shell or inherited handles are used.
"""
from __future__ import annotations

import ctypes as C
import os
import subprocess
from ctypes import wintypes as W
from pathlib import Path

from ..safeio import guarded, local_volume
from .api import Library

__all__ = ['KillOnClose', 'environment']


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
