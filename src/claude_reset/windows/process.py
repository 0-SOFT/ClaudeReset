"""Windows processes: starting programs, a retained handle, the identity facts of a token, the compute systems.

Modules above the platform start programs only through these functions. SubprocessError is re-exported so that
they can catch a failed or timed-out tool.
"""
from __future__ import annotations
from collections.abc import Callable
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
from subprocess import SubprocessError

from ..errors import SafetyError
from .api import Library
from .powershell import NO_WINDOW

__all__ = ['RetainedProcess', 'SubprocessError', 'command_line', 'compute_systems', 'kill_tree', 'remove_folder_later',
           'run_attached', 'run_quietly', 'start_console', 'start_piped', 'start_quietly', 'token_facts']

NEW_CONSOLE, DETACHED = 0x00000010, 0x00000008   # CREATE_NEW_CONSOLE, DETACHED_PROCESS


class RetainedProcess:
    """Read-only process witness: retain the same Windows handle through shutdown."""

    def __init__(self, pid: int) -> None:
        self.handle = None
        if type(pid) is not int or not 0 < pid <= 0xffffffff:
            raise SafetyError('Invalid controller PID')
        self.api = Library('kernel32')
        try:
            self.handle = self.api.OpenProcess(0x1000 | 0x100000, False, pid)
            if not self.handle:
                raise SafetyError('Controller process unavailable')
            times = [C.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(C.byref(t) for t in times)):
                raise SafetyError('Controller generation unavailable')
            self.created = times[0].value
        except BaseException:
            self.close()
            raise

    def wait(self, milliseconds: int) -> bool:
        result = self.api.WaitForSingleObject(self.handle, milliseconds)
        if result not in (0, 258):
            raise SafetyError('Controller wait failed')
        return result == 0

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self) -> RetainedProcess:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def token_facts(pid: int) -> dict:
    """The package family and AppContainer facts of a process token; token_read_failed when any read fails."""
    k, a = Library('kernel32'), Library('advapi32')
    handle = k.OpenProcess(0x1000, False, pid)
    token = W.HANDLE()
    if not handle:
        return {'token_read_failed': True}
    try:
        n = W.UINT()
        result = {'package': None, 'token_read_failed': True}
        code = k.GetPackageFamilyName(handle, C.byref(n), None)
        if code == 122 and 0 < n.value <= 1024:
            value = C.create_unicode_buffer(n.value)
            if k.GetPackageFamilyName(handle, C.byref(n), value) == 0:
                result['package'] = value.value
        elif code != 15700:
            return result
        if not a.OpenProcessToken(handle, 8, C.byref(token)):
            return result
        needed, flag = W.DWORD(), W.DWORD()
        if not a.GetTokenInformation(token, 29, C.byref(flag), 4, C.byref(needed)):
            return result
        result['appcontainer'] = bool(flag.value)
        a.GetTokenInformation(token, 30, None, 0, C.byref(needed))
        if not 4 <= needed.value <= 65536:
            return result
        buffer = C.create_string_buffer(needed.value)
        if not a.GetTokenInformation(token, 30, buffer, len(buffer), C.byref(needed)):
            return result
        result.update(capability_count=W.DWORD.from_buffer(buffer).value, token_read_failed=False)
        return result
    finally:
        if token:
            k.CloseHandle(token)
        k.CloseHandle(handle)


def compute_systems(timeout: float = 10) -> object | None:
    """The host compute systems as `hcsdiag list -raw` reports them (parsed JSON), or None when it refuses.

    A tool that cannot start or does not finish in time raises OSError (TimeoutError); unreadable output ValueError.
    """
    try:
        process = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/hcsdiag.exe'), 'list', '-raw'],
                                 capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError('hcsdiag did not finish') from exc
    if process.returncode != 0:
        return None
    return json.loads(process.stdout.decode('utf-8-sig'))


# --- starting programs ----------------------------------------------------------------------------

def run_quietly(argv: list[str], *, timeout: float, text: bool = True) -> subprocess.CompletedProcess:
    """Run a program without a window and wait for it; its output is captured (as text unless text=False)."""
    return subprocess.run(argv, capture_output=True, text=text, timeout=timeout, creationflags=NO_WINDOW)


def run_attached(argv: list[str], environment: dict[str, str]) -> int:
    """Run a program on this console with the given environment; its exit code."""
    return subprocess.run(argv, env=environment).returncode


def start_quietly(argv: list[str]) -> subprocess.Popen:
    """Start a program without a shell; it runs on by itself and its output is discarded."""
    return subprocess.Popen(argv, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start_console(argv: list[str], *, cwd: str | None, environment: dict[str, str]) -> subprocess.Popen:
    """Start a program in a new console window."""
    return subprocess.Popen(argv, cwd=cwd, env=environment, creationflags=NEW_CONSOLE)


def start_piped(argv: list[str], *, cwd: str | None, environment: dict[str, str]) -> subprocess.Popen:
    """Start a program without a window; its standard input and outputs are pipes to this process."""
    return subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=NO_WINDOW)


def kill_tree(pid: int) -> None:
    """End a process and every process it started."""
    subprocess.run(['taskkill', '/T', '/F', '/PID', str(pid)], capture_output=True, creationflags=NO_WINDOW)


def command_line(args: list[str]) -> str:
    """Arguments joined the way a Windows program splits them again."""
    return subprocess.list2cmdline(args)


def remove_folder_later(folder: Path, *, spawn: Callable[..., object] | None = None) -> None:
    """A detached cmd deletes the folder a few seconds after this process exits (a program cannot delete itself)."""
    (spawn or subprocess.Popen)(['cmd.exe', '/d', '/c', f'ping -n 6 127.0.0.1 >nul & rmdir /s /q "{folder}"'],
                                cwd=os.environ.get('SystemRoot', 'C:\\Windows'), creationflags=DETACHED | NO_WINDOW,
                                close_fds=True)
