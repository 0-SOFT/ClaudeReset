"""Windows PowerShell: the one interpreter path, the one way to start it and to quote a value, two ways to run a script."""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import subprocess

from ..errors import SafetyError
from collections.abc import Callable
from typing import Any

__all__ = ['NO_WINDOW', 'executable', 'ps_json', 'quote', 'run', 'start']

NO_WINDOW = 0x08000000   # CREATE_NO_WINDOW
STOP_ON_ERROR = '$ErrorActionPreference="Stop"; '


def executable() -> Path:
    return Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


def quote(value: object) -> str:
    """A PowerShell single-quoted string literal holding value exactly."""
    return "'" + str(value).replace("'", "''") + "'"


def start(arguments: list[str], *, text: bool, timeout: float,
          runner: Callable[..., subprocess.CompletedProcess] | None = None) -> subprocess.CompletedProcess:
    """Run PowerShell without a profile, a prompt or a window and wait for it; its output is captured."""
    return (runner or subprocess.run)([str(executable()), '-NoProfile', '-NonInteractive', *arguments],
                                      capture_output=True, text=text, timeout=timeout, creationflags=NO_WINDOW)


def run(script: str, runner: Callable[..., subprocess.CompletedProcess] | None=None, timeout: float=60) -> tuple[int, str, str]:
    """Run a script; returns (exit code, stdout, stderr trimmed to 300 characters on one line).

    The error text is kept because a failed registration must be explainable; callers decide what to show."""
    result = start(['-Command', STOP_ON_ERROR + script], text=True, timeout=timeout, runner=runner)
    return result.returncode, (result.stdout or '').strip(), ' '.join((result.stderr or '').split())[:300]


def ps_json(script: str) -> Any:
    """Run a script that prints JSON and return the parsed value (None for no output).

    Any failure raises one fixed message: stderr can contain user paths or secrets and is never passed on."""
    if os.name != 'nt':
        raise SafetyError('This operation requires Windows')
    encoded = base64.b64encode((STOP_ON_ERROR + script).encode('utf-16-le')).decode()
    try:
        result = start(['-EncodedCommand', encoded], text=False, timeout=55)
    except (subprocess.TimeoutExpired, OSError):
        raise SafetyError('Windows inspection timed out or could not start', code='windows_inspection_failed') from None
    if result.returncode:
        raise SafetyError('Windows inspection failed')
    text = result.stdout.decode('utf-8-sig', errors='replace').strip()
    return json.loads(text) if text else None
