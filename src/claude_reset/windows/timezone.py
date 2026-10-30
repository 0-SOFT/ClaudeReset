"""The Windows time zone: switch to Istanbul only when that keeps the current UTC offset; the clock never changes."""
from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from ..errors import SafetyError
from .inventory import inspect_windows

__all__ = ['set_istanbul_same_offset']


def set_istanbul_same_offset(*, inspect: Callable[[], dict] = inspect_windows,
                             run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict:
    """Switch to the Istanbul time zone when it keeps the UTC offset; the clock itself is never changed.
    inspect reads the Windows state and run starts tzutil."""
    state = inspect()['timezone']
    if state['offset_minutes'] != state['candidate_offset_minutes']:
        raise SafetyError('Istanbul does not preserve the current UTC offset; no change made', code='istanbul_offset')
    tool = Path(os.environ['SystemRoot']) / 'System32/tzutil.exe'
    result = run([str(tool), '/s', 'Turkey Standard Time'], capture_output=True, timeout=15, creationflags=0x08000000)
    if result.returncode:
        raise SafetyError('Windows refused the time-zone change; clock was not adjusted', code='time_zone_refused')
    after = inspect()['timezone']
    if after['id'] != 'Turkey Standard Time' or after['offset_minutes'] != state['offset_minutes']:
        raise SafetyError('Time-zone verification failed')
    return {'timezone': 'Turkey Standard Time', 'clock_adjusted': False}
