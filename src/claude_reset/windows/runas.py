"""Start a program elevated: Windows shows the UAC prompt and the program runs without a window."""
from __future__ import annotations

from collections.abc import Sequence
import subprocess

from .api import Library

__all__ = ['start_elevated']

SW_HIDE = 0


def start_elevated(executable: str, arguments: Sequence[str]) -> int:
    """ShellExecute 'runas'; the result is greater than 32 when Windows started the program."""
    return Library('shell32').ShellExecuteW(None, 'runas', executable, subprocess.list2cmdline(list(arguments)), None,
                                            SW_HIDE) or 0
