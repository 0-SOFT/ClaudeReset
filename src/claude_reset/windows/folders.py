"""Windows known folders, read from the shell rather than from environment variables."""
from __future__ import annotations

import ctypes
import os
import uuid
from pathlib import Path

from ..errors import SafetyError
from .api import Library

__all__ = ['drive_type', 'physical_local_appdata', 'program_files']

LOCAL_APPDATA = uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091')   # FOLDERID_LocalAppData
NO_PACKAGE_REDIRECTION = 0x10000                                    # KF_FLAG_NO_PACKAGE_REDIRECTION
CSIDL_PROGRAM_FILES = 0x26


def physical_local_appdata() -> Path:
    """LocalAppData without package redirection: the same folder for packaged and ordinary hosts."""
    if os.name != 'nt':
        raise SafetyError('This build targets Windows')
    folder = (ctypes.c_ubyte * 16).from_buffer_copy(LOCAL_APPDATA.bytes_le)
    shell, ole = Library('shell32'), Library('ole32')
    result = ctypes.c_void_p()
    try:
        if shell.SHGetKnownFolderPath(ctypes.byref(folder), NO_PACKAGE_REDIRECTION, None, ctypes.byref(result)) != 0:
            raise SafetyError('Unredirected LocalAppData is unavailable')
        return Path(ctypes.wstring_at(result))
    finally:
        if result.value:
            ole.CoTaskMemFree(result)


def drive_type(root: str) -> int:
    """GetDriveTypeW of a volume root: 2 removable, 3 fixed, 4 remote, 5 CD-ROM, 6 RAM disk, 0/1 unknown."""
    return Library('kernel32').GetDriveTypeW(root)


def program_files() -> Path:
    shell = Library('shell32')
    value = ctypes.create_unicode_buffer(260)
    if shell.SHGetFolderPathW(None, CSIDL_PROGRAM_FILES, None, 0, value) != 0 or not value.value:
        raise SafetyError('The Windows Program Files location is unavailable')
    return Path(value.value)

