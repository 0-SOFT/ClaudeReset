"""Registry policy values: one string value under a key of the current user and of the machine.

Which key and value the program owns is decided above this layer (config)."""
from __future__ import annotations

import winreg
from collections.abc import Collection

__all__ = ['HIVES', 'delete_string', 'holds_string', 'replace_string']

HIVES = (('user', winreg.HKEY_CURRENT_USER), ('machine', winreg.HKEY_LOCAL_MACHINE))


def replace_string(hive: int, key: str, name: str, value: str, allowed: Collection[str]) -> bool:
    """Create the key when needed and set a REG_SZ value. When the value already holds something not in
    `allowed`, or is not a string, nothing is written and the result is False."""
    with winreg.CreateKeyEx(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as handle:
        try:
            current, kind = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            current, kind = None, winreg.REG_SZ
        if current is not None and (current not in allowed or kind != winreg.REG_SZ):
            return False
        winreg.SetValueEx(handle, name, 0, winreg.REG_SZ, value)
    return True


def delete_string(hive: int, key: str, name: str, expected: str) -> bool:
    """Delete a REG_SZ value only when it holds exactly `expected`; True when it was deleted."""
    try:
        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as handle:
            current, kind = winreg.QueryValueEx(handle, name)
            if current == expected and kind == winreg.REG_SZ:
                winreg.DeleteValue(handle, name)
                return True
    except FileNotFoundError:
        pass
    return False


def holds_string(hive: int, key: str, name: str, expected: str) -> bool:
    """True when the value exists and holds exactly `expected` as REG_SZ."""
    try:
        with winreg.OpenKey(hive, key, 0, winreg.KEY_READ) as handle:
            current, kind = winreg.QueryValueEx(handle, name)
            return current == expected and kind == winreg.REG_SZ
    except FileNotFoundError:
        return False
