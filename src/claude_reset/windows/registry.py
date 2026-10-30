"""The current user's registry keys (HKCU): read the values of one key, remove it."""
from __future__ import annotations

__all__ = ['UserKey']


class UserKey:
    """One key under HKEY_CURRENT_USER, such as the uninstall entry of a per-user program."""

    def __init__(self, path: str) -> None:
        self.path = path

    def values(self) -> dict:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.path) as key:
                result, index = {}, 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        return result
                    result[name], index = value, index + 1
        except FileNotFoundError:
            return {}

    def delete(self) -> None:
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.path)
        except FileNotFoundError:
            pass
