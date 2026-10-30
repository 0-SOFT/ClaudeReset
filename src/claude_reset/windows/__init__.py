"""The Windows platform layer: every call into Windows APIs, PowerShell and Windows services lives here.

The names below keep `from claude_reset.windows import ...` working for code outside this source tree:
the local tunnel worker installed on users' computers imports DPAPI this way. They load on first use, so
importing one platform module does not load the others.
"""

from types import MappingProxyType

__all__ = ['DPAPI', 'inspect_runtime', 'inspect_windows', 'ps_json', 'set_istanbul_same_offset']


# Where each name lives.
HOMES = MappingProxyType({'DPAPI': 'dpapi', 'inspect_runtime': 'inventory', 'inspect_windows': 'inventory',
                         'ps_json': 'powershell', 'set_istanbul_same_offset': 'timezone'})


def __getattr__(name):
    if name in HOMES:
        from importlib import import_module
        return getattr(import_module('.' + HOMES[name], __name__), name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
