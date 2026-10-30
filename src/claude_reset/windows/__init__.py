"""The Windows platform layer: every call into Windows APIs, PowerShell and Windows services lives here.

The names below keep `from claude_reset.windows import ...` working for code outside this source tree:
the local tunnel worker installed on users' computers imports DPAPI this way. They load on first use, so
importing one platform module does not load the others.
"""

__all__ = ['DPAPI', 'inspect_runtime', 'inspect_windows', 'ps_json', 'set_istanbul_same_offset']


def __getattr__(name):
    if name in __all__:
        from . import system
        return getattr(system, name)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
