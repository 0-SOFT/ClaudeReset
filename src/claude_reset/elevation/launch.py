"""Start the elevated child that carries out one persisted claim: the operation's own mode of this program."""
from __future__ import annotations

import sys
from pathlib import Path
from types import MappingProxyType

from .. import config, layout
from ..errors import SafetyError
from ..windows.runas import start_elevated

__all__ = ['FLAGS', 'dispatch_request']

# The command-line mode that serves each elevated operation.
FLAGS = MappingProxyType({'start': '--strict-guard-serve', 'remove': '--strict-guard-remove-serve',
                          'autostart': '--strict-guard-autostart-serve',
                          'autostart-off': '--strict-guard-autostart-off-serve',
                          'package-register': '--l1-package-register-serve',
                          'package-remove': '--l1-package-remove-serve'})


def dispatch_request(request, *, executable=None, exclude_extension=False):
    """Dispatch a persisted claim, optionally using the newly built frozen program."""
    arguments = [FLAGS[request.operation], '--report', request.receipt,
                 '--state-root', request.state_root, '--uac-request-id', request.request_id]
    if exclude_extension:
        if request.operation != 'remove':
            raise SafetyError('Extension exclusion requires a removal receipt')
        arguments.append('--exclude-vscode-extension')
    frozen_program = executable is not None
    executable = str(executable) if frozen_program else sys.executable
    if not frozen_program and not getattr(sys, 'frozen', False):
        arguments.insert(0, str(layout.SOURCE_DIR / 'launcher.py'))
        windowless = Path(executable).with_name(config.PYTHONW)
        if not windowless.is_file():
            raise SafetyError('Windowless Python is required')
        executable = str(windowless)
    return start_elevated(executable, arguments)
