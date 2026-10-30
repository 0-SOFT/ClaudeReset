"""Launch the bundled worker with verified MSIX identity, without launching Claude."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import time
from .native_worker import FAMILY
from ..errors import SafetyError
from ..safeio import guarded, atomic_bytes, remove_owned
from ..windows import process
from ..windows.system import DPAPI, ps_json
from .. import config
from .. import layout
from ..model.ids import new_id


def call_native(paths, operation, **arguments):
    from ..layout import Paths
    if paths.state != Paths.current().state:
        raise SafetyError('Native worker requires the current user application state directory')
    nonce = new_id()
    # LocalAppData is virtualized by MSIX. IPC must use a non-virtualized user
    # directory so both identities see the same encrypted request/response.
    root = guarded(layout.ipc_home(paths.home), paths.home)
    directory = guarded(root / nonce, root)
    directory.mkdir(parents=True)
    crypto = DPAPI()
    request = {'schema': 1, 'family': FAMILY, 'nonce': nonce, 'operation': operation,
               'expires': time.time() + 45, **arguments}
    path = directory / 'request.dpapi'
    atomic_bytes(path, crypto.encrypt(json.dumps(request).encode()), root)
    if getattr(sys, 'frozen', False):
        executable, args = sys.executable, ['--native-worker', str(path)]
    else:
        executable = str(Path(sys.executable).with_name(config.PYTHONW))
        args = [str(layout.SOURCE_DIR / 'launcher.py'), '--native-worker', str(path)]
    quote = lambda text: "'" + text.replace("'", "''") + "'"
    command = ('Invoke-CommandInDesktopPackage -PackageFamilyName ' + quote(FAMILY) +
               ' -AppId Claude -Command ' + quote(executable) +
               ' -Args ' + quote(process.command_line(args)) + ' -PreventBreakaway')
    try:
        ps_json(command)
        deadline = time.monotonic() + 55
        response = directory / 'response.dpapi'
        while time.monotonic() < deadline:
            if guarded(response, root).exists():
                if response.stat().st_size > 4_000_000:
                    raise SafetyError('Native response too large')
                result = json.loads(crypto.decrypt(response.read_bytes()))
                if result.get('nonce') != nonce or not result.get('ok'):
                    raise SafetyError('Native package operation failed; inspect its checkpoint before retrying')
                return result['payload']
            time.sleep(0.1)
        raise SafetyError('Native operation timed out; its outcome must be verified before retrying')
    finally:
        # Requests are never reused. A late worker cannot execute an expired request.
        remove_owned(directory, root)
