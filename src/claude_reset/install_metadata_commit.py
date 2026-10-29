"""Bounded retry of an unchanged protected metadata rename only.

No retry of uncertain mutation outcomes: both file identities and hashes must
still match the pre-attempt snapshot. No ACL/attribute changes or UI prompts.
"""
import ctypes as C
import hashlib
import re
import time
from .windows_pin import PinnedFile
from .safeio import SafetyError

PREFIXES={'install-journal.json':'journal-', 'stage-receipts.json':'receipt-',
          'configuration-receipts.json':'receipt-', 'runtime-signature-receipts.json':'receipt-'}
DELAYS=(0.02,0.05,0.10)


def _snapshot(path,optional=False):
    from .install_receipts import identity
    try:path.lstat()
    except FileNotFoundError:
        if optional:return None
        raise SafetyError('Metadata rename source disappeared; outcome requires recovery')
    with PinnedFile(path,limit=65536) as pin:
        return identity(pin.api,pin.handle),pin.sha256


def replace_metadata(journal,temporary,destination,expected_bytes):
    prefix=PREFIXES.get(destination.name)
    if (not journal.lock or temporary.parent!=journal.directory or destination.parent!=journal.directory
            or prefix is None or not re.fullmatch(re.escape(prefix)+'[a-f0-9]{32}\\.tmp',temporary.name)
            or not isinstance(expected_bytes,bytes) or len(expected_bytes)>65536):
        raise SafetyError('Fixed protected metadata rename and exclusive lock required')
    source=_snapshot(temporary);prior=_snapshot(destination,True)
    if source[1]!=hashlib.sha256(expected_bytes).hexdigest():
        raise SafetyError('Metadata temporary bytes changed before commit')
    for attempt in range(len(DELAYS)+1):
        if not journal.lock:raise SafetyError('Metadata commit lock was released')
        if journal.api.MoveFileExW(str(temporary),str(destination),1|8):return
        error=C.get_last_error()
        if error not in (5,32) or attempt==len(DELAYS):
            raise SafetyError(f'Cannot commit protected metadata (Win32 error {error})')
        time.sleep(DELAYS[attempt])
        if (not journal.lock or _snapshot(temporary)!=source or _snapshot(destination,True)!=prior):
            raise SafetyError('Metadata rename outcome or ownership changed; no retry')
