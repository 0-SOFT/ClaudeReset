"""Exclusive Windows journal I/O; production storage must already be protected."""
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import uuid
from .backend_spec import document
from .install_transaction import validate
from .safeio import SafetyError, guarded, local_volume
from .gateway_profile import local_path


class _LocalFile:
    """Native I/O primitive only. Does not establish administrator ownership."""
    def __init__(self, directory):
        self.directory = Path(local_path(str(directory)))
        guarded(local_volume(self.directory), self.directory, allow_root=True)
        self.path = self.directory / 'install-journal.json'
        self.lock = None
        self.api = C.WinDLL('kernel32', use_last_error=True)
        self.api.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE]
        self.api.CreateFileW.restype = W.HANDLE
        self.api.CloseHandle.argtypes = [W.HANDLE]; self.api.CloseHandle.restype = W.BOOL
        self.api.MoveFileExW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
        self.api.MoveFileExW.restype = W.BOOL
        lock_path = self.directory / 'install.lock'
        guarded(local_volume(lock_path), self.directory)
        # No sharing; creation does not truncate existing lock contents.
        self.lock = self.api.CreateFileW(str(lock_path), 0xC0000000, 0, None, 4, 0x00200000, None)
        if self.lock in (None, C.c_void_p(-1).value):
            self.lock = None
            raise SafetyError('Another installer owns the journal lock, or the lock is inaccessible')

    def load(self):
        if not self.lock: raise SafetyError('Installation journal is closed')
        from .windows_pin import PinnedFile
        try:
            self.path.lstat()
        except FileNotFoundError:
            return None
        with PinnedFile(self.path, limit=65536) as pinned:
            return validate(document(pinned.data))

    def save(self, value):
        if not self.lock: raise SafetyError('Installation journal is closed')
        value = validate(value)
        previous = self.load()
        if previous is not None and any(previous[k] != value[k] for k in ('generation', 'package_sha256')):
            raise SafetyError('A journal from another installation cannot be overwritten')
        data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
        temporary = self.directory / ('journal-' + uuid.uuid4().hex + '.tmp')
        # The protected directory supplies the inherited ACL. No arbitrary
        # destination is accepted from the journal. Keep failed temp evidence.
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # REPLACE_EXISTING | WRITE_THROUGH. Not a power-loss acceptance claim.
        from .install_metadata_commit import replace_metadata
        replace_metadata(self,temporary,self.path,data)
        if self.load() != value:
            raise SafetyError('Installation journal readback differs')

    def close(self):
        if self.lock:
            self.api.CloseHandle(self.lock); self.lock = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class ProtectedJournal(_LocalFile):
    """Fixed location, elevated caller, administrator-owned storage; no creation.

    An installer must create and protect the directory in its bootstrap step.
    This class never repairs ACLs or adopts a user-controlled installation.
    """
    def __init__(self):
        from .service_store import program_files, verify_paths
        shell = C.WinDLL('shell32')
        shell.IsUserAnAdmin.argtypes = []; shell.IsUserAnAdmin.restype = W.BOOL
        if not shell.IsUserAnAdmin():
            raise SafetyError('Protected journal requires the already elevated installer')
        parent = program_files() / 'ClaudeReset'
        root = parent / 'Installer'
        verify_paths([parent, root], [parent, root])
        for name in ('install.lock', 'install-journal.json'):
            path = root / name
            try: path.lstat()
            except FileNotFoundError: continue
            verify_paths([path], [])
        super().__init__(root)
