from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import ctypes


class SafetyError(RuntimeError):
    pass


def local_volume(path: Path) -> Path:
    """Reject mapped network drives before opening or enumerating a path."""
    path = Path(path)
    if not path.is_absolute() or str(path).startswith(('\\\\', '//')):
        raise SafetyError('An absolute local volume path is required')
    if os.name == 'nt':
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        api.GetDriveTypeW.restype = ctypes.c_uint
        if api.GetDriveTypeW(path.anchor) not in (2, 3, 6):
            raise SafetyError('Remote, missing or unknown volumes are not supported')
    return path


def reparse(path: Path) -> bool:
    try:
        info = path.lstat()
        return path.is_symlink() or bool(getattr(info, 'st_file_attributes', 0) & 0x400)
    except FileNotFoundError:
        return False


def guarded(path: Path, root: Path, *, allow_root: bool = False) -> Path:
    """Reject traversal and *all* ancestor reparse points before resolving."""
    if '..' in Path(path).parts or '..' in Path(root).parts:
        raise SafetyError('Traversal is not allowed')
    # Windows aliases, ADS and device names can escape a textual path boundary.
    if os.name == 'nt':
        reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
        for part in (*Path(path).parts[1:], *Path(root).parts[1:]):
            if ':' in part or part.endswith((' ', '.')) or part.split('.')[0].upper() in reserved:
                raise SafetyError('Unsafe Windows path alias')
        if str(path).startswith(('\\\\?\\', '\\\\.\\')):
            raise SafetyError('Device namespace paths are forbidden')
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    try:
        path.relative_to(root)
    except ValueError:
        raise SafetyError('Target is outside the approved root') from None
    if path == root and not allow_root:
        raise SafetyError('Deleting the approved root itself is forbidden')
    for ancestor in (path, *path.parents, root, *root.parents):
        if reparse(ancestor):
            raise SafetyError('Reparse point or symbolic link in the target path')
    if not path.resolve().is_relative_to(root.resolve()):
        raise SafetyError('Resolved target is outside the approved root')
    return path


def tree_entries(path: Path, root: Path):
    """Read-only scan: validate ancestors per directory, leaves via no-follow stat.

    Mutations still call guarded on each exact target. Directory identity is
    checked after enumeration so a replaced/reparse ancestor invalidates a scan.
    """
    path = guarded(path, root, allow_root=True)
    if not path.exists():
        return
    initial = path.lstat()
    yield path, initial
    if not stat.S_ISDIR(initial.st_mode):
        return
    pending = [path]
    reserved = {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}
    while pending:
        directory = guarded(pending.pop(), root, allow_root=True)
        before = directory.stat()
        with os.scandir(directory) as children:
            for child in children:
                if os.name == 'nt' and (':' in child.name or child.name.endswith((' ','.')) or child.name.split('.')[0].upper() in reserved):
                    raise SafetyError('Unsafe Windows path alias')
                # DirEntry.stat on Windows can return stale directory timestamps
                # and a zero inode from FindFirstFile. Fetch fresh identity.
                info = os.stat(child.path, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & 0x400:
                    raise SafetyError('Reparse point or symbolic link in the target path')
                item = Path(child.path)
                yield item, info
                if stat.S_ISDIR(info.st_mode):
                    pending.append(item)
        after = guarded(directory, root, allow_root=True).stat()
        if (before.st_ino,before.st_mtime_ns) != (after.st_ino,after.st_mtime_ns):
            raise SafetyError('Directory changed during inventory')


def walk_files(path: Path, root: Path):
    for item, info in tree_entries(path, root):
        if stat.S_ISREG(info.st_mode):
            yield item


def fingerprint(path: Path, root: Path) -> str:
    """Plan freshness: paths, sizes, timestamps and file identity, never user content."""
    path = guarded(path, root, allow_root=True)
    digest = hashlib.sha256()
    if not path.exists():
        return 'absent'
    for item, info in sorted(tree_entries(path,root),key=lambda entry:str(entry[0])):
        digest.update(repr((str(item.relative_to(root)), info.st_size, info.st_mtime_ns, info.st_ino)).encode())
    return digest.hexdigest()


def remove_owned(path: Path, root: Path):
    """One-shell-independent deletion, rejects reparse points, never removes root."""
    path = guarded(path, root)
    if not path.exists():
        return
    # Validate the entire subtree before the first mutation.
    list(walk_files(path, root))
    if path.is_file():
        unlink_owned(path, root)
        return
    for directory, dirs, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            unlink_owned(Path(directory) / name, root)
        for name in dirs:
            guarded(Path(directory) / name, root).rmdir()
    guarded(path, root).rmdir()


def unlink_owned(path: Path, root: Path):
    path = guarded(path, root)
    try:
        path.unlink()
    except PermissionError:
        # Windows rejects unlink of read-only files even when deletion is
        # authorized by the ACL. Change only this attribute on this exact
        # already-selected file; never take ownership or widen permissions.
        import stat
        if os.name != 'nt' or not path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY:
            raise
        original_mode = path.stat().st_mode
        guarded(path, root).chmod(original_mode | stat.S_IWRITE)
        try:
            guarded(path, root).unlink()
        except OSError:
            if guarded(path, root).exists():
                path.chmod(original_mode)
            raise


def atomic_bytes(path: Path, content: bytes, root: Path):
    path = guarded(path, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    guarded(path.parent, root, allow_root=True)
    fd, temporary = tempfile.mkstemp(prefix='.write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        guarded(path, root)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path: Path, value, root: Path):
    atomic_bytes(path, json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8'), root)
