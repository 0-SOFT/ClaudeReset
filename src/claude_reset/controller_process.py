"""Read-only process witness: retain the same Windows handle through shutdown."""
import ctypes as C
from ctypes import wintypes as W

from .safeio import SafetyError


def _identity(row, state_root):
    """Require the supported start protocol, including its exact state scope."""
    if (not isinstance(row, dict) or type(row.get('schema')) is not int
            or row['schema'] != 1 or row.get('operation') != 'start'
            or row.get('state_root') != str(state_root)
            or not isinstance(row.get('request_id'), str)
            or len(row['request_id']) != 32
            or any(c not in '0123456789abcdef' for c in row['request_id'])
            or not isinstance(row.get('instance'), str) or not row['instance']
            or type(row.get('pid')) is not int or not 0 < row['pid'] <= 0xffffffff
            or type(row.get('process_created')) is not int or row['process_created'] <= 0):
        raise SafetyError('Controller identity unavailable')
    return tuple(row[k] for k in ('instance', 'pid', 'process_created',
                                 'schema', 'operation', 'state_root', 'request_id'))


def observe_request(request, *, process_factory=None):
    """Observe one recorded controller, never infer absence from missing status.

    An exited handle proves only this process exited, not that resources were
    removed or that another (including legacy) controller cannot own them.
    No stop request, wait loop, lock acquisition or network call is performed.
    """
    import json
    from pathlib import Path
    from .safeio import guarded

    process_factory = process_factory or Process
    try:
        root = Path(request.state_root)
        path = guarded(root / 'strict-guard' / 'status.json', root)

        def identity():
            with path.open('rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise SafetyError('Controller status unavailable')
            row = json.loads(raw)
            result = _identity(row, root)
            if any(row.get(key) != getattr(request, key)
                   for key in ('request_id', 'operation', 'state_root')):
                raise SafetyError('Controller identity unavailable')
            return result

        expected = identity()
        with process_factory(expected[1]) as process:
            if process.created != expected[2] or identity() != expected:
                return 'unknown'
            exited = process.wait(0)
            if identity() != expected:
                return 'unknown'
            return 'exited' if exited else 'running'
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SafetyError):
        return 'unknown'


class Process:
    def __init__(self, pid):
        self.handle = None
        if type(pid) is not int or not 0 < pid <= 0xffffffff:
            raise SafetyError('Invalid controller PID')
        self.api = C.WinDLL('kernel32', use_last_error=True)
        for name, args, result in (
            ('OpenProcess', [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
            ('GetProcessTimes', [W.HANDLE, *([C.POINTER(C.c_uint64)] * 4)], W.BOOL),
            ('WaitForSingleObject', [W.HANDLE, W.DWORD], W.DWORD),
            ('CloseHandle', [W.HANDLE], W.BOOL),
        ):
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        try:
            self.handle = self.api.OpenProcess(0x1000 | 0x100000, False, pid)
            if not self.handle:
                raise SafetyError('Controller process unavailable')
            times = [C.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *(C.byref(t) for t in times)):
                raise SafetyError('Controller generation unavailable')
            self.created = times[0].value
        except BaseException:
            self.close()
            raise

    def wait(self, milliseconds):
        result = self.api.WaitForSingleObject(self.handle, milliseconds)
        if result not in (0, 258):
            raise SafetyError('Controller wait failed')
        return result == 0

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def generation(pid):
    with Process(pid) as process:
        return process.created


def close_and_wait(folder, read, write, requested, *, process_factory=None):
    process_factory = process_factory or Process
    state = read(folder / 'status.json', folder)
    identity = _identity(state, folder.parent)
    instance, pid, created = identity[:3]
    with process_factory(pid) as process:
        if process.created != created:
            raise SafetyError('Controller generation changed')
        # Bind the request to the status used to open the retained handle.
        def unchanged():
            fresh = read(folder / 'status.json', folder)
            return _identity(fresh, folder.parent) == identity
        if not unchanged():
            raise SafetyError('Controller identity changed')
        write(folder / 'close.request', {'requested': requested, 'instance': instance}, folder)
        return process.wait(90000) and unchanged()
