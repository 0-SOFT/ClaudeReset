"""Recorded admitted process witnesses; never a complete process inventory."""
from dataclasses import asdict
import json
import os
from pathlib import Path

from . import controller_process
from .safeio import guarded, SafetyError


def _path(request):
    root = Path(request.state_root)
    return guarded(root / 'strict-guard' / ('process-' + request.request_id + '.json'), root)


def record(request):
    """Called under admission.lock after consumption, before any child effect.

    A failed write leaves consumption intact and prevents the handler starting.
    Includes start before status publication. Refused launches and descendants
    are not covered by this witness; it does not prove inventory completeness.
    """
    from .uac_request import _save_exclusive
    pid = os.getpid()
    created = controller_process.generation(pid)
    _save_exclusive(_path(request), {'schema': 1, 'request': asdict(request),
                                   'pid': pid, 'process_created': created})


def observe(request, *, process_factory=None):
    """Observe the exact admitted process, independently of finish or status."""
    process_factory = process_factory or controller_process.Process
    try:
        def read():
            with _path(request).open('rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise SafetyError('Process record unavailable')
            row = json.loads(raw)
            if (not isinstance(row, dict) or type(row.get('schema')) is not int
                    or row['schema'] != 1 or row.get('request') != asdict(request)
                    or type(row.get('pid')) is not int or not 0 < row['pid'] <= 0xffffffff
                    or type(row.get('process_created')) is not int or row['process_created'] <= 0):
                raise SafetyError('Process identity unavailable')
            return row
        expected = read()
        with process_factory(expected['pid']) as process:
            if process.created != expected['process_created'] or read() != expected:
                return 'unknown'
            exited = process.wait(0)
            if read() != expected:
                return 'unknown'
            return 'exited' if exited else 'running'
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SafetyError):
        return 'unknown'
