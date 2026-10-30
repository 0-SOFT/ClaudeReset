"""Recorded admitted process witnesses; never a complete process inventory."""
from dataclasses import asdict
import os
from pathlib import Path

from ..network import controller_process
from ..safeio import guarded
from .. import layout
from . import claims


def witness_path(request):
    """The file that records the admitted child process of this request."""
    root = Path(request.state_root)
    return guarded(layout.controller_folder(root) / ('process-' + request.request_id + '.json'), root)


def record(request):
    """Called under admission.lock after consumption, before any child effect.

    A failed write leaves consumption intact and prevents the handler starting.
    Includes start before status publication. Refused launches and descendants
    are not covered by this witness; it does not prove inventory completeness.
    """
    pid = os.getpid()
    created = controller_process.generation(pid)
    claims.save_exclusive(witness_path(request), {'schema': 1, 'request': asdict(request),
                                   'pid': pid, 'process_created': created})
