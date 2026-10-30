"""The controller's status file: the controller writes it, everyone else reads it through here."""
from __future__ import annotations

from pathlib import Path

from .. import layout
from ..errors import SafetyError
from ..model.status import Network
from ..safeio import atomic_json, read_json

__all__ = ['current_instance', 'exists', 'read', 'read_or_empty', 'status', 'write']


def exists(folder: Path) -> bool:
    return (folder / layout.CONTROLLER_STATUS).is_file()


def read(folder: Path) -> dict:
    """The last state the controller published; raises when it is missing, too large or not JSON."""
    return read_json(folder / layout.CONTROLLER_STATUS, folder)


def read_or_empty(folder: Path) -> dict:
    """The last state the controller published, or {} when there is none or it cannot be read."""
    try:
        state = read(folder)
    except (OSError, ValueError, SafetyError):
        return {}
    return state if isinstance(state, dict) else {}


def current_instance(folder: Path) -> str | None:
    """Instance id of the controller that last wrote the status file (None when there is none)."""
    instance = read_or_empty(folder).get('instance')
    return instance if isinstance(instance, str) else None


def write(folder: Path, state: dict) -> None:
    atomic_json(folder / layout.CONTROLLER_STATUS, state, folder)


def status(paths) -> dict:
    """The controller's last report, marked as needing a live check: a file is not a WFP attestation."""
    folder = layout.controller(paths)
    if not exists(folder):
        return {'status': Network.STRICT_NOT_INSTALLED, 'passed': False}
    row = read(folder)
    # A status file is not a live WFP attestation. Never authorize from this file.
    return {'status': Network.STRICT_CONTROLLER_LAST_REPORT, 'last_report': row,
            'passed': False, 'requires_live_verification': True}
