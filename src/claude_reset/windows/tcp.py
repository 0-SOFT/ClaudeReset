"""Plain TCP reachability of a host and port: is something listening there. No data is sent."""
from __future__ import annotations

import socket

from ..errors import error_kind

__all__ = ['connect', 'listening']


def connect(host: str, port: int, timeout: float = 2.0) -> str:
    """'connected', or the kind of error the connection attempt raised."""
    try:
        socket.create_connection((host, port), timeout).close()
        return 'connected'
    except OSError as exc:
        return error_kind(exc)


def listening(host: str, port: int, timeout: float = .3) -> bool:
    return connect(host, port, timeout) == 'connected'
