"""Reachability probe for the selected encrypted exit, run before any block.

The result carries no address: public reports must not repeat the peer. A
timeout is only evidence while no peer-scoped filter exists, so callers run this
before enabling restrictions and treat any non-reachable status as "do not
block", never as permission to continue through another path.
"""
import ipaddress
import socket
import time

from ..errors import SafetyError
from ..model.status import Measurement

__all__ = ['probe', 'public_address']


def public_address(value, *, ipv4=False):
    try:
        address = ipaddress.ip_address(value) if isinstance(value, str) else None
        if (address is None or not address.is_global or str(address) != value
                or '%' in value or (ipv4 and address.version != 4)):
            raise ValueError()
    except ValueError:
        raise SafetyError('A canonical public IP address is required') from None
    return value


def probe(address, port, timeout=5.0, connector=socket.create_connection):
    public_address(address)
    if type(port) is not int or not 0 < port < 65536:
        raise SafetyError('Invalid exit port')
    if not 0 < timeout <= 30:
        raise SafetyError('Invalid probe timeout')
    started = time.monotonic()
    try:
        connector((address, port), timeout=timeout).close()
        status, reason = Measurement.REACHABLE, None
    except socket.timeout:
        status, reason = Measurement.UNREACHABLE, 'timeout'
    except ConnectionRefusedError:
        status, reason = Measurement.UNREACHABLE, 'refused'
    except OSError:
        status, reason = Measurement.UNREACHABLE, 'network-error'
    return {'status': status, 'reason': reason, 'elapsed': round(time.monotonic() - started, 2)}

