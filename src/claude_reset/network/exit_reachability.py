"""Reachability probe for the selected encrypted exit, run before any block.

The result carries no address: public reports must not repeat the peer. A
timeout is only evidence while no peer-scoped filter exists, so callers run this
before enabling restrictions and treat any non-reachable status as "do not
block", never as permission to continue through another path.
"""
import socket
import time

from ..backend.spec import public_address
from ..errors import SafetyError
from ..model.status import Measurement


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


def probe_spec(spec, timeout=5.0, connector=socket.create_connection):
    return probe(spec['peer_address'], spec['peer_port'], timeout, connector)


def may_block(result):
    return result.get('status') == Measurement.REACHABLE
