import socket

import pytest

from claude_reset.model.status import Measurement
from claude_reset.network import exit_reachability as reach
from claude_reset.safeio import SafetyError

PEER = '93.184.216.34'


class Closed:
    def close(self): pass


def raising(exc):
    def connector(*args, **kwargs): raise exc
    return connector


def test_reachable_allows_blocking():
    result = reach.probe(PEER, 9444, connector=lambda *a, **k: Closed())
    assert result['status'] == 'reachable' and result['reason'] is None
    assert result['status'] == Measurement.REACHABLE


@pytest.mark.parametrize('exc,reason', [
    (socket.timeout(), 'timeout'), (ConnectionRefusedError(), 'refused'), (OSError(), 'network-error')])
def test_failures_never_allow_blocking(exc, reason):
    result = reach.probe(PEER, 9444, connector=raising(exc))
    assert result['status'] == 'unreachable' and result['reason'] == reason
    assert result['status'] != Measurement.REACHABLE


def test_result_does_not_repeat_the_peer():
    result = reach.probe(PEER, 9444, connector=raising(socket.timeout()))
    assert PEER not in repr(result)


@pytest.mark.parametrize('address,port,timeout', [
    ('127.0.0.1', 9444, 5), ('10.0.0.1', 9444, 5), (PEER, 0, 5), (PEER, 70000, 5),
    (PEER, True, 5), (PEER, 9444, 0), (PEER, 9444, 600)])
def test_invalid_inputs_are_rejected(address, port, timeout):
    with pytest.raises(SafetyError):
        reach.probe(address, port, timeout, connector=lambda *a, **k: Closed())


