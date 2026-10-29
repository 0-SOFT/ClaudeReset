import socket
import threading

import pytest

from claude_reset import l1_mechanism as mech
from claude_reset import strict_guard

CLOSED = {'tcp_v4': '10013', 'tcp_v6': '10013', 'tcp_backend': '10013', 'tcp_controller': '10013', 'tcp_gate': '10013'}
OPEN = dict(CLOSED, tcp_gate='connected', proxy_https='200')
CONTROL = {'loopback_direct': 'connected', 'internet_direct': 'connected'}


def test_expected_behaviour_passes():
    result = mech.verdict(CONTROL, CLOSED, OPEN, CLOSED)
    assert result == {'verdict': 'mechanism_passed', 'failures': [], 'internet_control': 'connected'}


@pytest.mark.parametrize('control, before, opened, after, failure', [
    (CONTROL, dict(CLOSED, tcp_v4='connected'), OPEN, CLOSED, 'package_not_closed_before_permit'),
    (CONTROL, dict(CLOSED, tcp_gate='10061'), OPEN, CLOSED, 'package_not_closed_before_permit'),   # refused != forbidden
    (CONTROL, CLOSED, dict(OPEN, tcp_backend='connected'), CLOSED, 'permit_opened_more_than_the_gate'),
    (CONTROL, CLOSED, dict(OPEN, tcp_v6='connected'), CLOSED, 'permit_opened_more_than_the_gate'),
    (CONTROL, CLOSED, dict(OPEN, tcp_gate='10013'), CLOSED, 'gate_not_reachable_with_permit'),
    (CONTROL, CLOSED, dict(OPEN, proxy_https='Timeout'), CLOSED, 'https_through_relay_failed'),
    (CONTROL, CLOSED, OPEN, dict(CLOSED, tcp_gate='connected'), 'package_not_closed_after_revoke'),
    ({'loopback_direct': 'timeout'}, CLOSED, OPEN, CLOSED, 'control_loopback_not_reachable'),
])
def test_every_deviation_is_named_and_fails(control, before, opened, after, failure):
    result = mech.verdict(control, before, opened, after)
    assert result['verdict'] == 'mechanism_failed' and failure in result['failures']


def test_missing_internet_control_is_reported_not_hidden():
    result = mech.verdict({'loopback_direct': 'connected'}, CLOSED, OPEN, CLOSED)
    assert result['verdict'] == 'mechanism_passed' and result['internet_control'] == 'not_measured'


def test_a_probe_without_any_fields_never_passes():
    assert mech.verdict(CONTROL, {}, {}, {})['verdict'] == 'mechanism_failed'


def test_direct_backend_carries_a_connect_through_the_real_relay():
    sink = socket.socket()
    sink.bind(('127.0.0.1', 0))
    sink.listen(1)
    sink.settimeout(5)

    def answer():
        connection, _ = sink.accept()
        with connection:
            connection.sendall(b'SINK:' + connection.recv(16))
    threading.Thread(target=answer, daemon=True).start()
    backend = mech.DirectBackend(0).start()
    relay = strict_guard.create_transport(f'http://127.0.0.1:{backend.port}', lambda stream: True, port=0)
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1', relay.port), timeout=3) as client:
            authority = f'127.0.0.1:{sink.getsockname()[1]}'
            client.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                header += client.recv(1)
            assert header.startswith(b'HTTP/1.1 200')
            client.sendall(b'ping')
            assert client.recv(16) == b'SINK:ping'
        assert backend.connections == [authority]
    finally:
        relay.close()
        backend.close()
        sink.close()


def test_direct_backend_refuses_anything_but_connect():
    backend = mech.DirectBackend(0).start()
    try:
        with socket.create_connection(('127.0.0.1', backend.port), timeout=3) as client:
            client.sendall(b'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n')
            assert client.recv(64).startswith(b'HTTP/1.1 405')
    finally:
        backend.close()


def test_preconditions_name_the_missing_package_and_busy_ports(monkeypatch):
    from claude_reset import package_isolation
    monkeypatch.setattr(package_isolation, 'installed', lambda *a, **k: None)
    monkeypatch.setattr(mech, 'connect', lambda host, port, timeout=2.0: 'connected' if port == 25082 else 'refused')
    errors = mech.precondition_errors()
    assert any(e.startswith('package_not_registered') for e in errors)
    assert any(e.startswith('port_25082_in_use') for e in errors) and not any('25080' in e for e in errors)


def test_preconditions_are_empty_on_a_ready_pc(monkeypatch):
    from claude_reset import netguard, package_isolation
    monkeypatch.setattr(package_isolation, 'installed',
                        lambda *a, **k: (netguard.OWNED_PACKAGE[0], 'ClaudeReset.NetworkIsolation_1.0.0.0_neutral__79st3xwgefr0c', package_isolation.PUBLISHER))
    monkeypatch.setattr(mech, 'connect', lambda host, port, timeout=2.0: 'ConnectionRefusedError')
    assert mech.precondition_errors() == []
