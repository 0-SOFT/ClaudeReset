import socket
import threading

import pytest

from claude_reset import tunnel_transport as transport
from claude_reset.connections import read_exact
from test_tunnel_transport import Backend


@pytest.mark.parametrize('host', ['sentry.io', 'o1158394.ingest.us.sentry.io', 'http-intake.logs.us5.datadoghq.com', 'datadoghq.com'])
def test_vendor_names_and_their_subdomains_match(host):
    assert transport.is_denied(host, transport.TELEMETRY_SUFFIXES)


@pytest.mark.parametrize('host', ['notsentry.io', 'sentry.io.example.com', 'claude.ai', 'api.anthropic.com', 'datadoghq.com.evil.test'])
def test_other_names_do_not_match(host):
    assert not transport.is_denied(host, transport.TELEMETRY_SUFFIXES)


def test_nothing_is_denied_by_default():
    assert transport.ConnectRelay.deny == ()
    assert not transport.is_denied('o1158394.ingest.us.sentry.io', transport.ConnectRelay.deny)


def connect(relay, authority):
    with socket.create_connection(('127.0.0.1', relay.port), timeout=2) as client:
        client.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'))
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            data = client.recv(1)
            if not data:
                break
            response.extend(data)
        return bytes(response)


def test_denied_name_never_reaches_backend_and_other_names_pass():
    blocked = Backend('http')
    relay = transport.ConnectRelay(blocked.url, lambda s: True, port=0)
    relay.deny = transport.TELEMETRY_SUFFIXES
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        assert connect(relay, 'o1158394.ingest.us.sentry.io:443').startswith(b'HTTP/1.1 403')
        assert blocked.names == []
    finally:
        relay.close()
        blocked.close()
    allowed = Backend('http')
    relay = transport.ConnectRelay(allowed.url, lambda s: True, port=0)
    relay.deny = transport.TELEMETRY_SUFFIXES
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        assert connect(relay, 'claude.ai:443').startswith(b'HTTP/1.1 200')
        assert allowed.names == [b'claude.ai:443']
    finally:
        relay.close()
        allowed.close()
