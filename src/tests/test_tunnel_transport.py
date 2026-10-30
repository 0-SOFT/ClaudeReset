import base64
import socket
import threading

import pytest
from loopback_only import loopback_only

from claude_reset.network import tunnel_transport as transport
from claude_reset.network.connections import read_exact
from claude_reset.safeio import SafetyError


class Backend:
    def __init__(self, scheme, *, refuse=False):
        self.scheme, self.refuse = scheme, refuse
        self.names, self.payload = [], []
        self.headers = []
        self.error = None
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(); self.listener.settimeout(2)
        self.url = f'{scheme}://127.0.0.1:{self.listener.getsockname()[1]}'
        self.thread = threading.Thread(target=self.run, daemon=True); self.thread.start()

    def run(self):
        try:
            with self.listener.accept()[0] as stream:
                stream.settimeout(2)
                if self.scheme == 'http':
                    request = bytearray()
                    while not request.endswith(b'\r\n\r\n'):
                        data = stream.recv(1)
                        if not data:return
                        request.extend(data)
                    self.names.append(bytes(request).split(b' ')[1])
                    self.headers.append(bytes(request))
                    stream.sendall(b'HTTP/1.1 '+(b'403 Denied' if self.refuse else b'200 OK')+b'\r\n\r\n')
                else:
                    greeting = stream.recv(3)
                    if not greeting:return
                    assert greeting == b'\x05\x01\x00'
                    stream.sendall(b'\x05\x00')
                    prefix = read_exact(stream, 5)
                    assert prefix[:4] == b'\x05\x01\x00\x03'
                    self.names.append(read_exact(stream, prefix[4]))
                    assert read_exact(stream, 2) == b'\x01\xbb'
                    stream.sendall(b'\x05'+(b'\x05' if self.refuse else b'\x00')+b'\x00\x01\x7f\0\0\1\0\0')
                if self.refuse:return
                while data := stream.recv(100):
                    self.payload.append(data);stream.sendall(data)
        except (OSError, AssertionError) as exc:
            self.error = exc
        finally:self.listener.close()

    def close(self):
        self.listener.close();self.thread.join(3)


@pytest.mark.parametrize('scheme', ['http', 'socks5'])
def test_selected_backend_receives_remote_name_and_only_then_client_payload(scheme, monkeypatch):
    backend = Backend(scheme)
    real_getaddrinfo = socket.getaddrinfo
    def local_only(host, *a, **kw):
        assert host == '127.0.0.1', 'Destination hostname must never enter Windows DNS'
        return real_getaddrinfo(host, *a, **kw)
    monkeypatch.setattr(socket, 'getaddrinfo', local_only)
    checked = []
    relay = transport.ConnectRelay(backend.url, lambda s: checked.append(True) or True, port=0)
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1', relay.port), timeout=2) as client:
            client.sendall(b'CONNECT service.invalid:443 HTTP/1.1\r\nHost: service.invalid:443\r\n\r\n')
            response = bytearray()
            while not response.endswith(b'\r\n\r\n'):response.extend(client.recv(1))
            assert response.startswith(b'HTTP/1.1 200')
            client.sendall(b'FIXTURE');assert read_exact(client, 7) == b'FIXTURE'
            relay.close()
            try:assert client.recv(1) == b''
            except OSError:pass
        assert checked == [True]
        assert backend.names == ([b'service.invalid:443'] if scheme == 'http' else [b'service.invalid'])
        assert backend.payload == [b'FIXTURE']
    finally:relay.close();backend.close()
    assert backend.error is None


@pytest.mark.parametrize('scheme', ['http', 'socks5'])
def test_unverified_peer_gets_neither_destination_nor_payload(scheme):
    backend = Backend(scheme)
    try:
        with pytest.raises(SafetyError):transport.open_stream(backend.url, 'service.invalid', 443, lambda s: False)
    finally:backend.close()
    assert backend.names == [] and backend.payload == []


@pytest.mark.parametrize('scheme', ['http', 'socks5'])
def test_backend_failure_has_no_direct_retry(scheme, monkeypatch):
    backend = Backend(scheme, refuse=True)
    original = socket.create_connection
    attempts = []
    def track(address, *a, **kw):attempts.append(address);return original(address, *a, **kw)
    monkeypatch.setattr(socket, 'create_connection', track)
    try:
        with pytest.raises(SafetyError):transport.open_stream(backend.url, 'service.invalid', 443, lambda s: True)
    finally:backend.close()
    assert attempts == [('127.0.0.1', int(backend.url.rsplit(':', 1)[1]))]
    assert backend.payload == []


@pytest.mark.parametrize('authority', ['a.invalid:0', 'a.invalid:65536', 'a.invalid:443\r\nInjected:x',
                                      'user@a.invalid:443', 'a.invalid/path:443', 'a..invalid:443',
                                      '-bad.invalid:443', '[::1%2]:443', '::1:443'])
def test_ambiguous_or_injected_destinations_rejected(authority):
    with pytest.raises((SafetyError, ValueError)):transport.destination(authority)


def test_remote_backend_is_not_silently_contacted():
    with pytest.raises(SafetyError):transport.ConnectRelay('http://192.0.2.1:8080', lambda s: True, port=0)


def test_ipv6_authority_is_normalized_without_resolution():
    assert transport.destination('[2001:db8::1]:443') == ('2001:db8::1', 443)


@pytest.mark.parametrize('auth', [None, ('fixture-user', 'fixture-password')])
@pytest.mark.parametrize('refuse', [False, True])
def test_remote_http_connect_and_basic_login(auth, refuse, monkeypatch):
    backend = Backend('http', refuse=refuse)
    original = socket.create_connection
    attempts, verified = [], []
    def fake_remote(address, *args, **kwargs):
        attempts.append(address)
        return original(('127.0.0.1', int(backend.url.rsplit(':', 1)[1])), *args, **kwargs)
    monkeypatch.setattr(socket, 'create_connection', fake_remote)
    def verify(stream):
        verified.append(True)
        assert backend.headers == []
        return True
    try:
        if refuse:
            with pytest.raises(SafetyError) as error:
                transport.open_stream('http://8.8.8.8:8080', 'service.invalid', 443,
                                      verify, remote=True, auth=auth)
            assert str(error.value) == 'HTTP backend refused CONNECT'
            for secret in ('fixture-user', 'fixture-password', '8.8.8.8'):
                assert secret not in str(error.value)
        else:
            with transport.open_stream('http://8.8.8.8:8080', 'service.invalid', 443,
                                       verify, remote=True, auth=auth) as stream:
                stream.sendall(b'FIXTURE')
                assert read_exact(stream, 7) == b'FIXTURE'
        assert attempts == [('8.8.8.8', 8080)]
        assert verified == [True]
        assert backend.names == [b'service.invalid:443']
        expected = b'' if auth is None else (
            b'Proxy-Authorization: Basic ' + base64.b64encode(b'fixture-user:fixture-password') + b'\r\n')
        assert backend.headers == [b'CONNECT service.invalid:443 HTTP/1.1\r\n'
                                   b'Host: service.invalid:443\r\n' + expected + b'\r\n']
    finally:
        backend.close()
    assert backend.error is None


@pytest.mark.parametrize('auth', [('bad:user', 'secret'), ('user', 'secret\r\nInjected:yes'),
                                 ('user', ''), ('user', 'x' * 256), 'user:secret'])
def test_http_credentials_rejected_before_connection(auth, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Invalid credentials must not open a connection')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    with pytest.raises(SafetyError, match='^Invalid HTTP proxy credentials$'):
        transport.open_stream('http://8.8.8.8:8080', 'service.invalid', 443,
                              lambda stream: True, remote=True, auth=auth)


def test_http_credentials_are_not_sent_to_unverified_peer():
    backend = Backend('http')
    try:
        with pytest.raises(SafetyError, match='owner is not verified'):
            transport.open_stream(backend.url, 'service.invalid', 443,
                                  lambda stream: False, auth=('fixture-user', 'fixture-password'))
    finally:
        backend.close()
    assert backend.headers == []
