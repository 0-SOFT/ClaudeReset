import json
import socket
import threading
import types

import pytest
from loopback_only import loopback_only

from claude_reset.network import remote_backend as rb
from claude_reset.network import tunnel_transport as transport
from claude_reset.network.connections import read_exact
from claude_reset.safeio import SafetyError

HOST = '93.184.216.34'          # a literal public address; never contacted by these tests
USER, PASSWORD = 'user-x', 'pa55word'


def profile(**changes):
    value = {'schema': 1, 'adapter': rb.ADAPTER, 'host': HOST, 'port': 33540, 'username': USER, 'password': PASSWORD}
    value.update(changes)
    return value


class FakeSocks:
    """SOCKS5 server on loopback with optional RFC 1929 login; records what it was asked for."""
    def __init__(self, *, user=USER, password=PASSWORD, offer_auth=True, connect_reply=0, drop_connect=False):
        self.user, self.password, self.offer_auth = user, password, offer_auth
        self.connect_reply, self.drop_connect = connect_reply, drop_connect
        self.requests, self.logins, self.error = [], [], None
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        try:
            with self.listener.accept()[0] as s:
                s.settimeout(3)
                assert read_exact(s, 1) == b'\x05'
                methods = read_exact(s, read_exact(s, 1)[0])
                if self.offer_auth and b'\x02' in methods:
                    s.sendall(b'\x05\x02')
                    assert read_exact(s, 1) == b'\x01'
                    user = read_exact(s, read_exact(s, 1)[0]).decode()
                    password = read_exact(s, read_exact(s, 1)[0]).decode()
                    self.logins.append((user, password))
                    ok = (user, password) == (self.user, self.password)
                    s.sendall(b'\x01' + (b'\x00' if ok else b'\x01'))
                    if not ok:
                        return
                elif b'\x00' in methods:
                    s.sendall(b'\x05\x00')
                else:
                    s.sendall(b'\x05\xff')
                    return
                head = read_exact(s, 4)
                assert head[:3] == b'\x05\x01\x00' and head[3] == 3
                name = read_exact(s, read_exact(s, 1)[0]).decode()
                read_exact(s, 2)
                self.requests.append(name)
                if self.drop_connect:
                    return
                s.sendall(bytes([5, self.connect_reply]) + b'\x00\x01\x7f\x00\x00\x01\x00\x00')
                if self.connect_reply:
                    return
                while data := s.recv(100):
                    s.sendall(data)
        except (OSError, AssertionError) as exc:
            self.error = exc


def loopback_open(socks, **kwargs):
    """The remote flag is for public peers; the wire code is identical, so tests drive it over loopback."""
    return transport.open_stream(f'socks5://127.0.0.1:{socks.port}', 'claude.ai', 443, lambda s: True, **kwargs)


# ------------------------------------------------------------------ profile
def test_a_valid_profile_is_accepted_and_describes_the_peer_without_secrets():
    assert rb.validate(profile())['host'] == HOST
    assert rb.proxy_url(profile()) == f'socks5://{HOST}:33540' and rb.auth_of(profile()) == (USER, PASSWORD)
    assert rb.auth_of(profile(username='', password='')) is None


@pytest.mark.parametrize('changes', [
    {'host': 'proxy.example.org'}, {'host': '10.0.0.5'}, {'host': '::1'}, {'port': 0}, {'port': 70000}, {'port': '33540'},
    {'username': 'a b'}, {'password': 'x' * 300}, {'username': '', 'password': 'secret'}, {'username': 'u', 'password': ''},
    {'adapter': 'other'}, {'schema': 2}, {'extra': 1},
])
def test_unsafe_or_unsupported_profiles_are_refused(changes):
    with pytest.raises(SafetyError):
        rb.validate(profile(**changes))


def test_decode_rejects_duplicates_garbage_and_oversize():
    for data in (b'not json', b'[]', b'{"schema":1,"schema":1}', b'x' * 5000):
        with pytest.raises(SafetyError):
            rb.decode(data)


def test_profile_is_sealed_at_rest_and_removable(tmp_path):
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    assert rb.load(paths) is None
    rb.save(paths, profile())
    raw = (paths.state / rb.FILE).read_bytes()
    assert PASSWORD.encode() not in raw and USER.encode() not in raw and HOST.encode() not in raw
    assert rb.load(paths) == profile()
    assert rb.remove(paths) is True and rb.load(paths) is None and rb.remove(paths) is True


# ------------------------------------------------------------------ transport
def test_login_is_sent_and_the_destination_name_goes_to_the_proxy_not_to_dns(monkeypatch):
    socks = FakeSocks()
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, 'getaddrinfo', lambda host, *a, **k: (_ for _ in ()).throw(AssertionError('DNS')) if host == 'claude.ai' else real(host, *a, **k))
    stream = loopback_open(socks, auth=(USER, PASSWORD))
    stream.close()
    assert socks.logins == [(USER, PASSWORD)] and socks.requests == ['claude.ai']


def test_wrong_password_is_refused_and_no_destination_is_sent():
    socks = FakeSocks()
    with pytest.raises(SafetyError, match='authentication failed'):
        loopback_open(socks, auth=(USER, 'wrong'))
    assert socks.requests == []


def test_a_proxy_that_demands_a_login_when_none_is_configured_is_refused():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(3)

    def serve():
        try:
            with listener.accept()[0] as s:
                s.settimeout(3)
                s.recv(16)
                s.sendall(bytes([5, 2]))                      # "I want username/password"
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    with pytest.raises(SafetyError, match='unsupported authentication'):
        transport.open_stream(f'socks5://127.0.0.1:{listener.getsockname()[1]}', 'claude.ai', 443, lambda s: True)
    listener.close()


def test_remote_mode_accepts_only_a_literal_public_peer(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Rejected endpoints must not open a connection')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    with pytest.raises(SafetyError):
        transport.open_stream('socks5://10.1.2.3:1080', 'claude.ai', 443, lambda s: True, remote=True)
    with pytest.raises(SafetyError):
        transport.open_stream('http://10.1.2.3:8080', 'claude.ai', 443, lambda s: True, remote=True)
    with pytest.raises(SafetyError):
        transport.open_stream('socks5://93.184.216.34:1080', 'claude.ai', 443, lambda s: True)   # loopback rule still applies by default
    with pytest.raises(SafetyError):
        transport.ConnectRelay('socks5://10.1.2.3:1080', lambda s: True, port=0, remote=True)
    with pytest.raises(SafetyError):
        transport.ConnectRelay('socks5://93.184.216.34:1080', lambda s: True, port=0)


def test_the_relay_carries_a_client_connect_through_an_authenticated_proxy():
    socks = FakeSocks()
    relay = transport.ConnectRelay(f'socks5://127.0.0.1:{socks.port}', lambda s: True, port=0, auth=(USER, PASSWORD))
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1', relay.port), timeout=3) as client:
            client.sendall(b'CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n')
            head = b''
            while not head.endswith(b'\r\n\r\n'):
                head += client.recv(1)
            assert head.startswith(b'HTTP/1.1 200')
            client.sendall(b'ping')
            assert read_exact(client, 4) == b'ping'
    finally:
        relay.close()
    assert socks.logins == [(USER, PASSWORD)] and socks.requests == ['claude.ai']


def test_the_relay_still_refuses_telemetry_names_before_the_proxy_sees_them():
    socks = FakeSocks()
    relay = transport.ConnectRelay(f'socks5://127.0.0.1:{socks.port}', lambda s: True, port=0, auth=(USER, PASSWORD))
    relay.deny = transport.TELEMETRY_SUFFIXES
    threading.Thread(target=relay.serve, daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1', relay.port), timeout=3) as client:
            client.sendall(b'CONNECT o1.ingest.sentry.io:443 HTTP/1.1\r\nHost: x:443\r\n\r\n')
            assert client.recv(64).startswith(b'HTTP/1.1 403')
    finally:
        relay.close()
    assert socks.requests == [] and socks.logins == []


# ------------------------------------------------------------------ install
def write(tmp_path, value):
    path = tmp_path / 'p.json'
    path.write_text(json.dumps(value))
    return path


def test_install_proves_peer_and_login_then_seals_and_never_returns_the_address_or_password(tmp_path):
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    result = rb.install(paths, write(tmp_path, profile()), probe=lambda h, p: {'status': 'reachable'},
                        test=lambda p: {'ok': True}, measure=lambda p: {'status': 'measured', 'exit_ip': '203.0.113.7', 'address_family': 4})
    assert result['status'] == 'installed' and result['socks5_login_and_connect'] and result['exit_measured']
    text = json.dumps(result)
    assert PASSWORD not in text and HOST not in text and '203.0.113.7' not in text and USER not in text
    assert result['elevation_used'] is False and result['firewall_changed'] is False
    assert rb.load(paths) == profile()


def test_install_stops_before_saving_when_the_peer_or_the_login_fails(tmp_path):
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    down = rb.install(paths, write(tmp_path, profile()), probe=lambda h, p: {'status': 'unreachable', 'reason': 'timeout'})
    assert down['status'] == 'not_installed' and down['reason'] == 'peer_unreachable' and rb.load(paths) is None
    bad = rb.install(paths, write(tmp_path, profile()), probe=lambda h, p: {'status': 'reachable'},
                     test=lambda p: {'ok': False, 'reason': 'SOCKS5 authentication failed'})
    assert bad['status'] == 'not_installed' and 'authentication' in bad['reason'] and rb.load(paths) is None


def test_install_never_overwrites_an_existing_profile(tmp_path):
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    rb.save(paths, profile())
    result = rb.install(paths, write(tmp_path, profile(port=1)), probe=lambda h, p: pytest.fail('must not probe'))
    assert result['status'] == 'not_started' and rb.load(paths)['port'] == 33540


def test_backend_install_routes_a_socks5_profile_to_the_remote_installer(tmp_path):
    from claude_reset.backend import install as backend_install
    called = {}
    remote = lambda paths, file: called.setdefault('file', file) and {'status': 'installed'}
    result = backend_install.install(types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local'),
                                     write(tmp_path, profile()), install_remote=remote)
    assert result == {'status': 'installed'} and called['file']


def test_readiness_treats_a_remote_profile_as_the_backend():
    from claude_reset.network import l1_check
    base = {'os_build': 26200, 'cpu_architecture': 9, 'bfe': 'Running', 'free_gb': 50, 'allow_unsigned': True, 'extensions': ['2.1.311'],
            'desktop': None, 'tasks': {}, 'listeners': {}, 'cli': {'present': False}, 'program_files': [], 'consent': False}
    plain = l1_check.evaluate(dict(base, remote_backend=False))
    remote = l1_check.evaluate(dict(base, remote_backend=True))
    ids = lambda report: {c['id']: c['status'] for c in report['checks']}
    assert ids(plain)['backend_task'] == 'missing' and ids(remote)['backend_task'] == 'ok' and ids(remote)['backend_listening'] == 'ok'


def test_connection_check_with_a_remote_backend_measures_through_the_proxy_not_the_missing_loopback_port(tmp_path):
    """Regression (second PC): --connection-check measured 127.0.0.1:25080, where nothing listens with a remote backend."""
    from claude_reset.network import connections
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    paths.state.mkdir()
    rb.save(paths, profile())
    connections.save(paths, {'schema': 1, 'local_proxy': 'http://127.0.0.1:25080', 'router_proxy': None,
                             'expected_exit_ips': ['93.184.216.35']})
    seen = []
    remote = lambda prof: seen.append(prof['host']) or {'status': 'measured', 'exit_ip': '93.184.216.35', 'address_family': 4}
    result = rb.check_saved(paths, measure_remote=remote, measure_local=lambda proxy: pytest.fail('loopback measured'))
    assert result['passed'] is True and seen == [HOST]
    moved = lambda prof: {'status': 'measured', 'exit_ip': '8.8.4.4', 'address_family': 4}
    assert rb.check_saved(paths, measure_remote=moved)['passed'] is False


def test_connection_check_without_a_remote_backend_is_unchanged(tmp_path):
    from claude_reset.network import connections
    paths = types.SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    paths.state.mkdir()
    connections.save(paths, {'schema': 1, 'local_proxy': 'http://127.0.0.1:25080', 'router_proxy': None,
                             'expected_exit_ips': ['93.184.216.35']})
    asked = []
    local = lambda proxy: asked.append(proxy) or {'status': 'measured', 'exit_ip': '93.184.216.35', 'address_family': 4}
    result = rb.check_saved(paths, measure_remote=lambda prof: pytest.fail('no remote proxy is saved'), measure_local=local)
    assert result['passed'] is True and asked == ['http://127.0.0.1:25080']


@pytest.mark.parametrize('adapter', [rb.ADAPTER, rb.HTTP_ADAPTER])
def test_backend_import_dispatches_both_remote_types(tmp_path, adapter):
    from claude_reset.backend import install as backend_install
    calls = []
    remote = lambda paths, file: calls.append(file) or {'status': 'installed'}
    paths = types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local')
    source = write(tmp_path, profile(adapter=adapter))
    assert backend_install.install(paths, source, install_remote=remote) == {'status': 'installed'}
    assert calls == [source]


def test_http_measure_uses_existing_relay(monkeypatch):
    from test_tunnel_transport import Backend
    server = Backend('http')
    original = socket.create_connection
    attempts = []
    def route(address, *args, **kwargs):
        if address == (HOST, 33540):
            attempts.append(address)
            address = ('127.0.0.1', int(server.url.rsplit(':', 1)[1]))
        return original(address, *args, **kwargs)
    monkeypatch.setattr(socket, 'create_connection', route)
    def measure(url):
        with transport.open_stream(url, 'fixture.invalid', 443, lambda _: True) as stream:
            stream.sendall(b'fixture')
            assert read_exact(stream, 7) == b'fixture'
        return {'status': 'measured', 'exit_ip': HOST}
    try:
        assert rb.measure_exit(profile(adapter=rb.HTTP_ADAPTER), measure=measure)['status'] == 'measured'
        assert attempts == [(HOST, 33540)]
        assert server.names == [b'fixture.invalid:443']
    finally:
        server.close()
