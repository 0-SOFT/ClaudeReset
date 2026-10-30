"""Functional connection checks use synthetic profiles and loopback servers only."""
import json
import socket
import threading
from contextlib import contextmanager

import pytest

from test_reset import paths, FakeCrypto
from claude_reset.backend import location as backend_location
from claude_reset.network import connections as c, legacy_guard as netguard
from claude_reset.reset import verification
from claude_reset import cli
from claude_reset.safeio import SafetyError
from claude_reset import config
from claude_reset import layout
from cli_env import folders


def profile(**updates):
    return {'schema': 1, 'local_proxy': 'http://127.0.0.1:25080',
            'router_proxy': None, 'expected_exit_ips': ['8.8.8.8'], **updates}


@pytest.mark.parametrize('value', ['http://localhost:8', 'http://user:secret@127.0.0.1:8',
                                 'https://127.0.0.1:8', 'http://127.0.0.1:8/', 'http://127.0.0.1:8?q=secret',
                                 'http://127.0.0.1:8\n', 'http://0.0.0.0:8', 'http://[::]:8',
                                 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'file:///data'])
def test_proxy_endpoint_refuses_ambiguous_or_secret_urls(value):
    with pytest.raises(SafetyError):
        c.endpoint(value)


def test_ipv6_proxy_and_multiple_exit_families():
    p = profile(local_proxy='socks5://[::1]:1080', expected_exit_ips=['8.8.8.8', '2001:4860:4860::8888'])
    assert c.validate(p) == p


@pytest.mark.parametrize('updates', [{'expected_exit_ips': []}, {'expected_exit_ips': ['127.0.0.1']},
                                   {'expected_exit_ips': ['8.8.8.8', '8.8.8.8']}, {'schema': True},
                                   {'local_proxy': 'http://192.168.1.1:8'}, {'secret': 'DO_NOT_STORE'}])
def test_invalid_profile_cannot_be_saved(paths, updates):
    with pytest.raises(SafetyError):
        c.save(paths, profile(**updates), crypto=FakeCrypto())
    assert not (paths.state / layout.CONNECTION_PROFILE).exists()


def test_profile_dpapi_roundtrip_and_redacted_receipt(paths):
    result = c.save(paths, profile())  # Actual Windows DPAPI, temporary directory.
    raw = (paths.state / layout.CONNECTION_PROFILE).read_bytes()
    assert b'8.8.8.8' not in raw and b'127.0.0.1' not in raw
    assert c.load(paths) == profile()
    assert '8.8.8.8' not in json.dumps(result)
    assert result['clients_reconfigured'] is False


def test_unknown_profile_fields_are_not_accepted_on_load(paths):
    c.save(paths, profile(), crypto=FakeCrypto())
    path = paths.state / layout.CONNECTION_PROFILE
    path.write_bytes(FakeCrypto().encrypt(json.dumps(profile(allow_direct=True)).encode()))
    with pytest.raises(SafetyError):
        c.load(paths, crypto=FakeCrypto())


@pytest.mark.parametrize('router,local,selected,calls', [
    ('8.8.8.8', '1.1.1.1', 'router', 1),
    ('1.1.1.1', '8.8.8.8', 'local', 2),
    (None, '8.8.8.8', 'local', 2),
    ('1.1.1.1', '1.1.1.1', None, 2),
    (None, None, None, 2),
])
def test_router_candidate_local_fallback_and_refusal(router, local, selected, calls):
    p = profile(router_proxy='http://192.168.1.1:8080')
    seen = []
    def measure(proxy):
        seen.append(proxy)
        ip = router if proxy == p['router_proxy'] else local
        return {'status': 'measured', 'exit_ip': ip} if ip else {'status': 'measurement_failed'}
    result = c.check(p, include_router=True, measure_fn=measure)
    assert result['selected_candidate'] == selected
    assert result['passed'] is bool(selected)
    assert len(seen) == calls
    assert result['full_tunnel_verified'] is False and result['clients_reconfigured'] is False
    assert all(ip not in json.dumps(result) for ip in ('8.8.8.8', '1.1.1.1', '192.168.1.1'))


def test_router_is_never_contacted_without_explicit_request():
    seen = []
    result = c.check(profile(router_proxy='http://192.168.1.1:8080'),
                     measure_fn=lambda proxy: seen.append(proxy) or {'status': 'measured', 'exit_ip': '8.8.8.8'})
    assert seen == ['http://127.0.0.1:25080']
    assert result['measurements']['router']['status'] == 'not_requested'


@contextmanager
def proxy_server(handler):
    errors = []
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(3)
        port = server.getsockname()[1]
        def run():
            try:
                with server.accept()[0] as client:
                    client.settimeout(3)
                    handler(client)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            yield port
        finally:
            thread.join(4)
            assert not thread.is_alive()
            if errors:
                raise errors[0]


def read_header(client):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        data.extend(c.read_exact(client, 1))
    return bytes(data)


def test_real_http_connect_ignores_environment_and_keeps_destination_remote(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('NO_PROXY', '*')
    def handler(client):
        assert read_header(client) == b'CONNECT claude.ai:443 HTTP/1.1\r\nHost: claude.ai:443\r\n\r\n'
        client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\nOK')
    with proxy_server(handler) as port:
        with c.connect(f'http://127.0.0.1:{port}', config.CLAUDE_HOST) as stream:
            assert c.read_exact(stream, 2) == b'OK'


def test_real_socks5_sends_domain_without_local_target_dns():
    def handler(client):
        assert c.read_exact(client, 3) == b'\x05\x01\x00'
        client.sendall(b'\x05\x00')
        assert c.read_exact(client, 5) == b'\x05\x01\x00\x03\x09'
        assert c.read_exact(client, 11) == b'claude.ai\x01\xbb'
        client.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbbOK')
    with proxy_server(handler) as port:
        with c.connect(f'socks5://127.0.0.1:{port}', config.CLAUDE_HOST) as stream:
            assert c.read_exact(stream, 2) == b'OK'


@pytest.mark.parametrize('response', [b'HTTP/1.1 407 Authentication required\r\n\r\n',
                                      b'HTTP/1.1 302 Redirect\r\nLocation: http://secret\r\n\r\n'])
def test_http_proxy_refusal_never_redirects_or_falls_back(response):
    def handler(client):
        read_header(client)
        client.sendall(response)
    with proxy_server(handler) as port:
        result = c.measure(f'http://127.0.0.1:{port}')
    assert result == {'status': 'measurement_failed', 'error_type': 'OSError'}


def test_failed_tls_is_not_accepted_as_exit_measurement():
    def handler(client):
        read_header(client)
        client.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
        client.recv(4096)  # Receive ClientHello, then send invalid TLS.
        client.sendall(b'NOT-TLS\r\n')
    with proxy_server(handler) as port:
        result = c.measure(f'http://127.0.0.1:{port}')
    assert result['status'] == 'measurement_failed'
    assert 'exit_ip' not in result


def test_guard_probe_refuses_changed_backend_before_any_network(monkeypatch):
    monkeypatch.setattr(backend_location, 'locate_guard', lambda: object())
    monkeypatch.setattr(backend_location, 'status', lambda _: {'passed': False})
    monkeypatch.setattr(netguard, 'https_status', lambda *a: pytest.fail('Unsafe network request'))
    assert netguard.probe(None)['network_requests'] == 0


def test_cli_profile_save_check_and_nonzero_exit_on_mismatch(paths, monkeypatch, capsys):
    root = folders(monkeypatch, paths)
    source = paths.local / 'connection.json'
    source.write_text(json.dumps(profile()), encoding='utf-8')
    assert cli.main(['--connection-save', str(source)] + root) == 0
    monkeypatch.setattr(c, 'measure', lambda _: {'status': 'measured', 'exit_ip': '1.1.1.1'})
    assert cli.main(['--connection-check'] + root) == 2
    assert '1.1.1.1' not in capsys.readouterr().out


def test_new_acceptance_excludes_physical_tests_but_reads_old_evidence():
    current = verification.template('a' * 32, ['code'])
    assert current['schema'] == 2
    assert set(current['failure_tests']) == set(verification.FUNCTIONAL_FAILURES)
    assert 'windows_reboot' in verification.summarize(current)['excluded_by_owner']
    old = verification.template('a' * 32, ['code'], schema=1)
    assert verification.summarize(old)['excluded_by_owner'] == []
    current['excluded_by_owner'].append('T-10')
    with pytest.raises(SafetyError):
        verification.summarize(current)
