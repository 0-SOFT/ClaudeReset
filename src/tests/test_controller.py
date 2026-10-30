import ctypes
import functools
import json
import socket
import threading
from unittest.mock import MagicMock

import pytest
from scripted import Strict
from test_reset import paths

from claude_reset import config, layout
from claude_reset.network import connections, controller_status, gate_rules
from claude_reset.network import controller as guard
from claude_reset.network import strict_wfp as w
from claude_reset.network.relay import Relay
from claude_reset.safeio import SafetyError


def identity():
    return w.Identity('package', config.OWNED_PACKAGE[0])


@pytest.mark.parametrize('dns_passed', [True, False])
def test_dns_result_alone_cannot_authorize_all_delegated_traffic(dns_passed):
    from claude_reset.network import brokered_dns
    result = brokered_dns.coverage_gate(measure=lambda: {'passed': dns_passed})
    assert result['passed'] is False and result['delegated_ipc_verified'] is False
    assert not result['helper_process_thread_boundary_verified']
    assert not result['helper_bootstrap_before_execution_verified']
    assert not result['helper_token_integrity_verified']


@pytest.mark.parametrize('backend_fails', [False, True])
@pytest.mark.parametrize('request_id', [None, 'a' * 32])
def test_controller_installs_denies_before_checks_and_never_opens_with_incomplete_coverage(paths, monkeypatch, backend_fails, request_id):
    calls = []
    class FakeEngine:
        def __init__(self, *, dynamic=False):
            assert not dynamic, 'A live permission must never be created before complete coverage'
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def ensure_sublayer(self): pass
        def install(self, rules): calls.append(('install', rules))
    kernel = MagicMock()
    kernel.CreateMutexW.return_value = 1
    kernel.WaitForSingleObject.return_value = 0
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **kw: kernel)
    def backend(p):
        assert len(calls) == 1 and all(r.action == w.BLOCK for r in calls[0][1])
        if backend_fails:
            raise SafetyError('fixture backend refused')
        return None, {'engine_path': str(paths.home / 'fixture-engine.exe')}, {'outbounds': [{'server': '1.1.1.1', 'server_port': 443}]}, {}
    monkeypatch.setattr(gate_rules, 'backend', backend)
    # DPAPI goes through the patched kernel above, so the saved profile is read from a stand-in.
    monkeypatch.setattr(connections, 'load', lambda p: {'local_proxy': config.BACKEND_URL, 'router_proxy': None})
    probe = Strict(check={'passed': True}, coverage={'passed': False})
    monkeypatch.setattr(guard, 'create_transport', lambda *a, **kw: pytest.fail('Relay opened before coverage'))
    monkeypatch.setattr(guard, 'configure_future_clients', lambda p: pytest.fail('Client settings changed before coverage'))
    report = paths.home / 'fixture-controller.json'
    from claude_reset.elevation.request import prepare
    request = prepare(paths, 'start', scheduler=request_id is None)
    if request_id is not None:
        request_id = request.request_id
    result = guard.serve(paths, report, request_id=request_id, engine=FakeEngine, probe=probe)
    assert result['finished'] is True
    if request_id:
        assert result['request_id'] == request_id and result['operation'] == 'start'
        assert result['state_root'] == str(paths.state)
        assert json.loads(report.read_text('utf-8')) == result
    expected = 'blocked_error' if backend_fails else 'direct_sockets_blocked_coverage_incomplete'
    assert result['state'] == expected
    assert result['persistent_boundary'] and not result['live_permit_session']
    assert result['passed'] is False and result['full_tunnel_verified'] is False


def test_boundary_denies_both_directions_and_ip_families_without_loopback_exception():
    rules = w.deny_rules([identity()])
    assert {r.layer for r in rules} == {'connect_v4', 'connect_v6', 'recv_v4', 'recv_v6'}
    for rule in rules:
        rule.validate()
        assert rule.action == w.BLOCK and rule.persistent
        assert rule.address is None and rule.port is None


def test_permit_only_targets_exact_tcp_relay_and_is_not_persistent():
    rules = w.relay_permits([identity()], config.RELAY_PORT)
    assert len(rules) == 1
    rule = rules[0]; rule.validate()
    assert rule.layer == 'connect_v4' and rule.address == '127.0.0.1' and rule.port == config.RELAY_PORT
    assert not rule.persistent


@pytest.mark.parametrize('name', ['chrome.exe', 'Code.exe', 'python.exe', 'pythonw.exe', 'powershell.exe', 'cmd.exe',
                                'pwsh.exe', 'Discord.exe', 'svchost.exe', 'codex.exe', 'codex-windows-sandbox-service.exe'])
def test_shared_application_cannot_receive_a_strict_identity_filter(tmp_path, name):
    p = tmp_path / name; p.write_bytes(b'fixture')
    with pytest.raises(SafetyError):
        w.Identity('app', str(p)).validate()


def test_unknown_package_and_missing_identity_rejected():
    for kind, value in [('package', 'Other_App'), ('all', ''), ('app', '*')]:
        with pytest.raises(SafetyError):
            w.Identity(kind, value).validate()


@pytest.mark.parametrize('layer,address,port', [('recv_v4', '127.0.0.1', 1000), ('connect_v6', '::1', 1000),
                                            ('connect_v4', '127.0.0.1', 0), ('connect_v4', '127.0.0.1', None)])
def test_broad_or_incoming_permit_is_rejected(layer, address, port):
    with pytest.raises(SafetyError):
        w.Rule(identity(), layer, w.PERMIT, address, port, False).validate()


def test_changed_persistent_endpoint_cannot_create_an_additional_slot(tmp_path):
    p = tmp_path / 'sing-box.exe'; p.write_bytes(b'fixture')
    engine = w.Identity('app', str(p))
    a = w.Rule(engine, 'connect_v4', w.PERMIT, '1.1.1.1', 443, True)
    b = w.Rule(engine, 'connect_v4', w.PERMIT, '8.8.8.8', 8443, True)
    assert a.key.value() == b.key.value()
    assert a != b  # Native readback validates the actual endpoint separately.


def test_status_file_is_never_a_live_permission(paths):
    folder = layout.controller(paths); folder.mkdir(parents=True)
    (folder/'status.json').write_text(json.dumps({'state': 'relay_open', 'passed': True, 'pid': 1}))
    result = controller_status.status(paths)
    assert not result['passed'] and result['requires_live_verification']


def test_close_request_is_tied_to_a_specific_controller_instance(paths, monkeypatch):
    from test_close_ownership import FixtureProcess

    from claude_reset.network import controller_process
    monkeypatch.setattr(controller_process, 'close_and_wait',
                        functools.partial(controller_process.close_and_wait, process_factory=FixtureProcess))
    folder = layout.controller(paths); folder.mkdir(parents=True)
    (folder/'status.json').write_text(json.dumps({'schema': 1, 'operation': 'start', 'request_id': 'a' * 32, 'state_root': str(paths.state), 'instance': 'fixture-instance', 'pid': 42, 'process_created': 123}))
    assert guard.request_close(paths)['filters_removed'] is False
    assert json.loads((folder/'close.request').read_text())['instance'] == 'fixture-instance'


def echo_server():
    server = socket.socket(); server.bind(('127.0.0.1',0)); server.listen()
    received=[]
    def run():
        try:
            with server.accept()[0] as client:
                while data:=client.recv(4096):
                    received.append(data); client.sendall(data)
        except OSError: pass
    threading.Thread(target=run,daemon=True).start()
    return server, received


def test_relay_forwards_only_after_backend_identity_verification_and_closes_active_stream():
    server, received = echo_server()
    checked = []
    relay = Relay(server.getsockname(), lambda s: checked.append(s.getpeername()) or True, port=0)
    threading.Thread(target=relay.serve,daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1',relay.port),timeout=2) as client:
            client.sendall(b'CLAUDE-FIXTURE'); assert client.recv(32)==b'CLAUDE-FIXTURE'
            assert checked and received==[b'CLAUDE-FIXTURE']
            relay.close()
            try: assert client.recv(1)==b''
            except OSError: pass
    finally:
        relay.close(); server.close()


def test_relay_sends_no_client_bytes_to_an_unattributed_backend():
    server, received = echo_server()
    relay = Relay(server.getsockname(), lambda s: False, port=0)
    threading.Thread(target=relay.serve,daemon=True).start()
    try:
        with socket.create_connection(('127.0.0.1',relay.port),timeout=2) as client:
            client.sendall(b'MUST-NOT-FORWARD')
            try: assert client.recv(1)==b''
            except OSError: pass
        assert received==[]
    finally:
        relay.close(); server.close()
