import os
from types import SimpleNamespace
import sys
import pytest
from claude_reset import backend_boundary as boundary, backend_runtime as runtime
from claude_reset.service_identity import Process, service_sid
from claude_reset.safeio import SafetyError


def test_service_sid_matches_windows_sc_showsid():
    assert service_sid('ClaudeResetBackend') == 'S-1-5-80-1273353730-1210726768-4111292639-1389890719-3310960783'
    assert service_sid('ClaudeResetGateway') == 'S-1-5-80-2988034842-2677518123-960294122-3545279043-1251282625'
    with pytest.raises(SafetyError): service_sid('Dnscache')


def test_current_user_cannot_impersonate_backend_service():
    with pytest.raises(SafetyError, match='LocalSystem service token'):
        Process(os.getpid(), image=getattr(sys, '_base_executable', sys.executable), service='ClaudeResetBackend')


def test_source_runtime_cannot_start_or_write_installation(monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError('No platform activity permitted')
    monkeypatch.setattr(runtime, 'Process', forbidden)
    monkeypatch.setattr(runtime, 'atomic_bytes', forbidden)
    monkeypatch.setattr(runtime, 'Engine', forbidden)
    monkeypatch.setattr(sys, 'argv', ['runtime','--service'])
    assert runtime.main() == 1
    monkeypatch.setattr(sys, 'argv', ['runtime','--command','cmd.exe'])
    assert runtime.main() == 2


def test_backend_boundary_contains_no_client_or_shared_process_permits(tmp_path):
    paths = boundary.layout(tmp_path)
    for name in ('engine','gateway','runtime','backend'):
        paths[name].parent.mkdir(parents=True,exist_ok=True); paths[name].write_bytes(b'fixture')
    closed, opened = boundary.rules(tmp_path,peer_address='1.1.1.1',peer_port=443,backend_port=1080,gateway_port=1081)
    assert len(closed) == 16 and all(rule.persistent for rule in closed)
    assert len(opened) == 5 and not any(rule.persistent for rule in opened)
    assert {rule.identity.value for rule in opened} == {str(paths[name]) for name in ('engine','gateway','runtime')}
    assert sum(rule.address != '127.0.0.1' for rule in opened) == 1
    for rule in (*closed,*opened): rule.validate()


def test_probe_uses_http_gateway_even_with_socks_backend(monkeypatch):
    platform = runtime.Platform(); platform.protocol = 'socks5'
    platform.spec = {'gateway_port':1081,'expected_exit_ips':['8.8.8.8']}
    observed = []
    def measurement(proxy):
        observed.append(proxy); return {'status':'measured','exit_ip':'8.8.8.8'}
    monkeypatch.setattr(runtime,'measure',measurement)
    assert platform.probe() is True and observed == ['http://127.0.0.1:1081']
    platform.spec['expected_exit_ips'] = ['9.9.9.9']
    assert platform.probe() is False


@pytest.mark.parametrize('failure',[None,'missing','changed'])
def test_reservation_sublayer_is_checked_before_accepting_matching_filters(monkeypatch,tmp_path,failure):
    events=[]
    keys={f'{service}:{layer}:{allow}' for service in ('ClaudeResetBackend','ClaudeResetGateway') for layer in boundary.RESERVATION_LAYERS for allow in (False,True)}
    class Engine:
        handle=1
        def _call(self,*args):pass
        def own_keys(self):return {'deny'}
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def existing_sublayer(self):return True
        def exists_verified(self,rule):return True
    class Reservation(Engine):
        def __init__(self,path,service,port,**kwargs):self.service=service
        def own_keys(self):return keys
        def native(self,layer,allow):return SimpleNamespace(filterKey=SimpleNamespace(value=lambda:f'{self.service}:{layer}:{allow}')),[]
        def existing_sublayer(self):
            events.append('sublayer')
            if failure=='changed':raise SafetyError('changed reservation security')
            return failure!='missing'
        def verified(self,*args):events.append('filter');return True
    monkeypatch.setattr(boundary,'Engine',Engine)
    monkeypatch.setattr(boundary,'Reservation',Reservation)
    monkeypatch.setattr(boundary,'rules',lambda *a,**kw:([SimpleNamespace(key=SimpleNamespace(value=lambda:'deny'))],['expected']))
    spec=dict(peer_address='1.1.1.1',peer_port=443,backend_port=1080,gateway_port=1081)
    if failure:
        with pytest.raises(SafetyError):boundary.verify_installed(tmp_path,spec)
        assert events==['sublayer']
    else:
        assert boundary.verify_installed(tmp_path,spec)==['expected']
        assert events==(['sublayer']+['filter']*8)*2
