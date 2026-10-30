"""Gateway start/cleanup on modeled SCM; never opens or controls host services."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from claude_reset.windows import gateway_service as module
from claude_reset.safeio import SafetyError
from claude_reset.backend.lifecycle import Generation
from test_backend_lifecycle import Platform

class Api:
    def __init__(self):self.state=1;self.pid=0;self.stops=[];self.closed=[]
    def StartServiceW(self,*args):self.state=4;self.pid=101;return True
    def ControlService(self,handle,control,ignored):
        self.stops.append((self.pid,control));self.state=1;self.pid=0;return True
    def CloseServiceHandle(self,handle):self.closed.append(handle);return True

class Process:
    pid=101
    def __init__(self):self.alive=True;self.closed=0
    def running(self):return self.alive
    def close(self):self.closed+=1

def gateway():
    g=module.Gateway.__new__(module.Gateway)
    g.image=Path('C:/fixture/ClaudeResetGateway.exe');g.manager=11;g.service=22
    g.process=None;g.started=False;g.cleanup_unconfirmed=False;g.api=Api()
    g.verify_config=lambda:None
    g.status=lambda:SimpleNamespace(state=g.api.state,pid=g.api.pid)
    return g

def reject_identity(g,monkeypatch):
    def reject(*args,**kwargs):
        g.api.pid=202
        raise SafetyError('Fixture process identity rejected')
    monkeypatch.setattr(module,'Process',reject)

def test_start_identity_failure_never_stops_an_unbound_replacement(monkeypatch):
    g=gateway();reject_identity(g,monkeypatch)
    with pytest.raises(SafetyError):g.start()
    assert g.api.stops==[]
    assert g.api.closed==[22,11]
    assert g.cleanup_unconfirmed is True
    with pytest.raises(SafetyError):g.close()
    with pytest.raises(SafetyError):g.start()
    assert g.api.stops==[]

def test_repeated_cleanup_retains_a_known_replacement_failure():
    g=gateway();g.started=True;g.process=Process();held=g.process
    g.api.state=4;g.api.pid=202
    with pytest.raises(SafetyError):g.close()
    with pytest.raises(SafetyError):g.close()
    assert g.api.stops==[] and held.closed==1 and g.api.closed==[22,11]

@pytest.mark.parametrize('state,pid',[(2,0),(4,101),(4,202)])
def test_no_stop_without_a_verified_process_generation(state,pid):
    g=gateway();g.started=True;g.api.state=state;g.api.pid=pid
    with pytest.raises(SafetyError):g.close()
    assert g.api.stops==[] and g.cleanup_unconfirmed is True

def test_owned_generation_exit_is_observed_and_handles_released_once():
    g=gateway();g.started=True;g.process=Process();held=g.process
    g.api.state=4;g.api.pid=101
    def exiting():
        result=SimpleNamespace(state=g.api.state,pid=g.api.pid)
        g.api.state=1;g.api.pid=0;held.alive=False
        return result
    g.status=exiting
    g.close();g.close()
    assert g.api.stops==[] and held.closed==1
    assert g.api.closed==[22,11] and g.cleanup_unconfirmed is False

def test_already_stopped_unknown_process_needs_no_stop():
    g=gateway();g.started=True
    g.close();g.close()
    assert g.api.stops==[] and g.cleanup_unconfirmed is False

def test_backend_revokes_lease_and_reports_unconfirmed_gateway_cleanup(monkeypatch):
    g=gateway();reject_identity(g,monkeypatch)
    class Runtime(Platform):
        def start_gateway(self,child):return g.start()
        def close(self):
            self.step('close_platform');g.close()
    platform=Runtime();generation=Generation(platform)
    with pytest.raises(SafetyError):generation.start()
    assert g.api.stops==[]
    assert generation.state=='BLOCKED_CLEANUP_UNCONFIRMED'
    assert platform.events[-3:]==['close_lease','close_child','close_platform']
    assert generation.status()['client_admission'] is False


def test_start_timeout_does_not_stop_an_unbound_pending_service():
    g=gateway()
    def pending(*args):g.api.state=2;g.api.pid=0;return True
    g.api.StartServiceW=pending
    with pytest.raises(SafetyError):g.start(timeout=0)
    assert not g.api.stops and g.cleanup_unconfirmed is True
    assert g.api.closed==[22,11]


@pytest.mark.parametrize('raises',[False,True])
def test_unknown_start_call_result_remains_unconfirmed(raises):
    g=gateway()
    def uncertain(*args):
        g.api.state=4;g.api.pid=202
        if raises:raise SafetyError('Fixture start result lost')
        return False
    g.api.StartServiceW=uncertain
    class Runtime(Platform):
        def start_gateway(self,child):return g.start()
        def close(self):
            self.step('close_platform');g.close()
    platform=Runtime();generation=Generation(platform)
    with pytest.raises(SafetyError):generation.start()
    assert not g.api.stops and generation.state=='BLOCKED_CLEANUP_UNCONFIRMED'
    assert g.api.closed==[22,11] and g.cleanup_unconfirmed is True
    with pytest.raises(SafetyError):g.start()
    assert platform.events[-3:]==['close_lease','close_child','close_platform']


def test_replacement_after_status_snapshot_never_receives_stop():
    g=gateway();g.started=True;g.process=Process();g.api.state=4;g.api.pid=101
    def snapshot():
        result=SimpleNamespace(state=g.api.state,pid=g.api.pid)
        g.api.pid=202
        return result
    g.status=snapshot
    with pytest.raises(SafetyError):g.close()
    assert g.api.stops==[] and g.cleanup_unconfirmed is True


def test_live_gateway_without_cooperative_exit_is_not_forcibly_stopped():
    g=gateway();g.started=True;g.process=Process();g.api.state=4;g.api.pid=101
    with pytest.raises(SafetyError):g.close(timeout=0)
    assert g.api.stops==[] and g.cleanup_unconfirmed is True


def test_stopped_scm_with_still_live_owned_process_is_not_confirmed():
    g=gateway();g.started=True;g.process=Process()
    with pytest.raises(SafetyError):g.close(timeout=0)
    assert g.api.stops==[] and g.cleanup_unconfirmed is True


def test_backend_engine_exit_precedes_gateway_exit_observation():
    g=gateway();g.started=True;g.process=Process();held=g.process
    g.api.state=4;g.api.pid=101
    class Child:
        def resume(self):pass
        def close(self):
            platform.step('close_child')
            assert 'close_lease' in platform.events
            # Model the gateway's held-engine health callback after job closure.
            held.alive=False;g.api.state=1;g.api.pid=0
    class Runtime(Platform):
        def suspended_engine(self):return Child()
        def start_gateway(self,child):return g
        def close(self):
            self.step('close_platform');g.close()
    platform=Runtime();generation=Generation(platform)
    generation.start();generation.close()
    assert generation.state=='BLOCKED' and generation.closed
    assert not g.api.stops and held.closed==1 and g.api.closed==[22,11]
