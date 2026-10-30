"""BFE models only: reject additional rules before accepting runtime boundaries."""
from types import SimpleNamespace
import pytest
from claude_reset.backend import boundary as b
from claude_reset.safeio import SafetyError
from wfp_fakes import FakeSession
from functools import partial

@pytest.fixture
def model(tmp_path):
    key=lambda value:SimpleNamespace(value=lambda:value)
    closed=[SimpleNamespace(key=key('deny'))];opened=[SimpleNamespace(key=key('permit'))]
    reserve={f'{service}:{layer}:{allow}' for service in ('ClaudeResetBackend','ClaudeResetGateway') for layer in b.RESERVATION_LAYERS for allow in (False,True)}
    state={'strict':{'deny'},'reserved':reserve,'events':[],'missing':set(),'reading':False,'fail':None}
    class Engine(FakeSession):
        def __init__(self):super().__init__();state['engine']=self
        def __enter__(self):return self
        def __exit__(self,*args):
            state['events'].append('engine-close')
            if state.get('real_close'):
                from claude_reset.network.strict_wfp import Engine as ActualEngine
                ActualEngine.close(self)
        def native(self,name,*args,**kwargs):
            state['events'].append(name)
            if state['fail']==name:raise SafetyError('synthetic BFE failure')
            if name=='FwpmTransactionBegin0':
                assert args[-1]==1;state['reading']=True
            elif name in ('FwpmTransactionAbort0','FwpmEngineClose0'):state['reading']=False
            else:raise AssertionError('No BFE write allowed')
        def existing_sublayer(self):assert state['reading'];return True
        def own_keys(self):assert state['reading'];return state['strict']
        def exists_verified(self,rule):assert state['reading'];return rule.key.value() not in state['missing']
    class Reservation:
        def __init__(self,path,service,port,**kwargs):self.service=service
        def __enter__(self):return self
        def __exit__(self,*args):state['events'].append('reservation-close')
        def native(self,layer,allow):return SimpleNamespace(filterKey=key(f'{self.service}:{layer}:{allow}')),[]
        def existing_sublayer(self):assert state['reading'];return True
        def own_keys(self):assert state['reading'];return state['reserved']
        def verified(self,layer,allow):assert state['reading'];return f'{self.service}:{layer}:{allow}' not in state['missing']
    state['verify']=partial(b.verify_installed,engine=Engine,reservation=Reservation,expected=lambda *a,**kw:(closed,opened))
    spec=dict(peer_address='1.1.1.1',peer_port=443,backend_port=1080,gateway_port=1081)
    return state,tmp_path,spec,opened

@pytest.mark.parametrize('where',['strict','reserved'])
def test_extra_rule_blocks_backend_startup(model,where):
    state,root,spec,_=model;state[where].add('unexpected-permit')
    with pytest.raises(SafetyError):state['verify'](root,spec)


@pytest.mark.parametrize('active',[False,True])
@pytest.mark.parametrize('fault',[None,'extra','missing-deny','missing-reservation','changed-deny','changed-reservation','wrong-phase'])
def test_exact_snapshot_before_and_during_lease(model,active,fault):
    state,root,spec,opened=model
    if active:state['strict'].add('permit')
    if fault=='extra':state['strict'].add('foreign-permit')
    elif fault=='missing-deny':state['strict'].remove('deny')
    elif fault=='missing-reservation':state['reserved'].pop()
    elif fault=='changed-deny':state['missing'].add('deny')
    elif fault=='changed-reservation':state['missing'].add(next(iter(state['reserved'])))
    elif fault=='wrong-phase':
        if active:state['strict'].remove('permit')
        else:state['strict'].add('permit')
    if fault:
        with pytest.raises(SafetyError):state['verify'](root,spec,active_lease=active)
    else:assert state['verify'](root,spec,active_lease=active)==opened
    assert state['events']==['FwpmTransactionBegin0','FwpmTransactionAbort0','reservation-close','reservation-close','engine-close']
    assert state['reading'] is False


@pytest.mark.parametrize('failure',['FwpmTransactionBegin0','FwpmTransactionAbort0'])
def test_failed_read_transaction_cannot_accept_boundary(model,failure):
    state,root,spec,_=model;state['fail']=failure
    with pytest.raises(SafetyError):state['verify'](root,spec)
    assert state['events'][-3:]==['reservation-close','reservation-close','engine-close']
    assert ('FwpmTransactionAbort0' in state['events'])==(failure!='FwpmTransactionBegin0')


def test_runtime_recheck_uses_active_lease_phase():
    from claude_reset.backend import runtime
    observed=[];platform=runtime.Platform(verify=lambda root,spec,**kwargs:observed.append(kwargs))
    platform.spec={};platform.opened=['permit']
    platform.verify_boundary(SimpleNamespace(exists_verified=lambda rule:True))
    assert observed==[{'active_lease':True}]



def test_failed_snapshot_abort_still_closes_owned_bfe_session(model):
    state,root,spec,_=model;state['fail']='FwpmTransactionAbort0';state['real_close']=True
    with pytest.raises(SafetyError):state['verify'](root,spec)
    assert state['events'].count('FwpmTransactionAbort0')==2
    assert state['events'][-1]=='FwpmEngineClose0'
    assert not state['engine'].handle and state['engine'].in_transaction is False
