from copy import deepcopy
import pytest
from claude_reset import install_scm as s
from claude_reset.safeio import SafetyError


class Model:
    """SCM model only; never registers a real service."""
    def __init__(self,failure=None,corruption=None):
        self.failure=failure;self.corruption=corruption;self.events=[];self.created=False
        self.closed=False;self.disabled=False;self.spec=None
    def event(self,name):
        self.events.append(name)
        if self.failure==name:raise OSError('injected '+name)
    def create(self,spec):
        self.event('create');self.spec=deepcopy(spec)
        self.created=True;self.disabled=spec['start']==4
        return 17
    def protect(self,handle):assert handle==17;self.event('protect')
    def set_sid(self,handle,spec):assert handle==17;self.event('sid')
    def snapshot(self,handle,spec):
        assert handle==17;self.event('snapshot')
        result=dict(spec,owner='S-1-5-32-544',dacl_present=True,dacl_null=False,state=1,pid=0,
            rules=[dict(sid=sid,mask=0xF01FF,type=0,flags=0) for sid in ('S-1-5-18','S-1-5-32-544')])
        if self.corruption:result.update(self.corruption)
        return result
    def release(self,handle):assert handle==17;self.events.append('release');self.closed=True
    def receipt(self,state,spec):
        self.event('receipt:'+state)
        # Callback cannot alter the spec subsequently used by native operations.
        spec['binary']='attacker.exe';spec['start']=2
    def verify_closed(self):self.event('closed');return True


@pytest.mark.parametrize('name',s.SERVICES)
def test_new_service_stays_disabled_after_success(name):
    model=Model()
    assert s._register_disabled(model,name,model.receipt,model.verify_closed)=={
        'name':name,'registered_disabled':True,'client_admission':False}
    assert model.disabled and model.closed
    assert model.spec['binary']!='attacker.exe'
    assert model.events==['closed','receipt:intent','closed','create','protect','sid','snapshot',
                          'receipt:disabled','closed','release']
    assert not s.ACCESS & (0x10|0x20|0x10000)


@pytest.mark.parametrize('result',[
    {},None,
    dict(marker_bound=False,service='ClaudeResetBackend',may_delete=False,client_admission=False),
    dict(marker_bound=True,service='SbieDrv',may_delete=False,client_admission=False),
    dict(marker_bound=True,service='ClaudeResetBackend',may_delete=True,client_admission=False),
    dict(marker_bound=True,service='ClaudeResetBackend',may_delete=False,client_admission=True),
])
def test_service_marker_hook_must_confirm_exact_nonpermissive_result(result):
    model=Model()
    with pytest.raises(SafetyError):s._register_disabled(model,'ClaudeResetBackend',model.receipt,
        model.verify_closed,prepare_service=lambda *args:result)
    assert model.closed and model.disabled and 'receipt:disabled' not in model.events


def test_service_marker_hook_cannot_change_following_registration_specification():
    model=Model()
    def prepare(native,handle,spec):
        spec['start']=2;spec['binary']='attacker.exe'
        return dict(marker_bound=True,service='ClaudeResetBackend',may_delete=False,client_admission=False)
    assert s._register_disabled(model,'ClaudeResetBackend',model.receipt,model.verify_closed,
                               prepare_service=prepare)['registered_disabled']
    assert model.spec['start']==4 and model.spec['binary']!='attacker.exe'


@pytest.mark.parametrize('failure',['closed','receipt:intent','create','protect','sid','snapshot','receipt:disabled'])
def test_registration_failure_never_starts_or_deletes(failure):
    model=Model(failure)
    with pytest.raises(OSError):s._register_disabled(model,'SbieDrv',model.receipt,model.verify_closed)
    if model.created:assert model.disabled and model.closed
    else:assert not model.closed
    assert 'receipt:disabled' not in model.events or failure=='receipt:disabled'


@pytest.mark.parametrize('corruption',[
    {'binary':'changed.exe'},{'start':3},{'type':32},{'account':'other'},
    {'dependencies':'other'},{'group':'other'},{'error':0},{'sid_type':0},
    {'state':4},{'pid':99},{'owner':'S-1-5-21-123'},{'dacl_null':True},
    {'rules':[dict(sid='S-1-5-11',mask=0xF01FF,type=0,flags=0)]},
])
def test_drift_rejected_on_same_handle(corruption):
    model=Model(corruption=corruption)
    with pytest.raises(SafetyError):s._register_disabled(model,'ClaudeResetBackend',model.receipt,model.verify_closed)
    assert model.disabled and model.closed and 'receipt:disabled' not in model.events


@pytest.mark.parametrize('name',['Discord','Codex','SbieDrv extra','sbieDrv',None,{},''])
def test_unknown_name_never_reaches_scm(name):
    model=Model()
    with pytest.raises(SafetyError):s._register_disabled(model,name,model.receipt,model.verify_closed)
    assert model.events==[]


def test_second_closed_check_failure_prevents_creation():
    model=Model();calls=0
    def verify():
        nonlocal calls
        calls+=1
        if calls==2:raise SafetyError('boundary drift')
        return True
    with pytest.raises(SafetyError):s._register_disabled(model,'SbieSvc',model.receipt,verify)
    assert not model.created


def test_final_closed_check_failure_retains_disabled_service():
    model=Model();calls=0
    def verify():
        nonlocal calls
        calls+=1
        if calls==3:raise SafetyError('boundary drift')
        return True
    with pytest.raises(SafetyError):s._register_disabled(model,'SbieSvc',model.receipt,verify)
    assert model.disabled and model.closed


@pytest.mark.parametrize('value',[None,False,0,1,'true',{}])
def test_unknown_or_false_boundary_result_never_creates_service(value):
    model=Model()
    with pytest.raises(SafetyError):s._register_disabled(model,'SbieSvc',model.receipt,lambda:value)
    assert model.events==[]


@pytest.mark.parametrize('change',[{'name':'Codex'},{'binary':'C:\\other.exe'},
    {'type':1},{'start':3},{'sid_type':True},{'account':'other'},{'extra':'command'}])
def test_native_creation_rejects_modified_spec_before_windows_call(change):
    native=s.Native.__new__(s.Native)  # No admin/API construction in this test.
    spec={**s.specification('ClaudeResetBackend'),**change}
    with pytest.raises(SafetyError):native.create(spec)


@pytest.mark.parametrize('name',s.SERVICES)
def test_native_create_marshalling_never_requests_start_or_adopts(name,monkeypatch):
    monkeypatch.setattr(s,'require_vacant_registry_slot',lambda requested:None)
    calls=[]
    class API:
        def CreateServiceW(self,*args):calls.append(args);return 91
    native=s.Native.__new__(s.Native);native.api=API();native.manager=73
    spec=s.specification(name)
    assert native.create(spec)==91
    args=calls[0]
    assert args[:7]==(73,name,name,s.ACCESS,spec['type'],4,1)
    assert args[7]==spec['binary']
    assert args[8:11]==(None,None,None)
    assert args[11:]==(('LocalSystem' if spec['type']==16 else None),None)


def test_compiled_security_descriptor_parses_with_real_windows_api():
    import ctypes as C
    reader=s.Reader();pointer=C.c_void_p()
    convert=reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[C.c_wchar_p,C.c_uint32,C.POINTER(C.c_void_p),C.c_void_p]
    convert.restype=C.c_int
    assert convert(s.SDDL,1,C.byref(pointer),None)
    try:
        row=reader.descriptor(pointer)
        row.update(name='ClaudeResetBackend',sid_type=1)
        assert s.validate_security(row)
        assert {r['sid'] for r in row['rules']}=={'S-1-5-18','S-1-5-32-544'}
    finally:reader.kernel.LocalFree(pointer)


def test_driver_preparation_runs_before_disabled_receipt_and_failure_keeps_disabled():
    model=Model()
    def prepare(native,handle):
        assert native is model and handle==17
        model.events.append('binding');raise SafetyError('binding failed')
    with pytest.raises(SafetyError):s._register_disabled(model,'SbieDrv',model.receipt,model.verify_closed,prepare_driver=prepare)
    assert model.disabled and model.closed and 'receipt:disabled' not in model.events
    assert model.events[-2:]==['binding','release']


@pytest.mark.parametrize('result',[None,False,True,{'policy_bound':True},
    dict(policy_bound=1,driver_started=False,client_admission=False),
    dict(policy_bound=True,driver_started=True,client_admission=False)])
def test_unknown_driver_preparation_result_cannot_complete_registration(result):
    model=Model()
    with pytest.raises(SafetyError):
        s._register_disabled(model,'SbieDrv',model.receipt,model.verify_closed,prepare_driver=lambda *a:result)
    assert model.disabled and model.closed and 'receipt:disabled' not in model.events


def test_released_native_handle_loses_creation_authority():
    native=s.Native.__new__(s.Native);native._created={17:'SbieDrv'}
    class API:
        def CloseServiceHandle(self,handle):assert handle==17;return True
    native.api=API();native.require_created(17,'SbieDrv');native.release(17)
    with pytest.raises(SafetyError):native.require_created(17,'SbieDrv')


@pytest.mark.parametrize('result',[0,2,5,3])
def test_orphan_or_unreadable_registry_slot_is_not_adopted(monkeypatch,result):
    import ctypes as C
    from claude_reset import install_registry as r
    events=[]
    class Api:
        def RegOpenKeyExW(self,root,key,options,access,out):
            assert key==r.KEY and options==8 and access==r.ACCESS
            events.append('open')
            if result==0:C.cast(out,C.POINTER(C.c_void_p))[0]=17
            return result
        def RegCloseKey(self,handle):events.append('close')
    class Reader:
        api=Api()
    monkeypatch.setattr(r,'Native',Reader)
    if result==2:s.require_vacant_registry_slot('SbieDrv')
    else:
        with pytest.raises(SafetyError):s.require_vacant_registry_slot('SbieDrv')
    assert events==(['open','close'] if result==0 else ['open'])
