from pathlib import Path
import ctypes as C
import pytest
from claude_reset import install_registry_bind as b,install_registry as r,install_scm as s
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile


def acl():
    return dict(owner='S-1-5-32-544',dacl_present=True,dacl_null=False,protected=True,
        rules=[dict(sid=sid,mask=r.ALL,type=0,flags=2) for sid in r.OWNERS])


@pytest.fixture
def setup(monkeypatch):
    events=[]
    services=s.Native.__new__(s.Native);services._created={17:'SbieDrv'}
    def snapshot(handle,spec):
        events.append('snapshot')
        return dict(spec,state=1,pid=0,owner='S-1-5-32-544',dacl_present=True,dacl_null=False,
            rules=[dict(sid=sid,mask=0xF01FF,type=0,flags=0) for sid in r.OWNERS])
    services.snapshot=snapshot
    policy=PinnedFile.__new__(PinnedFile);policy.handle=99;policy.path=Path(r.expected_path());policy.sha256='a'*64
    monkeypatch.setattr(b,'verify_paths',lambda *args:events.append('acl'))
    class Writer:
        failure=None;existing=None;bound=False;bad=False
        def action(self,name):
            events.append(name)
            if self.failure==name:raise OSError('injected failure')
        def open(self):self.action('open');return 19
        def value(self,handle,name):
            assert handle==19
            if name=='SymbolicLinkValue':return None
            if self.existing:return self.existing
            if self.bound:return 1,((r.expected_path() if not self.bad else 'C:\\foreign.ini')+'\0').encode('utf-16-le')
            return None
        def protect(self,handle):self.action('protect')
        def write(self,handle):self.action('write');self.bound=True
        def flush(self,handle):self.action('flush')
        def security(self,handle):self.action('security');return acl()
        def close_key(self,handle):events.append('close')
    writer=Writer()
    def receipt(state,digest):assert digest=='a'*64;writer.action(state)
    def closed():writer.action('closed');return True
    return writer,services,policy,receipt,closed,events


def run(fixture):
    writer,services,policy,receipt,closed,_=fixture
    return b._bind_created_driver(writer,services,17,policy,receipt,closed)


def test_binding_requires_intent_flush_same_handle_readback_and_closed_boundary(setup):
    assert run(setup)==dict(policy_bound=True,driver_started=False,client_admission=False)
    assert setup[-1]==['snapshot','acl','closed','open','intent','closed','protect','closed','write',
                      'flush','security','snapshot','closed','bound','close']


@pytest.mark.parametrize('failure',['closed','open','intent','protect','write','flush','security','bound'])
def test_each_failure_leaves_no_success_receipt_or_service_start(setup,failure):
    setup[0].failure=failure
    with pytest.raises(OSError):run(setup)
    events=setup[-1]
    if 'open' in events and failure!='open':assert events[-1]=='close'
    if failure!='bound':assert 'bound' not in events
    assert not any(x in events for x in ('start','delete','rollback'))


def test_foreign_existing_binding_never_overwritten(setup):
    setup[0].existing=(1,b'foreign')
    with pytest.raises(SafetyError):run(setup)
    assert setup[-1]==['snapshot','acl','closed','open','close']


def test_changed_binding_after_write_never_committed(setup):
    setup[0].bad=True
    with pytest.raises(SafetyError):run(setup)
    assert 'bound' not in setup[-1] and setup[-1][-1]=='close'


@pytest.mark.parametrize('change',['released','wrong_service','wrong_file','closed_file'])
def test_existing_or_released_service_and_wrong_policy_rejected_before_registry(setup,change):
    if change=='released':setup[1]._created.clear()
    if change=='wrong_service':setup[1]._created[17]='SbieSvc'
    if change=='wrong_file':setup[2].path=Path('C:/foreign.ini')
    if change=='closed_file':setup[2].handle=None
    with pytest.raises(SafetyError):run(setup)
    assert 'open' not in setup[-1]


def test_registry_descriptor_has_expected_permissions_in_windows_parser():
    from claude_reset.install_service_security import Reader
    from claude_reset.wfp_security import decode
    reader=Reader();pointer=C.c_void_p()
    fn=reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    fn.argtypes=[C.c_wchar_p,C.c_uint32,C.POINTER(C.c_void_p),C.c_void_p];fn.restype=C.c_int
    assert fn(b.SDDL,1,C.byref(pointer),None)
    try:assert r.validate_security(decode(reader,pointer))
    finally:reader.kernel.LocalFree(pointer)


def test_native_write_only_marshals_fixed_reg_sz():
    calls=[]
    class Api:
        def RegSetValueExW(self,key,name,reserved,kind,data,size):
            calls.append((key,name,reserved,kind,C.string_at(data,size)));return 0
    native=b.Native.__new__(b.Native);native.api=Api();native.write(19)
    assert calls==[(19,'IniPath',0,1,(r.expected_path()+'\0').encode('utf-16-le'))]
    assert not b.ACCESS&(4|32|0x10000) # no create-subkey/link/delete
