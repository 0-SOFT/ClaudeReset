"""Native return-code failures modeled without opening any system object."""
import ctypes as C
from types import SimpleNamespace
import pytest
from claude_reset import install_registry as registry, install_registry_bind as binding
from claude_reset import install_service_security as security, install_inventory as inventory
from claude_reset.safeio import SafetyError
from test_install_registry_bind import setup


@pytest.mark.parametrize('status',[5,6,1018])
def test_registry_writer_does_not_hide_close_failure(status):
    writer=binding.Native.__new__(binding.Native)
    writer.api=SimpleNamespace(RegCloseKey=lambda key:status)
    with pytest.raises(SafetyError):writer.close_key(17)


def test_registry_writer_accepts_successful_close():
    writer=binding.Native.__new__(binding.Native)
    writer.api=SimpleNamespace(RegCloseKey=lambda key:0)
    writer.close_key(17)


def test_completed_binding_does_not_return_success_after_failed_close(setup):
    from test_install_registry_bind import run
    writer=setup[0]
    writer.api=SimpleNamespace(RegCloseKey=lambda key:5)
    writer.close_key=lambda handle:binding.Native.close_key(writer,handle)
    with pytest.raises(SafetyError):run(setup)
    # The binding itself was flushed and verified. Its receipt does not claim
    # successful cleanup or a successful enclosing installation transaction.
    assert 'bound' in setup[-1]
    assert not any(event in setup[-1] for event in ('start','delete','rollback'))


def test_matching_policy_is_not_reported_when_inspection_key_close_fails():
    from test_install_registry import security as descriptor
    reader=registry.Native.__new__(registry.Native)
    def opened(root,key,options,access,result):
        C.cast(result,C.POINTER(C.c_void_p))[0]=17
        return 0
    reader.api=SimpleNamespace(RegOpenKeyExW=opened,RegCloseKey=lambda key:5)
    reader.security=lambda handle:descriptor()
    reader.value=lambda handle,name:None if name=='SymbolicLinkValue' else (
        1,(registry.expected_path()+'\0').encode('utf-16-le'))
    with pytest.raises(SafetyError):reader.inspect()


@pytest.mark.parametrize('fault',['service','manager'])
def test_service_security_inspection_fails_and_still_closes_manager(fault):
    from test_install_service_security import row
    events=[]
    reader=security.Reader.__new__(security.Reader)
    def close(handle):
        events.append(handle)
        return handle!=(17 if fault=='service' else 73)
    reader.api=SimpleNamespace(OpenSCManagerW=lambda *args:73,
        OpenServiceW=lambda *args:17,CloseServiceHandle=close)
    reader.read_handle=lambda handle,name:dict(row(),name=name)
    with pytest.raises(SafetyError):reader.inspect()
    assert events[-1]==73 and 17 in events


def test_missing_service_inventory_is_not_accepted_after_manager_close_failure(monkeypatch):
    class Fn:
        def __init__(self,call):self.call=call
        def __call__(self,*args):return self.call(*args)
    def missing(*args):C.set_last_error(1060);return None
    api=SimpleNamespace(OpenSCManagerW=Fn(lambda *args:73),OpenServiceW=Fn(missing),
        CloseServiceHandle=Fn(lambda handle:False),QueryServiceStatusEx=Fn(lambda *args:False),
        QueryServiceConfigW=Fn(lambda *args:False))
    monkeypatch.setattr(inventory.C,'WinDLL',lambda *args,**kwargs:api)
    with pytest.raises(SafetyError):inventory.services()
