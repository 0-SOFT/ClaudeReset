"""Native return-code failures modeled without opening any system object."""
import ctypes as C
from types import SimpleNamespace
import pytest
from claude_reset.windows import service_security as security
from claude_reset.windows import service_inventory as inventory
from claude_reset.safeio import SafetyError


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
