from types import SimpleNamespace
import pytest
from claude_reset.install_service_attestation import NativeReader
from claude_reset.safeio import SafetyError


def test_reader_manager_close_failure_remains_retryable():
    reader=NativeReader.__new__(NativeReader)
    reader.manager=73
    reader.api=SimpleNamespace(CloseServiceHandle=lambda handle:False)
    with pytest.raises(SafetyError):reader.close()
    assert reader.manager==73
    reader.api.CloseServiceHandle=lambda handle:True
    reader.close()
    assert reader.manager is None


def test_auxiliary_deletion_handle_is_retained_on_close_failure():
    reader=NativeReader.__new__(NativeReader)
    reader.manager=73
    calls=[]
    def close(handle):
        calls.append(handle)
        return handle==73
    reader.api=SimpleNamespace(CloseServiceHandle=close)
    with pytest.raises(SafetyError):reader.release_auxiliary(91)
    with pytest.raises(SafetyError):reader.close()
    assert calls==[91,91,73]
    assert reader.manager is None and reader._pending_auxiliary=={91}
    reader.api.CloseServiceHandle=lambda handle:True
    reader.close()
    assert not reader._pending_auxiliary

@pytest.mark.parametrize('kind',['marked','pending'])
def test_deletion_request_cannot_succeed_when_its_handle_does_not_close(kind,monkeypatch):
    from claude_reset.install_scm import specification
    from claude_reset.install_service_attestation import HeldAttestation
    from claude_reset.install_creation_attestation import HeldPendingCreation
    from claude_reset import install_attested_cleanup as marked, install_creation_cleanup as pending
    reader=NativeReader.__new__(NativeReader)
    reader.manager=73
    reader.api=SimpleNamespace(OpenServiceW=lambda *args:91,
        CloseServiceHandle=lambda handle:False,DeleteService=lambda handle:True)
    reader.snapshot=lambda *args:None
    spec=specification('SbieDrv')
    if kind=='marked':
        held=HeldAttestation.__new__(HeldAttestation)
        held.reader=reader;held.verify_service=lambda name:None
        monkeypatch.setattr(marked,'validate_snapshot',lambda *args:None)
        with pytest.raises(SafetyError):marked._request_delete(held,spec,lambda:True)
    else:
        held=HeldPendingCreation.__new__(HeldPendingCreation)
        held.reader=reader;held.handle=17;held.spec=spec
        held.marker={'state':'bound','marker':{}}
        held.verify=lambda:None;held.require_closed=lambda:True
        monkeypatch.setattr(pending,'validate_creation_snapshot',lambda *args:None)
        with pytest.raises(SafetyError):pending._request(held)
