from types import SimpleNamespace
import pytest
from claude_reset import install_scm as s
from claude_reset.safeio import SafetyError


def native_with_close(close):
    native = s.Native.__new__(s.Native)
    native.api = SimpleNamespace(CloseServiceHandle=close)
    native._created = {17: 'SbieDrv', 18: 'SbieSvc'}
    native.manager = 73
    return native


def test_failed_close_preserves_creation_handle_for_retry():
    calls = []
    def close(handle):
        calls.append(handle)
        return len(calls) > 1
    native = native_with_close(close)
    with pytest.raises(SafetyError):
        native.release(17)
    native.require_created(17, 'SbieDrv')
    native.release(17)
    assert calls == [17, 17]
    with pytest.raises(SafetyError):
        native.require_created(17, 'SbieDrv')


def test_failed_manager_close_preserves_handle_for_retry():
    native = native_with_close(lambda handle: False)
    with pytest.raises(SafetyError):
        native.close()
    assert native.manager == 73
    native.api.CloseServiceHandle = lambda handle: True
    native.close()
    assert native.manager is None


def test_held_close_attempts_all_handles_and_retains_only_failed():
    calls = []
    def close(handle):
        calls.append(handle)
        return handle != 18
    native = native_with_close(close)
    held = s.HeldRegistrations()
    held.retain(native, 17, s.specification('SbieDrv'))
    held.retain(native, 18, s.specification('SbieSvc'))
    with pytest.raises(SafetyError):
        held.close()
    assert calls == [18, 17]
    assert [row[1] for row in held.items] == [18]
    assert native._created == {18: 'SbieSvc'}
    native.api.CloseServiceHandle = lambda handle: True
    held.close()
    assert held.items == [] and native._created == {}


def test_auxiliary_close_failure_is_retained_and_retried_during_native_close():
    calls = []
    def close(handle):
        calls.append(handle)
        return handle == 73
    native = native_with_close(close)
    with pytest.raises(SafetyError):
        native.release_auxiliary(91)
    with pytest.raises(SafetyError):
        native.close()
    assert calls == [91, 91, 73]
    assert native.manager is None
    assert native._pending_auxiliary == {91}
    native.api.CloseServiceHandle = lambda handle: True
    native.close()
    assert not native._pending_auxiliary


def test_deletion_handle_close_failure_cannot_confirm_rollback():
    from claude_reset import install_scm_cleanup as cleanup
    from test_install_scm_cleanup import NativeModel, register
    native = NativeModel()
    held = s.HeldRegistrations()
    register(native, held)
    original = native.api.CloseServiceHandle
    native.api.CloseServiceHandle = lambda handle: False if handle == 91 else original(handle)
    receipts = []
    completed = []
    with pytest.raises(SafetyError):
        cleanup._rollback_held_registrations(held,
            lambda state, spec: receipts.append(state), lambda: True, completed=completed)
    assert receipts == ['delete_intent']
    assert native.deleted == ['SbieDrv']
    assert len(held.items) == 1 and completed == []
    assert native._pending_auxiliary == {91}
    native.api.CloseServiceHandle = original
    native.close()
    held.close()
    assert not native._pending_auxiliary and not held.items
