import pytest
from claude_reset import install_scm as s,install_scm_cleanup as c
from claude_reset.safeio import SafetyError
from test_install_scm import Model


class NativeModel(s.Native):
    """No native constructor/API calls; original-handle lifetime is modeled."""
    def __init__(self):
        self.model=Model();self.displays={};self._created={};self.manager=73;self.next_handle=10
        self.deleted=[];self.open_fails=False;self.delete_fails=False;self.changed=False
        owner=self
        class Delete:
            def __call__(self,handle):
                assert handle==91
                owner.model.events.append('delete')
                if owner.delete_fails:return False
                owner.deleted.append(owner.opened);return True
        class Api:
            DeleteService=Delete()
            def OpenServiceW(self,manager,name,access):
                assert manager==73 and access==c.DELETE_ACCESS
                assert name in owner._created.values()
                owner.model.events.append('open-delete');owner.opened=name
                return None if owner.open_fails else 91
            def CloseServiceHandle(self,handle):owner.model.events.append('close:'+str(handle));return True
        self.api=Api()
    def create(self,spec,*,creation_marker=None):
        from claude_reset.install_service_markers import creation_display
        self.displays[spec['name']]=creation_display(creation_marker,spec) if creation_marker else spec['name']
        self.next_handle+=1;handle=self.next_handle
        self._created[handle]=spec['name'];self.model.events.append('create');return handle
    def protect(self,handle):self.model.event('protect')
    def set_sid(self,handle,spec):self.model.event('sid')
    def snapshot(self,handle,spec):
        result=self.model.snapshot(17,spec)
        result['display']=self.displays.get(spec['name'],spec['name'])
        if self.changed:result['state']=4
        return result


def register(native,held,name='SbieDrv'):
    return s._register_disabled(native,name,native.model.receipt,native.model.verify_closed,held=held)


def test_retained_registrations_rollback_reverse_order_without_stop_or_false_absence():
    native=NativeModel();held=s.HeldRegistrations()
    for name in s.SERVICES:register(native,held,name)
    assert len(held.items)==4 and len(native._created)==4
    events=[]
    result=c._rollback_held_registrations(held,lambda state,spec:events.append((state,spec['name'])),lambda:True)
    assert native.deleted==list(reversed(s.SERVICES))
    assert not held.items and not native._created
    assert result['absence_verified'] is False and result['client_admission'] is False
    assert [state for state,_ in events]==['delete_intent','delete_requested']*4
    assert all(row['absence_verified'] is False for row in result['services'])
    assert not c.DELETE_ACCESS&(2|0x10|0x20) # no change-config/start/stop


def test_failed_registration_keeps_creation_handle_for_explicit_recovery():
    native=NativeModel();native.model.failure='protect';held=s.HeldRegistrations()
    with pytest.raises(OSError):register(native,held)
    assert len(held.items)==1 and native._created
    held.close()
    assert not native._created and not native.deleted


@pytest.mark.parametrize('failure',['ownership','running','open','delete','closed','receipt'])
def test_failed_cleanup_retains_original_handle_and_cannot_complete_undo(failure):
    native=NativeModel();held=s.HeldRegistrations();register(native,held)
    if failure=='ownership':native._created.clear()
    if failure=='running':native.changed=True
    if failure=='open':native.open_fails=True
    if failure=='delete':native.delete_fails=True
    def receipt(state,spec):
        if failure=='receipt':raise OSError('durability failed')
    try:
        with pytest.raises((SafetyError,OSError)):
            c._rollback_held_registrations(held,receipt,lambda:failure!='closed')
        assert len(held.items)==1 and not native.deleted
        if failure in ('ownership','running','closed','receipt'):
            assert 'open-delete' not in native.model.events
    finally:held.close()


def test_successful_delete_with_failed_receipt_remains_uncertain_and_held():
    native=NativeModel();held=s.HeldRegistrations();register(native,held)
    def receipt(state,spec):
        if state=='delete_requested':raise OSError('durability failed')
    try:
        with pytest.raises(OSError):c._rollback_held_registrations(held,receipt,lambda:True)
        assert native.deleted==['SbieDrv'] and len(held.items)==1
    finally:held.close()


def test_closed_registration_handle_cannot_authorize_reopened_name():
    native=NativeModel();held=s.HeldRegistrations();register(native,held)
    _,handle,spec=held.items[0];held.close()
    with pytest.raises(SafetyError):c._remove_current_registration(native,handle,spec,lambda:True)
    assert 'open-delete' not in native.model.events


@pytest.mark.parametrize('failure',[None,'service','registry','incomplete','boundary'])
def test_absence_requires_scm_and_registry_after_all_handles_close(monkeypatch,failure):
    from claude_reset import install_inventory as inventory
    native=NativeModel();held=s.HeldRegistrations();register(native,held)
    result=c._rollback_held_registrations(held,lambda *a:None,lambda:True)
    rows=[dict(name=name,exists=name=='SbieDrv' and failure=='service') for name in s.SERVICES]
    monkeypatch.setattr(inventory,'services',lambda:rows[:-1] if failure=='incomplete' else rows)
    def registry(name):
        assert name=='SbieDrv'
        if failure=='registry':raise SafetyError('orphan key')
    monkeypatch.setattr(s,'require_vacant_registry_slot',registry)
    if failure:
        with pytest.raises(SafetyError):c._confirm_removal(result,lambda:failure!='boundary')
    else:assert c._confirm_removal(result,lambda:True)==dict(services=['SbieDrv'],absence_verified=True,client_admission=False)


@pytest.mark.parametrize('names',[None,'SbieDrv',['SbieDrv','SbieDrv'],['Codex'],[{}],[1]])
def test_absence_inspection_refuses_invalid_names_before_boundary_or_scm(names):
    def unexpected():raise AssertionError('Invalid names must be rejected first')
    with pytest.raises(SafetyError):c._confirm_absence(names,unexpected)


@pytest.mark.parametrize('fault',['none','missing','entry','order','unknown','bool'])
def test_absence_inspection_refuses_malformed_inventory(monkeypatch,fault):
    from claude_reset import install_inventory as inventory
    rows=[dict(name=n,exists=False) for n in s.SERVICES]
    if fault=='none':rows=None
    elif fault=='missing':rows.pop()
    elif fault=='entry':rows[0]=None
    elif fault=='order':rows.reverse()
    elif fault=='unknown':rows[0]['name']='Codex'
    elif fault=='bool':rows[0]['exists']=0
    monkeypatch.setattr(inventory,'services',lambda:rows)
    def unexpected(name):raise AssertionError('Malformed SCM snapshot must be rejected first')
    monkeypatch.setattr(s,'require_vacant_registry_slot',unexpected)
    with pytest.raises(SafetyError):c._confirm_absence(['SbieDrv'],lambda:True)
