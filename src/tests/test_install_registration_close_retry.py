"""Retry only a confirmed deletion's failed creation-handle close."""
import pytest
from claude_reset import install_scm as scm, install_scm_cleanup as cleanup
from claude_reset.safeio import SafetyError
from test_install_scm_cleanup import NativeModel,register


@pytest.mark.parametrize('phase',['delete_intent','delete_requested'])
def test_unknown_receipt_outcome_cannot_replay_raw_rollback(phase):
    native=NativeModel();held=scm.HeldRegistrations();register(native,held)
    events=[]
    def record(state,spec):
        events.append(state)
        if state==phase:raise OSError('uncertain durable write')
    with pytest.raises(OSError):cleanup._rollback_held_registrations(held,record,lambda:True)
    before=list(native.deleted)
    with pytest.raises(SafetyError):
        cleanup._rollback_held_registrations(held,lambda *args:None,lambda:True)
    assert native.deleted==before
    held.close()


def test_original_handle_close_retry_never_repeats_delete_or_receipt():
    native=NativeModel();held=scm.HeldRegistrations();register(native,held)
    release=native.release;failed=[False]
    def fail_once(handle):
        if not failed[0]:failed[0]=True;raise SafetyError('creation close failed')
        release(handle)
    native.release=fail_once
    receipts=[];completed=[]
    record=lambda state,spec:receipts.append((state,spec['name']))
    with pytest.raises(SafetyError):
        cleanup._rollback_held_registrations(held,record,lambda:True,completed=completed)
    assert native.deleted==['SbieDrv'] and len(held.items)==1 and not completed
    result=cleanup._rollback_held_registrations(held,record,lambda:True,completed=completed)
    assert native.deleted==['SbieDrv'] and not held.items
    assert receipts==[('delete_intent','SbieDrv'),('delete_requested','SbieDrv')]
    assert len(result['services'])==1 and result['absence_verified'] is False


@pytest.mark.parametrize('fault',['closed_boundary','lost_handle','changed_spec','changed_result'])
def test_pending_close_requires_same_held_identity_and_closed_boundary(fault):
    native=NativeModel();held=scm.HeldRegistrations();register(native,held)
    release=native.release
    def fail(handle):raise SafetyError('creation close failed')
    native.release=fail
    with pytest.raises(SafetyError):
        cleanup._rollback_held_registrations(held,lambda *args:None,lambda:True)
    native.release=release
    if fault=='lost_handle':native._created.clear()
    if fault=='changed_spec':held.items[-1][2]['name']='SbieSvc'
    if fault=='changed_result':held.pending_close[-1]['absence_verified']=True
    with pytest.raises(SafetyError):
        cleanup._rollback_held_registrations(held,lambda *args:pytest.fail('No receipt replay'),
                                            lambda:fault!='closed_boundary')
    assert native.deleted==['SbieDrv']


def test_service_step_resumes_failed_creation_close_with_durable_receipt(tmp_path,monkeypatch):
    from test_install_service_step import prepared
    from claude_reset.install_removal_receipts import RemovalReceipts
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        step.apply();tx['state']='recovering';step.store.journal.save(tx)
        release=native.release;failed=[False]
        def fail_once(handle):
            if not failed[0]:failed[0]=True;raise SafetyError('creation close failed')
            release(handle)
        native.release=fail_once
        with pytest.raises(SafetyError):step.recover()
        assert native.deleted==['SbieDrv'] and not step.deleted
        receipt=RemovalReceipts(step.store.journal).load()
        assert receipt['services'][0]['state']=='delete_requested'
        assert receipt['absence_verified'] is False and 'remove-denies' not in events
        assert step.recover()['services_recovered'] is True
        assert native.deleted==list(reversed(scm.SERVICES))
        assert not step.held.items and len(step.deleted)==4
