"""Protected-file fixtures; all deletion and registry operations are modeled."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_attested_cleanup as c,install_recovery_inputs as inputs_module
from claude_reset.install_service_attestation import HeldAttestation
from claude_reset.install_reservations import ReservationReceipt
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.install_scm import SERVICES
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_service_attestation import readers


@contextmanager
def setup(tmp_path,monkeypatch,*,reservations=True,signed=None):
    with prepared(tmp_path,monkeypatch,signed=signed) as (step,tx,events,native):
        step.apply();step.held.close();assert not native._created
        tx['state']='recovering';step.store.journal.save(tx)
        if reservations:
            value=json.loads((step.store.journal.directory/ReservationReceipt.filename).read_bytes())
            receipt=ReservationReceipt(step.store.journal,value['keys'])
            receipt.recover_record('remove_intent');receipt.recover_record('removed')
        _,handles,keys,values=readers(step,native,monkeypatch)
        monkeypatch.setattr(inputs_module,'program_files',lambda:tmp_path)
        monkeypatch.setattr(inputs_module,'verify_paths',lambda *args:None)
        state=dict(fault=None,closed=True,pending=False)
        with inputs_module.RecoveryInputs(step.store,step.generation) as inputs,HeldAttestation(step.store,step.generation) as held:
            class Delete:
                def __call__(self,handle):
                    assert handle in handles and handle[0]=='delete'
                    if state['fault']=='delete':return False
                    native.deleted.append(handle[1]);return True
            class Api:
                DeleteService=Delete()
                def OpenServiceW(self,manager,name,access):
                    assert manager==73 and access==c.DELETE_ACCESS
                    assert ('service',name) in handles
                    if state['fault']=='open':return None
                    if state['fault']=='snapshot':native.changed=True
                    handle=('delete',name);handles.add(handle);return handle
                def CloseServiceHandle(self,handle):
                    if state['fault']=='handle-close':return False
                    handles.remove(handle);return True
            held.reader.manager=73;held.reader.api=Api()
            def confirm(result,closed):
                assert not handles and not keys and closed() is True
                if state['pending']:raise SafetyError('modeled pending SCM removal')
                assert [r['name'] for r in result['services']]==native.deleted
                return dict(services=native.deleted[:],absence_verified=True,client_admission=False)
            monkeypatch.setattr(c,'_confirm_removal',confirm)
            yield step,inputs,held,native,state,values,handles


def cleanup(fixture):
    step,inputs,held,_,state,_,_=fixture
    return c.AttestedCleanup(step.store,inputs,held,step.generation,lambda generation:state['closed'])


def test_reopened_marked_services_delete_in_reverse_with_no_creation_handle_forgery(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,_,_,handles=fixture;operation=cleanup(fixture)
        result=operation.run()
        assert result==dict(services_removed=4,absence_verified=True,client_admission=False)
        assert native.deleted==list(reversed(SERVICES)) and not native._created
        assert held.closed and not handles and operation.run()==result
        assert RemovalReceipts(step.store.journal).load()['absence_verified'] is True
        assert json.loads((step.store.journal.directory/'boundary-receipt.json').read_bytes())['state']=='committed'


@pytest.mark.parametrize('fault',['open','delete','snapshot','marker','closed'])
def test_attested_cleanup_faults_never_delete_an_unconfirmed_target(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch) as fixture:
        _,_,held,native,state,values,handles=fixture;operation=cleanup(fixture)
        state['fault']=fault
        if fault=='marker':values['SbieDrv']=(3,b'foreign')
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):operation.run()
        assert not native.deleted and not held.closed and len(handles)==4


@pytest.mark.parametrize('after',[1,2,3,4])
def test_only_same_object_confirmed_prefix_resumes_without_duplicate_deletion(tmp_path,monkeypatch,after):
    with setup(tmp_path,monkeypatch) as fixture:
        _,_,held,native,_,_,handles=fixture;operation=cleanup(fixture)
        operation.verifier=lambda generation:len(native.deleted)<after
        with pytest.raises(SafetyError):operation.run()
        assert len(operation.completed)==after and len(handles)==4 and not held.closed
        with pytest.raises(SafetyError,match='Unknown deletion'):cleanup(fixture)
        operation.verifier=lambda generation:True
        assert operation.run()['absence_verified']
        assert native.deleted==list(reversed(SERVICES)) and not handles


@pytest.mark.parametrize('durable',[False,True])
def test_unknown_completion_is_never_replayed_or_promoted_from_disk(tmp_path,monkeypatch,durable):
    with setup(tmp_path,monkeypatch) as fixture:
        _,_,held,native,_,_,handles=fixture;operation=cleanup(fixture)
        original=RemovalReceipts.record
        def fail(receipt,state,spec):
            if state!='delete_requested' or durable:original(receipt,state,spec)
            if state=='delete_requested':raise OSError('unknown completion durability')
        monkeypatch.setattr(RemovalReceipts,'record',fail)
        with pytest.raises(OSError):operation.run()
        monkeypatch.setattr(RemovalReceipts,'record',original)
        with pytest.raises(SafetyError,match='Unknown deletion'):operation.run()
        assert native.deleted==['SbieDrv'] and not operation.completed and len(handles)==4
        assert not held.closed


def test_pending_absence_rechecks_without_reopening_or_redeleting_services(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        _,_,held,native,state,_,handles=fixture;operation=cleanup(fixture);state['pending']=True
        with pytest.raises(SafetyError,match='pending'):operation.run()
        assert held.closed and not handles and len(native.deleted)==4
        state['pending']=False;assert operation.run()['absence_verified']
        assert native.deleted==list(reversed(SERVICES))


def test_listener_reservations_must_be_removed_before_service_deletion(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch,reservations=False) as fixture:
        with pytest.raises(SafetyError):cleanup(fixture)
        assert not fixture[3].deleted


def test_failed_deletion_handle_close_retains_uncertain_intent(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,state,_,handles=fixture
        operation=cleanup(fixture);state['fault']='handle-close'
        try:
            with pytest.raises(SafetyError):operation.run()
            receipt=RemovalReceipts(step.store.journal).load()
            assert receipt['services'][-1]['state']=='delete_intent'
            assert receipt['absence_verified'] is False
            assert native.deleted==['SbieDrv'] and not operation.completed
            assert len(handles)==5 and held.reader._pending_auxiliary
            with pytest.raises(SafetyError):operation.run()
            assert native.deleted==['SbieDrv']
        finally:state['fault']=None
