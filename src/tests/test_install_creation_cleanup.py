"""Real staged-file fixtures; SCM/registry/ACL mutations exclusively modeled."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_creation_cleanup as c,install_creation_attestation as a
from claude_reset import install_recovery_inputs as ri
from claude_reset.install_creation_cleanup_receipt import CreationCleanupReceipt
from claude_reset.install_reservations import ReservationReceipt
from claude_reset.install_scm_cleanup import DELETE_ACCESS
from claude_reset.safeio import SafetyError
from test_install_creation_attestation import pending


@contextmanager
def setup(tmp_path,monkeypatch,present=True,*,signed=None):
    with pending(tmp_path,monkeypatch,present=present,signed=signed) as (step,native,state,handles,keys):
        record=json.loads((step.store.journal.directory/ReservationReceipt.filename).read_bytes())
        receipt=ReservationReceipt(step.store.journal,record['keys'])
        receipt.recover_record('remove_intent');receipt.recover_record('removed')
        monkeypatch.setattr(ri,'program_files',lambda:tmp_path)
        monkeypatch.setattr(ri,'verify_paths',lambda *args:None)
        monkeypatch.setattr(c,'verify_paths',lambda *args:None)
        original=a.NativeReader.release
        state.update(deleted=False,fault=None)
        def release(reader,handle):
            original(reader,handle)
            if state['deleted']:state['present']=False
        monkeypatch.setattr(a.NativeReader,'release',release)
        class Delete:
            def __call__(self,handle):
                assert handle in handles and handle[0]=='delete'
                if state['fault']=='delete':return False
                native.deleted.append(handle[1]);state['deleted']=True
                return True
        class Api:
            DeleteService=Delete()
            def OpenServiceW(self,manager,name,access):
                assert access==DELETE_ACCESS and ('service',name) in handles
                if state['fault']=='open':return None
                handle=('delete',name);handles.add(handle);return handle
            def CloseServiceHandle(self,handle):
                if state['fault']=='handle-close':return False
                handles.remove(handle);return True
        with ri.RecoveryInputs(step.store,step.generation) as inputs:
            with a.HeldPendingCreation(step.store,step.generation,lambda g:state['closed']) as held:
                held.reader.manager=73;held.reader.api=Api()
                yield step,inputs,held,native,state,handles,keys


def operation(fixture):
    step,inputs,held,_,state,*_=fixture
    return c.PendingCreationCleanup(step.store,inputs,held,step.generation,lambda g:state['closed'])


@pytest.mark.parametrize('present',[True,False])
def test_cleanup_confirms_absence_preserves_creation_history_and_denies(tmp_path,monkeypatch,present):
    with setup(tmp_path,monkeypatch,present) as fixture:
        step,_,_,native,_,handles,keys=fixture
        source=(step.store.journal.directory/'service-receipts.json').read_bytes()
        cleanup=operation(fixture);result=cleanup.run()
        assert result['absence_verified'] and result['new_deletion_request'] is present
        assert result['client_admission'] is False
        assert len(native.deleted)==int(present) and not handles and not keys
        with pytest.raises(SafetyError):cleanup.run()
        assert (step.store.journal.directory/'service-receipts.json').read_bytes()==source
        assert json.loads((step.store.journal.directory/'boundary-receipt.json').read_bytes())['state']=='committed'
        receipt=CreationCleanupReceipt(step.store,step.generation).load()
        assert receipt['absence_verified'] and len(receipt['attempts'])==int(present)


@pytest.mark.parametrize('fault',['open','delete','foreign','closed','inputs','completion'])
def test_failed_or_changed_cleanup_cannot_replay_on_same_object(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch) as fixture:
        step,inputs,_,native,state,*_=fixture
        cleanup=operation(fixture)
        begin=CreationCleanupReceipt.begin
        def changed(receipt):
            identifier=begin(receipt)
            if fault=='foreign':state['foreign']=True
            if fault=='closed':state['closed']=False
            if fault=='inputs':inputs.close()
            return identifier
        monkeypatch.setattr(CreationCleanupReceipt,'begin',changed)
        if fault=='completion':
            def lost(*args):raise OSError('result lost')
            monkeypatch.setattr(CreationCleanupReceipt,'requested',lost)
        state['fault']=fault
        with pytest.raises((SafetyError,OSError)):cleanup.run()
        with pytest.raises(SafetyError):cleanup.run()
        receipt=CreationCleanupReceipt(step.store,step.generation).load()
        assert not receipt['absence_verified'] and receipt['attempts'][-1]['state']=='delete_intent'
        assert len(native.deleted)==int(fault=='completion')


@pytest.mark.parametrize('known',['requested','absent','original-requested','original-absent'])
def test_present_service_after_known_deletion_or_absence_is_not_adopted(tmp_path,monkeypatch,known):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,*_=fixture
        receipt=CreationCleanupReceipt(step.store,step.generation)
        if known=='requested':receipt.requested(receipt.begin())
        elif known=='absent':receipt.observe_absence(dict(services=[held.spec['name']],absence_verified=True,client_admission=False))
        else:
            from claude_reset.install_removal_receipts import RemovalReceipts
            original=RemovalReceipts(step.store.journal)
            if known=='original-requested':
                original.record('delete_intent',held.spec);original.record('delete_requested',held.spec)
            else:original.confirm_observed(dict(services=[held.spec['name']],absence_verified=True,client_admission=False))
        with pytest.raises(SafetyError):operation(fixture)
        assert not native.deleted


def test_failed_pending_deletion_handle_close_cannot_confirm_or_replay(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,held,native,state,handles,_=fixture
        cleanup=operation(fixture);state['fault']='handle-close'
        try:
            with pytest.raises(SafetyError):cleanup.run()
            receipt=CreationCleanupReceipt(step.store,step.generation).load()
            assert receipt['attempts'][-1]['state']=='delete_intent'
            assert receipt['absence_verified'] is False
            assert len(native.deleted)==1 and len(handles)==2
            assert held.reader._pending_auxiliary
            with pytest.raises(SafetyError):cleanup.run()
            assert len(native.deleted)==1
        finally:state['fault']=None
