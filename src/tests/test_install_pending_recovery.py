"""Absent pending creation integrates only with recovery, never full ownership."""
import json
import pytest
from claude_reset import install_recovery_records as records
from claude_reset import install_remaining_attestation as remaining
from claude_reset import install_removal_confirmation as confirmation
from claude_reset import install_reconciled_cleanup as cleanup
from claude_reset.install_service_attestation import HeldAttestation
from claude_reset.install_creation_cleanup_receipt import CreationCleanupReceipt
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.safeio import SafetyError
from test_install_creation_cleanup import setup,operation
from test_install_reconciled_cleanup import setup as remaining_setup,operation as remaining_operation


def prepare(fixture,monkeypatch):
    step,_,held,_,state,*_=fixture
    monkeypatch.setattr(records,'verify_paths',lambda *args:None)
    monkeypatch.setattr(confirmation,'verify_paths',lambda *args:None)
    monkeypatch.setattr(cleanup,'verify_paths',lambda *args:None)
    monkeypatch.setattr(remaining,'NativeReader',type(held.reader))
    monkeypatch.setattr(remaining,'RegistryReader',type(held.registry))
    return lambda:state['closed']


def test_pending_absence_allows_recovery_without_promoting_source_or_markers(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch,present=False) as fixture:
        step,inputs,_,native,state,*_=fixture;closed=prepare(fixture,monkeypatch)
        operation(fixture).run()
        before=records.creation_records(step.store,step.generation)
        assert records.recovery_records(step.store,step.generation,closed)==before
        with pytest.raises(SafetyError):HeldAttestation(step.store,step.generation)
        with remaining.HeldRemainingAttestation(step.store,step.generation,lambda g:closed()) as held:
            assert not held.items and len(held.absent)==1
            result=cleanup.ReconciledCleanup(step.store,inputs,held,step.generation,lambda g:closed()).run()
            assert result['absence_verified'] and result['new_deletion_requests']==0
        assert records.creation_records(step.store,step.generation)==before
        assert RemovalReceipts(step.store.journal).load()['completion_basis']=='observed_absence'
        assert not native.deleted


@pytest.mark.parametrize('marker_state',['intent','missing','bound'])
def test_remaining_completed_prefix_cleans_up_after_absent_pending_last(tmp_path,monkeypatch,marker_state):
    with remaining_setup(tmp_path,monkeypatch,1) as fixture:
        step,_,native,absent,state,handles,keys,_,attest=fixture
        directory=step.store.journal.directory
        path=directory/'service-receipts.json';source=json.loads(path.read_bytes())
        source['services'][-1]['state']='intent';path.write_bytes(json.dumps(source).encode())
        path=directory/'service-marker-receipts.json';markers=json.loads(path.read_bytes())
        if marker_state=='missing':markers['services'].pop()
        else:markers['services'][-1]['state']=marker_state
        path.write_bytes(json.dumps(markers).encode())
        from claude_reset import install_creation_attestation as creation
        monkeypatch.setattr(creation,'program_files',lambda:tmp_path)
        monkeypatch.setattr(creation,'verify_paths',lambda *args:None)
        monkeypatch.setattr(records,'verify_paths',lambda *args:None)
        receipt=CreationCleanupReceipt(step.store,step.generation)
        observed=records._confirm_absence(['SbieDrv'],lambda:True)
        receipt.observe_absence(observed)
        before=records.creation_records(step.store,step.generation)
        with attest() as held:
            result=remaining_operation(fixture,held).run()
        assert result['new_deletion_requests']==3 and result['services_absent']==4
        assert len(native.deleted)==3 and not handles and not keys and len(absent)==4
        assert records.creation_records(step.store,step.generation)==before


@pytest.mark.parametrize('fault',['missing','not-observed','reappeared','closed','acl','drift'])
def test_pending_absence_is_fresh_not_receipt_only_authority(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch,present=False) as fixture:
        step,_,_,native,state,*_=fixture;closed=prepare(fixture,monkeypatch)
        if fault!='missing':operation(fixture).run()
        receipt=CreationCleanupReceipt(step.store,step.generation)
        if fault=='not-observed':
            value=receipt.load();value['absence_verified']=False;receipt.save(value)
        if fault=='reappeared':state['present']=True
        if fault=='closed':state['closed']=False
        if fault=='acl':
            def refused(*args):raise SafetyError('untrusted receipt')
            monkeypatch.setattr(records,'verify_paths',refused)
        if fault=='drift':
            original=records._confirm_absence
            def changed(*args):
                result=original(*args);receipt.path.unlink();return result
            monkeypatch.setattr(records,'_confirm_absence',changed)
        with pytest.raises(SafetyError):records.recovery_records(step.store,step.generation,closed)
        assert not native.deleted
