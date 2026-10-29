"""Recovery coordinator with real staging and modeled administrative operations."""
import json
import pytest
from claude_reset import install_registered_recovery as r
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.safeio import SafetyError
from test_install_reconciled_cleanup import setup


@pytest.mark.parametrize('absent_count,pending',[(0,False),(1,False),(4,False),(1,True)])
def test_ordered_reopen_removes_denies_only_after_all_services_absent(tmp_path,monkeypatch,absent_count,pending):
    with setup(tmp_path,monkeypatch,absent_count) as fixture:
        step,_,native,absent,state,handles,keys,_,attest=fixture
        if pending:
            from claude_reset import install_creation_attestation as creation,install_service_attestation as a
            from claude_reset import install_creation_cleanup as pending_cleanup,install_recovery_records as records
            for filename in ('service-receipts.json','service-marker-receipts.json'):
                path=step.store.journal.directory/filename;value=json.loads(path.read_bytes())
                value['services'][-1]['state']='intent';path.write_bytes(json.dumps(value).encode())
            monkeypatch.setattr(creation,'program_files',lambda:tmp_path)
            monkeypatch.setattr(creation,'verify_paths',lambda *args:None)
            monkeypatch.setattr(creation,'NativeReader',a.NativeReader)
            monkeypatch.setattr(creation,'RegistryReader',a.RegistryReader)
            monkeypatch.setattr(pending_cleanup,'verify_paths',lambda *args:None)
            monkeypatch.setattr(records,'verify_paths',lambda *args:None)
        monkeypatch.setattr(r,'HeldRemainingAttestation',lambda *args:attest())
        calls=[]
        def remove(store,payload,generation,closed):
            assert not handles and not keys and len(absent)==4 and closed(generation) is True
            calls.append('remove-denies')
            receipt=BoundaryReceipt(store.journal,[rule.key.value() for rule in r._held_rules(store,payload)])
            receipt.recover_record('remove_intent');receipt.recover_record('removed')
            return dict(deny_filters_removed=16,client_admission=False)
        monkeypatch.setattr(r,'_remove_backend_denies',remove)
        journal=step.store.journal.load()
        result=r.recover_registered_services(step.store,step.generation,lambda g:state['closed'])
        assert result==dict(services_recovered=True,services_absent=4,new_deletion_requests=4-absent_count,
                            deny_filters_removed=16,client_admission=False)
        assert calls==['remove-denies'] and len(native.deleted)==4-absent_count
        assert step.store.journal.load()==journal
        with pytest.raises(SafetyError):r.recover_registered_services(step.store,step.generation,lambda g:True)
        assert calls==['remove-denies']


@pytest.mark.parametrize('fault',['closed','removal-error','no-receipt','wrong-result'])
def test_uncertain_final_cleanup_is_not_reported_as_recovered(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch,4) as fixture:
        step,_,native,_,state,_,_,_,attest=fixture
        monkeypatch.setattr(r,'HeldRemainingAttestation',lambda *args:attest())
        calls=[]
        def remove(*args):
            calls.append('remove-denies')
            if fault=='removal-error':raise SafetyError('unknown WFP outcome')
            if fault=='wrong-result':return dict(deny_filters_removed=0,client_admission=True)
            return dict(deny_filters_removed=16,client_admission=False)
        monkeypatch.setattr(r,'_remove_backend_denies',remove)
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):r.recover_registered_services(step.store,step.generation,lambda g:state['closed'])
        assert not native.deleted
        assert len(calls)==int(fault!='closed')


def test_unrecorded_foreign_slot_preserves_initial_denies(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch,4) as fixture:
        step,_,native,absent,_,_,_,_,attest=fixture
        for filename in ('service-receipts.json','service-marker-receipts.json'):
            path=step.store.journal.directory/filename;value=json.loads(path.read_bytes())
            value['services']=value['services'][:1];path.write_bytes(json.dumps(value).encode())
        absent.remove('SbieSvc')
        monkeypatch.setattr(r,'HeldRemainingAttestation',lambda *args:attest())
        def forbidden(*args):pytest.fail('Cannot remove initial denies beside a foreign service')
        monkeypatch.setattr(r,'_remove_backend_denies',forbidden)
        with pytest.raises(SafetyError):r.recover_registered_services(step.store,step.generation,lambda g:True)
        assert not native.deleted
        assert json.loads((step.store.journal.directory/BoundaryReceipt.filename).read_bytes())['state']=='committed'
