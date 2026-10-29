import json
import pytest
from claude_reset import install_service_recovery as r,install_registered_recovery as registered
from claude_reset import install_cleanup_observation as observation
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.safeio import SafetyError
from test_install_reconciled_cleanup import setup
from test_install_cleanup_observation import Model


def final_queries(monkeypatch):
    monkeypatch.setattr(r,'verify_paths',lambda *args:None)
    monkeypatch.setattr(observation,'Engine',Model)


@pytest.mark.parametrize('absent_count',[0,4])
def test_dispatcher_runs_real_registration_recovery_then_fresh_absence(tmp_path,monkeypatch,absent_count):
    with setup(tmp_path,monkeypatch,absent_count) as f:
        step,_,native,absent,state,handles,registry,_,attest=f
        final_queries(monkeypatch)
        monkeypatch.setattr(registered,'HeldRemainingAttestation',lambda *args:attest())
        def remove(store,payload,generation,closed):
            assert not handles and not registry and len(absent)==4 and closed(generation)
            receipt=BoundaryReceipt(store.journal,[v.key.value() for v in registered._held_rules(store,payload)])
            receipt.recover_record('remove_intent');receipt.recover_record('removed')
            return dict(deny_filters_removed=16,client_admission=False)
        monkeypatch.setattr(registered,'_remove_backend_denies',remove)
        tx=step.store.journal.load();source=r.ServiceReceipts(step.store.journal).load()
        result=r.recover_service_step(step.store,step.generation,lambda g:state['closed'])
        assert result['recovery_route']=='registrations' and not result['payload_removed']
        assert not result['client_admission'] and not result['journal_advanced']
        assert len(native.deleted)==4-absent_count
        assert step.store.journal.load()==tx and r.ServiceReceipts(step.store.journal).load()==source


def test_dispatcher_empty_route_preserves_unknown_creation_phase(tmp_path,monkeypatch):
    from test_install_empty_service_recovery import empty_fixture
    with empty_fixture(tmp_path,monkeypatch,False,'intent',True) as (f,events,calls):
        step=f[0];final_queries(monkeypatch)
        result=r.recover_service_step(step.store,step.generation,lambda g:True)
        assert result['recovery_route']=='empty' and not result['services_created'] and not calls
        record=json.loads((step.store.journal.directory/BoundaryReceipt.filename).read_bytes())
        assert record['previous_state']=='intent' and record['completion_basis']=='observed_absence'


def test_dispatcher_boundary_tail_never_redeletes_services(tmp_path,monkeypatch):
    from test_install_boundary_reconciliation import fixture
    from test_install_service_boundary_recovery import prepare
    with fixture(tmp_path,monkeypatch,False,'remove_intent') as f:
        step=f[0];prepare(f,monkeypatch);final_queries(monkeypatch)
        result=r.recover_service_step(step.store,step.generation,lambda g:True)
        assert result['recovery_route']=='boundary' and result['new_deletion_requests']==0


def test_reservation_route_does_not_adopt_unknown_initial_creation(tmp_path,monkeypatch):
    from test_install_reservation_confirmation import fixture
    with fixture(tmp_path,monkeypatch,True,'intent') as f:
        step,_,held,native,state,parents,_=f;held.close();final_queries(monkeypatch)
        with pytest.raises(SafetyError,match='Uncertain reservation creation'):
            r.recover_service_step(step.store,step.generation,lambda g:state['closed'])
        assert not native.deleted and not any('FwpmFilterDeleteByKey0' in p.events for p in parents)


@pytest.mark.parametrize('fault',['closed','acl','later-history','unknown-boundary','missing-boundary','wrong-result','present-after-recovery'])
def test_dispatcher_refuses_inconsistent_or_unverified_completion(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch,4) as f:
        step=f[0];final_queries(monkeypatch);calls=[]
        directory=step.store.journal.directory
        if fault=='later-history':
            path=directory/r.ReservationReceipt.filename;v=json.loads(path.read_bytes());v['state']='committed'
            path.write_bytes(json.dumps(v).encode());(directory/'service-removal-receipts.json').write_bytes(b'unknown')
        if fault=='missing-boundary':(directory/BoundaryReceipt.filename).unlink()
        if fault=='unknown-boundary':
            path=directory/BoundaryReceipt.filename;v=json.loads(path.read_bytes());v['state']='remove_intent'
            path.write_bytes(json.dumps(v).encode())
        if fault=='acl':
            def denied(*args):raise SafetyError('untrusted metadata ACL')
            monkeypatch.setattr(r,'verify_paths',denied)
        def action(store,generation,closed):
            calls.append('recovery')
            if fault=='present-after-recovery':
                path=directory/BoundaryReceipt.filename;v=json.loads(path.read_bytes());v['state']='removed'
                path.write_bytes(json.dumps(v).encode())
                return dict(services_recovered=True,client_admission=False)
            return dict(services_recovered=True,client_admission=True)
        monkeypatch.setattr(r,'recover_registered_services',action)
        if fault=='present-after-recovery':
            class Reappeared(Model):
                def __init__(self):super().__init__();self.fault='present-FwpmFilterGetByKey0'
            monkeypatch.setattr(observation,'Engine',Reappeared)
        with pytest.raises(SafetyError):r.recover_service_step(step.store,step.generation,lambda g:fault!='closed')
        assert len(calls)==int(fault in ('wrong-result','present-after-recovery')) and not f[2].deleted
