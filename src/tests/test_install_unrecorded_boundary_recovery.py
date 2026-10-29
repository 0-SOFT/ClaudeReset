import pytest
from claude_reset import install_empty_service_recovery as empty,install_service_recovery as dispatcher
from claude_reset import install_cleanup_observation as observation
from claude_reset.safeio import SafetyError
from test_install_empty_service_recovery import empty_fixture
from test_install_cleanup_observation import Model


@pytest.mark.parametrize('source_missing',[False,True])
@pytest.mark.parametrize('coordinated',[False,True])
def test_failure_before_initial_intent_only_confirms_absence_without_inventing_receipts(tmp_path,monkeypatch,source_missing,coordinated):
    with empty_fixture(tmp_path,monkeypatch,False,'intent',source_missing) as (f,_,_):
        step=f[0];directory=step.store.journal.directory
        for name in ('boundary-receipt.json','reservation-receipt.json'):(directory/name).unlink()
        monkeypatch.setattr(observation,'Engine',Model)
        monkeypatch.setattr(dispatcher,'verify_paths',lambda *args:None)
        before={p.name:p.read_bytes() for p in directory.iterdir() if p.is_file() and p.name!='install.lock'}
        action=dispatcher.recover_service_step if coordinated else empty.recover_empty_service_step
        result=action(step.store,step.generation,lambda g:True)
        assert result['services_recovered'] and result['boundary_absent'] and not result['initial_boundary_recorded']
        assert not result['payload_removed'] and not result['client_admission']
        assert {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file() and p.name!='install.lock'}==before
        assert not f[2].deleted and step.store.journal.lock


@pytest.mark.parametrize('fault',['reservation-receipt.json','reservation-reconciliation-log.json',
    'boundary-reconciliation-log.json','present','query','late-receipt','journal','service','closed'])
def test_missing_history_never_adopts_present_objects_or_later_evidence(tmp_path,monkeypatch,fault):
    with empty_fixture(tmp_path,monkeypatch,False,'intent',True) as (f,_,_):
        step,_,native,absent,state,*_=f;directory=step.store.journal.directory
        for name in ('boundary-receipt.json','reservation-receipt.json'):(directory/name).unlink()
        class Query(Model):
            def __init__(self):
                super().__init__()
                if fault=='present':self.fault='present-FwpmSubLayerGetByKey0'
                if fault=='query':self.fault='FwpmFilterGetByKey0'
            def close(self):
                super().close()
                if fault=='late-receipt':(directory/'boundary-receipt.json').write_bytes(b'late unknown evidence')
                if fault=='journal':
                    value=step.store.journal.load();value['state']='recovery_required';step.store.journal.save(value)
        monkeypatch.setattr(observation,'Engine',Query)
        if fault.endswith('.json'):(directory/fault).write_bytes(b'preserve inconsistent evidence')
        if fault=='service':absent.remove('SbieSvc')
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):
            empty.recover_empty_service_step(step.store,step.generation,lambda g:state['closed'])
        assert not native.deleted
        assert (directory/'boundary-receipt.json').exists() is (fault=='late-receipt')
