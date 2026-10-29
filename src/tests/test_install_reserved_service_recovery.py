import json
from types import SimpleNamespace
import pytest
from claude_reset import install_reserved_service_recovery as r,install_reservation_reconciliation as reconcile
from claude_reset import install_reservations as reservations
from claude_reset.safeio import SafetyError
from test_install_reservation_confirmation import fixture


@pytest.mark.parametrize('phase,present',[('committed',True),('intent',False),('intent',True)])
def test_reservations_finish_before_fresh_service_deletion_scope(tmp_path,monkeypatch,phase,present):
    with fixture(tmp_path,monkeypatch,present,phase) as f:
        step,_,old_held,native,state,_,path=f;old_held.close();state['allow_mutation']=True
        monkeypatch.setattr(reconcile,'verify_paths',lambda *args:None)
        captured=[];factory=r.HeldAttestation;calls=[]
        def held(*args):
            result=factory(*args);captured.append(result);return result
        monkeypatch.setattr(r,'HeldAttestation',held)
        def services(store,generation,closed):
            assert closed(generation) is True and captured[-1].closed
            assert json.loads(path.read_bytes())['state']=='removed'
            calls.append('services');return dict(services_recovered=True,client_admission=False)
        monkeypatch.setattr(r,'recover_registered_services',services)
        if phase=='intent' and present:
            with pytest.raises(SafetyError):r.recover_reserved_services(step.store,step.generation,lambda g:state['closed'])
            assert not calls
        else:
            result=r.recover_reserved_services(step.store,step.generation,lambda g:state['closed'])
            assert calls==['services'] and result['reservations_absent']
            assert result['new_reservation_removal_transaction'] is present
        assert not native.deleted


def test_legacy_reservation_path_cannot_bypass_reconciliation_history(tmp_path,monkeypatch):
    (tmp_path/'reservation-reconciliation-log.json').write_bytes(b'preserve unknown history')
    store=SimpleNamespace(journal=SimpleNamespace(directory=tmp_path))
    monkeypatch.setattr(reservations,'_installation_inputs',lambda *args,**kwargs:(None,None,None,None))
    with pytest.raises(SafetyError,match='reconciliation protocol'):
        reservations._remove_attested_initial_reservations(store,None,None,'a'*32,None,lambda g:True)
