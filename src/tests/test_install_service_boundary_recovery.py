import json
import pytest
from claude_reset import install_service_boundary_recovery as r
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.install_scm import SERVICES
from claude_reset.safeio import SafetyError
from test_install_boundary_reconciliation import fixture


def prepare(f,monkeypatch):
    step,*_=f
    RemovalReceipts(step.store.journal).confirm_observed(dict(services=list(reversed(SERVICES)),
                                                           absence_verified=True,client_admission=False))
    monkeypatch.setattr(r,'verify_paths',lambda *args:None)


@pytest.mark.parametrize('phase,present',[('committed',True),('remove_intent',True),('remove_intent',False),('removed',False)])
def test_boundary_tail_rechecks_all_services_without_replaying_service_deletion(tmp_path,monkeypatch,phase,present):
    with fixture(tmp_path,monkeypatch,present,phase) as f:
        step,_,state,events,_=f;prepare(f,monkeypatch)
        before=RemovalReceipts(step.store.journal).load();journal=step.store.journal.load()
        result=r.recover_removed_service_boundary(step.store,step.generation,lambda g:state['closed'])
        assert result==dict(services_recovered=True,services_absent=4,new_deletion_requests=0,
                            deny_filters_absent=16,new_deny_removal_transaction=present,client_admission=False)
        assert RemovalReceipts(step.store.journal).load()==before and step.store.journal.load()==journal
        assert events==(['remove'] if present else [])


@pytest.mark.parametrize('fault',['missing','not-confirmed','marker','closed','initial-intent'])
def test_unknown_service_completion_cannot_authorize_boundary_tail(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch,phase='intent' if fault=='initial-intent' else 'committed') as f:
        step,_,state,events,_=f
        if fault!='missing':prepare(f,monkeypatch)
        else:monkeypatch.setattr(r,'verify_paths',lambda *args:None)
        if fault=='not-confirmed':
            receipt=RemovalReceipts(step.store.journal);value=receipt.load()
            value.update(schema=1,absence_verified=False);del value['completion_basis'];receipt.save(value)
        if fault=='marker':
            path=step.store.journal.directory/'service-marker-receipts.json';value=json.loads(path.read_bytes())
            value['services'][-1]['state']='intent';path.write_bytes(json.dumps(value).encode())
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):r.recover_removed_service_boundary(step.store,step.generation,lambda g:state['closed'])
        assert not events
