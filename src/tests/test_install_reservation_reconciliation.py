import pytest
from claude_reset import install_reservation_reconciliation as r
from claude_reset.safeio import SafetyError
from test_install_reservation_confirmation import fixture


def run(f,monkeypatch):
    step,inputs,held,_,state,*_=f
    monkeypatch.setattr(r,'verify_paths',lambda *args:None);state['allow_mutation']=True
    return r.reconcile_committed_reservations(step.store,inputs,held,step.generation,lambda g:state['closed'])


def history(f):
    step,_,_,_,_,_,path=f
    import json
    value=json.loads(path.read_bytes())
    return r.ReservationAttempts(r.ReservationReceipt(step.store.journal,value['keys']))


@pytest.mark.parametrize('present,phase',[(True,'committed'),(True,'remove_intent'),(False,'committed'),(False,'remove_intent')])
def test_owned_pair_reconciles_with_separate_attempts_and_keeps_initial_denies(tmp_path,monkeypatch,present,phase):
    with fixture(tmp_path,monkeypatch,present,phase) as f:
        _,_,held,native,state,parents,_=f
        result=run(f,monkeypatch)
        assert result['reservations_absent'] and result['new_removal_transaction'] is present and not result['client_admission']
        log=history(f);before=log.load()
        assert before['absence_verified'] and len(before['attempts'])==int(present)
        assert state['strict'] and not state['present'] and not held.closed and not native.deleted
        assert sum(p.events.count('FwpmFilterDeleteByKey0') for p in parents)==16*int(present)
        assert run(f,monkeypatch)['new_removal_transaction'] is False and log.load()==before


@pytest.mark.parametrize('fault',['before-commit','after-commit','completion-write'])
def test_uncertain_pair_removal_rechecks_current_state_without_inventing_old_success(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch,True,'committed') as f:
        _,_,_,native,state,parents,_=f;state['fault']=fault
        original=r.ReservationAttempts.committed
        if fault=='completion-write':
            def lost(*args):raise OSError('completion write failed')
            monkeypatch.setattr(r.ReservationAttempts,'committed',lost)
        with pytest.raises((SafetyError,OSError)):run(f,monkeypatch)
        before=history(f).load()['attempts'];assert len(before)==1 and before[0]['state']=='remove_intent'
        state['fault']=None;monkeypatch.setattr(r.ReservationAttempts,'committed',original)
        assert run(f,monkeypatch)['reservations_absent']
        assert history(f).load()['attempts'][:1]==before and not native.deleted


@pytest.mark.parametrize('fault',['initial-intent','known-commit','known-absence','closed-after-intent'])
def test_unknown_creation_and_reappeared_pairs_never_authorize_deletion(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch,True,'intent' if fault=='initial-intent' else 'committed') as f:
        _,_,_,native,state,parents,_=f
        if fault=='known-commit':
            log=history(f);log.committed(log.begin())
        if fault=='known-absence':
            log=history(f);log.observe_absence(dict(keys=log.receipt.keys,state='absent',transaction_consistent=True,
                                                   settings_changed=False,client_admission=False))
        if fault=='closed-after-intent':
            original=r.ReservationAttempts.begin
            def changed(log):identifier=original(log);state['closed']=False;return identifier
            monkeypatch.setattr(r.ReservationAttempts,'begin',changed)
        with pytest.raises(SafetyError):run(f,monkeypatch)
        assert not native.deleted and not any('FwpmFilterDeleteByKey0' in p.events for p in parents)
