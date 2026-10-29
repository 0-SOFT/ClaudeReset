"""Real journal/files, modeled BFE transactions; no system WFP changes."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_boundary_reconciliation as r,install_boundary_confirmation as c
from claude_reset.strict_wfp import Engine
from claude_reset.install_boundary_attempts import BoundaryAttempts
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.safeio import SafetyError
from test_install_reconciled_cleanup import setup


@contextmanager
def fixture(tmp_path,monkeypatch,present=True,phase='committed',*,signed=None):
    with setup(tmp_path,monkeypatch,4,signed=signed) as original:
        step,inputs,_,_,state,*_=original
        path=step.store.journal.directory/BoundaryReceipt.filename;value=json.loads(path.read_bytes())
        value['state']=phase;path.write_bytes(json.dumps(value).encode())
        state.update(present=present,fault=None);events=[]
        keys={v.key.value() for v in r._held_rules(step.store,inputs.payload)}
        def factory():
            engine=Engine.__new__(Engine);engine.handle=17;engine.dynamic=False;engine._transaction=False
            engine.existing_sublayer=lambda:state['present']
            engine.own_keys=lambda:keys if state['present'] else set()
            engine.exists_verified=lambda rule:state['present']
            def call(name,signature,*args):
                assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0')
                if name=='FwpmTransactionBegin0':assert args[-1]==1
            engine._call=call;engine.close=lambda:None
            def remove(rules,closed):
                assert closed() is True and {v.key.value() for v in rules}==keys
                events.append('remove')
                if state['fault']=='before-commit':raise SafetyError('unknown outcome before commit')
                state['present']=False
                if state['fault']=='after-commit':raise SafetyError('commit reply lost')
                assert closed() is True
            engine.remove_recorded_denies=remove
            return engine
        monkeypatch.setattr(c,'Engine',factory);monkeypatch.setattr(r,'Engine',factory)
        monkeypatch.setattr(c,'verify_paths',lambda *args:None);monkeypatch.setattr(r,'verify_paths',lambda *args:None)
        receipt=BoundaryReceipt(step.store.journal,[v.key.value() for v in r._held_rules(step.store,inputs.payload)])
        yield step,inputs,state,events,BoundaryAttempts(receipt)


def run(f):
    step,inputs,state,*_=f
    return r.reconcile_committed_boundary(step.store,inputs,step.generation,lambda g:state['closed'])


@pytest.mark.parametrize('present,phase',[(True,'committed'),(True,'remove_intent'),(False,'committed'),(False,'remove_intent')])
def test_current_owned_set_is_reconciled_without_inventing_old_commit_results(tmp_path,monkeypatch,present,phase):
    with fixture(tmp_path,monkeypatch,present,phase) as f:
        step,_,state,events,log=f
        result=run(f)
        assert result['boundary_absent'] and result['new_removal_transaction'] is present and not result['client_admission']
        history=log.load();assert history['absence_verified'] and len(history['attempts'])==int(present)
        assert log.receipt.load()['previous_state']==phase
        assert events==(['remove'] if present else [])
        assert run(f)['new_removal_transaction'] is False and log.load()==history


@pytest.mark.parametrize('fault',['before-commit','after-commit','completion-write'])
def test_uncertain_attempt_retained_when_fresh_observation_allows_recovery(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as f:
        _,_,state,events,log=f;state['fault']=fault
        original=BoundaryAttempts.committed
        if fault=='completion-write':
            def lost(*args):raise OSError('completion write lost')
            monkeypatch.setattr(BoundaryAttempts,'committed',lost)
        with pytest.raises((SafetyError,OSError)):run(f)
        previous=log.load()['attempts'];assert len(previous)==1 and previous[0]['state']=='remove_intent'
        state['fault']=None;monkeypatch.setattr(BoundaryAttempts,'committed',original)
        assert run(f)['boundary_absent']
        assert log.load()['attempts'][:1]==previous
        assert len(events)==(2 if fault=='before-commit' else 1)


@pytest.mark.parametrize('known',['initial-intent','committed','absent','drift-after-intent'])
def test_unknown_creation_or_contradictory_present_objects_are_not_adopted(tmp_path,monkeypatch,known):
    with fixture(tmp_path,monkeypatch,phase='intent' if known=='initial-intent' else 'committed') as f:
        step,_,state,events,log=f
        if known=='committed':log.committed(log.begin())
        if known=='absent':
            log.observe_absence(dict(keys=log.receipt.keys,state='absent',transaction_consistent=True,
                                    settings_changed=False,client_admission=False))
        if known=='drift-after-intent':
            original=BoundaryAttempts.begin
            def changed(history):
                identifier=original(history);state['closed']=False;return identifier
            monkeypatch.setattr(BoundaryAttempts,'begin',changed)
        with pytest.raises(SafetyError):run(f)
        assert not events and state['present']


def test_attempt_history_is_bounded_and_cannot_be_rebound_or_rewritten(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as f:
        _,_,_,events,log=f
        for _ in range(16):log.begin()
        before=log.load()
        with pytest.raises(SafetyError):log.begin()
        assert log.load()==before
        for field,value in [('schema',True),('source_sha256','0'*64),('absence_verified',1)]:
            changed=dict(before);changed[field]=value
            with pytest.raises(SafetyError):log.save(changed)
        changed=dict(before,attempts=[before['attempts'][0],before['attempts'][0]])
        with pytest.raises(SafetyError):log.save(changed)
        assert not events and log.load()==before


@pytest.mark.parametrize('phase',['committed','remove_intent'])
def test_empty_step_uses_real_reconciliation_order_with_modeled_bfe(tmp_path,monkeypatch,phase):
    from claude_reset import install_empty_service_recovery as empty
    with fixture(tmp_path,monkeypatch,phase=phase) as f:
        step,_,state,events,log=f;directory=step.store.journal.directory
        for filename in ('service-receipts.json','service-marker-receipts.json'):
            path=directory/filename;value=json.loads(path.read_bytes());value['services']=[]
            path.write_bytes(json.dumps(value).encode())
        (directory/'policy-binding-receipt.json').unlink()
        monkeypatch.setattr(empty,'verify_paths',lambda *args:None)
        result=empty.recover_empty_service_step(step.store,step.generation,lambda g:state['closed'])
        assert result['services_recovered'] and not result['client_admission']
        assert events==['remove'] and log.load()['absence_verified']
