import json
import pytest
from claude_reset import install_boundary_confirmation as c
from claude_reset.strict_wfp import Engine
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.safeio import SafetyError
from test_install_reconciled_cleanup import setup


def engine_model(fixture,monkeypatch,present=False):
    step,inputs,*_=fixture;events=[]
    keys={r.key.value() for r in c._held_rules(step.store,inputs.payload)}
    engine=Engine.__new__(Engine);engine.handle=17;engine.dynamic=False;engine._transaction=False
    engine.existing_sublayer=lambda:present
    engine.own_keys=lambda:keys if present else set()
    engine.exists_verified=lambda rule:present
    def call(name,signature,*args):
        assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0')
        if name=='FwpmTransactionBegin0':assert args[-1]==1
        events.append(name)
    engine._call=call;engine.close=lambda:events.append('close')
    monkeypatch.setattr(c,'Engine',lambda:engine)
    monkeypatch.setattr(c,'verify_paths',lambda *args:None)
    return events


@pytest.mark.parametrize('previous',['intent','committed','remove_intent','removed'])
def test_actual_absence_preserves_uncertain_previous_phase_without_replay(tmp_path,monkeypatch,previous):
    with setup(tmp_path,monkeypatch,4) as fixture:
        step,inputs,native,_,state,*_=fixture;events=engine_model(fixture,monkeypatch)
        path=step.store.journal.directory/BoundaryReceipt.filename;old=json.loads(path.read_bytes())
        old['state']=previous;path.write_bytes(json.dumps(old).encode())
        result=c.reconcile_boundary_absence(step.store,inputs,step.generation,lambda g:state['closed'])
        current=json.loads(path.read_bytes())
        assert current==dict(old,schema=2,state='removed',previous_state=previous,completion_basis='observed_absence')
        assert result['deletion_replayed'] is False and result['client_admission'] is False
        assert events==['FwpmTransactionBegin0','FwpmTransactionAbort0','close'] and not native.deleted
        c.reconcile_boundary_absence(step.store,inputs,step.generation,lambda g:True)
        assert json.loads(path.read_bytes())==current
        assert len(events)==6


@pytest.mark.parametrize('fault',['present','foreign-service','closed','inputs','acl','receipt-drift','reservation-drift','wrong-generation'])
def test_absence_confirmation_cannot_promote_unverified_or_changed_evidence(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch,4) as fixture:
        step,inputs,native,absent,state,*_=fixture;events=engine_model(fixture,monkeypatch,fault=='present')
        path=step.store.journal.directory/BoundaryReceipt.filename;original=path.read_bytes()
        if fault=='foreign-service':absent.remove('SbieSvc')
        if fault=='closed':state['closed']=False
        if fault=='inputs':inputs.close()
        if fault=='acl':
            def refused(*args):raise SafetyError('unprotected receipt')
            monkeypatch.setattr(c,'verify_paths',refused)
        if fault in ('receipt-drift','reservation-drift'):
            observe=c.observe_initial_denies
            def changed(*args):
                result=observe(*args)
                if fault=='receipt-drift':
                    value=json.loads(path.read_bytes());value['state']='remove_intent';path.write_bytes(json.dumps(value).encode())
                else:(step.store.journal.directory/'reservation-receipt.json').unlink()
                return result
            monkeypatch.setattr(c,'observe_initial_denies',changed)
        with pytest.raises(SafetyError):c.reconcile_boundary_absence(step.store,inputs,
            'f'*32 if fault=='wrong-generation' else step.generation,lambda g:state['closed'])
        assert not native.deleted
        assert json.loads(path.read_bytes())['schema']==1
        if fault!='receipt-drift':assert path.read_bytes()==original
