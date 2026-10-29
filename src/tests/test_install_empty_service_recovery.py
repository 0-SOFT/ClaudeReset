import json
from contextlib import contextmanager
import pytest
from claude_reset import install_empty_service_recovery as r
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.safeio import SafetyError
from test_install_reconciled_cleanup import setup
from test_install_boundary_confirmation import engine_model


@contextmanager
def empty_fixture(tmp_path,monkeypatch,present,phase,source_missing=False):
    with setup(tmp_path,monkeypatch,4) as fixture:
        step,_,_,_,_,_,_,_,_=fixture
        directory=step.store.journal.directory
        for filename in ('service-receipts.json','service-marker-receipts.json'):
            path=directory/filename
            if source_missing:path.unlink()
            else:
                value=json.loads(path.read_bytes());value['services']=[];path.write_bytes(json.dumps(value).encode())
        (directory/'policy-binding-receipt.json').unlink()
        path=directory/BoundaryReceipt.filename;value=json.loads(path.read_bytes());value['state']=phase
        path.write_bytes(json.dumps(value).encode())
        monkeypatch.setattr(r,'verify_paths',lambda *args:None)
        events=engine_model(fixture,monkeypatch,present)
        calls=[]
        def reconcile(store,inputs,generation,closed):
            assert closed(generation) is True
            if present:calls.append('remove')
            from claude_reset.install_boundary import _held_rules
            receipt=BoundaryReceipt(store.journal,[v.key.value() for v in _held_rules(store,inputs.payload)])
            receipt.confirm_absent(dict(keys=receipt.keys,state='absent',transaction_consistent=True,
                                        settings_changed=False,client_admission=False))
            return dict(boundary_absent=True,new_removal_transaction=present,historical_attempts_replayed=False,client_admission=False)
        monkeypatch.setattr(r,'reconcile_committed_boundary',reconcile)
        yield fixture,events,calls


@pytest.mark.parametrize('present,phase,missing',[(False,'intent',True),(False,'intent',False),
    (False,'remove_intent',False),(False,'removed',False),(True,'committed',True),(True,'committed',False),
    (True,'remove_intent',False)])
def test_failure_before_service_creation_recovers_only_proven_boundary(tmp_path,monkeypatch,present,phase,missing):
    with empty_fixture(tmp_path,monkeypatch,present,phase,missing) as (fixture,events,calls):
        step,_,native,_,state,*_=fixture;journal=step.store.journal.load()
        result=r.recover_empty_service_step(step.store,step.generation,lambda g:state['closed'])
        assert result==dict(services_recovered=True,services_created=False,boundary_absent=True,
                            payload_removed=False,client_admission=False)
        assert calls==(['remove'] if present else []) and not native.deleted
        assert step.store.journal.load()==journal
        value=json.loads((step.store.journal.directory/BoundaryReceipt.filename).read_bytes())
        assert value['state']=='removed'
        if not present:assert value['previous_state']==phase and value['completion_basis']=='observed_absence'


@pytest.mark.parametrize('fault',['intent-present','binding','marker-without-source','foreign','closed','drift'])
def test_empty_history_does_not_authorize_foreign_or_uncertain_mutations(tmp_path,monkeypatch,fault):
    phase='remove_intent' if fault=='uncertain-delete' else 'intent'
    with empty_fixture(tmp_path,monkeypatch,fault in ('intent-present','uncertain-delete'),phase,True) as (fixture,events,calls):
        step,_,native,absent,state,*_=fixture;directory=step.store.journal.directory
        if fault=='binding':(directory/'policy-binding-receipt.json').write_bytes(b'foreign')
        if fault=='marker-without-source':(directory/'service-marker-receipts.json').write_bytes(b'foreign')
        if fault=='foreign':absent.remove('SbieSvc')
        if fault=='closed':state['closed']=False
        if fault=='drift':
            original=r.inspect_recovery_boundary
            def changed(*args):
                result=original(*args);(directory/'service-reconciliation-log.json').write_bytes(b'changed');return result
            monkeypatch.setattr(r,'inspect_recovery_boundary',changed)
        with pytest.raises(SafetyError):r.recover_empty_service_step(step.store,step.generation,lambda g:state['closed'])
        assert not calls and not native.deleted
        assert json.loads((directory/BoundaryReceipt.filename).read_bytes())['state']==phase
