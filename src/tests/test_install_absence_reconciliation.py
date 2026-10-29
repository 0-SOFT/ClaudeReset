"""Real protected-file fixtures; modeled service deletion and absence inspection."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_removal_confirmation as c,install_inventory as inventory,install_scm as scm
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.install_recovery_inputs import RecoveryInputs
from claude_reset.safeio import SafetyError
from test_install_attested_cleanup import setup,cleanup


@contextmanager
def uncertain(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,inputs,held,native,state,_,handles=fixture
        original=RemovalReceipts.record
        def fail(receipt,phase,spec):
            if phase=='delete_requested' and spec['name']==scm.SERVICES[0]:
                raise OSError('lost completion before durable write')
            return original(receipt,phase,spec)
        monkeypatch.setattr(RemovalReceipts,'record',fail)
        with pytest.raises(OSError):cleanup(fixture).run()
        monkeypatch.setattr(RemovalReceipts,'record',original)
        assert len(native.deleted)==4
        held.close();inputs.close();assert not handles
        monkeypatch.setattr(c,'verify_paths',lambda *args:None)
        checks=[]
        def snapshot():
            checks.append('scm')
            return [dict(name=n,exists=state['pending'] and n==scm.SERVICES[0]) for n in scm.SERVICES]
        def vacant(name):
            checks.append(name)
            if state['fault']=='registry':raise SafetyError('orphan key')
        monkeypatch.setattr(inventory,'services',snapshot)
        monkeypatch.setattr(scm,'require_vacant_registry_slot',vacant)
        with RecoveryInputs(step.store,step.generation) as fresh:
            yield step,fresh,native,state,checks


def reconcile(fixture):
    step,inputs,_,state,_=fixture
    return c.reconcile_recorded_absence(step.store,inputs,step.generation,lambda g:state['closed'])


def test_unknown_last_result_is_preserved_while_actual_absence_is_confirmed(tmp_path,monkeypatch):
    with uncertain(tmp_path,monkeypatch) as fixture:
        step,inputs,native,_,checks=fixture
        receipt=RemovalReceipts(step.store.journal);before=receipt.load()
        assert before['services'][-1]['state']=='delete_intent' and not before['absence_verified']
        result=reconcile(fixture);after=receipt.load()
        assert result==dict(services_removed=4,absence_verified=True,deletion_replayed=False,
                           client_admission=False,completion_basis='observed_absence',deletion_outcome_known=False)
        assert after['services']==before['services'] and after['schema']==2
        assert after['completion_basis']=='observed_absence' and after['absence_verified']
        assert checks==['scm',*reversed(scm.SERVICES)]
        assert reconcile(fixture)==result and len(native.deleted)==4 and len(checks)==10
        with pytest.raises(SafetyError):receipt.record('delete_requested',before['services'][-1]['spec'])
        with pytest.raises(SafetyError):c.confirm_recorded_removal(step.store,inputs,step.generation,lambda g:True)
        assert json.loads((step.store.journal.directory/'boundary-receipt.json').read_bytes())['state']=='committed'


@pytest.mark.parametrize('fault',['earlier-intent','marker','pending','registry','closed','drift'])
def test_ambiguous_or_incomplete_scope_is_never_replayed_or_confirmed(tmp_path,monkeypatch,fault):
    with uncertain(tmp_path,monkeypatch) as fixture:
        step,_,native,state,checks=fixture;directory=step.store.journal.directory
        receipt=directory/'service-removal-receipts.json'
        if fault in ('partial','earlier-intent','known-result'):
            value=json.loads(receipt.read_bytes())
            if fault=='partial':value['services'].pop()
            elif fault=='earlier-intent':value['services'][0]['state']='delete_intent'
            else:value['services'][-1]['state']='delete_requested'
            receipt.write_bytes(json.dumps(value).encode())
        if fault=='marker':
            path=directory/'service-marker-receipts.json';value=json.loads(path.read_bytes())
            value['services'][-1]['state']='intent';path.write_bytes(json.dumps(value).encode())
        if fault=='pending':state['pending']=True
        if fault=='registry':state['fault']='registry'
        if fault=='closed':state['closed']=False
        if fault=='drift':
            original=c._confirm_absence
            def changed(names,closed):
                result=original(names,closed)
                value=step.store.journal.load();value['state']='recovery_required';step.store.journal.save(value)
                return result
            monkeypatch.setattr(c,'_confirm_absence',changed)
        with pytest.raises(SafetyError):reconcile(fixture)
        assert len(native.deleted)==4
        assert json.loads(receipt.read_bytes())['absence_verified'] is False
        if fault in ('earlier-intent','marker','closed'):assert checks==[]


@pytest.mark.parametrize('durable',[False,True])
def test_failed_observation_write_can_only_resume_with_fresh_absence(tmp_path,monkeypatch,durable):
    with uncertain(tmp_path,monkeypatch) as fixture:
        step,_,native,state,checks=fixture;original=RemovalReceipts.save
        def fail(receipt,value):
            if durable:original(receipt,value)
            raise OSError('observation durability unknown')
        monkeypatch.setattr(RemovalReceipts,'save',fail)
        with pytest.raises(OSError):reconcile(fixture)
        monkeypatch.setattr(RemovalReceipts,'save',original)
        state['pending']=True
        with pytest.raises(SafetyError):reconcile(fixture)
        state['pending']=False
        assert reconcile(fixture)['absence_verified'] and len(native.deleted)==4
        assert checks.count('scm')==3


@pytest.mark.parametrize('history',['missing','empty','partial','known'])
def test_complete_absence_never_invents_missing_deletion_history(tmp_path,monkeypatch,history):
    with uncertain(tmp_path,monkeypatch) as fixture:
        step,_,native,_,_=fixture;receipt=RemovalReceipts(step.store.journal)
        original=receipt.load()
        if history=='missing':receipt.path.unlink();states=[]
        else:
            if history=='empty':original['services']=[]
            elif history=='partial':original['services']=original['services'][:2]
            else:original['services'][-1]['state']='delete_requested'
            receipt.save(original);states=original['services']
        result=reconcile(fixture);after=receipt.load()
        assert after['services']==states and after['absence_verified'] is True
        assert result['deletion_outcome_known'] is (history=='known')
        assert len(native.deleted)==4 and result['deletion_replayed'] is False
