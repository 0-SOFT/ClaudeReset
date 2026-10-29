"""Actual staged files/journals; all SCM, registry and WFP mutations modeled."""
from contextlib import contextmanager
import json
import uuid
import pytest
from claude_reset import install_reconciled_cleanup as c,install_removal_confirmation as confirmation
from claude_reset import install_recovery_inputs as inputs_module,install_service_attestation as a
from claude_reset.install_remaining_attestation import HeldRemainingAttestation
from claude_reset.install_reconciliation_log import ReconciliationLog
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.install_reservations import ReservationReceipt
from claude_reset.install_scm import SERVICES,specification
from claude_reset.install_scm_cleanup import DELETE_ACCESS
from claude_reset.safeio import SafetyError
from test_install_remaining_attestation import partial


@contextmanager
def setup(tmp_path,monkeypatch,count=1,*,signed=None):
    with partial(tmp_path,monkeypatch,count,signed=signed) as fixture:
        step,native,absent,state,handles,keys,values=fixture
        directory=step.store.journal.directory
        record=json.loads((directory/ReservationReceipt.filename).read_bytes())
        reservations=ReservationReceipt(step.store.journal,record['keys'])
        reservations.recover_record('remove_intent');reservations.recover_record('removed')
        monkeypatch.setattr(inputs_module,'program_files',lambda:tmp_path)
        monkeypatch.setattr(inputs_module,'verify_paths',lambda *args:None)
        monkeypatch.setattr(c,'verify_paths',lambda *args:None)
        monkeypatch.setattr(confirmation,'verify_paths',lambda *args:None)
        pending=set();state['fault']=None
        reader_type=a.NativeReader;original_release=reader_type.release;original_open=reader_type.open_optional
        original_service_open=reader_type.open;registry_type=a.RegistryReader;original_key_open=registry_type.open
        def service_open(reader,name):
            handle=original_service_open(reader,name);handles.remove(handle)
            handle=(*handle,uuid.uuid4().hex);handles.add(handle);return handle
        def key_open(reader,name):
            key=original_key_open(reader,name);keys.remove(key)
            key=(*key,uuid.uuid4().hex);keys.add(key);return key
        monkeypatch.setattr(reader_type,'open',service_open)
        monkeypatch.setattr(registry_type,'open',key_open)
        def release(reader,handle):
            original_release(reader,handle)
            if handle[1] in pending and not any(h[0]=='service' and h[1]==handle[1] for h in handles):
                pending.remove(handle[1]);absent.add(handle[1])
        def optional(reader,name):
            if name in pending:raise SafetyError('marked for deletion')
            return original_open(reader,name)
        monkeypatch.setattr(reader_type,'release',release)
        monkeypatch.setattr(reader_type,'open_optional',optional)
        class Delete:
            def __call__(self,handle):
                assert handle in handles and handle[0]=='delete'
                if state['fault']=='delete':return False
                native.deleted.append(handle[1]);pending.add(handle[1])
                if state['fault']=='closed':state['closed']=False
                return True
        class Api:
            DeleteService=Delete()
            def OpenServiceW(self,manager,name,access):
                assert manager==73 and access==DELETE_ACCESS and any(h[:2]==('service',name) for h in handles)
                if state['fault']=='open':return None
                handle=('delete',name);handles.add(handle);return handle
            def CloseServiceHandle(self,handle):handles.remove(handle);return True
        def attest():
            held=HeldRemainingAttestation(step.store,step.generation,lambda g:state['closed'])
            held.reader.manager=73;held.reader.api=Api();return held
        with inputs_module.RecoveryInputs(step.store,step.generation) as inputs:
            yield step,inputs,native,absent,state,handles,keys,values,attest


def operation(fixture,held):
    step,inputs,_,_,state,*_=fixture
    return c.ReconciledCleanup(step.store,inputs,held,step.generation,lambda g:state['closed'])


@pytest.mark.parametrize('absent_count',[0,1,2,3,4])
def test_remaining_verified_objects_are_deleted_once_with_separate_attempt_history(tmp_path,monkeypatch,absent_count):
    with setup(tmp_path,monkeypatch,absent_count) as fixture:
        step,_,native,absent,_,handles,keys,_,attest=fixture
        with attest() as held:
            cleanup=operation(fixture,held);result=cleanup.run()
            assert result==dict(services_absent=4,new_deletion_requests=4-absent_count,
                                historical_requests_replayed=False,absence_verified=True,client_admission=False)
            with pytest.raises(SafetyError):cleanup.run()
        assert not handles and not keys and len(native.deleted)==4-absent_count and len(absent)==4
        history=ReconciliationLog(step.store.journal).load()['attempts']
        assert len(history)==1 and history[0]['state']=='complete'
        receipt=RemovalReceipts(step.store.journal).load()
        assert receipt['services']==[] and receipt['completion_basis']=='observed_absence'
        assert json.loads((step.store.journal.directory/'boundary-receipt.json').read_bytes())['state']=='committed'


@pytest.mark.parametrize('fault',['open','delete','completion','completion-durable','closed'])
def test_failed_attempt_requires_fresh_attestation_and_preserves_original_uncertainty(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,native,absent,state,handles,keys,_,attest=fixture
        original=ReconciliationLog.record
        def record(log,identifier,phase,spec):
            if phase!='delete_requested' or fault=='completion-durable':original(log,identifier,phase,spec)
            if phase=='delete_requested':raise OSError('completion result lost')
        if fault.startswith('completion'):monkeypatch.setattr(ReconciliationLog,'record',record)
        else:state['fault']=fault
        with attest() as held:
            cleanup=operation(fixture,held)
            with pytest.raises((SafetyError,OSError)):cleanup.run()
            with pytest.raises(SafetyError):cleanup.run()
            if native.deleted:
                with pytest.raises(SafetyError):attest()
        assert not handles and not keys
        previous=ReconciliationLog(step.store.journal).load()['attempts']
        assert len(previous)==1 and previous[0]['state']=='running'
        monkeypatch.setattr(ReconciliationLog,'record',original);state.update(fault=None,closed=True)
        with attest() as fresh:assert operation(fixture,fresh).run()['absence_verified']
        history=ReconciliationLog(step.store.journal).load()['attempts']
        assert history[:-1]==previous and history[-1]['state']=='complete'
        assert len(native.deleted)==len(set(native.deleted))==3 and len(absent)==4


def test_unknown_original_intent_is_never_rewritten_as_success(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,native,_,_,_,_,_,attest=fixture
        receipt=RemovalReceipts(step.store.journal)
        receipt.record('delete_intent',specification('SbieDrv'));receipt.record('delete_requested',specification('SbieDrv'))
        receipt.record('delete_intent',specification('SbieSvc'));before=receipt.load()['services']
        with attest() as held:assert operation(fixture,held).run()['absence_verified']
        assert receipt.load()['services']==before and len(native.deleted)==3


def test_previously_confirmed_request_cannot_authorize_deleting_a_present_slot(tmp_path,monkeypatch):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,native,_,_,_,_,_,attest=fixture
        receipt=RemovalReceipts(step.store.journal)
        for name in ('SbieDrv','SbieSvc'):
            receipt.record('delete_intent',specification(name));receipt.record('delete_requested',specification(name))
        with attest() as held:
            with pytest.raises(SafetyError,match='Previously confirmed'):operation(fixture,held)
        assert not native.deleted and ReconciliationLog(step.store.journal).load() is None


@pytest.mark.parametrize('fault',['marker','inputs','reservation','log','closed'])
def test_drift_after_intent_is_refused_before_new_deletion(tmp_path,monkeypatch,fault):
    with setup(tmp_path,monkeypatch) as fixture:
        step,inputs,native,_,state,_,_,values,attest=fixture
        original=ReconciliationLog.record
        def changed(log,identifier,phase,spec):
            original(log,identifier,phase,spec)
            if phase!='delete_intent':return
            if fault=='marker':values[spec['name']]=(3,b'changed')
            elif fault=='inputs':inputs.close()
            elif fault=='closed':state['closed']=False
            elif fault=='reservation':
                path=step.store.journal.directory/ReservationReceipt.filename
                value=json.loads(path.read_bytes());value['keys'].reverse();path.write_bytes(json.dumps(value).encode())
            else:
                value=log.load();value['attempts'][-1]['services'][-1]['state']='delete_requested';log.save(value)
        monkeypatch.setattr(ReconciliationLog,'record',changed)
        with attest() as held:
            with pytest.raises(SafetyError):operation(fixture,held).run()
        assert not native.deleted


@pytest.mark.parametrize('durable',[False,True])
def test_unknown_attempt_creation_never_reaches_service_mutation(tmp_path,monkeypatch,durable):
    with setup(tmp_path,monkeypatch) as fixture:
        step,_,native,_,_,_,_,_,attest=fixture
        original=ReconciliationLog.save
        def fail(log,value):
            if durable:original(log,value)
            raise OSError('attempt receipt durability unknown')
        monkeypatch.setattr(ReconciliationLog,'save',fail)
        with attest() as held:
            with pytest.raises(OSError):operation(fixture,held).run()
        assert not native.deleted
        monkeypatch.setattr(ReconciliationLog,'save',original)
        with attest() as fresh:assert operation(fixture,fresh).run()['absence_verified']
        attempts=ReconciliationLog(step.store.journal).load()['attempts']
        assert len(attempts)==(2 if durable else 1)
        if durable:assert attempts[0]['state']=='running' and attempts[0]['services']==[]
