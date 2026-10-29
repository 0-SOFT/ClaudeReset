"""Query-only reconciliation fixtures; no native service or registry mutation."""
import ctypes as C
from contextlib import contextmanager
import pytest
from claude_reset import install_remaining_attestation as r,install_service_attestation as a
from claude_reset import install_inventory as inventory,install_scm as scm
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_service_attestation import readers


@contextmanager
def partial(tmp_path,monkeypatch,count=2,*,signed=None):
    with prepared(tmp_path,monkeypatch,signed=signed) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        _,handles,keys,values=readers(step,native,monkeypatch)
        absent=set(scm.SERVICES[len(scm.SERVICES)-count:]) if count else set()
        state=dict(closed=True,orphan=False,pending=False)
        reader_type=a.NativeReader
        def optional(reader,name):
            if state['pending']:raise SafetyError('pending service deletion')
            return None if name in absent else reader.open(name)
        monkeypatch.setattr(reader_type,'open_optional',optional,raising=False)
        monkeypatch.setattr(r,'NativeReader',reader_type);monkeypatch.setattr(r,'RegistryReader',a.RegistryReader)
        monkeypatch.setattr(inventory,'services',lambda:[dict(name=n,exists=n not in absent) for n in scm.SERVICES])
        def vacant(name):
            if state['orphan']:raise SafetyError('orphan registry key')
            assert name in absent
        monkeypatch.setattr(scm,'require_vacant_registry_slot',vacant)
        yield step,native,absent,state,handles,keys,values


@pytest.mark.parametrize('count',[0,1,2,3,4])
def test_only_remaining_handles_are_held_without_claiming_original_creation(tmp_path,monkeypatch,count):
    with partial(tmp_path,monkeypatch,count) as (step,native,absent,state,handles,keys,_):
        with r.HeldRemainingAttestation(step.store,step.generation,lambda g:state['closed']) as held:
            result=held.verify()
            assert len(handles)==len(keys)==4-count and not native._created
            assert result['observed_absent_services']==[n for n in scm.SERVICES if n in absent]
            assert [row['name'] for row in result['services']]==[n for n in scm.SERVICES if n not in absent]
            assert result['may_delete'] is False and result['client_admission'] is False
            assert result['original_creation_identity_verified'] is False
        assert not handles and not keys and not native.deleted


@pytest.mark.parametrize('fault',['hole','orphan','pending','marker','closed'])
def test_incomplete_or_foreign_partial_evidence_releases_query_handles(tmp_path,monkeypatch,fault):
    with partial(tmp_path,monkeypatch) as (step,native,absent,state,handles,keys,values):
        if fault=='hole':absent.clear();absent.add(scm.SERVICES[0])
        if fault in ('orphan','pending'):state[fault]=True
        if fault=='marker':values[scm.SERVICES[0]]=(3,b'foreign')
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):r.HeldRemainingAttestation(step.store,step.generation,lambda g:state['closed'])
        assert not handles and not keys and not native.deleted


def test_absent_prefix_is_rechecked_while_remaining_objects_stay_held(tmp_path,monkeypatch):
    with partial(tmp_path,monkeypatch) as (step,native,absent,state,handles,keys,_):
        with r.HeldRemainingAttestation(step.store,step.generation,lambda g:True) as held:
            absent.remove('SbieDrv')
            with pytest.raises(SafetyError):held.verify_service('ClaudeResetBackend')
            assert len(handles)==2 and not native.deleted
        assert not handles and not keys


@pytest.mark.parametrize('error',[1060,1072,5,0,6])
def test_optional_native_open_accepts_only_definite_nonexistence(error):
    class Api:
        def OpenServiceW(self,manager,name,access):
            assert manager==73 and name=='SbieDrv' and access==a.ACCESS
            C.set_last_error(error);return None
    reader=a.NativeReader.__new__(a.NativeReader);reader.api=Api();reader.manager=73
    if error==1060:assert reader.open_optional('SbieDrv') is None
    else:
        with pytest.raises(SafetyError):reader.open_optional('SbieDrv')
