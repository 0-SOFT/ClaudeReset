"""Read-only pending-creation protocol fixtures; native mutations are modeled."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_creation_attestation as c,install_service_attestation as a
from claude_reset import install_inventory as inventory,install_scm as scm
from claude_reset.install_service_markers import MarkerReceipts,VALUE
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_service_attestation import readers
from test_install_creation_security import service,key


@contextmanager
def pending(tmp_path,monkeypatch,marker_state='intent',present=True,defaults=True,*,signed=None):
    with prepared(tmp_path,monkeypatch,signed=signed) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        directory=step.store.journal.directory
        path=directory/'service-receipts.json';source=json.loads(path.read_bytes())
        source['services']=source['services'][:1];source['services'][-1]['state']='intent'
        path.write_bytes(json.dumps(source).encode())
        marker_path=directory/MarkerReceipts.filename;markers=json.loads(marker_path.read_bytes())
        markers['services']=markers['services'][:1]
        if marker_state=='missing':markers['services']=[]
        else:markers['services'][-1]['state']=marker_state
        marker_path.write_bytes(json.dumps(markers).encode())
        _,handles,keys,values=readers(step,native,monkeypatch)
        if marker_state=='missing':marker_path.unlink()
        state=dict(present=present,orphan=False,closed=True,foreign=False,link=False)
        reader_type=a.NativeReader;registry_type=a.RegistryReader
        original_snapshot=reader_type.snapshot;original_value=registry_type.value
        def optional(reader,name):return reader.open(name) if state['present'] else None
        def snapshot(reader,handle,spec):
            value=original_snapshot(reader,handle,spec)
            if defaults:
                initial=service()[1]
                for name in ('rules','sid_type','owner'):value[name]=initial[name]
            return value
        def registry_value(reader,handle,name):
            if name=='SymbolicLinkValue' and state['link']:return 6,b'link'
            if name==VALUE:
                if state['foreign']:return 3,b'foreign'
                if marker_state=='intent':return None
            return original_value(reader,handle,name)
        monkeypatch.setattr(reader_type,'open_optional',optional,raising=False)
        monkeypatch.setattr(reader_type,'snapshot',snapshot)
        monkeypatch.setattr(registry_type,'value',registry_value)
        if defaults:monkeypatch.setattr(registry_type,'security',lambda *args:key())
        monkeypatch.setattr(c,'NativeReader',reader_type);monkeypatch.setattr(c,'RegistryReader',registry_type)
        monkeypatch.setattr(c,'program_files',lambda:tmp_path);monkeypatch.setattr(c,'verify_paths',lambda *args:None)
        monkeypatch.setattr(inventory,'services',lambda:[dict(name=n,exists=state['present'] if n==scm.SERVICES[0] else True) for n in scm.SERVICES])
        def vacant(name):
            assert name==scm.SERVICES[0]
            if state['orphan']:raise SafetyError('orphan key')
        monkeypatch.setattr(scm,'require_vacant_registry_slot',vacant)
        yield step,native,state,handles,keys


@pytest.mark.parametrize('marker_state,defaults',[('intent',True),('intent',False),('bound',False)])
def test_pending_creation_binding_is_read_only_and_never_promotes_installation(tmp_path,monkeypatch,marker_state,defaults):
    with pending(tmp_path,monkeypatch,marker_state,defaults=defaults) as (step,native,state,handles,keys):
        before=(step.store.journal.directory/'service-receipts.json').read_bytes()
        with c.HeldPendingCreation(step.store,step.generation,lambda g:state['closed']) as held:
            result=held.verify()
            assert result['service_present'] and result['creation_binding_verified']
            assert result['may_delete'] is False and result['client_admission'] is False
            assert len(handles)==len(keys)==1 and not native._created
        assert not handles and not keys and not native.deleted
        assert (step.store.journal.directory/'service-receipts.json').read_bytes()==before


@pytest.mark.parametrize('marker_state',['missing','intent','bound'])
def test_absent_pending_slot_never_requires_inventing_a_marker(tmp_path,monkeypatch,marker_state):
    with pending(tmp_path,monkeypatch,marker_state,present=False) as (step,native,state,handles,keys):
        with c.HeldPendingCreation(step.store,step.generation,lambda g:True) as held:
            result=held.verify()
            assert not result['service_present'] and not result['creation_binding_verified']
            state['present']=True
            with pytest.raises(SafetyError):held.verify()
        assert not handles and not keys and not native.deleted


@pytest.mark.parametrize('fault',['missing','display','foreign','link','closed','orphan','bound-defaults'])
def test_unknown_or_changed_pending_object_is_not_claimed(tmp_path,monkeypatch,fault):
    marker='missing' if fault=='missing' else 'bound' if fault=='bound-defaults' else 'intent'
    with pending(tmp_path,monkeypatch,marker,present=fault!='orphan') as (step,native,state,handles,keys):
        if fault=='display':native.displays[scm.SERVICES[0]]='foreign'
        if fault in ('foreign','link','orphan'):state[fault]=True
        if fault=='closed':state['closed']=False
        with pytest.raises(SafetyError):c.HeldPendingCreation(step.store,step.generation,lambda g:state['closed'])
        assert not handles and not keys and not native.deleted
