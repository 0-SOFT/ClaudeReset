"""Fresh-reader recovery evidence with real fixture receipts and modeled SCM/HKLM."""
import json
import pytest
from claude_reset import install_service_attestation as a
from claude_reset.install_service_markers import MarkerReceipts,encoded,VALUE
from claude_reset.install_scm import specification
from claude_reset.safeio import SafetyError
from test_install_service_step import prepared
from test_install_registry_bind import acl


def readers(step,native,monkeypatch,fault=None):
    events=[];handles=set();keys=set()
    markers=MarkerReceipts(step.store.journal).load()
    values={row['marker']['service']:(3,encoded(row['marker'],specification(row['marker']['service']),
                step.generation,markers['package_sha256'])) for row in markers['services']}
    class ServiceReader:
        def __init__(self):events.append('reader-open')
        def open(self,name):
            if fault=='service-open' and len(handles)==2:raise SafetyError('modeled missing service')
            handle=('service',name);handles.add(handle);return handle
        def snapshot(self,handle,spec):
            assert handle in handles
            result=native.snapshot(handle,spec)
            if fault=='running':result['state']=4
            if fault=='enabled':result['start']=3
            if fault=='display':result['display']=spec['name']
            return result
        def release(self,handle):handles.remove(handle);events.append('service-close')
        def release_auxiliary(self,handle):
            from claude_reset.install_scm import Native
            return Native.release_auxiliary(self,handle)
        def close(self):
            for handle in tuple(getattr(self,'_pending_auxiliary',())):self.release_auxiliary(handle)
            events.append('reader-close')
    class RegistryReader:
        def open(self,name):
            if fault=='registry-open' and len(keys)==2:raise SafetyError('modeled missing key')
            key=('key',name);keys.add(key);return key
        def security(self,key):
            assert key in keys
            result=acl()
            if fault=='acl':result['protected']=False
            return result
        def value(self,key,name):
            assert key in keys
            if name=='SymbolicLinkValue':return (6,b'link') if fault=='link' else None
            assert name==VALUE
            if fault=='wrong-marker':return 3,b'foreign'
            if fault=='wrong-kind':return 1,values[key[1]][1]
            return values[key[1]]
        def close_key(self,key):keys.remove(key);events.append('key-close')
    monkeypatch.setattr(a,'NativeReader',ServiceReader)
    monkeypatch.setattr(a,'RegistryReader',RegistryReader)
    monkeypatch.setattr(a,'program_files',lambda:step.store.directories['root'].path.parent)
    # Fixtures use current-user test ACLs; production administrative ACL checks
    # are separately exercised in service_store/install_reopen tests.
    monkeypatch.setattr(a,'verify_paths',lambda *args:None)
    return events,handles,keys,values


def test_fresh_query_handles_verify_completed_markers_without_claiming_creation(tmp_path,monkeypatch):
    with prepared(tmp_path,monkeypatch) as (step,tx,_,native):
        step.apply();step.held.close();assert not native._created
        tx['state']='recovering';step.store.journal.save(tx)
        events,handles,keys,values=readers(step,native,monkeypatch)
        before={p:p.read_bytes() for p in step.store.journal.directory.glob('*.json')}
        with a.HeldAttestation(step.store,step.generation) as held:
            report=held.verify()
            assert report['generation_markers_verified'] and len(report['services'])==4
            assert not report['original_creation_identity_verified'] and not report['may_delete']
            assert not report['client_admission'] and len(handles)==len(keys)==4
            assert not native._created and not native.deleted
            assert all('nonce' not in row for row in report['services'])
            assert held.verify_service('SbieDrv')==report['services'][-1]
            with pytest.raises(SafetyError):held.verify_service('foreign-service')
        assert not handles and not keys and events[-1]=='reader-close'
        assert all(p.read_bytes()==data for p,data in before.items())
        with pytest.raises(SafetyError,match='closed'):held.verify()


@pytest.mark.parametrize('fault',['service-open','registry-open','running','enabled','acl','link','wrong-marker','wrong-kind','display'])
def test_failed_reopen_releases_all_query_handles_without_mutation(tmp_path,monkeypatch,fault):
    with prepared(tmp_path,monkeypatch) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        events,handles,keys,_=readers(step,native,monkeypatch,fault)
        with pytest.raises(SafetyError):a.HeldAttestation(step.store,step.generation)
        assert not handles and not keys and events[-1]=='reader-close'
        assert not native._created and not native.deleted


@pytest.mark.parametrize('fault',['missing','intent','generation','active-later-step','applying'])
def test_unproven_generation_refused_before_scm_open(tmp_path,monkeypatch,fault):
    with prepared(tmp_path,monkeypatch) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        events,handles,keys,_=readers(step,native,monkeypatch)
        receipt=MarkerReceipts(step.store.journal)
        if fault=='missing':receipt.path.unlink()
        if fault=='intent':
            value=receipt.load();value['services'][-1]['state']='intent'
            receipt.path.write_bytes(json.dumps(value).encode())
        if fault=='active-later-step':
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='verify_installed',state='intent'))
            step.store.journal.save(tx)
        if fault=='applying':tx['state']='applying';step.store.journal.save(tx)
        with pytest.raises(SafetyError):a.HeldAttestation(step.store,'c'*32 if fault=='generation' else step.generation)
        assert not events and not handles and not keys


@pytest.mark.parametrize('fault',['journal','marker','running'])
def test_held_attestation_rechecks_evidence_and_liveness(tmp_path,monkeypatch,fault):
    with prepared(tmp_path,monkeypatch) as (step,tx,_,native):
        step.apply();step.held.close();tx['state']='recovering';step.store.journal.save(tx)
        _,handles,keys,values=readers(step,native,monkeypatch)
        with a.HeldAttestation(step.store,step.generation) as held:
            if fault=='journal':tx['state']='recovery_required';step.store.journal.save(tx)
            if fault=='marker':values['SbieDrv']=(3,b'changed')
            if fault=='running':native.changed=True
            with pytest.raises(SafetyError):held.verify()
            assert len(handles)==len(keys)==4
        assert not handles and not keys and not native.deleted


def test_attestation_access_has_no_service_or_registry_mutation_rights():
    assert a.ACCESS==0x20005
    assert not a.ACCESS&(2|0x10|0x20|0x10000|0x40000|0x80000)
    assert not a.registry.ACCESS&(2|4|32|0x10000|0x40000|0x80000)
