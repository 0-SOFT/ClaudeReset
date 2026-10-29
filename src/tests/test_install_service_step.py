"""Real staged files and durable receipts; all SCM/BFE/registry operations modeled."""
from contextlib import contextmanager,ExitStack
import uuid
import pytest
from claude_reset import install_service_step as s,install_scm as scm,install_boundary as b
from claude_reset.install_files_step import ProtectedFilesStep
from claude_reset.install_binding_receipts import BindingReceipt
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture
from test_install_scm_cleanup import NativeModel
from test_install_service_markers import Writer
from claude_reset.install_service_markers import MarkerReceipts


@contextmanager
def prepared(tmp_path,monkeypatch,failure=None,*,signed=None):
    events=[];native=NativeModel();keys=[str(uuid.uuid4()) for _ in range(16)]
    from claude_reset import install_prepared_boundary as prepared_boundary
    # This coordinator fixture models BFE. The complete readback is exercised
    # separately with the query-only transaction model.
    monkeypatch.setattr(prepared_boundary,'verify_prepared_boundary',lambda *args:dict(client_admission=False))
    monkeypatch.setattr(scm,'program_files',lambda:tmp_path)
    monkeypatch.setattr(b,'program_files',lambda:tmp_path)
    monkeypatch.setattr(s,'program_files',lambda:tmp_path)
    def create():
        events.append('scm-open')
        if failure=='scm-open':raise SafetyError('injected')
        return native
    monkeypatch.setattr(s,'Native',create)
    def install_denies(store,payload,generation,closed):
        assert closed(generation) is True;events.append('denies')
        receipt=s.BoundaryReceipt(store.journal,[r.key.value() for r in b._held_rules(store,payload)])
        receipt.record('intent')
        if failure=='deny-commit':raise SafetyError('injected')
        receipt.record('committed')
    def remove_denies(store,payload,generation,closed):
        assert not native._created;assert closed(generation) is True;events.append('remove-denies')
        receipt=s.BoundaryReceipt(store.journal,[r.key.value() for r in b._held_rules(store,payload)])
        receipt.recover_record('remove_intent');receipt.recover_record('removed')
    monkeypatch.setattr(s,'_install_backend_denies',install_denies)
    monkeypatch.setattr(s,'_remove_backend_denies',remove_denies)
    def driver(store,pin,generation,closed):
        def bind(service,handle):
            assert closed() is True;events.append('bind')
            if failure=='bind':raise SafetyError('injected')
            receipt=BindingReceipt(store.journal,pin);receipt.record('intent',pin.sha256);receipt.record('bound',pin.sha256)
            return dict(policy_bound=True,driver_started=False,client_admission=False)
        return bind
    monkeypatch.setattr(s,'driver_preparation',driver)
    writer=Writer()
    native.registry_fixture=writer
    from claude_reset import install_created_verification as final,install_registry as registry
    from test_install_registry_bind import acl
    class FinalReader:
        def open(self,name):return name
        def close_key(self,key):pass
        def security(self,key):return acl()
        def value(self,key,name):
            if name=='SymbolicLinkValue':return None
            if name=='IniPath':return (1,(registry.expected_path()+'\0').encode('utf-16-le'))
            return writer.values.get(key)
    monkeypatch.setattr(final,'RegistryReader',FinalReader)
    from claude_reset import install_service_markers as marker_module
    monkeypatch.setattr(marker_module,'Native',lambda:writer)
    def install_reservations(store,payload,config,generation,held,closed):
        assert len(held.items)==4;events.append('reservations')
        receipt=s.ReservationReceipt(store.journal,keys);receipt.record('intent')
        if failure=='reservation-commit':raise SafetyError('injected')
        receipt.record('committed')
        return dict(reservation_filters=16,client_admission=False)
    def remove_reservations(store,payload,config,generation,held,closed):
        assert len(held.items)==4;assert not native.deleted;events.append('remove-reservations')
        receipt=s.ReservationReceipt(store.journal,keys)
        receipt.recover_record('remove_intent');receipt.recover_record('removed')
    monkeypatch.setattr(s,'_install_initial_reservations',install_reservations)
    monkeypatch.setattr(s,'_remove_initial_reservations',remove_reservations)
    def confirm(result,closed):
        assert not native._created;assert closed() is True;events.append('confirm-absence')
        return dict(services=[r['name'] for r in result['services']],absence_verified=True,client_admission=False)
    monkeypatch.setattr(s,'_confirm_removal',confirm)
    def confirm_names(names,closed):
        assert not native._created and closed() is True;events.append('recheck-absence')
        return dict(services=names,absence_verified=True,client_admission=False)
    monkeypatch.setattr(s,'_confirm_absence',confirm_names)
    options={} if signed is None else dict(payload_bytes=signed['image'])
    with fixture(tmp_path,monkeypatch,root_name='ClaudeReset',**options) as (store,source,tx,spec,data),ExitStack() as stack:
        signatures=None
        if signed is not None:
            from claude_reset.install_runtime_signature import PinnedRuntimeSignatures
            from test_install_runtime_signature_tree import tree
            signatures=stack.enter_context(PinnedRuntimeSignatures(*tree(tmp_path,signed)))
        with ProtectedFilesStep(store,source,'a'*32,lambda g:True) as files:
            files.apply(spec,data,['C:\\'],runtime_signatures=signatures)
            payload,config=files.payload,files.configuration
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'));store.journal.save(tx)
            with s.DisabledServiceStep(store,payload,config,'a'*32,lambda g:True,
                    runtime_signatures=files.runtime_signatures) as step:
                yield step,tx,events,native


def test_coordinated_apply_and_recovery_keep_original_handles_until_reservations_removed(tmp_path,monkeypatch):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        assert step.apply()==dict(services_disabled=4,deny_filters=16,reservation_filters=16,client_admission=False)
        assert events==['denies','scm-open','bind','reservations'] and len(step.held.items)==4
        with pytest.raises(SafetyError):step.apply()
        tx['state']='recovering';step.store.journal.save(tx)
        assert step.recover()==dict(services_recovered=True,client_admission=False)
        assert events[-3:]==['remove-reservations','confirm-absence','remove-denies']
        assert native.deleted==list(reversed(scm.SERVICES))
        assert step.recover()==dict(services_recovered=True,client_admission=False)
        assert len(events)==8 and events[-1]=='recheck-absence'


@pytest.mark.parametrize('fault',['marker','display','running','policy','key-link','key-acl','key-read',
                                'missing-marker-receipt','released-handles','closed-policy'])
def test_final_created_bindings_are_read_after_the_entire_registration(tmp_path,monkeypatch,fault):
    from claude_reset import install_created_verification as final
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        real=s._install_initial_reservations
        reader=final.RegistryReader
        closed=[]
        class ChangedReader(reader):
            def close_key(self,key):closed.append(key)
            def security(self,key):
                result=super().security(key)
                if fault=='key-acl':result['protected']=False
                return result
            def value(self,key,name):
                if fault=='key-read':raise OSError('modeled query failure')
                if fault=='key-link' and name=='SymbolicLinkValue':return 6,b'link'
                if fault=='policy' and name=='IniPath':return 1,'C:\\foreign.ini\0'.encode('utf-16-le')
                return super().value(key,name)
        def changed(*args):
            result=real(*args)
            if fault=='marker':native.registry_fixture.values['ClaudeResetBackend']=(3,b'changed')
            if fault=='display':native.displays['ClaudeResetBackend']='foreign'
            if fault=='running':native.changed=True
            if fault=='missing-marker-receipt':(step.store.journal.directory/MarkerReceipts.filename).unlink()
            if fault=='released-handles':step.held.close()
            if fault=='closed-policy':step.configuration.pins['Policy/Sandboxie.ini'].close()
            monkeypatch.setattr(final,'RegistryReader',ChangedReader)
            return result
        monkeypatch.setattr(s,'_install_initial_reservations',changed)
        with pytest.raises((SafetyError,OSError)):step.apply()
        assert events[-1]=='reservations' and not native.deleted
        assert step.store.journal.load()['entries'][-1]==dict(step='install_services',state='intent')
        if fault in ('marker','policy','key-link','key-acl','key-read'):assert closed


def test_prior_final_check_accepted_changed_marker_negative_control(tmp_path,monkeypatch):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        real=s._install_initial_reservations
        def changed(*args):
            result=real(*args)
            native.registry_fixture.values['ClaudeResetBackend']=(3,b'changed')
            return result
        monkeypatch.setattr(s,'_install_initial_reservations',changed)
        # Reproduce the former sequence with its missing final binding check.
        monkeypatch.setattr(s,'verify_created_bindings',lambda *args:None)
        assert step.apply()['services_disabled']==4
        assert not native.deleted


@pytest.mark.parametrize('failure',['scm-open','bind','deny-commit','reservation-commit'])
def test_partial_installation_preserves_unknown_wfp_outcome(tmp_path,monkeypatch,failure):
    with prepared(tmp_path,monkeypatch,failure) as (step,tx,events,native):
        with pytest.raises(SafetyError):step.apply()
        tx['state']='recovering';step.store.journal.save(tx)
        if failure in ('deny-commit','reservation-commit'):
            with pytest.raises(SafetyError):step.recover()
            assert not native.deleted
        else:
            assert step.recover()['services_recovered'] is True
            assert events[-1]=='remove-denies'
        assert 'reservations' not in events or failure=='reservation-commit'


@pytest.mark.parametrize('fault',['old-evidence','old-reconciliation','old-pending','old-boundary-attempt','old-reservation-attempt','closed-verifier','generation','closed-step','no-original-handles'])
def test_unaccepted_coordinator_cannot_mutate(tmp_path,monkeypatch,fault):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        if fault=='old-evidence':(step.store.journal.directory/'boundary-receipt.json').write_bytes(b'preserve')
        if fault=='old-reconciliation':(step.store.journal.directory/'service-reconciliation-log.json').write_bytes(b'preserve')
        if fault=='old-pending':(step.store.journal.directory/'pending-creation-cleanup.json').write_bytes(b'preserve')
        if fault=='old-boundary-attempt':(step.store.journal.directory/'boundary-reconciliation-log.json').write_bytes(b'preserve')
        if fault=='old-reservation-attempt':(step.store.journal.directory/'reservation-reconciliation-log.json').write_bytes(b'preserve')
        if fault=='closed-verifier':step.verifier=lambda g:None
        if fault=='generation':step.generation='b'*32
        if fault=='closed-step':step.close()
        if fault=='no-original-handles':
            tx['state']='recovering';step.store.journal.save(tx)
            with pytest.raises(SafetyError):step.recover()
        else:
            with pytest.raises(SafetyError):step.apply()
        assert not events and not native.deleted


@pytest.mark.parametrize('fault',['closed-driver','closed-policy','missing-policy','missing-receipt',
                                'wrong-file','incomplete-receipt'])
def test_all_staging_is_checked_before_any_wfp_or_scm_mutation(tmp_path,monkeypatch,fault):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        if fault=='closed-driver':step.payload.pins['Sandboxie/x64/SbieDrv.sys'].close()
        if fault=='closed-policy':step.configuration.pins['Policy/Sandboxie.ini'].close()
        if fault=='missing-policy':step.configuration.pins.pop('Policy/Sandboxie.ini').close()
        if fault=='missing-receipt':
            (step.store.journal.directory/'configuration-receipts.json').unlink()
        if fault=='wrong-file':
            a,b='Sandboxie/x64/SbieDrv.sys','Sandboxie/x64/SbieDll.dll'
            step.payload.pins[a],step.payload.pins[b]=step.payload.pins[b],step.payload.pins[a]
        if fault=='incomplete-receipt':
            receipt=s.ConfigurationReceipts(step.store.journal);record=receipt.load()
            record['files'][-1]['state']='created';receipt._save(record)
        with pytest.raises(SafetyError):step.apply()
        assert not step.attempted and not events and not native.deleted
        assert not (step.store.journal.directory/'boundary-receipt.json').exists()
        assert not (step.store.journal.directory/'service-receipts.json').exists()


@pytest.mark.parametrize('after',[1,2,3])
def test_same_process_recovery_resumes_only_confirmed_deletion_prefix(tmp_path,monkeypatch,after):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        step.apply();tx['state']='recovering';step.store.journal.save(tx)
        step.verifier=lambda generation:len(native.deleted)<after
        with pytest.raises(SafetyError):step.recover()
        assert len(step.deleted)==after and len(step.held.items)==4-after
        assert 'remove-denies' not in events and 'confirm-absence' not in events
        step.verifier=lambda generation:True
        assert step.recover()['services_recovered'] is True
        assert native.deleted==list(reversed(scm.SERVICES))
        assert not step.held.items and len(step.deleted)==4
        assert events.count('remove-reservations')==1 and events.count('remove-denies')==1


@pytest.mark.parametrize('durable',[False,True])
def test_uncertain_delete_receipt_cannot_be_resumed_from_readback(tmp_path,monkeypatch,durable):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        step.apply();tx['state']='recovering';step.store.journal.save(tx)
        original=s.RemovalReceipts.record
        def fail(receipt,state,spec):
            if state!='delete_requested' or durable:original(receipt,state,spec)
            if state=='delete_requested':raise OSError('completion durability unknown')
        monkeypatch.setattr(s.RemovalReceipts,'record',fail)
        with pytest.raises(OSError):step.recover()
        assert native.deleted==['SbieDrv'] and not step.deleted and len(step.held.items)==4
        monkeypatch.setattr(s.RemovalReceipts,'record',original)
        with pytest.raises(SafetyError,match='confirmed in-memory'):step.recover()
        assert native.deleted==['SbieDrv'] and 'remove-denies' not in events


def test_durable_prefix_without_same_object_memory_cannot_authorize_continuation(tmp_path,monkeypatch):
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        step.apply();tx['state']='recovering';step.store.journal.save(tx)
        step.verifier=lambda generation:not native.deleted
        with pytest.raises(SafetyError):step.recover()
        assert len(step.deleted)==1
        step.deleted.clear();step.verifier=lambda generation:True
        with pytest.raises(SafetyError,match='confirmed in-memory'):step.recover()
        assert native.deleted==['SbieDrv'] and 'remove-denies' not in events


@pytest.mark.parametrize('fault',['service','registry','boundary'])
def test_previous_absence_never_bypasses_fresh_check_before_deny_removal(tmp_path,monkeypatch,fault):
    from claude_reset import install_scm_cleanup as removal,install_inventory as inventory
    with prepared(tmp_path,monkeypatch) as (step,tx,events,native):
        step.apply();tx['state']='recovering';step.store.journal.save(tx)
        original=s._remove_backend_denies
        def interrupted(*args):raise SafetyError('interrupted before removing denies')
        monkeypatch.setattr(s,'_remove_backend_denies',interrupted)
        with pytest.raises(SafetyError):step.recover()
        assert s.RemovalReceipts(step.store.journal).load()['absence_verified'] is True
        assert len(native.deleted)==4
        monkeypatch.setattr(s,'_remove_backend_denies',original)
        monkeypatch.setattr(s,'_confirm_absence',removal._confirm_absence)
        monkeypatch.setattr(inventory,'services',lambda:[dict(name=n,exists=fault=='service' and n=='SbieDrv') for n in scm.SERVICES])
        def vacant(name):
            if fault=='registry':raise SafetyError('recreated registry key')
        monkeypatch.setattr(scm,'require_vacant_registry_slot',vacant)
        if fault=='boundary':step.verifier=lambda g:False
        with pytest.raises(SafetyError):step.recover()
        assert 'remove-denies' not in events and len(native.deleted)==4
