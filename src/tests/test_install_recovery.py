"""Real fixture files/journals; no installed services, keys or WFP mutations."""
from contextlib import contextmanager
import pytest
from claude_reset import install_recovery as r
from claude_reset.install_files_step import ProtectedFilesStep
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture


@contextmanager
def staged(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        with ProtectedFilesStep(store,source,tx['generation'],lambda g:True) as files:
            files.apply(spec,data,['C:\\'])
        yield store,source,tx


def run(store,tx,revoke=lambda g:None,closed=lambda g:True):
    return r.recover_unfinished_installation(store,tx['generation'],tx['package_sha256'],revoke,closed)


def test_file_recovery_finishes_journal_and_retains_audit_without_service_calls(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        def forbidden(*args):pytest.fail('No service step was attempted')
        monkeypatch.setattr(r,'recover_service_step',forbidden)
        before={p:p.read_bytes() for p in store.journal.directory.glob('*.json') if p.name!='install-journal.json'}
        calls=[];result=run(store,tx,lambda g:calls.append(g))
        assert calls==[tx['generation']] and len(result['files']['removed'])==26
        assert result['transaction']['state']=='rolled_back_clients_closed'
        assert all(e['state']=='undone' for e in result['transaction']['entries'])
        assert result['audit_evidence_retained'] and result['bootstrap_directories_retained']
        assert not result['client_admission'] and not result['installed_version_uninstalled']
        assert all(p.read_bytes()==raw for p,raw in before.items())
        assert all(d.path.exists() for d in store.directories.values())
        with pytest.raises(SafetyError):run(store,tx)


@pytest.mark.parametrize('fault',['generation','package','terminal','later-step','no-lock','closed'])
def test_unaccepted_recovery_cannot_remove_payload(tmp_path,monkeypatch,fault):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        requested=dict(tx)
        if fault=='generation':requested['generation']='b'*32
        if fault=='package':requested['package_sha256']='c'*64
        if fault=='terminal':
            tx['state']='rolled_back_clients_closed'
            for e in tx['entries']:e['state']='undone'
            store.journal.save(tx)
        if fault=='later-step':
            tx['entries'][-1]['state']='done'
            tx['entries']+= [dict(step='install_services',state='done'),dict(step='verify_installed',state='intent')]
            store.journal.save(tx)
        lock=store.journal.lock
        if fault=='no-lock':store.journal.lock=None
        try:
            with pytest.raises(SafetyError):run(store,requested,closed=lambda g:fault!='closed')
        finally:store.journal.lock=lock
        assert all((store.directories['root'].path/name).exists() for name in source.pins)


@pytest.mark.parametrize('durable',[False,True])
def test_failed_recovery_intent_still_revokes_but_never_deletes(tmp_path,monkeypatch,durable):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        original=store.journal.save;events=[]
        def fail(value):
            if durable:original(value)
            raise OSError('intent durability unknown')
        monkeypatch.setattr(store.journal,'save',fail)
        with pytest.raises(OSError):run(store,tx,lambda g:events.append('revoke'))
        assert events==['revoke']
        assert all((store.directories['root'].path/name).exists() for name in source.pins)


def test_partial_file_removal_resumes_from_protected_journal(tmp_path,monkeypatch):
    from claude_reset import install_rollback as rollback
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        original=rollback._mark_delete;removed=[]
        def fail(pin):
            if len(removed)==1:raise OSError('modeled deletion interruption')
            original(pin);removed.append(pin.path)
        monkeypatch.setattr(rollback,'_mark_delete',fail)
        with pytest.raises(OSError):run(store,tx)
        assert len(removed)==1 and not removed[0].exists()
        assert store.journal.load()['state']=='recovery_required'
        monkeypatch.setattr(rollback,'_mark_delete',original)
        result=run(store,tx)
        assert len(result['files']['removed'])==25 and result['transaction']['state']=='rolled_back_clients_closed'


def test_changed_journal_is_not_overwritten_after_revocation(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        def revoke(generation):
            changed=store.journal.load();changed['state']='recovery_required';store.journal.save(changed)
        with pytest.raises(SafetyError,match='journal changed'):run(store,tx,revoke)
        assert store.journal.load()['state']=='recovery_required'
        assert all((store.directories['root'].path/name).exists() for name in source.pins)


@pytest.mark.parametrize('name',r.SERVICE_EVIDENCE)
def test_service_evidence_without_intent_never_bypasses_service_recovery(tmp_path,monkeypatch,name):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        path=store.journal.directory/name;path.write_bytes(b'unknown outcome')
        calls=[]
        with pytest.raises(SafetyError,match='without durable service intent'):run(store,tx,lambda g:calls.append(g))
        assert not calls and path.read_bytes()==b'unknown outcome' and store.journal.load()==tx
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


@pytest.mark.parametrize('result',[None,{},dict(services_recovered=1,client_admission=False,journal_advanced=False),
                                dict(services_recovered=True,client_admission=False,journal_advanced=True)])
def test_unconfirmed_service_recovery_never_advances_to_file_removal(tmp_path,monkeypatch,result):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
        store.journal.save(tx)
        monkeypatch.setattr(r,'recover_service_step',lambda *args:result)
        with pytest.raises(SafetyError,match='completion is not confirmed'):run(store,tx)
        assert store.journal.load()['state']=='recovery_required'
        assert store.journal.load()['entries'][-1]['state']=='intent'
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


def test_reappeared_file_is_preserved_and_terminal_commit_refused(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        original=r._rollback_installation_files
        target=store.directories['root'].path/'Engine/engine.exe'
        def changed(*args):
            result=original(*args);target.write_bytes(b'foreign replacement');return result
        monkeypatch.setattr(r,'_rollback_installation_files',changed)
        with pytest.raises(SafetyError,match='reappeared'):run(store,tx)
        assert target.read_bytes()==b'foreign replacement'
        assert store.journal.load()['state']=='recovery_required'
        assert all(e['state']=='undone' for e in store.journal.load()['entries'])
        with pytest.raises(SafetyError,match='reappeared'):run(store,tx)
        assert target.read_bytes()==b'foreign replacement'


def test_completed_cleanup_requires_fresh_service_absence_before_terminal_commit(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        run(store,tx)
        value=store.journal.load();value['state']='recovery_required'
        value['entries'].append(dict(step='install_services',state='undone'));store.journal.save(value)
        calls=[]
        def foreign(keys,closed):
            assert closed() is True and len(keys)==16
            calls.append('fresh-absence');raise SafetyError('modeled recreated service slot')
        monkeypatch.setattr(r,'require_cleanup_absence',foreign)
        with pytest.raises(SafetyError,match='recreated service'):run(store,tx)
        assert calls==['fresh-absence'] and store.journal.load()['state']=='recovery_required'


def test_real_recovery_protocol_precedes_actual_staged_file_removal(tmp_path,monkeypatch):
    from test_install_reconciled_cleanup import setup
    from test_install_service_recovery import final_queries
    from claude_reset import install_registered_recovery as registered
    from claude_reset.install_boundary_receipts import BoundaryReceipt
    with setup(tmp_path,monkeypatch,0) as f:
        step,inputs,native,absent,state,handles,keys,_,attest=f
        inputs.close();step.payload.close();step.configuration.close()
        final_queries(monkeypatch)
        monkeypatch.setattr(registered,'HeldRemainingAttestation',lambda *args:attest())
        events=[]
        def remove(store,payload,generation,closed):
            assert not handles and not keys and len(absent)==4 and closed(generation)
            events.append('remove-denies')
            receipt=BoundaryReceipt(store.journal,[v.key.value() for v in registered._held_rules(store,payload)])
            receipt.recover_record('remove_intent');receipt.recover_record('removed')
            return dict(deny_filters_removed=16,client_admission=False)
        monkeypatch.setattr(registered,'_remove_backend_denies',remove)
        real=r._rollback_installation_files
        def remove_files(*args):
            assert len(native.deleted)==4 and events==['revoke','remove-denies']
            events.append('remove-files');return real(*args)
        monkeypatch.setattr(r,'_rollback_installation_files',remove_files)
        tx=step.store.journal.load()
        result=run(step.store,tx,lambda g:events.append('revoke'),lambda g:state['closed'])
        assert result['services']['recovery_route']=='registrations' and len(result['files']['removed'])==26
        assert result['transaction']['state']=='rolled_back_clients_closed' and not result['client_admission']
        assert not handles and not keys and len(absent)==4


@pytest.mark.parametrize('moment',['revoke','before-delete','after-delete'])
def test_late_service_receipt_cannot_be_hidden_by_file_only_recovery(tmp_path,monkeypatch,moment):
    from claude_reset import install_rollback as rollback
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        target=store.journal.directory/'service-receipts.json'
        def appear():target.write_bytes(b'unknown service outcome')
        def revoke(generation):
            if moment=='revoke':appear()
        if moment=='before-delete':
            real=rollback.identity
            def identity(*args):
                result=real(*args);appear();return result
            monkeypatch.setattr(rollback,'identity',identity)
        if moment=='after-delete':
            real=r._rollback_installation_files
            def cleanup(*args):
                result=real(*args);appear();return result
            monkeypatch.setattr(r,'_rollback_installation_files',cleanup)
        with pytest.raises(SafetyError,match='without durable service intent'):
            run(store,tx,revoke)
        assert target.read_bytes()==b'unknown service outcome'
        assert store.journal.load()['state']=='recovery_required'
        if moment!='after-delete':
            assert all((store.directories['root'].path/n).exists() for n in source.pins)
