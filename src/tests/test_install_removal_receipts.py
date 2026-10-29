import pytest
from claude_reset.install_journal import _LocalFile
from claude_reset.install_removal_receipts import RemovalReceipts
from claude_reset.install_service_receipts import ServiceReceipts
from claude_reset.install_scm import HeldRegistrations,_register_disabled,SERVICES,specification
from claude_reset.install_scm_cleanup import _rollback_held_registrations,_confirm_removal
from claude_reset.safeio import SafetyError
from test_install_scm_cleanup import NativeModel
from test_install_service_receipts import initial


def test_durable_cleanup_is_not_completed_until_absence_is_verified(tmp_path,monkeypatch):
    from claude_reset import install_inventory as inventory,install_scm as scm
    native=NativeModel()
    with _LocalFile(tmp_path) as journal,HeldRegistrations() as held:
        tx=initial();journal.save(tx);registered=ServiceReceipts(journal);registered.begin()
        for name in SERVICES:_register_disabled(native,name,registered.record,lambda:True,held=held)
        tx['state']='recovering';journal.save(tx)
        receipts=RemovalReceipts(journal)
        result=_rollback_held_registrations(held,receipts.record,lambda:True)
        assert receipts.load()['absence_verified'] is False
        with pytest.raises(SafetyError):receipts.confirm(result)
        monkeypatch.setattr(inventory,'services',lambda:[dict(name=n,exists=False) for n in SERVICES])
        monkeypatch.setattr(scm,'require_vacant_registry_slot',lambda name:None)
        receipts.confirm(_confirm_removal(result,lambda:True))
        assert receipts.load()['absence_verified'] is True
    with _LocalFile(tmp_path) as journal:
        assert RemovalReceipts(journal).load()['absence_verified'] is True


@pytest.mark.parametrize('fault',['applying','wrong_order','no_intent','dependent_step'])
def test_invalid_removal_transition_never_persists(tmp_path,fault):
    with _LocalFile(tmp_path) as journal:
        tx=initial();journal.save(tx);services=ServiceReceipts(journal);services.begin()
        for name in SERVICES:
            services.record('intent',specification(name));services.record('disabled',specification(name))
        tx['state']='recovering'
        if fault=='applying':tx['state']='applying'
        if fault=='dependent_step':
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='verify_installed',state='intent'))
        journal.save(tx);receipts=RemovalReceipts(journal)
        name='ClaudeResetBackend' if fault=='wrong_order' else 'SbieDrv'
        state='delete_requested' if fault=='no_intent' else 'delete_intent'
        with pytest.raises(SafetyError):receipts.record(state,specification(name))
        assert not receipts.path.exists()


@pytest.mark.parametrize('fault',['basis','false-absence','unknown-state','wrong-spec','schema','earlier-intent'])
def test_observed_receipt_cannot_forge_known_completion_or_partial_absence(tmp_path,fault):
    with _LocalFile(tmp_path) as journal:
        tx=initial();journal.save(tx);services=ServiceReceipts(journal);services.begin()
        for name in SERVICES:
            services.record('intent',specification(name));services.record('disabled',specification(name))
        tx['state']='recovering';journal.save(tx)
        receipts=RemovalReceipts(journal)
        for name in reversed(SERVICES):
            receipts.record('delete_intent',specification(name))
            if name!=SERVICES[0]:receipts.record('delete_requested',specification(name))
        before=receipts.load()
        result=dict(services=list(reversed(SERVICES)),absence_verified=True,client_admission=False)
        with pytest.raises(SafetyError):receipts.confirm(result)
        receipts.confirm_observed(result)
        value=receipts.load();assert value['services']==before['services']
        if fault=='basis':value['completion_basis']='deletion_succeeded'
        elif fault=='false-absence':value['absence_verified']=False
        elif fault=='unknown-state':value['services'][-1]['state']='assumed_deleted'
        elif fault=='wrong-spec':value['services'][-1]['spec']=specification('SbieDrv')
        elif fault=='schema':value['schema']=True
        else:value['services'][0]['state']='delete_intent'
        with pytest.raises(SafetyError):receipts.save(value)
        assert receipts.load()['services']==before['services']
