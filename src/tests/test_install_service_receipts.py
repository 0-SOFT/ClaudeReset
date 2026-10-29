import json
import pytest
from claude_reset.install_journal import _LocalFile
from claude_reset.install_transaction import Transaction,STEPS
from claude_reset.install_service_receipts import ServiceReceipts
from claude_reset.install_scm import specification,_register_disabled
from claude_reset.safeio import SafetyError
from test_install_scm import Model


def initial():
    value=Transaction(None,'a'*32,'b'*64).value
    value['entries']=[dict(step=step,state='done') for step in STEPS[:4]]
    value['entries'][-1]['state']='intent'
    return value


def test_all_disabled_registrations_are_recorded_on_disk(tmp_path):
    from claude_reset.install_inventory import SERVICES
    with _LocalFile(tmp_path) as journal:
        journal.save(initial());receipts=ServiceReceipts(journal);receipts.begin()
        for name in SERVICES:
            model=Model()
            _register_disabled(model,name,receipts.record,model.verify_closed)
        assert [r['state'] for r in receipts.load()['services']]==['disabled']*4
        with pytest.raises(SafetyError):receipts.begin()
    with _LocalFile(tmp_path) as journal:
        assert len(ServiceReceipts(journal).load()['services'])==4


@pytest.mark.parametrize('failure',['protect','sid','snapshot'])
def test_failure_after_creation_keeps_durable_intent(tmp_path,failure):
    with _LocalFile(tmp_path) as journal:
        journal.save(initial());receipts=ServiceReceipts(journal);receipts.begin()
        model=Model(failure)
        with pytest.raises(OSError):_register_disabled(model,'ClaudeResetBackend',receipts.record,model.verify_closed)
        assert receipts.load()['services'][0]['state']=='intent'
        assert model.disabled and model.closed
        with pytest.raises(SafetyError):receipts.record('intent',specification('ClaudeResetBackend'))


def test_final_receipt_write_failure_leaves_intent_and_disabled_service(tmp_path,monkeypatch):
    with _LocalFile(tmp_path) as journal:
        journal.save(initial());receipts=ServiceReceipts(journal);receipts.begin()
        real=receipts.save
        def fail(value):
            if value['services'] and value['services'][-1]['state']=='disabled':raise OSError('write failure')
            real(value)
        monkeypatch.setattr(receipts,'save',fail)
        model=Model()
        with pytest.raises(OSError):_register_disabled(model,'ClaudeResetBackend',receipts.record,model.verify_closed)
        assert model.disabled and model.closed
        assert receipts.load()['services'][0]['state']=='intent'


@pytest.mark.parametrize('change',['generation','spec','order','duplicate','unconfirmed'])
def test_tampered_receipts_are_rejected(tmp_path,change):
    with _LocalFile(tmp_path) as journal:
        journal.save(initial());receipts=ServiceReceipts(journal);receipts.begin()
        receipts.record('intent',specification('ClaudeResetBackend'))
        value=receipts.load()
        if change=='generation':value['generation']='c'*32
        elif change=='spec':value['services'][0]['spec']['start']=3
        elif change=='order':value['services'][0]['name']='SbieDrv'
        elif change=='duplicate':value['services']*=2
        elif change=='unconfirmed':value['services'].append(dict(name='ClaudeResetGateway',state='intent',spec=specification('ClaudeResetGateway')))
        receipts.path.write_text(json.dumps(value),encoding='utf-8')
        with pytest.raises(SafetyError):receipts.load()


def test_registration_requires_install_step_and_exclusive_lock(tmp_path):
    with _LocalFile(tmp_path) as journal:
        journal.save(Transaction(None,'a'*32,'b'*64).value)
        receipts=ServiceReceipts(journal)
        with pytest.raises(SafetyError):receipts.begin()
        with pytest.raises(SafetyError):_LocalFile(tmp_path)
    with pytest.raises(SafetyError):receipts.load()


def test_receipts_readable_during_recovery_but_no_new_registration(tmp_path):
    with _LocalFile(tmp_path) as journal:
        state=initial();journal.save(state)
        receipts=ServiceReceipts(journal);receipts.begin()
        receipts.record('intent',specification('ClaudeResetBackend'))
        state['state']='recovering';journal.save(state)
        assert receipts.load()['services'][0]['state']=='intent'
        with pytest.raises(SafetyError):receipts.record('disabled',specification('ClaudeResetBackend'))
