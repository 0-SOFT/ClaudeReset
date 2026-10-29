import json
from pathlib import Path
import pytest
from claude_reset.install_journal import _LocalFile
from claude_reset.install_binding_receipts import BindingReceipt
from claude_reset.install_config_stage import ConfigurationReceipts
from claude_reset.install_receipts import identity
from claude_reset.install_service_receipts import ServiceReceipts
from claude_reset.install_inventory import SERVICES
from claude_reset.install_scm import specification
from claude_reset.windows_pin import PinnedFile
from claude_reset.safeio import SafetyError
from test_install_service_receipts import initial
from test_install_registry_bind import setup


def prepare(journal,pin):
    journal.save(initial())
    services=ServiceReceipts(journal);services.begin()
    for name in SERVICES:
        spec=specification(name);services.record('intent',spec)
        if name!='SbieDrv':services.record('disabled',spec)
    tx=journal.load()
    rows=[dict(name=name,sha256=pin.sha256,state='complete',identity=identity(pin.api,pin.handle))
          for name in sorted(ConfigurationReceipts.names)]
    ConfigurationReceipts(journal)._save(dict(schema=1,generation=tx['generation'],
        package_sha256=tx['package_sha256'],files=rows))


def test_receipt_survives_lock_release_and_never_replays_intent(tmp_path):
    path=tmp_path/'policy.ini';path.write_bytes(b'closed fixture')
    with PinnedFile(path,limit=65536) as pin:
        with _LocalFile(tmp_path) as journal:
            prepare(journal,pin);receipt=BindingReceipt(journal,pin)
            receipt.record('intent',pin.sha256)
            assert receipt.load()['state']=='intent'
            receipt.record('bound',pin.sha256)
            assert receipt.load()['state']=='bound'
            with pytest.raises(SafetyError):receipt.record('intent',pin.sha256)
        with _LocalFile(tmp_path) as journal:
            receipt=BindingReceipt(journal,pin)
            assert receipt.load()['state']=='bound'
            with pytest.raises(SafetyError):receipt.record('bound',pin.sha256)


def test_byte_identical_replacement_does_not_match_receipt(tmp_path):
    path=tmp_path/'policy.ini';path.write_bytes(b'fixture')
    with _LocalFile(tmp_path) as journal:
        with PinnedFile(path,limit=65536) as pin:prepare(journal,pin)
        path.rename(tmp_path/'old.ini');path.write_bytes(b'fixture')
        with PinnedFile(path,limit=65536) as pin:
            with pytest.raises(SafetyError):BindingReceipt(journal,pin).record('intent',pin.sha256)
        assert not (tmp_path/'policy-binding-receipt.json').exists()


@pytest.mark.parametrize('change',['digest','generation','service_done','recovering','completion_without_intent'])
def test_mismatched_or_out_of_order_binding_cannot_commit(tmp_path,change):
    path=tmp_path/'policy.ini';path.write_bytes(b'fixture')
    with _LocalFile(tmp_path) as journal,PinnedFile(path,limit=65536) as pin:
        prepare(journal,pin);receipt=BindingReceipt(journal,pin)
        digest=pin.sha256;state='intent'
        if change=='digest':digest='e'*64
        if change=='generation':
            path=ConfigurationReceipts(journal).path
            value=json.loads(path.read_text());value['generation']='c'*32
            path.write_text(json.dumps(value))
        if change=='service_done':ServiceReceipts(journal).record('disabled',specification('SbieDrv'))
        if change=='recovering':
            tx=journal.load();tx['state']='recovering';journal.save(tx)
        if change=='completion_without_intent':state='bound'
        with pytest.raises(SafetyError):receipt.record(state,digest)
        assert not receipt.path.exists()


def test_staged_configuration_binds_through_durable_registration_hook(tmp_path,monkeypatch,setup):
    from claude_reset import install_registry_bind as b,install_registry as r
    from claude_reset.install_config_stage import _stage_configuration
    from test_install_config_stage import fixture
    writer,services,_,_,closed,events=setup
    with fixture(tmp_path,monkeypatch) as (store,payload,tx,spec,engine):
        with _stage_configuration(store,payload,'a'*32,spec,engine,['C:\\'],lambda g:True) as staged:
            policy=staged.pins['Policy/Sandboxie.ini']
            monkeypatch.setattr(r,'expected_path',lambda:str(policy.path))
            monkeypatch.setattr(b,'Native',lambda:writer)
            tx['entries'][-1]['state']='done'
            tx['entries'].append(dict(step='install_services',state='intent'));store.journal.save(tx)
            receipts=ServiceReceipts(store.journal);receipts.begin()
            for name in SERVICES:
                receipts.record('intent',specification(name))
                if name!='SbieDrv':receipts.record('disabled',specification(name))
            hook=b.driver_preparation(store,policy,'a'*32,closed)
            assert hook(services,17)['policy_bound'] is True
            assert BindingReceipt(store.journal,policy).load()['state']=='bound'
            assert receipts.load()['services'][-1]['state']=='intent' # SCM completion remains separate.
            assert not any(e in events for e in ('start','delete'))
