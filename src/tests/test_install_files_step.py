import pytest
from claude_reset import install_files_step as step_module
from claude_reset.install_files_step import ProtectedFilesStep
from claude_reset.install_config_stage import ConfigurationReceipts
from claude_reset.install_payload import FILES
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture


def test_staged_inputs_remain_pinned_until_ordered_recovery(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        with ProtectedFilesStep(store,source,tx['generation'],lambda g:True) as step:
            assert step.apply(spec,data,['C:\\'])==dict(payload_files=23,configuration_files=3,client_admission=False)
            assert len(step.payload.pins)==23 and len(step.configuration.pins)==3
            for pin in [*step.payload.pins.values(),*step.configuration.pins.values()]:
                with pytest.raises(OSError):pin.path.write_bytes(b'replacement')
            with pytest.raises(SafetyError,match='replayed'):step.apply(spec,data,['C:\\'])
            tx['state']='recovering';store.journal.save(tx)
            assert len(step.recover()['removed'])==26
            assert step.recover()['removed']==[]
            assert step.payload is None and step.configuration is None
            assert source.report()['payload_files']==23 and store.journal.lock


@pytest.mark.parametrize('fault',['configuration','old-receipt','boundary','existing-private','existing-payload',
                                'closed-manifest','closed-payload'])
def test_preflight_refusal_creates_no_payload_or_ownership(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        if fault=='closed-manifest':source.manifest.close()
        if fault=='closed-payload':source.pins['Engine/engine.exe'].close()
        if fault=='old-receipt':(store.journal.directory/'configuration-receipts.json').write_bytes(b'preserve')
        if fault=='existing-private':(store.directories['root'].path/'Policy/Sandboxie.ini').write_bytes(b'preserve')
        if fault=='existing-payload':(store.directories['root'].path/'Engine/engine.exe').write_bytes(b'preserve')
        before=set(store.directories['root'].path.rglob('*'))
        with ProtectedFilesStep(store,source,tx['generation'],lambda g:fault!='boundary') as step:
            with pytest.raises(SafetyError):step.apply(b'{}' if fault=='configuration' else spec,data,['C:\\'])
            assert not step.attempted
            assert set(store.directories['root'].path.rglob('*'))==before
            tx['state']='recovering';store.journal.save(tx)
            with pytest.raises(SafetyError):step.recover()


def test_private_write_failure_preserves_owned_files_then_recovers(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        def fail(self,pin):raise OSError('injected configuration completion failure')
        monkeypatch.setattr(ConfigurationReceipts,'complete',fail)
        with ProtectedFilesStep(store,source,tx['generation'],lambda g:True) as step:
            with pytest.raises(OSError):step.apply(spec,data,['C:\\'])
            assert len(step.payload.pins)==23 and step.configuration is None
            tx['state']='recovering';store.journal.save(tx)
            assert len(step.recover()['removed'])==24


def test_service_dependency_refuses_recovery_without_releasing_pins(tmp_path,monkeypatch):
    from claude_reset import install_cleanup_observation as observation
    from test_install_cleanup_observation import Model
    observations=[]
    class Query(Model):
        def __init__(self):super().__init__();observations.append(self)
    monkeypatch.setattr(observation,'Engine',Query)
    monkeypatch.setattr(observation,'_confirm_absence',lambda names,closed:closed())
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        with ProtectedFilesStep(store,source,tx['generation'],lambda g:True) as step:
            step.apply(spec,data,['C:\\'])
            tx['entries'][-1]['state']='done'
            tx['entries'].append(dict(step='install_services',state='intent'))
            tx['state']='recovering';store.journal.save(tx)
            with pytest.raises(SafetyError,match='Dependent steps'):step.recover()
            assert not observations
            assert all(pin.handle for pin in step.payload.pins.values())
            tx['entries'][-1]['state']='undone';store.journal.save(tx)
            assert len(step.recover()['removed'])==26
            assert len(observations)==27


def test_closed_object_only_releases_pins_and_does_not_delete_files(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        step=ProtectedFilesStep(store,source,tx['generation'],lambda g:True)
        step.apply(spec,data,['C:\\']);step.close()
        assert all((store.directories['root'].path/name).exists() for name in FILES)
        with pytest.raises(SafetyError,match='Open files step'):step.apply(spec,data,['C:\\'])
        assert store.journal.load()==tx
