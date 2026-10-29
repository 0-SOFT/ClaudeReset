"""Actual Windows file identities/sharing after releasing all original handles."""
from contextlib import contextmanager
import json
import pytest
from claude_reset import install_recovery_inputs as m,install_service_step as service
from claude_reset.install_files_step import ProtectedFilesStep
from claude_reset.install_store import Store,Directory
from claude_reset.install_journal import _LocalFile
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture


@contextmanager
def reopened(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch,root_name='ClaudeReset') as (old,source,tx,spec,data):
        with ProtectedFilesStep(old,source,tx['generation'],lambda g:True) as step:
            step.apply(spec,data,['C:\\'])
        tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
        tx['state']='recovering';old.journal.save(tx)
        directories={name:held.path for name,held in old.directories.items()}
        old.close();current=Store()
        try:
            for name,path in directories.items():current.directories[name]=Directory(path)
            current.journal=_LocalFile(directories['Installer'])
            monkeypatch.setattr(m,'program_files',lambda:tmp_path)
            monkeypatch.setattr(service,'program_files',lambda:tmp_path)
            # Test directories are ordinary user fixtures, not a production ACL.
            monkeypatch.setattr(m,'verify_paths',lambda *args:None)
            yield current,tx
        finally:current.close()


def test_recovery_reopens_all_26_exact_files_without_writes(tmp_path,monkeypatch):
    with reopened(tmp_path,monkeypatch) as (store,tx):
        with m.RecoveryInputs(store,tx['generation']) as inputs:
            assert inputs.report()==dict(payload_files=23,configuration_files=3,
                settings_changed=False,may_delete_services=False,client_admission=False)
            for pin in [*inputs.payload.pins.values(),*inputs.configuration.pins.values()]:
                with pytest.raises(OSError):pin.path.write_bytes(b'changed')
            assert inputs.configuration.pins['Backend/backend.json'].data
            assert store.journal.load()==tx
        with pytest.raises(SafetyError):inputs.report()
        (store.directories['root'].path/'Backend/backend.json').write_bytes(b'released')


@pytest.mark.parametrize('fault',['generation','state','missing','changed','same-bytes-replaced',
                                'partial-receipt','closed-parent','missing-receipt','acl'])
def test_recovery_rejects_unknown_inputs_and_releases_earlier_pins(tmp_path,monkeypatch,fault):
    with reopened(tmp_path,monkeypatch) as (store,tx):
        root=store.directories['root'].path;target=root/'Policy/Sandboxie.ini'
        if fault=='state':tx['state']='applying';store.journal.save(tx)
        if fault=='missing':target.unlink()
        if fault=='changed':target.write_bytes(b'changed')
        if fault=='same-bytes-replaced':
            data=target.read_bytes();target.rename(root/'Policy/old.ini');target.write_bytes(data)
        if fault=='partial-receipt':
            path=store.journal.directory/'configuration-receipts.json';value=json.loads(path.read_bytes())
            value['files'][-1]['state']='created';path.write_bytes(json.dumps(value).encode())
        if fault=='closed-parent':store.directories['Policy'].close()
        if fault=='missing-receipt':(store.journal.directory/'configuration-receipts.json').unlink()
        if fault=='acl':
            def refuse(*args):raise SafetyError('untrusted fixture ACL')
            monkeypatch.setattr(m,'verify_paths',refuse)
        with pytest.raises((SafetyError,OSError)):
            m.RecoveryInputs(store,'c'*32 if fault=='generation' else tx['generation'])
        # Even failures at the last policy input must close all prior file pins.
        (root/'Backend/ClaudeResetBackend.exe').write_bytes(b'previously pinned input released')


def test_individually_released_recovery_input_invalidates_report(tmp_path,monkeypatch):
    with reopened(tmp_path,monkeypatch) as (store,tx):
        with m.RecoveryInputs(store,tx['generation']) as inputs:
            inputs.payload.pins['Sandboxie/x64/SbieDrv.sys'].close()
            with pytest.raises(SafetyError):inputs.report()
