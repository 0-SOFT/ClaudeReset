"""Real CNG, owned temporary files/receipts; no privileged host mutations."""
from contextlib import contextmanager
import hashlib
import pytest
from claude_reset.install_files_step import ProtectedFilesStep
from claude_reset.install_runtime_signature import PinnedRuntimeSignatures,RUNTIME_SIDECARS
from claude_reset.install_runtime_stage import RuntimeSignatureReceipts
from claude_reset import install_service_step as service,install_recovery_inputs as recovery
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture as config_fixture
from test_install_runtime_signature import signed
from test_install_runtime_signature_tree import tree


@contextmanager
def fixture(tmp_path,monkeypatch,signed,closed=None):
    with config_fixture(tmp_path,monkeypatch,root_name='ClaudeReset',payload_bytes=signed['image']) as values:
        store,source,tx,spec,data=values
        monkeypatch.setattr(service,'program_files',lambda:tmp_path)
        monkeypatch.setattr(recovery,'program_files',lambda:tmp_path)
        monkeypatch.setattr(recovery,'verify_paths',lambda *args:None)
        with PinnedRuntimeSignatures(*tree(tmp_path,signed)) as signatures:
            with ProtectedFilesStep(store,source,tx['generation'],closed or (lambda g:True)) as step:
                yield step,signatures,tx,spec,data


def apply(step,signatures,spec,data):
    return step.apply(spec,data,['C:\\'],runtime_signatures=signatures)


def test_complete_sidecar_staging_is_held_and_rolled_back_by_exact_identity(tmp_path,monkeypatch,signed):
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        row=apply(step,signatures,spec,data)
        assert row==dict(payload_files=23,configuration_files=3,runtime_signature_files=11,client_admission=False)
        assert set(step.runtime_signatures.pins)==RUNTIME_SIDECARS
        receipt=RuntimeSignatureReceipts(step.store.journal).load()
        assert len(receipt['files'])==11 and all(r['state']=='complete' for r in receipt['files'])
        service._require_complete_staging(step.store,step.payload,step.configuration,step.runtime_signatures)
        with pytest.raises(SafetyError,match='remain held'):
            service._require_complete_staging(step.store,step.payload,step.configuration)
        for pin in step.runtime_signatures.pins.values():
            assert pin.data==signed['signature']
            with pytest.raises(OSError):pin.path.write_bytes(b'changed')
        tx['state']='recovering';step.store.journal.save(tx)
        assert len(step.recover()['removed'])==37
        assert step.recover()['removed']==[]
        assert signatures.inspect(step.source)['complete_signature_set_verified'] is True


@pytest.mark.parametrize('fault',['signature','closed-key','occupied','prior-receipt','untyped'])
def test_sidecar_preflight_fails_before_any_payload_write(tmp_path,monkeypatch,signed,fault):
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        root=step.store.directories['root'].path
        if fault=='signature':next(iter(signatures.signatures.values())).close()
        if fault=='closed-key':signatures.public_key.close()
        if fault=='occupied':(root/sorted(RUNTIME_SIDECARS)[0]).write_bytes(b'foreign')
        if fault=='prior-receipt':(step.store.journal.directory/RuntimeSignatureReceipts.filename).write_bytes(b'foreign')
        before={p:p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name!='install.lock'}
        with pytest.raises(SafetyError):apply(step,object() if fault=='untyped' else signatures,spec,data)
        assert not step.attempted
        assert {p:p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name!='install.lock'}==before


def test_partial_sidecar_receipt_failure_recovers_only_recorded_files(tmp_path,monkeypatch,signed):
    original=RuntimeSignatureReceipts.complete;calls=[]
    def fail(self,pin):
        calls.append(pin)
        if len(calls)==3:raise OSError('injected sidecar completion failure')
        return original(self,pin)
    monkeypatch.setattr(RuntimeSignatureReceipts,'complete',fail)
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        with pytest.raises(OSError):apply(step,signatures,spec,data)
        rows=RuntimeSignatureReceipts(step.store.journal).load()['files']
        assert len(rows)==3 and rows[-1]['state']=='created'
        tx['state']='recovering';step.store.journal.save(tx)
        assert len(step.recover()['removed'])==29


def test_unknown_sidecar_creation_does_not_authorize_any_deletion(tmp_path,monkeypatch,signed):
    def fail(self,handle):raise OSError('creation receipt unavailable')
    monkeypatch.setattr(RuntimeSignatureReceipts,'created',fail)
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        with pytest.raises(OSError):apply(step,signatures,spec,data)
        root=step.store.directories['root'].path
        before={p for p in root.rglob('*') if p.is_file()}
        tx['state']='recovering';step.store.journal.save(tx)
        with pytest.raises(SafetyError,match='Unrecorded'):step.recover()
        assert {p for p in root.rglob('*') if p.is_file()}==before


def test_boundary_lost_after_empty_sidecar_creation_retains_recovery_identity(tmp_path,monkeypatch,signed):
    allowed=[True];original=RuntimeSignatureReceipts.created
    def created(self,handle):
        original(self,handle);allowed[0]=False
    monkeypatch.setattr(RuntimeSignatureReceipts,'created',created)
    with fixture(tmp_path,monkeypatch,signed,lambda g:allowed[0]) as (step,signatures,tx,spec,data):
        with pytest.raises(SafetyError,match='boundary'):apply(step,signatures,spec,data)
        rows=RuntimeSignatureReceipts(step.store.journal).load()['files']
        assert len(rows)==1 and rows[0]['state']=='created' and rows[0]['identity'] is not None
        assert (step.store.directories['root'].path/rows[0]['name']).stat().st_size==0
        allowed[0]=True;tx['state']='recovering';step.store.journal.save(tx)
        assert len(step.recover()['removed'])==27


def test_legacy_staging_cannot_ignore_foreign_sidecars(tmp_path,monkeypatch,signed):
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        root=step.store.directories['root'].path
        path=root/sorted(RUNTIME_SIDECARS)[0];path.write_bytes(b'foreign')
        with pytest.raises(SafetyError,match='Occupied'):step.apply(spec,data,['C:\\'])
        assert not step.attempted and path.read_bytes()==b'foreign'
        assert not (root/'Engine/engine.exe').exists()


def test_recovery_rejects_short_signature_even_with_matching_edited_receipt(tmp_path,monkeypatch,signed):
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        apply(step,signatures,spec,data);step.close()
        receipts=RuntimeSignatureReceipts(step.store.journal);record=receipts.load()
        row=record['files'][0];path=step.store.directories['root'].path/row['name']
        path.write_bytes(b'x');row['sha256']=hashlib.sha256(b'x').hexdigest();receipts._save(record)
        tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
        tx['state']='recovering';step.store.journal.save(tx)
        with pytest.raises(SafetyError,match='Exact detached'):
            recovery.RecoveryInputs(step.store,tx['generation'])


@pytest.mark.parametrize('fault',[None,'not-passed','closed','short-cache','missing-receipt'])
def test_service_step_checks_sidecars_before_first_boundary_mutation(tmp_path,monkeypatch,signed,fault):
    events=[]
    def boundary(*args):
        events.append('first-boundary-operation')
        raise RuntimeError('stop fixture before any host mutation')
    monkeypatch.setattr(service,'_install_backend_denies',boundary)
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        apply(step,signatures,spec,data)
        staged=step.runtime_signatures
        if fault=='closed':next(iter(staged.pins.values())).close()
        if fault=='short-cache':next(iter(staged.pins.values())).data=b'x'
        if fault=='missing-receipt':(step.store.journal.directory/RuntimeSignatureReceipts.filename).unlink()
        tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
        step.store.journal.save(tx)
        with service.DisabledServiceStep(step.store,step.payload,step.configuration,tx['generation'],lambda g:True,
                runtime_signatures=None if fault=='not-passed' else staged) as services:
            if fault is None:
                with pytest.raises(RuntimeError,match='stop fixture'):services.apply()
                assert events==['first-boundary-operation']
            else:
                with pytest.raises(SafetyError):services.apply()
                assert events==[] and not services.attempted


@pytest.mark.parametrize('fault',[None,'missing','replaced','changed','closed-pin'])
def test_recovery_reopens_signatures_and_refuses_drift(tmp_path,monkeypatch,signed,fault):
    with fixture(tmp_path,monkeypatch,signed) as (step,signatures,tx,spec,data):
        apply(step,signatures,spec,data);step.close()
        tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
        tx['state']='recovering';step.store.journal.save(tx)
        path=step.store.directories['root'].path/sorted(RUNTIME_SIDECARS)[0]
        if fault in ('missing','replaced'):path.unlink()
        if fault=='replaced':path.write_bytes(signed['signature'])
        if fault=='changed':path.write_bytes(bytes(64))
        if fault in ('missing','replaced','changed'):
            with pytest.raises(SafetyError):recovery.RecoveryInputs(step.store,tx['generation'])
        else:
            with recovery.RecoveryInputs(step.store,tx['generation']) as inputs:
                assert inputs.report()['runtime_signature_files']==11
                if fault=='closed-pin':
                    next(iter(inputs.runtime_signatures.pins.values())).close()
                    with pytest.raises(SafetyError):inputs.report()
                else:
                    for pin in inputs.runtime_signatures.pins.values():
                        with pytest.raises(OSError):pin.path.write_bytes(b'changed')
        assert step.store.journal.load()==tx
