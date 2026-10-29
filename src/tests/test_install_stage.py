from contextlib import contextmanager
import hashlib
import json
import pytest
from claude_reset import install_payload as payload
from claude_reset.install_stage import _stage_payload
from claude_reset.install_store import Store,Directory
from claude_reset.install_journal import _LocalFile
from claude_reset.install_transaction import Transaction,STEPS
from claude_reset.safeio import SafetyError


@contextmanager
def fixture(tmp_path,monkeypatch,*,root_name='store',payload_bytes=None):
    bundle=tmp_path/'bundle';root=tmp_path/root_name
    bundle.mkdir();root.mkdir()
    data=b'synthetic inert payload' if payload_bytes is None else payload_bytes
    digest=hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(payload,'ENGINES',{'fixture':digest})
    files={name:{'sha256':digest,'bytes':len(data)} for name in payload.FILES}
    for name in files:
        p=bundle/'payload'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    raw=json.dumps({'payload':files}).encode()
    (bundle/'bundle-manifest.json').write_bytes(raw)
    package=hashlib.sha256(raw).hexdigest()
    store=Store()
    try:
        store.directories['root']=Directory(root)
        directories={name.rsplit('/',1)[0] for name in payload.FILES}|{'Installer'}
        for name in sorted(directories):
            path=root/name;path.mkdir(parents=True,exist_ok=True)
            store.directories[name]=Directory(path)
        store.journal=_LocalFile(root/'Installer')
        state=Transaction(None,'a'*32,package).value
        state['entries']=[{'step':step,'state':'done'} for step in STEPS[:2]]
        state['entries'].append({'step':'stage_protected_files','state':'intent'})
        store.journal.save(state)
        with payload.PinnedPayload(bundle,package) as source:
            yield store,source,state
    finally:store.close()


def test_all_payloads_are_copied_from_pins_and_stay_immutable(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,state['generation'],lambda g:True) as staged:
            assert set(staged.pins)==payload.FILES
            assert store.journal.load()==state  # The transaction commits done later.
            for name,pin in staged.pins.items():
                assert pin.sha256==source.pins[name].sha256
                with pytest.raises(OSError):pin.path.write_bytes(b'changed')


@pytest.mark.parametrize('change',[
    lambda v:v.update(state='recovering'),
    lambda v:v['entries'][-1].update(state='done'),
    lambda v:v['entries'].pop(),
])
def test_staging_requires_the_exact_durable_intent(tmp_path,monkeypatch,change):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        change(state);store.journal.save(state)
        with pytest.raises(SafetyError):_stage_payload(store,source,'a'*32,lambda g:True)
        assert not (store.directories['root'].path/'Engine/engine.exe').exists()


def test_existing_file_aborts_before_any_other_copy(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        path=store.directories['root'].path/'Sandboxie/x64/Start.exe';path.write_bytes(b'other owner')
        with pytest.raises(SafetyError):_stage_payload(store,source,'a'*32,lambda g:True)
        assert path.read_bytes()==b'other owner'
        assert not (store.directories['root'].path/'Engine/engine.exe').exists()


def test_missing_held_parent_aborts_before_any_copy(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        store.directories['Engine'].close()
        with pytest.raises(SafetyError):_stage_payload(store,source,'a'*32,lambda g:True)
        assert not (store.directories['root'].path/'Backend/ClaudeResetBackend.exe').exists()


def test_partial_copy_failure_keeps_evidence_without_open_pins(tmp_path,monkeypatch):
    import claude_reset.install_stage as stage
    real=stage._copy_pinned;calls=[]
    def fail_second(source,target,**kwargs):
        calls.append(target)
        if len(calls)==2:raise OSError('injected copy failure')
        return real(source,target,**kwargs)
    monkeypatch.setattr(stage,'_copy_pinned',fail_second)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(OSError):_stage_payload(store,source,'a'*32,lambda g:True)
        assert calls[0].read_bytes()==b'synthetic inert payload'
        calls[0].write_bytes(b'handle released')
        assert store.journal.load()==state


def test_other_generation_cannot_stage(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(SafetyError):_stage_payload(store,source,'b'*32,lambda g:True)


@pytest.mark.parametrize('refuse_at,expected_files', [(1,0),(2,0),(3,1),(4,1),(5,1),(70,23)])
def test_closed_boundary_loss_preserves_owned_partial_stage_for_recovery(
        tmp_path,monkeypatch,refuse_at,expected_files):
    from claude_reset.install_receipts import Receipts
    from claude_reset.install_rollback import _rollback_staged_files
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        calls=[]
        def closed(generation):
            assert generation==state['generation'];calls.append(generation)
            return len(calls)!=refuse_at
        with pytest.raises(SafetyError,match='Client boundary'):
            _stage_payload(store,source,state['generation'],closed)
        root=store.directories['root'].path
        present=[name for name in payload.FILES if (root/name).exists()]
        assert len(present)==expected_files and len(calls)==refuse_at
        receipt=Receipts(store.journal).load()
        if refuse_at==1:assert receipt is None
        elif refuse_at==3:
            assert receipt['files'][0]['state']=='created' and receipt['files'][0]['identity']
            assert (root/present[0]).read_bytes()==b''
        elif present:assert all(row['state']=='complete' for row in receipt['files'])
        # Refusal releases pins but neither guesses cleanup nor erases receipts.
        assert store.journal.load()==state
        state['state']='recovering';store.journal.save(state)
        result=_rollback_staged_files(store,state['generation'],lambda g:True)
        assert set(result['removed'])==set(present) and result['client_admission'] is False


@pytest.mark.parametrize('answer', [None,False,1])
def test_staging_requires_explicit_true_boundary(tmp_path,monkeypatch,answer):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(SafetyError,match='Client boundary'):
            _stage_payload(store,source,state['generation'],lambda g:answer)
        assert not (store.journal.directory/'stage-receipts.json').exists()


def test_staging_requires_callable_boundary_verifier(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(SafetyError):_stage_payload(store,source,state['generation'],None)
        assert not (store.journal.directory/'stage-receipts.json').exists()
