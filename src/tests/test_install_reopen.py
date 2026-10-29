import hashlib
import json
import pytest
from claude_reset.install_reopen import open_recovery_store
from claude_reset.install_transaction import STEPS
from claude_reset.safeio import SafetyError
from test_install_store import bootstrap_fixture,user_sid


def test_reopen_then_roll_back_inert_staging(tmp_path,bootstrap_fixture,monkeypatch):
    from claude_reset import install_payload as payload
    from claude_reset.install_stage import _stage_payload
    from claude_reset.install_rollback import _rollback_staged_files
    data=b'inert recovery fixture';digest=hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(payload,'ENGINES',{'fixture':digest})
    bundle=tmp_path/'bundle';bundle.mkdir()
    files={name:dict(sha256=digest,bytes=len(data)) for name in payload.FILES}
    for name in files:
        path=bundle/'payload'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    raw=json.dumps({'payload':files}).encode();(bundle/'bundle-manifest.json').write_bytes(raw)
    package=hashlib.sha256(raw).hexdigest()
    with bootstrap_fixture.create_store('a'*32,package) as store:
        state=store.journal.load()
        state['entries']=[dict(step=step,state='done') for step in STEPS[:3]]
        state['entries'][-1]['state']='intent';store.journal.save(state)
        with payload.PinnedPayload(bundle,package) as source:
            with _stage_payload(store,source,'a'*32,lambda g:True):pass
    # All old handles closed; this is a new store/lock, not reused fixture state.
    with open_recovery_store('a'*32,package) as store:
        assert store.journal.load()==state
        state['state']='recovering';store.journal.save(state)
        with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda generation:False)
        assert all((store.directories['root'].path/name).exists() for name in files)
        result=_rollback_staged_files(store,'a'*32,lambda generation:True)
        assert set(result['removed'])==set(files)
    with open_recovery_store('a'*32,package) as store:
        assert _rollback_staged_files(store,'a'*32,lambda generation:True)['removed']==[]


@pytest.mark.parametrize('fault',['directory','generation','package','terminal','missing','lock'])
def test_reopen_rejects_conflicts_without_changes(tmp_path,bootstrap_fixture,fault):
    with bootstrap_fixture.create_store('a'*32,'b'*64) as store:
        if fault=='lock':
            with pytest.raises(SafetyError):open_recovery_store('a'*32,'b'*64)
            return
        if fault=='terminal':
            state=store.journal.load();state['state']='rolled_back_clients_closed';store.journal.save(state)
    root=tmp_path/'ClaudeReset'
    if fault=='directory':
        (root/'Backend').rename(tmp_path/'old-backend');(root/'Backend').mkdir()
    elif fault=='missing':(root/'Installer/directory-receipts.json').unlink()
    before=sorted(str(p.relative_to(root)) for p in root.rglob('*'))
    with pytest.raises((SafetyError,OSError)):
        open_recovery_store('c'*32 if fault=='generation' else 'a'*32,
                            'd'*64 if fault=='package' else 'b'*64)
    assert sorted(str(p.relative_to(root)) for p in root.rglob('*'))==before
    root.rename(tmp_path/'released')
