"""Recover before payload intent using real temporary journals, never host changes."""
import pytest
from claude_reset import install_recovery as r
from claude_reset.safeio import SafetyError
from test_install_config_stage import fixture
from test_install_recovery import run
from test_install_store import bootstrap_fixture,user_sid


def early(store,tx,count,last='intent'):
    tx['entries']=tx['entries'][:count]
    if count:tx['entries'][-1]['state']=last
    store.journal.save(tx)


@pytest.mark.parametrize('count,last',[(0,'intent'),(1,'intent'),(1,'done'),(2,'intent'),(2,'done')])
def test_early_recovery_revokes_without_file_or_service_cleanup(tmp_path,monkeypatch,count,last):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        early(store,tx,count,last)
        def forbidden(*args):pytest.fail('No durable file/service operation exists')
        monkeypatch.setattr(r,'recover_service_step',forbidden)
        monkeypatch.setattr(r,'_rollback_installation_files',forbidden)
        before=set(store.directories['root'].path.rglob('*'));events=[]
        result=run(store,tx,lambda g:events.append(('revoke',g)))
        assert events==[('revoke',tx['generation'])]
        assert result['files'] is None and result['services'] is None
        assert result['transaction']['state']=='rolled_back_clients_closed'
        assert all(e['state']=='undone' for e in result['transaction']['entries'])
        assert set(store.directories['root'].path.rglob('*'))==before
        assert not result['client_admission'] and not result['installed_version_uninstalled']
        with pytest.raises(SafetyError):run(store,tx)


@pytest.mark.parametrize('name',(*r.FILE_EVIDENCE,*r.SERVICE_EVIDENCE))
def test_later_metadata_blocks_early_recovery_without_adoption(tmp_path,monkeypatch,name):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        early(store,tx,2)
        path=store.journal.directory/name;path.write_bytes(b'unknown outcome')
        events=[]
        with pytest.raises(SafetyError,match='without durable staging intent'):
            run(store,tx,lambda g:events.append(g))
        assert not events and store.journal.load()==tx and path.read_bytes()==b'unknown outcome'


@pytest.mark.parametrize('name',['Engine/engine.exe','Policy/Sandboxie.ini','Sandboxie/x64/SbieSvc.exe.sig'])
def test_unrecorded_destination_is_preserved(tmp_path,monkeypatch,name):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        early(store,tx,0)
        path=store.directories['root'].path/name;path.write_bytes(b'foreign')
        with pytest.raises(SafetyError,match='Occupied destination'):run(store,tx)
        assert store.journal.load()==tx and path.read_bytes()==b'foreign'


@pytest.mark.parametrize('metadata',[False,True])
def test_late_resource_prevents_early_terminal_commit(tmp_path,monkeypatch,metadata):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        early(store,tx,1)
        path=(store.journal.directory/'stage-receipts.json' if metadata else
              store.directories['root'].path/'Engine/engine.exe')
        def revoke(generation):path.write_bytes(b'late foreign resource')
        with pytest.raises(SafetyError,match='without durable staging intent'):run(store,tx,revoke)
        assert store.journal.load()['state']=='recovery_required'
        assert path.read_bytes()==b'late foreign resource'


def test_early_recovery_still_requires_closed_boundary(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,tx,spec,data):
        early(store,tx,0);events=[]
        with pytest.raises(SafetyError,match='verified closed'):
            run(store,tx,lambda g:events.append(g),lambda g:False)
        assert events==[tx['generation']]
        assert store.journal.load()['state']!='rolled_back_clients_closed'


@pytest.mark.parametrize('count',[0,2])
def test_reopened_bootstrap_can_finish_early_recovery(tmp_path,bootstrap_fixture,count):
    from claude_reset.install_reopen import open_recovery_store
    from claude_reset.install_transaction import STEPS
    with bootstrap_fixture.create_store('a'*32,'b'*64) as store:
        tx=store.journal.load()
        tx['entries']=[dict(step=step,state='done') for step in STEPS[:count]]
        if count:tx['entries'][-1]['state']='intent'
        store.journal.save(tx)
    root=tmp_path/'ClaudeReset'
    before={p:p.read_bytes() for p in root.rglob('*.json') if p.name!='install-journal.json'}
    with open_recovery_store('a'*32,'b'*64) as reopened:
        result=run(reopened,tx)
        assert result['transaction']['state']=='rolled_back_clients_closed'
        assert result['files'] is None and result['services'] is None
    assert all(p.read_bytes()==data for p,data in before.items())
    with pytest.raises(SafetyError):open_recovery_store('a'*32,'b'*64)
