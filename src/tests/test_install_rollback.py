import pytest
from claude_reset.install_stage import _stage_payload
from claude_reset.install_rollback import _rollback_staged_files
from claude_reset.install_receipts import Receipts
from claude_reset.safeio import SafetyError
from test_install_stage import fixture


def recover(store,state):
    state['state']='recovering';store.journal.save(state)


def test_owned_payload_rollback_is_idempotent_and_keeps_journal(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        recover(store,state);calls=[]
        def closed(generation):calls.append(generation);return True
        report=_rollback_staged_files(store,'a'*32,closed)
        assert len(report['removed'])==23 and report['client_admission'] is False
        assert calls and set(calls)=={'a'*32}  # Every verification uses the owned generation.
        assert store.journal.load()==state and len(Receipts(store.journal).load()['files'])==23
        assert _rollback_staged_files(store,'a'*32,closed)['removed']==[]


@pytest.mark.parametrize('reason',['replaced','changed','unrecorded','linked','busy'])
def test_one_conflict_preserves_all_payloads(tmp_path,monkeypatch,reason):
    from claude_reset.windows_pin import PinnedFile
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        recover(store,state)
        name=sorted(source.pins)[-1];path=store.directories['root'].path/name;busy=None
        if reason=='replaced':
            data=path.read_bytes();path.rename(path.with_suffix('.old'));path.write_bytes(data)
        elif reason=='changed':path.write_bytes(b'changed')
        elif reason=='unrecorded':
            receipts=Receipts(store.journal);value=receipts.load();value['files'].pop();receipts._save(value)
        elif reason=='linked':path.with_suffix('.alias').hardlink_to(path)
        else:busy=PinnedFile(path)
        try:
            with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda _:True)
            assert all((store.directories['root'].path/n).exists() for n in source.pins)
        finally:
            if busy:busy.close()


@pytest.mark.parametrize('responses',[[False],[None],[True,False]])
def test_closed_boundary_failure_preserves_every_file(tmp_path,monkeypatch,responses):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        recover(store,state);answers=iter(responses)
        with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda _:next(answers))
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


def test_applying_state_cannot_delete_files(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda _:True)
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


def test_recorded_partial_copy_can_be_removed(tmp_path,monkeypatch):
    real=Receipts.created
    def fail(self,handle):real(self,handle);raise OSError('injected copy failure')
    monkeypatch.setattr(Receipts,'created',fail)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(OSError):_stage_payload(store,source,'a'*32,lambda g:True)
        recover(store,state)
        assert _rollback_staged_files(store,'a'*32,lambda _:True)['removed']==[sorted(source.pins)[0]]


def test_interrupted_removal_can_retry_without_adopting_missing_files(tmp_path,monkeypatch):
    import claude_reset.install_rollback as rollback
    real=rollback._mark_delete;calls=[]
    def fail_second(pin):
        calls.append(pin.path)
        if len(calls)==2:raise SafetyError('injected removal failure')
        real(pin)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        recover(store,state)
        sentinel=store.directories['root'].path/'keep.txt';sentinel.write_bytes(b'not payload')
        monkeypatch.setattr(rollback,'_mark_delete',fail_second)
        with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda _:True)
        assert not calls[0].exists() and calls[1].exists()
        assert store.journal.load()==state
        monkeypatch.setattr(rollback,'_mark_delete',real)
        assert len(_rollback_staged_files(store,'a'*32,lambda _:True)['removed'])==22
        assert sentinel.read_bytes()==b'not payload'


@pytest.mark.parametrize('service_state',['intent','done'])
def test_pending_service_recovery_preserves_all_files(tmp_path,monkeypatch,service_state):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        state['entries'][-1]['state']='done'
        state['entries'].append(dict(step='install_services',state=service_state))
        recover(store,state)
        with pytest.raises(SafetyError,match='Services and dependent'):
            _rollback_staged_files(store,'a'*32,lambda _:True)
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


def test_unrecovered_boundary_preserves_files_even_if_services_marked_undone(tmp_path,monkeypatch):
    from claude_reset.install_boundary import IMAGES
    from claude_reset.install_boundary_receipts import BoundaryReceipt
    from claude_reset.strict_wfp import Identity,deny_rules
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        state['entries'][-1]['state']='done';state['entries'].append(dict(step='install_services',state='intent'))
        store.journal.save(state)
        keys=[r.key.value() for r in deny_rules([Identity('app',str(store.directories['root'].path/n)) for n in IMAGES])]
        BoundaryReceipt(store.journal,keys).record('intent')
        state['entries'][-1]['state']='undone';recover(store,state)
        with pytest.raises(SafetyError,match='WFP boundary'):_rollback_staged_files(store,'a'*32,lambda _:True)
        assert all((store.directories['root'].path/n).exists() for n in source.pins)


@pytest.mark.parametrize('fault',['service','sublayer','filter','after-first-delete','journal-drift',None])
def test_undone_service_step_needs_fresh_absence_before_each_file_removal(tmp_path,monkeypatch,fault):
    from claude_reset import install_cleanup_observation as observation,install_rollback as rollback
    from test_install_cleanup_observation import Model
    current={'deleted':0};queries=[];context={}
    class Query(Model):
        def __init__(self):
            super().__init__();queries.append(self)
            if fault=='sublayer':self.fault='present-FwpmSubLayerGetByKey0'
            if fault=='filter' or fault=='after-first-delete' and current['deleted']:
                self.fault='present-FwpmFilterGetByKey0'
        def close(self):
            super().close()
            if fault=='journal-drift':
                value=context['store'].journal.load();value['state']='recovery_required'
                context['store'].journal.save(value)
    monkeypatch.setattr(observation,'Engine',Query)
    def absent(names,closed):
        assert closed() is True
        if fault=='service':raise SafetyError('A service slot was occupied after prior recovery')
    monkeypatch.setattr(observation,'_confirm_absence',absent)
    original=rollback._mark_delete
    def remove(pin):original(pin);current['deleted']+=1
    monkeypatch.setattr(rollback,'_mark_delete',remove)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        context['store']=store
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        state['entries'][-1]['state']='done';state['entries'].append(dict(step='install_services',state='undone'))
        recover(store,state)
        if fault:
            with pytest.raises(SafetyError):_rollback_staged_files(store,'a'*32,lambda _:True)
            assert current['deleted']==int(fault=='after-first-delete')
            assert sum((store.directories['root'].path/n).exists() for n in source.pins)==23-current['deleted']
        else:
            assert len(_rollback_staged_files(store,'a'*32,lambda _:True)['removed'])==23
            assert len(queries)==24
            assert _rollback_staged_files(store,'a'*32,lambda _:True)['removed']==[]
        expected=dict(state,state='recovery_required') if fault=='journal-drift' else state
        assert store.journal.load()==expected
