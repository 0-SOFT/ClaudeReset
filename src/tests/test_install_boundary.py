import ctypes as C
import pytest
from claude_reset import strict_wfp as w,install_boundary as b
from claude_reset.install_boundary_receipts import BoundaryReceipt
from claude_reset.install_stage import _stage_payload
from claude_reset.safeio import SafetyError
from test_install_stage import fixture


def model(tmp_path,failure=None):
    path=tmp_path/'ClaudeResetBackend.exe';path.write_bytes(b'inert')
    rules=w.deny_rules([w.Identity('app',str(path))])
    engine=w.Engine.__new__(w.Engine);engine.dynamic=False;engine._transaction=False;engine.handle=17
    events=[];added=set();layer=[False]
    engine.existing_sublayer=lambda:failure=='existing' or layer[0]
    def ensure():
        assert engine._transaction;events.append('sublayer');layer[0]=True
        if failure=='sublayer':raise SafetyError('injected')
    engine.ensure_sublayer=ensure
    engine._native=lambda rule:(w.wfp.FILTER(filterKey=rule.key),[])
    engine.exists_verified=lambda rule:failure=='filter_collision' or (rule.key.value() in added and failure!='readback')
    def call(name,signature,*args):
        events.append(name)
        if name=='FwpmFilterAdd0':
            assert engine._transaction
            if failure=='add':raise SafetyError('injected')
            added.add(C.cast(args[1],C.POINTER(w.wfp.FILTER)).contents.filterKey.value())
        if name=='FwpmTransactionCommit0' and failure=='commit':raise SafetyError('injected')
        if name=='FwpmTransactionAbort0':added.clear();layer[0]=False
    engine._call=call
    count=[0]
    def closed():count[0]+=1;return not (failure=='closed_after' and count[0]>1)
    return engine,rules,events,added,layer,closed


def test_sublayer_and_denies_share_one_commit(tmp_path):
    engine,rules,events,added,layer,closed=model(tmp_path)
    engine.install_new_denies(rules,closed)
    assert events==['FwpmTransactionBegin0','sublayer']+['FwpmFilterAdd0']*4+['FwpmTransactionCommit0']
    assert len(added)==4 and layer[0] and not engine._transaction


@pytest.mark.parametrize('failure',['sublayer','add','readback','commit','closed_after','filter_collision'])
def test_any_precommit_failure_aborts_entire_initial_boundary(tmp_path,failure):
    engine,rules,events,added,layer,closed=model(tmp_path,failure)
    with pytest.raises(SafetyError):engine.install_new_denies(rules,closed)
    assert events[-1]=='FwpmTransactionAbort0'
    assert not added and not layer[0] and not engine._transaction


@pytest.mark.parametrize('reason',['existing','dynamic','duplicate','permit','empty','false_boundary'])
def test_unaccepted_initial_boundary_never_begins_transaction(tmp_path,reason):
    engine,rules,events,_,_,closed=model(tmp_path,'existing' if reason=='existing' else None)
    if reason=='dynamic':engine.dynamic=True
    if reason=='duplicate':rules.append(rules[0])
    if reason=='permit':rules=[w.Rule(rules[0].identity,'connect_v4',w.PERMIT,'127.0.0.1',1080,False)]
    if reason=='empty':rules=[]
    if reason=='false_boundary':closed=lambda:None
    with pytest.raises(SafetyError):engine.install_new_denies(rules,closed)
    assert not events


@pytest.mark.parametrize('fail_engine',[False,True])
def test_staged_backend_images_are_journalled_without_any_permits(tmp_path,monkeypatch,fail_engine):
    events=[]
    class Engine:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def install_new_denies(self,rules,closed):
            events.append('install')
            assert len(rules)==16 and all(r.action==w.BLOCK and r.persistent for r in rules)
            assert len({r.identity.value for r in rules})==4
            assert closed() is True
            for rule in rules:rule.validate()
            if fail_engine:raise SafetyError('injected BFE failure')
    monkeypatch.setattr(b,'Engine',Engine)
    monkeypatch.setattr(b,'program_files',lambda:tmp_path)
    with fixture(tmp_path,monkeypatch,root_name='ClaudeReset') as (store,payload,tx):
        with _stage_payload(store,payload,'a'*32,lambda g:True) as staged:
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'))
            store.journal.save(tx)
            if fail_engine:
                with pytest.raises(SafetyError):b._install_backend_denies(store,staged,'a'*32,lambda g:True)
            else:assert b._install_backend_denies(store,staged,'a'*32,lambda g:True)['deny_filters']==16
            keys=[rule.key.value() for rule in w.deny_rules([w.Identity('app',str(staged.pins[n].path)) for n in b.IMAGES])]
            value=BoundaryReceipt(store.journal,keys).load()
            assert value['state']==('intent' if fail_engine else 'committed')
            with pytest.raises(SafetyError):b._install_backend_denies(store,staged,'a'*32,lambda g:True)
            assert events==['install']


@pytest.mark.parametrize('failure',[None,'extra','missing','changed','delete','sublayer','readback','commit','closed_after'])
def test_recorded_deny_removal_is_exact_and_transactional(tmp_path,failure):
    engine,rules,events,added,layer,_=model(tmp_path)
    engine.install_new_denies(rules,lambda:True);events.clear()
    original=set(added)
    if failure=='missing':added.pop()
    before=set(added)
    engine.own_keys=lambda:set(added)|({'foreign'} if failure=='extra' else set())
    engine.exists_verified=lambda rule:rule.key.value() in added and failure!='changed'
    engine.existing_sublayer=lambda:layer[0] or failure=='readback'
    def call(name,signature,*args):
        events.append(name)
        if name=='FwpmFilterDeleteByKey0':
            added.remove(C.cast(args[1],C.POINTER(w.wfp.GUID)).contents.value())
            if failure=='delete':raise SafetyError('injected deletion failure')
        if name=='FwpmSubLayerDeleteByKey0':
            layer[0]=False
            if failure=='sublayer':raise SafetyError('injected sublayer failure')
        if name=='FwpmTransactionCommit0' and failure=='commit':raise SafetyError('injected commit failure')
        if name=='FwpmTransactionAbort0':added.update(original);layer[0]=True
    engine._call=call;count=[0]
    def closed():count[0]+=1;return failure!='closed_after' or count[0]==1
    if failure:
        with pytest.raises(SafetyError):engine.remove_recorded_denies(rules,closed)
        if failure in ('extra','missing','changed'):assert not events and added==before
        else:assert events[-1]=='FwpmTransactionAbort0' and added==original and layer[0]
    else:
        engine.remove_recorded_denies(rules,closed)
        assert not added and not layer[0]
        assert events==['FwpmTransactionBegin0']+['FwpmFilterDeleteByKey0']*4+['FwpmSubLayerDeleteByKey0','FwpmTransactionCommit0']


@pytest.mark.parametrize('fault',[None,'service_present','unconfirmed'])
def test_durable_boundary_cleanup_requires_confirmed_creation_and_absent_services(tmp_path,monkeypatch,fault):
    from claude_reset import install_inventory as inventory,install_scm as scm
    events=[]
    class Engine:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def install_new_denies(self,rules,closed):
            assert closed() is True
            if fault=='unconfirmed':raise SafetyError('unknown commit outcome')
        def remove_recorded_denies(self,rules,closed):
            assert closed() is True and len(rules)==16;events.append('remove')
    monkeypatch.setattr(b,'Engine',Engine);monkeypatch.setattr(b,'program_files',lambda:tmp_path)
    monkeypatch.setattr(inventory,'services',lambda:[dict(name=n,exists=fault=='service_present' and n=='SbieDrv') for n in inventory.SERVICES])
    monkeypatch.setattr(scm,'require_vacant_registry_slot',lambda name:None)
    with fixture(tmp_path,monkeypatch,root_name='ClaudeReset') as (store,payload,tx):
        with _stage_payload(store,payload,'a'*32,lambda g:True) as staged:
            tx['entries'][-1]['state']='done';tx['entries'].append(dict(step='install_services',state='intent'));store.journal.save(tx)
            if fault=='unconfirmed':
                with pytest.raises(SafetyError):b._install_backend_denies(store,staged,'a'*32,lambda g:True)
            else:b._install_backend_denies(store,staged,'a'*32,lambda g:True)
            tx['state']='recovering';store.journal.save(tx)
            if fault:
                with pytest.raises(SafetyError):b._remove_backend_denies(store,staged,'a'*32,lambda g:True)
                assert not events
            else:
                assert b._remove_backend_denies(store,staged,'a'*32,lambda g:True)['deny_filters_removed']==16
                keys=[rule.key.value() for rule in b._held_rules(store,staged)]
                assert BoundaryReceipt(store.journal,keys).load()['state']=='removed'
