import pytest
from claude_reset import strict_wfp as w
from claude_reset.install_boundary_observation import observe_initial_denies,READ_ONLY
from claude_reset.safeio import SafetyError


def model(tmp_path,state='present'):
    for i in range(4):(tmp_path/(str(i)+'.exe')).write_bytes(b'inert fixture')
    rules=w.deny_rules([w.Identity('app',str(tmp_path/(str(i)+'.exe'))) for i in range(4)])
    engine=w.Engine.__new__(w.Engine);engine.dynamic=False;engine._transaction=False;engine.handle=17
    keys={r.key.value() for r in rules};events=[]
    engine.existing_sublayer=lambda:state=='present'
    engine.own_keys=lambda:set(keys) if state=='present' else set()
    engine.exists_verified=lambda rule:state=='present'
    def call(name,signature,*args):
        assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0')
        if name=='FwpmTransactionBegin0':assert args==(17,READ_ONLY)
        else:assert args==(17,) and engine._transaction
        events.append(name)
    engine._call=call
    return engine,rules,keys,events


@pytest.mark.parametrize('state',['present','absent'])
def test_read_only_snapshot_distinguishes_complete_presence_and_absence(tmp_path,state):
    engine,rules,keys,events=model(tmp_path,state)
    result=observe_initial_denies(engine,rules,lambda:True)
    assert result==dict(keys=[r.key.value() for r in rules],state=state,transaction_consistent=True,
                        settings_changed=False,client_admission=False)
    assert events==['FwpmTransactionBegin0','FwpmTransactionAbort0'] and not engine._transaction


@pytest.mark.parametrize('fault',['empty-layer','missing','extra','orphan','altered','query-error','closed-mid','unknown-bool'])
def test_partial_foreign_and_unknown_state_never_produces_observation(tmp_path,fault):
    engine,rules,keys,events=model(tmp_path)
    if fault=='empty-layer':engine.own_keys=lambda:set();engine.exists_verified=lambda rule:False
    if fault=='missing':engine.own_keys=lambda:set(list(keys)[1:])
    if fault=='extra':engine.own_keys=lambda:keys|{'foreign'}
    if fault=='orphan':engine.existing_sublayer=lambda:False
    if fault=='unknown-bool':engine.exists_verified=lambda rule:1
    if fault in ('altered','query-error'):
        def refused(rule):raise SafetyError('Altered filter or failed query')
        engine.exists_verified=refused
    count=[0]
    def closed():count[0]+=1;return fault!='closed-mid' or count[0]<3
    with pytest.raises(SafetyError):observe_initial_denies(engine,rules,closed)
    assert events==['FwpmTransactionBegin0','FwpmTransactionAbort0'] and not engine._transaction


@pytest.mark.parametrize('fault',['dynamic','active','no-handle','duplicate','missing-rule','closed','begin','abort'])
def test_invalid_inputs_and_unknown_transaction_termination_refuse(tmp_path,fault):
    engine,rules,keys,events=model(tmp_path)
    if fault=='dynamic':engine.dynamic=True
    if fault=='active':engine._transaction=True
    if fault=='no-handle':engine.handle=None
    if fault=='duplicate':rules[-1]=rules[0]
    if fault=='missing-rule':rules.pop()
    original=engine._call
    def call(name,*args):
        original(name,*args)
        if fault=='begin' and name=='FwpmTransactionBegin0' or fault=='abort' and name=='FwpmTransactionAbort0':
            raise SafetyError('Unknown transaction result')
    engine._call=call
    with pytest.raises(SafetyError):observe_initial_denies(engine,rules,lambda:fault!='closed')
    if fault=='abort':assert engine._transaction is True
    elif fault!='active':assert engine._transaction is False
    if fault not in ('begin','abort'):assert not events
