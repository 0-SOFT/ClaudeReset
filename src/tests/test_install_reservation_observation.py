import pytest
from claude_reset.install_reservation_observation import observe_pair
from claude_reset.install_reservations import _install_pair
from claude_reset.safeio import SafetyError
from test_install_reservations import Parent,pair


@pytest.mark.parametrize('present',[True,False])
def test_pair_observation_uses_one_read_only_transaction_and_no_mutation(present):
    engine=Parent();views=pair(engine)
    if present:_install_pair(engine,views,lambda:True)
    engine.events.clear();before=set(engine.added);call=engine._call
    def read_only(name,signature,*args):
        assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0')
        if name=='FwpmTransactionBegin0':assert args[-1]==1
        return call(name,signature,*args)
    engine._call=read_only
    result=observe_pair(engine,views,lambda:True)
    assert result['state']==('present' if present else 'absent') and len(result['keys'])==16
    assert not result['settings_changed'] and not result['client_admission']
    assert engine.added==before and engine.layer is present
    assert engine.events==['FwpmTransactionBegin0','FwpmTransactionAbort0']


@pytest.mark.parametrize('fault',['extra','missing','orphan','empty','readback','closed','invalid-bool','borrowed-closed','foreign-service','duplicate-port'])
def test_partial_changed_or_unowned_pair_never_becomes_absence(fault):
    engine=Parent();views=pair(engine);_install_pair(engine,views,lambda:True);engine.events.clear()
    if fault=='extra':engine.added.add('foreign')
    if fault=='missing':engine.added.pop()
    if fault=='orphan':engine.layer=False
    if fault=='empty':engine.added.clear()
    if fault=='readback':engine.failure='readback'
    if fault=='invalid-bool':views[0].verified=lambda *args:1
    if fault=='borrowed-closed':views[0]._borrowed_closed=True
    if fault=='foreign-service':views[0].service='BITS'
    if fault=='duplicate-port':views[1].port=views[0].port
    before=set(engine.added)
    with pytest.raises(SafetyError):observe_pair(engine,views,lambda:fault!='closed')
    assert engine.added==before and not engine._transaction
    assert not any('Add' in e or 'Delete' in e or 'Commit' in e for e in engine.events)
