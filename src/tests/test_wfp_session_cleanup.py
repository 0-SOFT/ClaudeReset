"""No native BFE calls: session close must still run after an abort failure."""
from ctypes import wintypes as W
import pytest
from claude_reset.strict_wfp import Engine
from claude_reset.safeio import SafetyError

@pytest.mark.parametrize('abort_fail',[False,True])
@pytest.mark.parametrize('close_fail',[False,True])
def test_session_close_attempted_after_transaction_abort_failure(abort_fail,close_fail):
    engine=object.__new__(Engine);engine.handle=W.HANDLE(123);engine._transaction=True
    events=[]
    def call(name,*args,**kwargs):
        events.append(name)
        if (name=='FwpmTransactionAbort0' and abort_fail) or (name=='FwpmEngineClose0' and close_fail):
            raise SafetyError('synthetic '+name+' failure')
    engine._call=call
    if abort_fail or close_fail:
        with pytest.raises(SafetyError):engine.close()
    else:engine.close()
    assert events==['FwpmTransactionAbort0','FwpmEngineClose0']
    assert bool(engine.handle)==close_fail
    if not close_fail:
        assert engine._transaction is False
        engine.close()
        assert len(events)==2


@pytest.mark.parametrize('abort_fail',[False,True])
def test_failed_close_keeps_handle_for_explicit_retry(abort_fail):
    engine=object.__new__(Engine);engine.handle=W.HANDLE(123);engine._transaction=True;events=[]
    def fail(name,*args):
        events.append(name)
        if name=='FwpmEngineClose0' or abort_fail:raise SafetyError('synthetic failure')
    engine._call=fail
    with pytest.raises(SafetyError):engine.close()
    assert engine.handle.value==123 and engine._transaction==abort_fail
    engine._call=lambda name,*args:events.append(name)
    engine.close()
    assert not engine.handle and engine._transaction is False
    assert events==['FwpmTransactionAbort0','FwpmEngineClose0']+(['FwpmTransactionAbort0'] if abort_fail else [])+['FwpmEngineClose0']
