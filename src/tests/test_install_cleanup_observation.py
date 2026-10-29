import uuid
import pytest
from claude_reset import install_cleanup_observation as o,strict_wfp as w
from claude_reset.safeio import SafetyError


class Model(w.Engine):
    def __init__(self):
        self.handle=17;self.dynamic=False;self._transaction=False
        self.events=[];self.fault=None;self.freed=0
    def _call(self,name,signature,*args,**kwargs):
        self.events.append(name)
        assert name in ('FwpmTransactionBegin0','FwpmTransactionAbort0','FwpmSubLayerGetByKey0','FwpmFilterGetByKey0')
        if name=='FwpmTransactionBegin0':assert args==(17,o.READ_ONLY)
        if self.fault==name:raise SafetyError('injected query/transaction failure')
        if name.endswith('GetByKey0'):
            return 0 if self.fault=='present-'+name else 123 if self.fault=='unknown-code' else kwargs['allowed'][0]
        return 0
    def _free(self,pointer):self.freed+=1
    def close(self):self.handle=None


def keys():return [str(uuid.uuid4()) for _ in range(32)]


@pytest.mark.parametrize('fault',[None,'present-FwpmSubLayerGetByKey0','present-FwpmFilterGetByKey0',
    'FwpmSubLayerGetByKey0','FwpmFilterGetByKey0','FwpmTransactionBegin0','FwpmTransactionAbort0',
    'unknown-code','service','registry','closed'])
def test_query_only_absence_refuses_every_present_or_unknown_object(monkeypatch,fault):
    engine=Model();engine.fault=fault;checks=[]
    def vacant(names,closed):
        assert names==list(reversed(o.SERVICES));checks.append(names)
        if fault in ('service','registry'):raise SafetyError('occupied SCM/registry slot')
        if closed() is not True:raise SafetyError('not closed')
    monkeypatch.setattr(o,'_confirm_absence',vacant)
    if fault is None:
        result=o.observe_cleanup_absence(engine,keys(),lambda:True)
        assert result==dict(services_absent=4,sublayers_absent=2,filter_keys_absent=32,settings_changed=False,client_admission=False)
        assert engine.events.count('FwpmSubLayerGetByKey0')==2 and engine.events.count('FwpmFilterGetByKey0')==32
        assert len(checks)==4 and not engine._transaction
    else:
        with pytest.raises(SafetyError):o.observe_cleanup_absence(engine,keys(),lambda:fault!='closed')
        if fault=='FwpmTransactionAbort0':assert engine._transaction
        elif 'FwpmTransactionBegin0' in engine.events and fault!='FwpmTransactionBegin0':
            assert engine.events[-1]=='FwpmTransactionAbort0' and not engine._transaction
        if fault.startswith('present-'):assert engine.freed==1


@pytest.mark.parametrize('fault',['dynamic','active','handle','duplicate','invalid-key','short'])
def test_invalid_observation_context_never_queries(monkeypatch,fault):
    engine=Model();values=keys()
    if fault=='dynamic':engine.dynamic=True
    if fault=='active':engine._transaction=True
    if fault=='handle':engine.handle=None
    if fault=='duplicate':values[-1]=values[0]
    if fault=='invalid-key':values[0]='receipt text is not an API selector'
    if fault=='short':values.pop()
    with pytest.raises(SafetyError):o.observe_cleanup_absence(engine,values,lambda:True)
    assert not engine.events


def test_closed_or_scm_drift_on_session_close_is_rejected(monkeypatch):
    state={'closed':True}
    class Changed(Model):
        def close(self):super().close();state['closed']=False
    monkeypatch.setattr(o,'Engine',Changed)
    monkeypatch.setattr(o,'_confirm_absence',lambda names,closed:closed())
    with pytest.raises(SafetyError,match='closing observation'):
        o.require_cleanup_absence(keys(),lambda:state['closed'])
