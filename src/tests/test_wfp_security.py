from copy import deepcopy
import ctypes as C
import pytest
from claude_reset import wfp_security as s,wfp,strict_wfp as strict
from claude_reset.safeio import SafetyError


def row():
    return dict(owner='S-1-5-32-544',dacl_present=True,dacl_null=False,protected=True,
        rules=[dict(sid=sid,mask=s.ALL,type=0,flags=0) for sid in sorted(s.OWNERS)])


def test_descriptor_is_protected_and_admin_only_in_actual_windows_parser():
    with s.Descriptor() as descriptor:
        actual=s.decode(descriptor.reader,descriptor.pointer)
        assert s.validate(actual)
        assert actual==row()
    assert not descriptor.pointer


@pytest.mark.parametrize('change',[
    lambda v:v.update(owner='S-1-5-11'),lambda v:v.update(owner=[]),
    lambda v:v.update(dacl_present=False),lambda v:v.update(dacl_null=True),
    lambda v:v.update(protected=False),lambda v:v.update(rules=[]),
    lambda v:v['rules'].append(dict(sid='S-1-5-32-556',mask=0x3010b,type=0,flags=0)),
    lambda v:v['rules'][0].update(mask=0x20080),
    lambda v:v['rules'][0].update(mask=True),lambda v:v['rules'][0].update(flags=16),
    lambda v:v['rules'][0].update(type=1),
    lambda v:v['rules'][0].update(sid=v['rules'][1]['sid']),
])
def test_inherited_untrusted_or_incomplete_permissions_are_not_accepted(change):
    value=deepcopy(row());change(value)
    with pytest.raises(SafetyError):s.validate(value)


@pytest.mark.parametrize('kind',['filter','sublayer'])
def test_get_security_api_is_read_only_and_releases_result(kind):
    with s.Descriptor() as descriptor:
        events=[]
        class Engine:
            handle=17
            def _call(self,name,signature,*args):
                events.append(name)
                assert name in ('FwpmFilterGetSecurityInfoByKey0','FwpmSubLayerGetSecurityInfoByKey0')
                assert args[0]==17 and args[2:7]==(5,None,None,None,None)
                C.cast(args[-1],C.POINTER(C.c_void_p))[0]=descriptor.pointer.value
            def _free(self,pointer):events.append('free') # Descriptor context owns fixture allocation.
        assert s.verify(Engine(),kind,strict.SUBKEY)
        assert len(events)==2 and events[-1]=='free'


def test_readback_failure_frees_descriptor_without_repair(monkeypatch):
    with s.Descriptor() as descriptor:
        events=[]
        class Engine:
            handle=1
            def _call(self,name,signature,*args):
                events.append(name);C.cast(args[-1],C.POINTER(C.c_void_p))[0]=descriptor.pointer.value
            def _free(self,pointer):events.append('free')
        monkeypatch.setattr(s,'decode',lambda *a:dict(row(),protected=False))
        with pytest.raises(SafetyError):s.verify(Engine(),'filter',strict.SUBKEY)
        assert events==['FwpmFilterGetSecurityInfoByKey0','free']


@pytest.mark.parametrize('kind,key',[('container',strict.SUBKEY),('filter',wfp.GUID.of('00000000-0000-0000-0000-000000000000')),('filter',None)])
def test_container_or_unknown_object_is_never_inspected(kind,key):
    with pytest.raises(SafetyError):s.verify(object(),kind,key)


def test_strict_sublayer_creation_supplies_descriptor_before_readback(monkeypatch):
    engine=strict.Engine.__new__(strict.Engine);engine.dynamic=False;engine.handle=17
    checks=iter([False,True]);events=[]
    monkeypatch.setattr(engine,'existing_sublayer',lambda:next(checks))
    def call(name,signature,*args):
        assert name=='FwpmSubLayerAdd0'
        assert s.validate(s.decode(s.Reader(),args[-1]))
        events.append(name)
    monkeypatch.setattr(engine,'_call',call)
    engine.ensure_sublayer()
    assert events==['FwpmSubLayerAdd0']


def test_strict_filter_content_match_still_requires_security_readback(monkeypatch):
    from types import SimpleNamespace
    engine=strict.Engine.__new__(strict.Engine);engine.handle=17
    wanted=wfp.FILTER(filterKey=strict.SUBKEY,subLayerKey=strict.SUBKEY,flags=1)
    wanted.weight.type=1;wanted.weight.value.u8=1
    engine._native=lambda rule:(wanted,[])
    def call(name,signature,*args,**kwargs):
        assert name=='FwpmFilterGetByKey0'
        C.cast(args[-1],C.POINTER(C.POINTER(wfp.FILTER)))[0]=C.pointer(wanted)
        return 0
    engine._call=call;freed=[];engine._free=lambda ptr:freed.append(True)
    def reject(*args):raise SafetyError('untrusted ACL')
    monkeypatch.setattr(s,'verify',reject)
    with pytest.raises(SafetyError,match='untrusted ACL'):
        engine.exists_verified(SimpleNamespace(identity=SimpleNamespace(kind='app')))
    assert freed==[True]


@pytest.mark.parametrize('present',[False,True])
def test_reservation_sublayer_readback_never_adds_missing_object(monkeypatch,present):
    from claude_reset import gateway_reservation as g
    engine=g.Reservation.__new__(g.Reservation);engine.handle=17
    data=(C.c_ubyte*len(g.MARK)).from_buffer_copy(g.MARK)
    wanted=strict.SUBLAYER(key=g.SUB,flags=1,data=wfp.BLOB(len(g.MARK),data),weight=61100)
    events=[]
    def call(name,signature,*args,**kwargs):
        events.append(name)
        assert name=='FwpmSubLayerGetByKey0'
        if not present:return 0x80320007
        C.cast(args[-1],C.POINTER(C.POINTER(strict.SUBLAYER)))[0]=C.pointer(wanted)
        return 0
    engine._call=call;engine._free=lambda pointer:events.append('free')
    def verify(instance,kind,key):
        assert instance is engine and kind=='sublayer' and key.value()==g.SUB.value()
        events.append('security');return True
    monkeypatch.setattr(s,'verify',verify)
    assert engine.existing_sublayer() is present
    assert events==(['FwpmSubLayerGetByKey0','free','security'] if present else ['FwpmSubLayerGetByKey0'])
