import ctypes as C
import uuid
import pytest
from claude_reset.network import gateway_reservation as g, strict_wfp as w
from claude_reset.safeio import SafetyError
from claude_reset.windows.wfp_session import Session
from wfp_fakes import fake


class Parent(fake(w.Engine)):
    """An open persistent strict session that records every native call."""
    def __init__(self):
        super().__init__(17);self.events=[]
    def close(self):self.events.append('parent-close');self.handle=None
    def free(self,pointer):self.events.append('free')
    def native(self,name,*args,**kwargs):self.events.append(name)


class View(g.Reservation):
    """A reservation view without image or service checks: only the borrowing is real."""
    def __init__(self,service,port,*,engine):
        self.service,self.port,self.borrowed=service,port,True
        Session.__init__(self,borrow=engine)


def test_borrowed_reservation_closes_only_view_and_never_parent(tmp_path):
    path=tmp_path/'engine.exe';path.write_bytes(b'inert');parent=Parent()
    view=g.Reservation(path,'ClaudeResetBackend',1080,engine=parent,descriptor=b'fixture descriptor')
    view.call('read',[]);view.close()
    assert parent.handle==17 and parent.events==['read']
    with pytest.raises(SafetyError):view.call('read',[])
    with pytest.raises(SafetyError):view.install()
    assert parent.handle==17


def test_borrowed_view_cannot_use_closed_parent(tmp_path):
    path=tmp_path/'engine.exe';path.write_bytes(b'inert');parent=Parent()
    view=g.Reservation(path,'ClaudeResetBackend',1080,engine=parent,descriptor=b'fixture descriptor');parent.close()
    with pytest.raises(SafetyError):view.call('read',[])


def test_reservation_enumeration_does_not_count_strict_or_foreign_sublayers():
    from ctypes import wintypes as W
    parent=Parent();view=View('ClaudeResetBackend',1080,engine=parent)
    keys=[w.wfp.GUID.of(uuid.uuid4()) for _ in range(3)]
    filters=[w.wfp.FILTER(filterKey=key,subLayerKey=sub) for key,sub in
             zip(keys,[g.SUB,w.SUBKEY,w.wfp.GUID.of(uuid.uuid4())])]
    pointers=(C.POINTER(w.wfp.FILTER)*3)(*[C.pointer(f) for f in filters])
    def call(name,*args,**kwargs):
        parent.events.append(name)
        if name=='FwpmFilterCreateEnumHandle0':C.cast(args[2],C.POINTER(W.HANDLE))[0]=91
        if name=='FwpmFilterEnum0':
            C.cast(args[3],C.POINTER(C.POINTER(C.POINTER(w.wfp.FILTER))))[0]=pointers
            C.cast(args[4],C.POINTER(W.DWORD))[0]=3
    parent.native=call
    assert view.own_keys()=={keys[0].value()}
    assert parent.own_keys()=={keys[1].value()}
    assert parent.events.count('free')==2
    assert parent.events.count('FwpmFilterDestroyEnumHandle0')==2
