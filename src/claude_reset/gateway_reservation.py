"""Reserve only a Claude gateway TCP port for its exact service image and SID.

Persistent bind and receive rules prevent a different listener replacing a dead
controller. No default firewall policy, interface, route or DNS is changed.
Installation is separate from authorizing clients to use the gateway.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
from pathlib import Path
import uuid
from . import wfp
from .strict_wfp import Engine, SUBLAYER, BLOCK, PERMIT
from .safeio import SafetyError

NS = uuid.UUID('6ef4230b-dc85-4fb8-9d93-34d274553a8a')
SUB = wfp.GUID.of(uuid.uuid5(NS, 'gateway-port-v1'))
MARK = b'ClaudeReset-Gateway-Reservation-v1'
PORT = wfp.GUID.of('0c1ba1af-5765-453f-af22-a8f791ac775b')
PROTOCOL = wfp.GUID.of('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7')
USER = wfp.GUID.of('af043a0a-b34d-4f86-979c-c90371af6e66')
LAYERS = ('1247d66d-0b60-4a15-8d44-7155d0f53a0c', '55a650e1-5f0a-4eca-a653-88f53b26aa8c',
          'e1cd9fe7-f4b5-4273-96c0-592e487b8650', 'a3b42c97-9f04-4672-b87e-cee9c483257f')


def service_descriptor(name):
    if name not in ('ClaudeResetGateway', 'ClaudeResetGatewayFixture', 'ClaudeResetBackend', 'ClaudeResetBackendFixture'):
        raise SafetyError('Only the owned gateway service can reserve a port')
    a, k = C.WinDLL('advapi32', use_last_error=True), C.WinDLL('kernel32')
    a.LookupAccountNameW.argtypes = [W.LPCWSTR,W.LPCWSTR,C.c_void_p,C.POINTER(W.DWORD),W.LPWSTR,C.POINTER(W.DWORD),C.POINTER(W.DWORD)]
    a.ConvertSidToStringSidW.argtypes = [C.c_void_p,C.POINTER(W.LPWSTR)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.POINTER(W.DWORD)]
    k.LocalFree.argtypes = [C.c_void_p]
    n, dn, use = W.DWORD(), W.DWORD(), W.DWORD()
    a.LookupAccountNameW(None,'NT SERVICE\\'+name,None,C.byref(n),None,C.byref(dn),C.byref(use))
    if C.get_last_error()!=122 or not 8<=n.value<=68 or not 1<=dn.value<=256:
        raise SafetyError('Gateway service SID is unavailable')
    sid, domain = C.create_string_buffer(n.value), C.create_unicode_buffer(dn.value)
    if not a.LookupAccountNameW(None,'NT SERVICE\\'+name,sid,C.byref(n),domain,C.byref(dn),C.byref(use)):
        raise SafetyError('Gateway service SID lookup failed')
    value, sd, length = W.LPWSTR(), C.c_void_p(), W.DWORD()
    if not a.ConvertSidToStringSidW(sid,C.byref(value)):
        raise SafetyError('Cannot encode service SID')
    try:
        if domain.value.casefold()!='nt service' or not value.value.startswith('S-1-5-80-'):
            raise SafetyError('Gateway service identity is not service-specific')
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:SYG:SYD:(A;;CC;;;'+value.value+')',1,C.byref(sd),C.byref(length)):
            raise SafetyError('Cannot construct service match descriptor')
        return C.string_at(sd,length.value)
    finally:
        if sd:k.LocalFree(sd)
        k.LocalFree(value)


class Reservation(Engine):
    def __init__(self, executable, service, port,*,engine=None):
        self.executable=Path(executable)
        expected = {'ClaudeResetGateway':'ClaudeResetGateway.exe','ClaudeResetGatewayFixture':'ClaudeResetGateway.exe',
                    'ClaudeResetBackend':'engine.exe','ClaudeResetBackendFixture':'engine.exe'}.get(service)
        if not expected or not self.executable.is_absolute() or self.executable.name!=expected or not self.executable.is_file():
            raise SafetyError('An exact existing gateway image is required')
        if type(port) is not int or not 1024<=port<49152:
            raise SafetyError('Use one dedicated non-ephemeral gateway port')
        self.descriptor=service_descriptor(service)
        self.service,self.port=service,port
        self.slot=f'{service}:{port}'
        self._borrowed_engine=engine;self._borrowed_closed=False
        if engine is None:super().__init__()
        else:
            if not isinstance(engine,Engine) or engine.dynamic is not False or not engine.handle:
                raise SafetyError('An open persistent parent WFP session is required')
            self.handle=engine.handle;self.dynamic=False;self._transaction=False

    def _call(self,*args,**kwargs):
        engine=getattr(self,'_borrowed_engine',None)
        if engine is None:return super()._call(*args,**kwargs)
        if self._borrowed_closed or not engine.handle:raise SafetyError('Borrowed WFP session is closed')
        return engine._call(*args,**kwargs)

    def _free(self,pointer):
        engine=getattr(self,'_borrowed_engine',None)
        if engine is None:return super()._free(pointer)
        return engine._free(pointer)

    def close(self):
        if getattr(self,'_borrowed_engine',None) is None:return super().close()
        self._borrowed_closed=True;self.handle=W.HANDLE()

    def existing_sublayer(self):
        """Read only; never create a missing reservation during runtime checks."""
        ptr=C.POINTER(SUBLAYER)()
        code=self._call('FwpmSubLayerGetByKey0',[W.HANDLE,C.POINTER(wfp.GUID),C.POINTER(C.POINTER(SUBLAYER))],self.handle,C.byref(SUB),C.byref(ptr),allowed=(0x80320007,))
        if not code:
            try:
                s=ptr.contents
                if s.flags!=1 or s.weight!=61100 or s.provider or s.data.size!=len(MARK) or C.string_at(s.data.data,s.data.size)!=MARK:
                    raise SafetyError('Gateway reservation sublayer changed')
            finally:self._free(ptr)
            from .wfp_security import verify
            verify(self,'sublayer',SUB)
            return True
        return False

    def own_keys(self):
        return self._keys_in_sublayer(SUB)

    def ensure_sublayer(self):
        if self.existing_sublayer():return
        data=(C.c_ubyte*len(MARK)).from_buffer_copy(MARK)
        s=SUBLAYER(key=SUB,display=wfp.DISPLAY('ClaudeReset gateway port',None),flags=1,data=wfp.BLOB(len(MARK),data),weight=61100)
        from .wfp_security import Descriptor
        with Descriptor() as security:
            self._call('FwpmSubLayerAdd0',[W.HANDLE,C.POINTER(SUBLAYER),C.c_void_p],self.handle,C.byref(s),security.pointer)
        if not self.existing_sublayer():raise SafetyError('New gateway sublayer readback failed')

    def native(self, layer, allow):
        keep=[];conditions=(wfp.CONDITION*(4 if allow else 2))()
        for c,field,dtype,value in zip(conditions,(PORT,PROTOCOL),(2,1),(self.port,6)):
            c.fieldKey,c.matchType=field,0;c.conditionValue.type=dtype;c.conditionValue.value.u32=value
        if allow:
            ptr=C.POINTER(wfp.BLOB)()
            self._call('FwpmGetAppIdFromFileName0',[W.LPCWSTR,C.POINTER(C.POINTER(wfp.BLOB))],str(self.executable),C.byref(ptr))
            try:app=C.string_at(ptr.contents.data,ptr.contents.size)
            finally:self._free(ptr)
            for c,field,data,dtype in zip(conditions[2:],(wfp.FIELD_APP_ID,USER),(app,self.descriptor),(12,14)):
                buf=(C.c_ubyte*len(data)).from_buffer_copy(data);blob=wfp.BLOB(len(data),buf);keep.extend((buf,blob))
                c.fieldKey,c.matchType=field,0;c.conditionValue.type=dtype;c.conditionValue.value.ptr=C.cast(C.pointer(blob),C.c_void_p).value
        key=wfp.GUID.of(uuid.uuid5(NS,f'{self.slot}:{layer}:{allow}'))
        mark=MARK+hashlib.sha256((self.slot+str(self.executable)).encode()+self.descriptor).digest()
        data=(C.c_ubyte*len(mark)).from_buffer_copy(mark);keep.extend((conditions,data))
        f=wfp.FILTER(filterKey=key,displayData=wfp.DISPLAY('ClaudeReset reserved gateway port',None),flags=1,
                     providerData=wfp.BLOB(len(mark),data),layerKey=wfp.GUID.of(layer),subLayerKey=SUB,
                     numFilterConditions=len(conditions),filterCondition=conditions)
        f.weight.type,f.weight.value.u8=1,15 if allow else 1;f.action.type=PERMIT if allow else BLOCK
        return f,keep

    def verified(self, layer, allow):
        wanted,keep=self.native(layer,allow);ptr=C.POINTER(wfp.FILTER)()
        code=self._call('FwpmFilterGetByKey0',[W.HANDLE,C.POINTER(wfp.GUID),C.POINTER(C.POINTER(wfp.FILTER))],self.handle,C.byref(wanted.filterKey),C.byref(ptr),allowed=(wfp.FWP_E_FILTER_NOT_FOUND,))
        if code:return False
        try:
            a=ptr.contents
            weight=C.cast(a.weight.value.ptr,C.POINTER(C.c_uint64)).contents.value>>60 if a.weight.type==4 else a.weight.value.u8
            if (a.layerKey.value()!=layer or a.subLayerKey.value()!=SUB.value() or a.providerKey or a.flags&~0x40!=1
                or weight!=wanted.weight.value.u8 or a.action.type!=wanted.action.type or a.numFilterConditions!=wanted.numFilterConditions
                or a.providerData.size!=wanted.providerData.size or C.string_at(a.providerData.data,a.providerData.size)!=C.string_at(wanted.providerData.data,wanted.providerData.size)):
                raise SafetyError('Gateway reservation readback differs')
            for x,y in zip(a.filterCondition[:a.numFilterConditions],wanted.filterCondition[:wanted.numFilterConditions]):
                if x.fieldKey.value()!=y.fieldKey.value() or x.matchType!=0 or x.conditionValue.type!=y.conditionValue.type:
                    raise SafetyError('Gateway reservation condition differs')
                if x.conditionValue.type in (12,14):
                    bx,by=[C.cast(z.conditionValue.value.ptr,C.POINTER(wfp.BLOB)).contents for z in (x,y)]
                    equal=bx.size==by.size and C.string_at(bx.data,bx.size)==C.string_at(by.data,by.size)
                else:equal=x.conditionValue.value.u32==y.conditionValue.value.u32
                if not equal:raise SafetyError('Gateway reservation target differs')
            from .wfp_security import verify
            verify(self,'filter',wanted.filterKey)
            return True
        finally:self._free(ptr)

    def install(self):
        if getattr(self,'_borrowed_engine',None) is not None:
            raise SafetyError('Borrowed reservation requires a coordinated transaction')
        from .service_store import verify_image
        verify_image(self.executable,self.service)
        self.ensure_sublayer()
        self._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],self.handle,0);self._transaction=True
        try:
            for layer in LAYERS:
                for allow in (False,True):
                    if self.verified(layer,allow):continue
                    f,keep=self.native(layer,allow);identifier=C.c_uint64()
                    from .wfp_security import Descriptor
                    with Descriptor() as security:
                        self._call('FwpmFilterAdd0',[W.HANDLE,C.POINTER(wfp.FILTER),C.c_void_p,C.POINTER(C.c_uint64)],self.handle,C.byref(f),security.pointer,C.byref(identifier))
                    if not self.verified(layer,allow):raise SafetyError('Gateway filter missing after installation')
            self._call('FwpmTransactionCommit0',[W.HANDLE],self.handle);self._transaction=False
        except BaseException:
            self._call('FwpmTransactionAbort0',[W.HANDLE],self.handle);self._transaction=False;raise

    def remove_fixture(self):
        if getattr(self,'_borrowed_engine',None) is not None:
            raise SafetyError('Borrowed reservation cannot run fixture cleanup')
        if self.service!='ClaudeResetGatewayFixture':raise SafetyError('Fixture cleanup cannot remove production reservations')
        for layer in LAYERS:
            for allow in (False,True):
                if self.verified(layer,allow):
                    f,keep=self.native(layer,allow)
                    self._call('FwpmFilterDeleteByKey0',[W.HANDLE,C.POINTER(wfp.GUID)],self.handle,C.byref(f.filterKey))
