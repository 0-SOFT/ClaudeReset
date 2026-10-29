"""Explicit security for owned WFP objects; never changes existing descriptors.

Default BFE inheritance includes other operators/services. New product objects
are created with their own protected DACL; drift is rejected, never repaired.
"""
import ctypes as C
from ctypes import wintypes as W
from .safeio import SafetyError
from .install_service_security import Reader
from . import wfp

OWNERS={'S-1-5-18','S-1-5-32-544'}
ALL=0xF07FF  # FWPM_GENERIC_ALL: STANDARD_RIGHTS_REQUIRED | FWPM_ACTRL_*.
SDDL='O:BAG:BAD:P(A;;0xF07FF;;;SY)(A;;0xF07FF;;;BA)'


def validate(row):
    if (not isinstance(row,dict) or not isinstance(row.get('owner'),str) or row['owner'] not in OWNERS
            or row.get('dacl_present') is not True or row.get('dacl_null') is not False
            or row.get('protected') is not True):
        raise SafetyError('Owned WFP object requires a protected administrator DACL')
    rules=row.get('rules')
    if not isinstance(rules,list) or len(rules)!=2:raise SafetyError('Unexpected WFP security principals')
    seen=set()
    for rule in rules:
        if (not isinstance(rule,dict) or set(rule)!={'sid','mask','type','flags'}
                or not isinstance(rule['sid'],str) or rule['sid'] not in OWNERS or rule['sid'] in seen
                or type(rule['mask']) is not int or rule['mask']!=ALL
                or type(rule['type']) is not int or rule['type']!=0
                or type(rule['flags']) is not int or rule['flags']!=0):
            raise SafetyError('Owned WFP permissions differ from the compiled descriptor')
        seen.add(rule['sid'])
    return True


def decode(reader,pointer):
    row=reader.descriptor(pointer)
    control=C.c_uint16();revision=W.DWORD()
    fn=reader.api.GetSecurityDescriptorControl
    fn.argtypes=[C.c_void_p,C.POINTER(C.c_uint16),C.POINTER(W.DWORD)];fn.restype=W.BOOL
    if not fn(pointer,C.byref(control),C.byref(revision)):
        raise SafetyError('WFP descriptor control unavailable')
    row['protected']=bool(control.value&0x1000)
    return row


class Descriptor:
    def __init__(self):
        self.pointer=C.c_void_p();self.reader=Reader()
        fn=self.reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
        fn.argtypes=[W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p];fn.restype=W.BOOL
        if not fn(SDDL,1,C.byref(self.pointer),None):raise SafetyError('Cannot construct WFP descriptor')
        try:validate(decode(self.reader,self.pointer))
        except BaseException:self.close();raise
    def close(self):
        if self.pointer:self.reader.kernel.LocalFree(self.pointer);self.pointer=C.c_void_p()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def verify(engine,kind,key):
    functions={'filter':'FwpmFilterGetSecurityInfoByKey0','sublayer':'FwpmSubLayerGetSecurityInfoByKey0'}
    if kind not in functions or not isinstance(key,wfp.GUID) or key.value()=='00000000-0000-0000-0000-000000000000':
        raise SafetyError('Only an exact owned WFP object can be inspected')
    pointer=C.c_void_p()
    try:
        engine._call(functions[kind],[W.HANDLE,C.POINTER(wfp.GUID),W.DWORD,
            C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)],
            engine.handle,C.byref(key),5,None,None,None,None,C.byref(pointer))
        if not pointer:raise SafetyError('WFP descriptor read returned no data')
        return validate(decode(Reader(),pointer))
    finally:
        if pointer:engine._free(pointer)
