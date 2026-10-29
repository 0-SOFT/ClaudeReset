"""Fresh read-only checks before removing files after service recovery.

No executable or service SID lookup is needed: interrupted file cleanup may
already have removed both. Receipt keys are queried only to refuse collisions,
never to authorize deleting a filter or adopting another installation.
"""
import ctypes as C
from ctypes import wintypes as W
import re
from . import wfp
from .strict_wfp import Engine,SUBLAYER,SUBKEY
from .gateway_reservation import SUB
from .install_boundary_observation import READ_ONLY
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .safeio import SafetyError


def observe_cleanup_absence(engine,keys,verify_closed):
    if (not isinstance(engine,Engine) or not engine.handle or engine.dynamic is not False
            or engine._transaction is not False or not callable(verify_closed)
            or not isinstance(keys,list) or len(keys) not in (16,32)
            or any(not isinstance(k,str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',k) for k in keys)
            or len(set(keys))!=len(keys)):
        raise SafetyError('Idle persistent query session and distinct cleanup keys required')
    def closed():
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    def vacant():
        _confirm_absence(list(reversed(SERVICES)),closed)
    vacant()
    engine._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],engine.handle,READ_ONLY)
    engine._transaction=True
    try:
        vacant()
        for key in (SUBKEY,SUB):
            pointer=C.POINTER(SUBLAYER)()
            code=engine._call('FwpmSubLayerGetByKey0',
                [W.HANDLE,C.POINTER(wfp.GUID),C.POINTER(C.POINTER(SUBLAYER))],
                engine.handle,C.byref(key),C.byref(pointer),allowed=(0x80320007,))
            if code==0:engine._free(pointer)
            if code!=0x80320007:raise SafetyError('Cleanup sublayer absence is unconfirmed')
        for text in keys:
            key=wfp.GUID.of(text);pointer=C.POINTER(wfp.FILTER)()
            code=engine._call('FwpmFilterGetByKey0',
                [W.HANDLE,C.POINTER(wfp.GUID),C.POINTER(C.POINTER(wfp.FILTER))],
                engine.handle,C.byref(key),C.byref(pointer),allowed=(wfp.FWP_E_FILTER_NOT_FOUND,))
            if code==0:engine._free(pointer)
            if code!=wfp.FWP_E_FILTER_NOT_FOUND:raise SafetyError('Cleanup filter absence is unconfirmed')
        vacant()
    finally:
        engine._call('FwpmTransactionAbort0',[W.HANDLE],engine.handle)
        engine._transaction=False
    vacant()
    return dict(services_absent=4,sublayers_absent=2,filter_keys_absent=len(keys),
                settings_changed=False,client_admission=False)


def require_cleanup_absence(keys,verify_closed):
    with Engine() as engine:result=observe_cleanup_absence(engine,keys,verify_closed)
    if verify_closed() is not True:raise SafetyError('Closed boundary changed while closing observation')
    _confirm_absence(list(reversed(SERVICES)),verify_closed)
    return result
