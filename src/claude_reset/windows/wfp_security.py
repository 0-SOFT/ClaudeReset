"""Explicit security for owned WFP objects; never changes existing descriptors.

Default BFE inheritance includes other operators/services. New product objects
are created with their own protected DACL; drift is rejected, never repaired.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from ..errors import SafetyError
from .service_security import OWNERS, Reader, plain_allow
from typing import TYPE_CHECKING
from . import wfp

if TYPE_CHECKING:
    from .wfp_session import Session

__all__ = ['ALL', 'Descriptor', 'OWNERS', 'decode', 'validate', 'verify']

ALL=0xF07FF  # FWPM_GENERIC_ALL: STANDARD_RIGHTS_REQUIRED | FWPM_ACTRL_*.
SDDL='O:BAG:BAD:P(A;;0xF07FF;;;SY)(A;;0xF07FF;;;BA)'


def validate(row: object) -> bool:
    if (not isinstance(row,dict) or not isinstance(row.get('owner'),str) or row['owner'] not in OWNERS
            or row.get('dacl_present') is not True or row.get('dacl_null') is not False
            or row.get('protected') is not True):
        raise SafetyError('Owned WFP object requires a protected administrator DACL')
    rules=row.get('rules')
    if not isinstance(rules,list) or len(rules)!=2:
        raise SafetyError('Unexpected WFP security principals')
    seen=set()
    for rule in rules:
        if not plain_allow(rule) or rule['sid'] not in OWNERS or rule['sid'] in seen or rule['mask'] != ALL:
            raise SafetyError('Owned WFP permissions differ from the compiled descriptor')
        seen.add(rule['sid'])
    return True


def decode(reader: Reader, pointer: C.c_void_p) -> dict:
    row=reader.descriptor(pointer)
    control=C.c_uint16()
    revision=W.DWORD()
    if not reader.api.GetSecurityDescriptorControl(pointer,C.byref(control),C.byref(revision)):
        raise SafetyError('WFP descriptor control unavailable')
    row['protected']=bool(control.value&0x1000)
    return row


class Descriptor:
    def __init__(self) -> None:
        self.pointer=C.c_void_p()
        self.reader=Reader()
        convert=self.reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
        if not convert(SDDL,1,C.byref(self.pointer),None):
            raise SafetyError('Cannot construct WFP descriptor')
        try:
            validate(decode(self.reader,self.pointer))
        except BaseException:
            self.close()
            raise
    def close(self) -> None:
        if self.pointer:
            self.reader.kernel.LocalFree(self.pointer)
            self.pointer=C.c_void_p()
    def __enter__(self):
        return self
    def __exit__(self,*args):
        self.close()


def verify(session: Session, kind: str, key: wfp.GUID) -> bool:
    """The owned object's security descriptor is exactly the compiled one (session: wfp_session.Session)."""
    if kind not in ('filter','sublayer') or not isinstance(key,wfp.GUID) or key.value()=='00000000-0000-0000-0000-000000000000':
        raise SafetyError('Only an exact owned WFP object can be inspected')
    pointer=None
    try:
        pointer=session.security_descriptor(kind,key)
        if not pointer:
            raise SafetyError('WFP descriptor read returned no data')
        return validate(decode(Reader(),pointer))
    finally:
        if pointer:
            session.free(pointer)
