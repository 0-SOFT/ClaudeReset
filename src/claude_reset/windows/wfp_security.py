"""Explicit security for owned WFP objects; never changes existing descriptors.

Default BFE inheritance includes other operators/services. New product objects
are created with their own protected DACL; drift is rejected, never repaired.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from typing import TYPE_CHECKING, TypedDict

from ..errors import SafetyError
from . import wfp
from .api import Library

if TYPE_CHECKING:
    from .wfp_session import Session

__all__ = ['ALL', 'Ace', 'Descriptor', 'OWNERS', 'Reader', 'decode', 'plain_allow', 'validate', 'verify']

ALL=0xF07FF  # FWPM_GENERIC_ALL: STANDARD_RIGHTS_REQUIRED | FWPM_ACTRL_*.
SDDL='O:BAG:BAD:P(A;;0xF07FF;;;SY)(A;;0xF07FF;;;BA)'
# SYSTEM and the Administrators group: the only principals that may own or change our objects.
OWNERS = frozenset({'S-1-5-18', 'S-1-5-32-544'})


class Ace(TypedDict):
    """One access control entry as Reader.descriptor reports it."""
    sid: str
    mask: int
    type: int
    flags: int


def plain_allow(rule: object) -> bool:
    """An ACCESS_ALLOWED entry without inheritance flags, with exactly the fields of Ace."""
    return (isinstance(rule, dict) and rule.keys() == Ace.__required_keys__ and isinstance(rule['sid'], str)
            and type(rule['mask']) is int and 0 <= rule['mask'] <= 0xFFFFFFFF
            and type(rule['type']) is int and rule['type'] == 0 and type(rule['flags']) is int and rule['flags'] == 0)


class Reader:
    def __init__(self) -> None:
        self.api, self.kernel = Library('advapi32'), Library('kernel32')

    def sid(self, pointer: C.c_void_p) -> str:
        text = W.LPWSTR()
        if not self.api.ConvertSidToStringSidW(pointer,C.byref(text)):
            raise SafetyError('Invalid ACL SID')
        try:
            return text.value
        finally:
            self.kernel.LocalFree(text)

    def descriptor(self, buffer: C.Array) -> dict:
        owner = C.c_void_p()
        defaulted = W.BOOL()
        if not self.api.GetSecurityDescriptorOwner(buffer,C.byref(owner),C.byref(defaulted)) or not owner:
            raise SafetyError('Security descriptor owner unavailable')
        result = {'owner':self.sid(owner)}
        present = W.BOOL()
        acl = C.c_void_p()
        if not self.api.GetSecurityDescriptorDacl(buffer,C.byref(present),C.byref(acl),C.byref(defaulted)):
            raise SafetyError('Security descriptor DACL unavailable')
        result.update(dacl_present=bool(present.value),dacl_null=not bool(acl),rules=[])
        if not present.value or not acl:
            return result
        # ACL header: revision/zero, size, ACE count, zero.
        count = C.c_uint16.from_address(acl.value+4).value
        if count>4096:
            raise SafetyError('DACL exceeds the bounded ACE count')
        for index in range(count):
            ace = C.c_void_p()
            if not self.api.GetAce(acl,index,C.byref(ace)) or not ace:
                raise SafetyError('ACE unavailable')
            kind,flags = C.string_at(ace,2)
            size = C.c_uint16.from_address(ace.value+2).value
            if kind!=0 or size<16:
                raise SafetyError('Only explicit ordinary allow ACEs are supported')
            result['rules'].append({'type':kind,'flags':flags,
                'mask':C.c_uint32.from_address(ace.value+4).value,'sid':self.sid(ace.value+8)})
        return result


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
