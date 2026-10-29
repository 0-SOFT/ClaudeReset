"""Read-only service DACL/SID checks for the fixed installation slots."""
import ctypes as C
from ctypes import wintypes as W
from .install_inventory import SERVICES
from .safeio import SafetyError
from .service_store import OWNERS

# CHANGE_CONFIG, START/STOP/PAUSE, USER_DEFINED_CONTROL, DELETE, WRITE_DAC/OWNER.
# Generic execute also maps to service control, unlike file execute.
MUTATE = 0x000D0172 | 0x10000000 | 0x20000000 | 0x40000000
ALL_ACCESS = 0xF01FF


def validate(row):
    if (not isinstance(row, dict) or not isinstance(row.get('name'),str) or row['name'] not in SERVICES
            or not isinstance(row.get('owner'),str) or row['owner'] not in OWNERS or row.get('dacl_present') is not True
            or row.get('dacl_null') is not False):
        raise SafetyError('Untrusted service owner or missing DACL')
    expected = 1 if row['name'] in SERVICES[:2] else 0
    if type(row.get('sid_type')) is not int or row['sid_type'] != expected:
        raise SafetyError('Service SID configuration differs')
    rules = row.get('rules')
    if not isinstance(rules, list) or not rules:
        raise SafetyError('Service DACL is empty or unreadable')
    control = {sid: 0 for sid in OWNERS}
    for rule in rules:
        if (not isinstance(rule, dict) or set(rule) != {'sid', 'mask', 'type', 'flags'}
                or not isinstance(rule['sid'], str) or type(rule['mask']) is not int
                or not 0 <= rule['mask'] <= 0xFFFFFFFF
                or type(rule['type']) is not int or rule['type'] != 0
                or type(rule['flags']) is not int or rule['flags'] != 0):
            raise SafetyError('Service DACL contains an unsupported ACE')
        if rule['sid'] not in OWNERS and rule['mask'] & MUTATE:
            raise SafetyError('An untrusted principal can control the service')
        if rule['sid'] in control:
            control[rule['sid']] |= rule['mask']
    if any(mask & ALL_ACCESS != ALL_ACCESS for mask in control.values()):
        raise SafetyError('Administrators and SYSTEM must retain explicit service control')
    return True


class Reader:
    def __init__(self):
        self.api = C.WinDLL('advapi32', use_last_error=True)
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        ptr = C.c_void_p
        signatures = {
            'OpenSCManagerW': ([W.LPCWSTR,W.LPCWSTR,W.DWORD], W.HANDLE),
            'OpenServiceW': ([W.HANDLE,W.LPCWSTR,W.DWORD], W.HANDLE),
            'CloseServiceHandle': ([W.HANDLE], W.BOOL),
            'QueryServiceObjectSecurity': ([W.HANDLE,W.DWORD,ptr,W.DWORD,C.POINTER(W.DWORD)], W.BOOL),
            'QueryServiceConfig2W': ([W.HANDLE,W.DWORD,ptr,W.DWORD,C.POINTER(W.DWORD)], W.BOOL),
            'GetSecurityDescriptorOwner': ([ptr,C.POINTER(ptr),C.POINTER(W.BOOL)], W.BOOL),
            'GetSecurityDescriptorDacl': ([ptr,C.POINTER(W.BOOL),C.POINTER(ptr),C.POINTER(W.BOOL)], W.BOOL),
            'GetAce': ([ptr,W.DWORD,C.POINTER(ptr)], W.BOOL),
            'ConvertSidToStringSidW': ([ptr,C.POINTER(W.LPWSTR)], W.BOOL),
        }
        for name,(args,result) in signatures.items():
            fn = getattr(self.api,name);fn.argtypes,fn.restype = args,result
        self.kernel.LocalFree.argtypes,self.kernel.LocalFree.restype = [ptr],ptr

    def sid(self, pointer):
        text = W.LPWSTR()
        if not self.api.ConvertSidToStringSidW(pointer,C.byref(text)):
            raise SafetyError('Invalid service ACL SID')
        try: return text.value
        finally: self.kernel.LocalFree(text)

    def descriptor(self, buffer):
        owner = C.c_void_p(); defaulted = W.BOOL()
        if not self.api.GetSecurityDescriptorOwner(buffer,C.byref(owner),C.byref(defaulted)) or not owner:
            raise SafetyError('Service owner unavailable')
        result = {'owner':self.sid(owner)}
        present = W.BOOL();acl = C.c_void_p()
        if not self.api.GetSecurityDescriptorDacl(buffer,C.byref(present),C.byref(acl),C.byref(defaulted)):
            raise SafetyError('Service DACL unavailable')
        result.update(dacl_present=bool(present.value),dacl_null=not bool(acl),rules=[])
        if not present.value or not acl: return result
        # ACL header: revision/zero, size, ACE count, zero.
        count = C.c_uint16.from_address(acl.value+4).value
        if count>4096: raise SafetyError('Service DACL exceeds the bounded ACE count')
        for index in range(count):
            ace = C.c_void_p()
            if not self.api.GetAce(acl,index,C.byref(ace)) or not ace:
                raise SafetyError('Service ACE unavailable')
            kind,flags = C.string_at(ace,2)
            size = C.c_uint16.from_address(ace.value+2).value
            if kind!=0 or size<16:
                raise SafetyError('Only explicit ordinary allow ACEs are supported')
            result['rules'].append({'type':kind,'flags':flags,
                'mask':C.c_uint32.from_address(ace.value+4).value,'sid':self.sid(ace.value+8)})
        return result

    def inspect(self):
        manager = self.api.OpenSCManagerW(None,None,1)
        if not manager: raise SafetyError('Service manager unavailable')
        rows = []
        try:
            for name in SERVICES:
                handle = self.api.OpenServiceW(manager,name,0x20001)  # READ_CONTROL | QUERY_CONFIG
                if not handle:
                    if C.get_last_error()!=1060: raise SafetyError('Cannot inspect service security: '+name)
                    rows.append({'name':name,'exists':False});continue
                try:
                    row = self.read_handle(handle,name)
                    try: validate(row);row['security_fields_match']=True
                    except SafetyError as exc: row.update(security_fields_match=False,reason=str(exc))
                    rows.append(row)
                finally:
                    if not self.api.CloseServiceHandle(handle):
                        raise SafetyError('Cannot close service security inspection handle')
        finally:
            if not self.api.CloseServiceHandle(manager):
                raise SafetyError('Cannot close service security inspection manager')
        return {'schema':1,'services':rows,'settings_changed':False,'client_admission':False,
                'limits':['Read-only snapshot; not ownership proof or installation authority.']}

    def read_handle(self,handle,name):
        """Read the held service object, without reopening a possibly replaced name."""
        if name not in SERVICES or not handle:raise SafetyError('Unknown service handle')
        needed = W.DWORD()
        self.api.QueryServiceObjectSecurity(handle,5,None,0,C.byref(needed))
        if not 20<=needed.value<=65536: raise SafetyError('Invalid service descriptor length')
        buffer = C.create_string_buffer(needed.value)
        if not self.api.QueryServiceObjectSecurity(handle,5,buffer,len(buffer),C.byref(needed)):
            raise SafetyError('Service descriptor read failed')
        row = dict(self.descriptor(buffer),name=name,exists=True)
        sid_type = W.DWORD()
        if name=='SbieDrv':row['sid_type']=0
        elif self.api.QueryServiceConfig2W(handle,5,C.byref(sid_type),4,C.byref(needed)):
            row['sid_type']=sid_type.value
        else:raise SafetyError('Service SID type unavailable')
        return row
