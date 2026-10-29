"""Read-only inspection of the fixed driver policy binding; no registry writes.

Matching fields are not ownership proof or authorization to start the driver.
The eventual installer must bind this check to held SCM/configuration receipts.
"""
import ctypes as C
from ctypes import wintypes as W
from .install_service_security import Reader
from .service_store import program_files,OWNERS
from .safeio import SafetyError

KEY=r'SYSTEM\CurrentControlSet\Services\SbieDrv'
ACCESS=0x20001|0x100  # READ_CONTROL | QUERY_VALUE | 64-bit view; no mutation.
ALL=0xF003F
MUTATE=0xD0026|0x10000000|0x40000000


def expected_path():
    return str(program_files()/'ClaudeReset/Policy/Sandboxie.ini')


def decode_string(kind,data):
    if type(kind) is not int or kind!=1 or not isinstance(data,bytes) or not 4<=len(data)<=520 or len(data)%2:
        raise SafetyError('IniPath must be a bounded literal REG_SZ')
    try:value=data.decode('utf-16-le',errors='strict')
    except UnicodeError as exc:raise SafetyError('IniPath is not valid UTF-16') from exc
    if not value.endswith('\0') or '\0' in value[:-1]:
        raise SafetyError('IniPath requires exactly one final terminator')
    return value[:-1]


def validate_security(row):
    if (not isinstance(row,dict) or not isinstance(row.get('owner'),str) or row['owner'] not in OWNERS
            or row.get('dacl_present') is not True or row.get('dacl_null') is not False
            or row.get('protected') is not True):
        raise SafetyError('Driver key requires protected administrative security')
    rules=row.get('rules')
    if not isinstance(rules,list) or not rules:raise SafetyError('Driver key DACL unavailable')
    rights={sid:0 for sid in OWNERS}
    for rule in rules:
        if (not isinstance(rule,dict) or set(rule)!={'sid','mask','type','flags'}
                or not isinstance(rule['sid'],str) or type(rule['mask']) is not int
                or not 0<=rule['mask']<=0xffffffff or type(rule['type']) is not int or rule['type']!=0
                or type(rule['flags']) is not int or rule['flags'] not in (0,2)):
            raise SafetyError('Unsupported driver key permission')
        if rule['sid'] not in OWNERS and rule['mask']&MUTATE:
            raise SafetyError('Untrusted principal can change the driver key')
        if rule['sid'] in rights:rights[rule['sid']]|=rule['mask']
    if any(mask&ALL!=ALL for mask in rights.values()):
        raise SafetyError('Administrative driver key control is incomplete')
    return True


class Native:
    def __init__(self):
        self.reader=Reader();self.api=self.reader.api
        ptr=C.c_void_p
        for name,args in (
            ('RegOpenKeyExW',[W.HANDLE,W.LPCWSTR,W.DWORD,W.DWORD,C.POINTER(W.HANDLE)]),
            ('RegCloseKey',[W.HANDLE]),
            ('RegQueryValueExW',[W.HANDLE,W.LPCWSTR,ptr,C.POINTER(W.DWORD),ptr,C.POINTER(W.DWORD)]),
            ('RegGetKeySecurity',[W.HANDLE,W.DWORD,ptr,C.POINTER(W.DWORD)]),
        ):
            fn=getattr(self.api,name);fn.argtypes=args;fn.restype=W.LONG

    def value(self,handle,name):
        # A fixed-size query avoids an unbounded allocation or trusting a size race.
        buffer=C.create_string_buffer(520);size=W.DWORD(len(buffer));kind=W.DWORD()
        rc=self.api.RegQueryValueExW(handle,name,None,C.byref(kind),buffer,C.byref(size))
        if rc==2:return None
        if rc or size.value>len(buffer):raise SafetyError('Driver registry value cannot be read safely')
        return kind.value,buffer.raw[:size.value]

    def inspect(self):
        handle=W.HANDLE()
        # OPEN_LINK inspects the final link object instead of following its target.
        rc=self.api.RegOpenKeyExW(W.HANDLE(-2147483646),KEY,8,ACCESS,C.byref(handle))
        report=dict(schema=1,key=KEY,exists=False,policy_binding_matches=False,
                    settings_changed=False,client_admission=False,may_mutate=False)
        if rc==2:return report
        if rc:raise SafetyError('Driver registry key is inaccessible')
        try:
            report['exists']=True
            if self.value(handle,'SymbolicLinkValue') is not None:
                raise SafetyError('Driver registry key cannot be a symbolic link')
            security=self.security(handle)
            value=self.value(handle,'IniPath')
            try:
                validate_security(security)
                if value is None or decode_string(*value)!=expected_path():
                    raise SafetyError('Driver policy binding differs from the private installation path')
            except SafetyError as exc:report['reason']=str(exc)
            else:report['policy_binding_matches']=True
            return report
        finally:
            if self.api.RegCloseKey(handle):
                raise SafetyError('Cannot close driver policy inspection key')

    def security(self,handle):
        size=W.DWORD()
        rc=self.api.RegGetKeySecurity(handle,5,None,C.byref(size))
        if rc!=122 or not 20<=size.value<=65536:raise SafetyError('Invalid driver key descriptor size')
        buffer=C.create_string_buffer(size.value)
        if self.api.RegGetKeySecurity(handle,5,buffer,C.byref(size)):
            raise SafetyError('Driver key security read failed')
        from .wfp_security import decode
        return decode(self.reader,buffer)


def inspect():
    return Native().inspect()
