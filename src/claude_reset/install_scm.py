"""Internal disabled-service registration, not a production installer entry point.

The caller must authenticate and pin the staged signed release, hold the protected
installation lock, persist intent, and verify closed clients before invoking this
primitive. No startup, deletion, adoption, elevation or transition to demand start.
"""
import ctypes as C
from ctypes import wintypes as W
from .safeio import SafetyError
from .install_inventory import SERVICES
from .install_ownership import configurations
from .install_store import _require_admin
from .service_store import program_files
from .install_service_security import Reader,validate as validate_security
from .gateway_service import Config,Status

SDDL='O:BAG:BAD:(A;;0xF01FF;;;SY)(A;;0xF01FF;;;BA)'
# QUERY_CONFIG, CHANGE_CONFIG, QUERY_STATUS, READ_CONTROL, WRITE_DAC, WRITE_OWNER.
# Deliberately excludes START, STOP and DELETE.
ACCESS=1|2|4|0x20000|0x40000|0x80000


def require_vacant_registry_slot(name):
    if name not in SERVICES:raise SafetyError('Unknown service registry slot')
    from .install_registry import Native as Registry,KEY,ACCESS as READ
    reader=Registry();handle=W.HANDLE()
    key=KEY.rsplit('\\',1)[0]+'\\'+name
    rc=reader.api.RegOpenKeyExW(W.HANDLE(-2147483646),key,8,READ,C.byref(handle))
    if rc==2:return
    if not rc:reader.api.RegCloseKey(handle)
    raise SafetyError('Service registry slot is occupied or cannot be inspected')


def specification(name):
    if not isinstance(name,str) or name not in SERVICES:raise SafetyError('Unknown installation service')
    value=dict(configurations(program_files()/'ClaudeReset')[name])
    value.update(name=name,start=4,error=1,group='',dependencies='',
                 sid_type=1 if name in SERVICES[:2] else 0)
    return value


def validate_snapshot(expected,actual):
    if not isinstance(actual,dict):raise SafetyError('Service readback unavailable')
    for key in ('name','binary','type','start','error','account','group','dependencies','sid_type'):
        if type(actual.get(key)) is not type(expected[key]) or actual[key]!=expected[key]:
            raise SafetyError('Disabled service configuration differs: '+key)
    if (type(actual.get('state')) is not int or actual['state']!=1
            or type(actual.get('pid')) is not int or actual['pid']!=0):
        raise SafetyError('New service is not stopped')
    validate_security(actual)


def validate_spec(value):
    if not isinstance(value,dict):raise SafetyError('Invalid disabled service specification')
    expected=specification(value.get('name'))
    if set(value)!=set(expected) or any(type(value[k]) is not type(v) or value[k]!=v for k,v in expected.items()):
        raise SafetyError('Only the compiled disabled service specification is permitted')
    return expected


class Native:
    def __init__(self):
        _require_admin()
        self.security=Reader();self.api=self.security.api
        ptr=C.c_void_p
        for name,args,result in [
            ('CreateServiceW',[W.HANDLE,W.LPCWSTR,W.LPCWSTR,W.DWORD,W.DWORD,W.DWORD,W.DWORD,
                              W.LPCWSTR,W.LPCWSTR,ptr,W.LPCWSTR,W.LPCWSTR,W.LPCWSTR],W.HANDLE),
            ('SetServiceObjectSecurity',[W.HANDLE,W.DWORD,ptr],W.BOOL),
            ('ConvertStringSecurityDescriptorToSecurityDescriptorW',[W.LPCWSTR,W.DWORD,C.POINTER(ptr),ptr],W.BOOL),
            ('ChangeServiceConfig2W',[W.HANDLE,W.DWORD,ptr],W.BOOL),
            ('QueryServiceConfigW',[W.HANDLE,ptr,W.DWORD,C.POINTER(W.DWORD)],W.BOOL),
            ('QueryServiceStatusEx',[W.HANDLE,C.c_int,ptr,W.DWORD,C.POINTER(W.DWORD)],W.BOOL),
        ]:
            fn=getattr(self.api,name);fn.argtypes,fn.restype=args,result
        self.manager=self.api.OpenSCManagerW(None,None,1|2)
        if not self.manager:raise SafetyError('Cannot open service manager for creation')

    def create(self,spec,*,creation_marker=None):
        spec=validate_spec(spec)
        display=spec['name']
        if creation_marker is not None:
            from .install_service_markers import creation_display
            display=creation_display(creation_marker,spec)
        require_vacant_registry_slot(spec['name'])
        # CreateService, never OpenService: an occupied name cannot be adopted.
        handle=self.api.CreateServiceW(self.manager,spec['name'],display,ACCESS,
            spec['type'],4,1,spec['binary'],None,None,None,
            'LocalSystem' if spec['type']==16 else None,None)
        if not handle:raise SafetyError('Service slot occupied or creation failed')
        if not hasattr(self,'_created'):self._created={}
        self._created[handle]=spec['name']
        return handle

    def protect(self,handle):
        descriptor=C.c_void_p()
        if not self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL,1,C.byref(descriptor),None):
            raise SafetyError('Cannot construct service security descriptor')
        try:
            if not self.api.SetServiceObjectSecurity(handle,5,descriptor):
                raise SafetyError('Cannot protect the newly created service')
        finally:self.security.kernel.LocalFree(descriptor)

    def set_sid(self,handle,spec):
        spec=validate_spec(spec)
        if spec['type']==1:return
        value=W.DWORD(spec['sid_type'])
        if not self.api.ChangeServiceConfig2W(handle,5,C.byref(value)):
            raise SafetyError('Cannot set service SID type')

    def snapshot(self,handle,spec):
        spec=validate_spec(spec)
        needed=W.DWORD()
        self.api.QueryServiceConfigW(handle,None,0,C.byref(needed))
        if not C.sizeof(Config)<=needed.value<=65536:raise SafetyError('Invalid service config size')
        buffer=C.create_string_buffer(needed.value)
        if not self.api.QueryServiceConfigW(handle,buffer,len(buffer),C.byref(needed)):
            raise SafetyError('Cannot read new service configuration')
        cfg=Config.from_buffer(buffer);status=Status()
        if not self.api.QueryServiceStatusEx(handle,0,C.byref(status),C.sizeof(status),C.byref(needed)):
            raise SafetyError('Cannot read new service status')
        row=self.security.read_handle(handle,spec['name'])
        row.update(display=cfg.display or '',binary=cfg.binary,type=cfg.type,start=cfg.start,error=cfg.error,
                   account=cfg.account or '',group=cfg.group or '',dependencies=cfg.dependencies or '',
                   state=status.state,pid=status.pid)
        return row

    def require_created(self,handle,name):
        if not handle or getattr(self,'_created',{}).get(handle)!=name:
            raise SafetyError('A still-held service created in this registration is required')

    def release(self,handle):
        if not self.api.CloseServiceHandle(handle):
            raise SafetyError('Cannot close service registration handle')
        getattr(self,'_created',{}).pop(handle,None)
    def release_auxiliary(self,handle):
        if not hasattr(self,'_pending_auxiliary'):self._pending_auxiliary=set()
        self._pending_auxiliary.add(handle)
        if not self.api.CloseServiceHandle(handle):
            raise SafetyError('Cannot close auxiliary service handle')
        self._pending_auxiliary.remove(handle)

    def close(self):
        failure=None
        for handle in tuple(getattr(self,'_pending_auxiliary',())):
            try:self.release_auxiliary(handle)
            except Exception as error:
                if failure is None:failure=error
        if self.manager:
            try:
                if not self.api.CloseServiceHandle(self.manager):
                    raise SafetyError('Cannot close installation service manager')
            except Exception as error:
                if failure is None:failure=error
            else:self.manager=None
        if failure is not None:raise failure
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class HeldRegistrations:
    """Keep creation handles through one installation, including failed steps."""
    def __init__(self):self.items=[];self.pending_close=None;self.uncertain_deletion=False
    def retain(self,native,handle,spec):
        if self.pending_close is not None or self.uncertain_deletion:
            raise SafetyError('Deletion cleanup is still pending')
        if not isinstance(native,Native):raise SafetyError('Native registration ownership required')
        native.require_created(handle,spec['name'])
        if any(row[2]['name']==spec['name'] for row in self.items):raise SafetyError('Registration already retained')
        self.items.append((native,handle,dict(spec)))
    def pending_close_result(self):
        if self.uncertain_deletion:
            raise SafetyError('Partial service deletion lacks confirmed in-memory progress')
        if self.pending_close is None:return None
        native,handle,spec,result=self.pending_close
        expected=dict(name=spec['name'],deletion_requested=True,absence_verified=False,client_admission=False)
        if not self.items or self.items[-1]!=(native,handle,spec) or result!=expected:
            raise SafetyError('Pending deletion close lost its original registration')
        native.require_created(handle,spec['name'])
        return dict(result)
    def close(self):
        failure=None
        for index in range(len(self.items)-1,-1,-1):
            native,handle,_=self.items[index]
            try:native.release(handle)
            except Exception as error:
                if failure is None:failure=error
            else:self.items.pop(index)
        if failure is not None:raise failure
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def _register_disabled(native,name,receipt,verify_closed,*,prepare_driver=None,prepare_service=None,prepare_creation=None,held=None):
    """One new fixed service. Receipt callbacks must be durable under installer lock.

    On any error leave the new service disabled and report failure. A receipt is
    not permanent SCM identity; future cleanup needs independent ownership checks.
    """
    spec=specification(name)
    if held is not None and (not isinstance(held,HeldRegistrations) or not isinstance(native,Native)):
        raise SafetyError('Native held registration set required')
    if prepare_driver is not None and (name!='SbieDrv' or not callable(prepare_driver)):
        raise SafetyError('Driver preparation is only supported for the new driver slot')
    if prepare_service is not None and not callable(prepare_service):
        raise SafetyError('Service preparation must be callable')
    if prepare_creation is not None and (not callable(prepare_creation) or prepare_service is None):
        raise SafetyError('Creation binding requires paired service preparation')
    if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    receipt('intent',dict(spec))
    if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    marker=None
    if prepare_creation is not None:
        from .install_service_markers import creation_display
        marker=prepare_creation(dict(spec))
        creation_display(marker,spec)
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    handle=native.create(spec,creation_marker=marker) if marker is not None else native.create(spec)
    retained=False
    try:
        if held is not None:
            held.retain(native,handle,spec);retained=True
        # No fallible receipt callback between creation and tightening the DACL.
        native.protect(handle)
        native.set_sid(handle,spec)
        if prepare_service is not None:
            if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
            result=prepare_service(native,handle,dict(spec))
            if (not isinstance(result,dict) or set(result)!={'marker_bound','service','client_admission','may_delete'}
                    or result['marker_bound'] is not True or result['service']!=name
                    or result['client_admission'] is not False or result['may_delete'] is not False):
                raise SafetyError('Service preparation did not confirm the exact ownership marker')
        if prepare_driver is not None:
            if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
            result=prepare_driver(native,handle)
            if (not isinstance(result,dict) or set(result)!={'policy_bound','driver_started','client_admission'}
                    or result['policy_bound'] is not True or result['driver_started'] is not False
                    or result['client_admission'] is not False):
                raise SafetyError('Driver preparation did not confirm a closed policy binding')
        actual=native.snapshot(handle,spec)
        validate_snapshot(spec,actual)
        if marker is not None:
            from .install_service_markers import validate_creation_snapshot
            validate_creation_snapshot(marker,spec,actual)
        receipt('disabled',dict(spec))
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        return {'name':name,'registered_disabled':True,'client_admission':False}
    finally:
        if not retained:native.release(handle)
