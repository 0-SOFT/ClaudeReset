"""Read-only held service/marker attestation for an unfinished installation.

This is not original SCM creation identity or permission to delete/start/adopt.
It never adds handles to Native._created. The future recovery adapter must also
verify files, policy, reservations and the closed client boundary.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
from .install_scm import Native as Services
from .install_service_security import Reader
from .install_service_receipts import ServiceReceipts
from .install_service_markers import MarkerReceipts,VALUE,encoded,validate_creation_snapshot
from . import install_registry as registry
from .install_store import Store,Directory
from .service_store import program_files,verify_paths
from .safeio import SafetyError

ACCESS=0x20000|1|4  # READ_CONTROL, QUERY_CONFIG, QUERY_STATUS; no DELETE/START.


class NativeReader:
    def __init__(self):
        self.security=Reader();self.api=self.security.api;self.manager=None
        ptr=C.c_void_p
        for name,args,result in [
            ('OpenSCManagerW',[W.LPCWSTR,W.LPCWSTR,W.DWORD],W.HANDLE),
            ('OpenServiceW',[W.HANDLE,W.LPCWSTR,W.DWORD],W.HANDLE),
            ('CloseServiceHandle',[W.HANDLE],W.BOOL),
            ('QueryServiceConfigW',[W.HANDLE,ptr,W.DWORD,C.POINTER(W.DWORD)],W.BOOL),
            ('QueryServiceStatusEx',[W.HANDLE,C.c_int,ptr,W.DWORD,C.POINTER(W.DWORD)],W.BOOL),
        ]:
            fn=getattr(self.api,name);fn.argtypes=args;fn.restype=result
        self.manager=self.api.OpenSCManagerW(None,None,1)
        if not self.manager:raise SafetyError('Cannot open SCM for ownership inspection')
    def open_optional(self,name):
        from .install_inventory import SERVICES
        if name not in SERVICES:raise SafetyError('Unknown service attestation slot')
        handle=self.api.OpenServiceW(self.manager,name,ACCESS)
        if not handle:
            if C.get_last_error()==1060:return None
            raise SafetyError('Recorded service is pending deletion or cannot be inspected')
        return handle
    def open(self,name):
        handle=self.open_optional(name)
        if handle is None:raise SafetyError('Recorded service cannot be held for inspection')
        return handle
    def snapshot(self,handle,spec):return Services.snapshot(self,handle,spec)
    def release(self,handle):
        if not self.api.CloseServiceHandle(handle):
            raise SafetyError('Cannot close service attestation handle')
    def release_auxiliary(self,handle):return Services.release_auxiliary(self,handle)
    def close(self):return Services.close(self)


class RegistryReader(registry.Native):
    def open(self,name):
        from .install_inventory import SERVICES
        if name not in SERVICES:raise SafetyError('Unknown service marker slot')
        key=registry.KEY.rsplit('\\',1)[0]+'\\'+name;handle=W.HANDLE()
        if self.api.RegOpenKeyExW(W.HANDLE(-2147483646),key,8,registry.ACCESS,C.byref(handle)):
            raise SafetyError('Recorded service marker key cannot be inspected')
        return handle
    def close_key(self,handle):
        if self.api.RegCloseKey(handle):
            raise SafetyError('Cannot close service marker inspection key')


def _records(store,generation):
    if not isinstance(store,Store) or not store.journal or not store.journal.lock:
        raise SafetyError('Held recovery store and exclusive lock required')
    tx=ServiceReceipts(store.journal).transaction()
    active=[row for row in tx['entries'] if row['state']!='undone']
    if (tx['generation']!=generation or tx['state'] not in ('recovering','recovery_required')
            or not active or active[-1]['step']!='install_services'):
        raise SafetyError('Service attestation requires its ordered recovery step')
    root=store.directories.get('root');installer=store.directories.get('Installer')
    if (not isinstance(root,Directory) or not root.handle or root.path!=program_files()/'ClaudeReset'
            or not isinstance(installer,Directory) or not installer.handle or installer.path!=root.path/'Installer'):
        raise SafetyError('Fixed held protected installation directories required')
    verify_paths([root.path,installer.path,*[installer.path/name for name in
                 ('install.lock','install-journal.json','service-receipts.json',MarkerReceipts.filename)]],
                 [root.path,installer.path])
    source=ServiceReceipts(store.journal).load();markers=MarkerReceipts(store.journal).load()
    if (not source or not source['services'] or not markers
            or len(source['services'])!=len(markers['services'])
            or any(row['state']!='bound' for row in markers['services'])):
        raise SafetyError('Every recorded service requires a completed ownership marker')
    return tx,source,markers


class HeldAttestation:
    """Owns query-only handles. Evidence is valid only while this object is held."""
    def __init__(self,store,generation):
        self.store=store;self.generation=generation;self.items=[];self.reader=None;self.registry=None
        self.closed=False
        self.transaction,self.source,self.markers=_records(store,generation)
        try:
            self.reader=NativeReader();self.registry=RegistryReader()
            for row in self.source['services']:
                handle=self.reader.open(row['name'])
                self.items.append((handle,None,row['spec']))
                key=self.registry.open(row['name'])
                self.items[-1]=(handle,key,row['spec'])
            self.verify()
        except BaseException:self.close();raise

    def _verify_metadata(self):
        if self.closed:raise SafetyError('Service attestation handles are closed')
        tx,source,markers=_records(self.store,self.generation)
        if (tx!=self.transaction or source!=self.source or markers!=self.markers
                or len(self.items)!=len(source['services'])):
            raise SafetyError('Service attestation generation or evidence changed')
        return tx

    def _verify_entry(self,index,tx):
        handle,key,spec=self.items[index];row=self.markers['services'][index]
        validate_creation_snapshot(row['marker'],spec,self.reader.snapshot(handle,spec))
        if self.registry.value(key,'SymbolicLinkValue') is not None:
            raise SafetyError('Service marker registry key is a link')
        registry.validate_security(self.registry.security(key))
        data=encoded(row['marker'],spec,tx['generation'],tx['package_sha256'])
        if self.registry.value(key,VALUE)!=(3,data):raise SafetyError('Protected service marker differs')
        validate_creation_snapshot(row['marker'],spec,self.reader.snapshot(handle,spec))
        return dict(name=spec['name'],marker_sha256=hashlib.sha256(data).hexdigest())

    def verify_service(self,name):
        tx=self._verify_metadata()
        matches=[i for i,(_,_,spec) in enumerate(self.items) if spec['name']==name]
        if len(matches)!=1:raise SafetyError('Service is not held by this attestation')
        return self._verify_entry(matches[0],tx)

    def verify(self):
        tx=self._verify_metadata()
        results=[self._verify_entry(index,tx) for index in range(len(self.items))]
        return dict(generation=self.generation,services=results,generation_markers_verified=True,
                    original_creation_identity_verified=False,may_delete=False,client_admission=False)

    def close(self):
        # Revoke evidence immediately, but retain every resource whose close
        # failed. A failure must not prevent cleanup of independent resources.
        self.closed=True;failure=None
        for index in range(len(self.items)-1,-1,-1):
            handle,key,spec=self.items[index]
            if key is not None:
                try:self.registry.close_key(key)
                except Exception as error:
                    if failure is None:failure=error
                else:key=None
            if handle is not None:
                try:self.reader.release(handle)
                except Exception as error:
                    if failure is None:failure=error
                else:handle=None
            if handle is None and key is None:self.items.pop(index)
            else:self.items[index]=(handle,key,spec)
        if self.reader is not None:
            try:self.reader.close()
            except Exception as error:
                if failure is None:failure=error
            else:
                if not self.items:self.reader=None
        if failure is not None:raise failure
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
