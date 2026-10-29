"""Bind only a newly created, still-disabled driver to a held private policy.

Internal primitive, no installer entry point or elevation. The caller must hold
the installation lock and persist receipt callbacks. No recovery/adoption of an
existing service, registry value or failed previous attempt is performed here.
"""
import ctypes as C
from ctypes import wintypes as W
from . import install_registry as registry
from .install_scm import Native as Services,specification,validate_snapshot
from .install_store import _require_admin
from .windows_pin import PinnedFile
from .service_store import verify_paths
from .safeio import SafetyError

SDDL='O:BAG:BAD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)'
ACCESS=registry.ACCESS|2|0x40000|0x80000


class Native(registry.Native):
    def __init__(self):
        _require_admin();super().__init__()
        for name,args in (
            ('RegSetKeySecurity',[W.HANDLE,W.DWORD,C.c_void_p]),
            ('RegSetValueExW',[W.HANDLE,W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD]),
            ('RegFlushKey',[W.HANDLE]),
        ):
            fn=getattr(self.api,name);fn.argtypes=args;fn.restype=W.LONG
        fn=self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
        fn.argtypes=[W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p];fn.restype=W.BOOL

    def open(self):
        handle=W.HANDLE()
        if self.api.RegOpenKeyExW(W.HANDLE(-2147483646),registry.KEY,8,ACCESS,C.byref(handle)):
            raise SafetyError('New driver key cannot be opened')
        return handle

    def protect(self,handle):
        descriptor=C.c_void_p()
        if not self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL,1,C.byref(descriptor),None):
            raise SafetyError('Cannot construct driver key security')
        try:
            if self.api.RegSetKeySecurity(handle,0x80000005,descriptor):
                raise SafetyError('Cannot protect new driver key')
        finally:self.reader.kernel.LocalFree(descriptor)
        registry.validate_security(self.security(handle))

    def write(self,handle):
        data=(registry.expected_path()+'\0').encode('utf-16-le')
        registry.decode_string(1,data)
        buffer=C.create_string_buffer(data)
        if self.api.RegSetValueExW(handle,'IniPath',0,1,buffer,len(data)):
            raise SafetyError('Cannot bind private driver policy')

    def flush(self,handle):
        if self.api.RegFlushKey(handle):raise SafetyError('Driver policy binding durability is unknown')

    def close_key(self,handle):
        if self.api.RegCloseKey(handle):
            raise SafetyError('Cannot close installation registry key')


def _bind_created_driver(writer,services,service_handle,policy,receipt,verify_closed):
    """No start/delete/rollback: any failure leaves the driver disabled.

    Receipt intent must be durable before registry mutation; completion is only
    recorded after flush and same-handle readback. A failed attempt requires a
    separate recovery transaction, never overwriting an existing IniPath.
    """
    if not isinstance(services,Services):raise SafetyError('Held native SCM registration required')
    services.require_created(service_handle,'SbieDrv')
    spec=specification('SbieDrv');validate_snapshot(spec,services.snapshot(service_handle,spec))
    if (not isinstance(policy,PinnedFile) or not policy.handle
            or str(policy.path)!=registry.expected_path()):
        raise SafetyError('Held private installation policy required')
    verify_paths([policy.path,policy.path.parent],[policy.path.parent])
    def closed():
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    closed()
    handle=writer.open()
    try:
        if writer.value(handle,'SymbolicLinkValue') is not None or writer.value(handle,'IniPath') is not None:
            raise SafetyError('Existing driver policy binding cannot be adopted')
        receipt('intent',policy.sha256)
        closed();writer.protect(handle)
        closed();writer.write(handle)
        writer.flush(handle)
        registry.validate_security(writer.security(handle))
        actual=writer.value(handle,'IniPath')
        if actual is None or registry.decode_string(*actual)!=registry.expected_path():
            raise SafetyError('Private driver policy readback differs')
        services.require_created(service_handle,'SbieDrv')
        validate_snapshot(spec,services.snapshot(service_handle,spec))
        closed();receipt('bound',policy.sha256)
        return dict(policy_bound=True,driver_started=False,client_admission=False)
    finally:writer.close_key(handle)


def driver_preparation(store,policy,generation,verify_closed):
    """Build the SCM registration hook from held store and durable file receipts."""
    from .install_store import Store,Directory
    from .install_binding_receipts import BindingReceipt
    if not isinstance(store,Store) or not store.journal or not store.journal.lock:
        raise SafetyError('Held installation store required')
    def prepare(services,handle):
        tx=store.journal.load()
        if not tx or tx['generation']!=generation:raise SafetyError('Installation generation differs')
        parent=store.directories.get('Policy')
        if (not isinstance(parent,Directory) or not parent.handle or not isinstance(policy,PinnedFile)
                or policy.path.parent!=parent.path):
            raise SafetyError('Held staged policy directory required')
        receipt=BindingReceipt(store.journal,policy)
        receipt.transaction(writing=True);receipt.staged()
        return _bind_created_driver(Native(),services,handle,policy,receipt.record,verify_closed)
    return prepare
