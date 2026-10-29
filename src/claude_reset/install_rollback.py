"""Internal staged-file rollback. No service, directory or policy removal.

The future privileged adapter supplies a real closed-boundary verifier. This
primitive is tested only against owned inert files, never an installed client.
"""
import ctypes as C
from ctypes import wintypes as W
from .install_payload import FILES
from .install_receipts import Receipts,identity
from .install_store import Store,Directory
from .safeio import SafetyError
from .install_remove_pin import RemovalPin
from .install_cleanup_observation import require_cleanup_absence
from .install_recovery_evidence import require_no_service_evidence


def _mark_delete(pin):
    mark=pin.api.SetFileInformationByHandle
    mark.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];mark.restype=W.BOOL
    disposition=C.c_ubyte(1)  # FILE_DISPOSITION_INFO.Boolean, not BOOL.
    if not mark(pin.handle,4,C.byref(disposition),C.sizeof(disposition)):
        raise SafetyError('Cannot remove owned staged file; recovery remains pending')


def _rollback_staged_files(store,generation,verify_closed):
    return _rollback_files(store,generation,verify_closed,[(FILES,Receipts)])


def _rollback_installation_files(store,generation,verify_closed):
    from .install_config_stage import ConfigurationReceipts
    from .install_configuration import FILES as CONFIGURATION_FILES
    from .install_runtime_stage import RuntimeSignatureReceipts
    return _rollback_files(store,generation,verify_closed,
                           [(FILES,Receipts),(CONFIGURATION_FILES,ConfigurationReceipts),
                            (RuntimeSignatureReceipts.names,RuntimeSignatureReceipts)])


def _rollback_files(store,generation,verify_closed,catalogs):
    if not isinstance(store,Store) or not store.journal or not callable(verify_closed):
        raise SafetyError('Held store and closed-boundary verifier required')
    transaction=store.journal.load()
    if (not transaction or transaction['generation']!=generation
            or transaction['state']!='recovering'
            or not any(e['step']=='stage_protected_files' and e['state']!='undone'
                       for e in transaction['entries'])):
        raise SafetyError('Durable file recovery intent required')
    stage_index=next(i for i,e in enumerate(transaction['entries']) if e['step']=='stage_protected_files')
    if any(e['state']!='undone' for e in transaction['entries'][stage_index+1:]):
        raise SafetyError('Services and dependent installation steps must be recovered before file removal')
    if verify_closed(generation) is not True:
        raise SafetyError('Client boundary was not verified closed')
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:raise SafetyError('Held root required')
    from .install_boundary import IMAGES
    from .install_boundary_receipts import BoundaryReceipt
    from .install_reservations import ReservationReceipt
    reservation=ReservationReceipt.require_removed_if_present(store.journal)
    from .strict_wfp import Identity,deny_rules
    keys=[r.key.value() for r in deny_rules([Identity('app',str(root.path/name)) for name in IMAGES])]
    boundary=BoundaryReceipt(store.journal,keys).load()
    if boundary is not None and boundary['state']!='removed':
        raise SafetyError('Recorded WFP boundary must be recovered before file removal')
    service_attempt=any(e['step']=='install_services' for e in transaction['entries'])
    def unchanged():
        if not service_attempt:require_no_service_evidence(store.journal)
        if store.journal.load()!=transaction:
            raise SafetyError('File recovery transaction changed')
        if (BoundaryReceipt(store.journal,keys).load()!=boundary
                or ReservationReceipt.require_removed_if_present(store.journal)!=reservation):
            raise SafetyError('File recovery boundary evidence changed')
    def fresh_cleanup():
        if verify_closed(generation) is not True:
            raise SafetyError('Client boundary is not verified closed before file removal')
        unchanged()
        if service_attempt or boundary is not None or reservation is not None:
            require_cleanup_absence(keys+([] if reservation is None else reservation['keys']),
                                    lambda:verify_closed(generation))
            unchanged()
    fresh_cleanup()
    rows={};names=set()
    for files,receipt_type in catalogs:
        names.update(files)
        record=receipt_type(store.journal).load()
        if record is not None:rows.update({r['name']:r for r in record['files']})
    pins={};removed=[]
    try:
        # Acquire every mutation handle before the first removal. A changed,
        # unrecorded, linked or busy resource aborts the whole preflight.
        for name in sorted(names):
            parent,leaf=name.rsplit('/',1);held=store.directories.get(parent)
            if not isinstance(held,Directory) or not held.handle or held.path!=root.path/parent:
                raise SafetyError('Recovery parent differs')
            path=held.path/leaf
            try:path.lstat()
            except FileNotFoundError:continue
            row=rows.get(name)
            if row is None or row['identity'] is None:
                raise SafetyError('Unrecorded staged resource requires separate recovery')
            pin=RemovalPin(path);pins[name]=pin
            if (identity(pin.api,pin.handle)!=row['identity']
                    or row['state']=='complete' and pin.sha256!=row['sha256']):
                raise SafetyError('Staged resource changed ownership or completed content')
        if verify_closed(generation) is not True:
            raise SafetyError('Client boundary was not verified closed before removal')
        for name,pin in reversed(list(pins.items())):
            # A final link/identity check uses the mutation handle, never a
            # path-based delete after a detached read-only inspection.
            if identity(pin.api,pin.handle)!=rows[name]['identity']:
                raise SafetyError('Staged resource identity changed before removal')
            # Identity inspection may outlive the preceding evidence check.
            fresh_cleanup()
            _mark_delete(pin)
            pin.close()
            try:pin.path.lstat()
            except FileNotFoundError:removed.append(name)
            else:raise SafetyError('Staged removal did not complete')
        return {'removed':removed,'client_admission':False}
    finally:
        for pin in reversed(list(pins.values())):pin.close()
