"""Delete only still-held registrations created by this installer process.

Never opens an existing service for adoption or stops a service. Cross-process
recovery requires a separate durable ownership protocol and is not implemented
by this primitive. Marked-for-deletion is not proof of completed removal.
"""
import ctypes as C
from ctypes import wintypes as W
from .install_scm import Native,HeldRegistrations,validate_spec,validate_snapshot
from .safeio import SafetyError

DELETE_ACCESS=0x10000|0x20000|1|4  # DELETE, READ_CONTROL, QUERY_CONFIG/STATUS only.


def _remove_current_registration(native,creation_handle,spec,verify_closed):
    if not isinstance(native,Native):raise SafetyError('Original native registration required')
    spec=validate_spec(spec)
    native.require_created(creation_handle,spec['name'])
    def closed():
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    closed();validate_snapshot(spec,native.snapshot(creation_handle,spec))
    # Holding the original SCM object prevents a deleted name being recreated.
    # If it is already marked for deletion, opening fails; never adopt a name.
    deletion_handle=native.api.OpenServiceW(native.manager,spec['name'],DELETE_ACCESS)
    if not deletion_handle:raise SafetyError('Held service cannot be opened for deletion')
    try:
        native.require_created(creation_handle,spec['name'])
        validate_snapshot(spec,native.snapshot(deletion_handle,spec))
        closed()
        fn=native.api.DeleteService;fn.argtypes=[W.HANDLE];fn.restype=W.BOOL
        if not fn(deletion_handle):raise SafetyError('Service deletion did not succeed')
        return dict(name=spec['name'],deletion_requested=True,absence_verified=False,client_admission=False)
    finally:native.release_auxiliary(deletion_handle)


def _rollback_held_registrations(held,receipt,verify_closed,*,completed=None):
    """Reverse-order deletion; record intent before mutation and retain on failure.

    Caller must separately verify name absence after every handle has closed.
    The returned report deliberately cannot complete an installer undo step.
    """
    if not isinstance(held,HeldRegistrations):raise SafetyError('Held registration set required')
    # The enclosing same-process step may retain confirmed progress across a
    # refusal between services. Never reconstruct this list from disk alone.
    results=[] if completed is None else completed
    if not isinstance(results,list):raise SafetyError('In-memory deletion progress required')
    if held.uncertain_deletion:
        raise SafetyError('Partial service deletion lacks confirmed in-memory progress')
    if held.pending_close is not None and not held.items:
        raise SafetyError('Pending deletion close lost its held registration')
    while held.items:
        native,handle,spec=held.items[-1]
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        result=held.pending_close_result()
        if result is None:
            held.uncertain_deletion=True
            receipt('delete_intent',dict(spec))
            result=_remove_current_registration(native,handle,spec,verify_closed)
            receipt('delete_requested',dict(spec))
            # Only a returned durable completion can authorize retrying just
            # the close. Never reconstruct this capability from a receipt.
            held.pending_close=(native,handle,dict(spec),dict(result))
            held.uncertain_deletion=False
        native.release(handle);held.items.pop();results.append(result);held.pending_close=None
    return dict(services=list(results),absence_verified=False,client_admission=False)


def _confirm_removal(result,verify_closed):
    """Read-only completion check; pending deletion never counts as absence."""
    from .install_inventory import SERVICES
    if (not isinstance(result,dict) or set(result)!={'services','absence_verified','client_admission'}
            or result['absence_verified'] is not False or result['client_admission'] is not False
            or not isinstance(result['services'],list)):
        raise SafetyError('Current registration deletion result required')
    names=[]
    for row in result['services']:
        if (not isinstance(row,dict) or set(row)!={'name','deletion_requested','absence_verified','client_admission'}
                or row['name'] not in SERVICES or row['name'] in names
                or row['deletion_requested'] is not True or row['absence_verified'] is not False
                or row['client_admission'] is not False):
            raise SafetyError('Invalid service deletion result')
        names.append(row['name'])
    return _confirm_absence(names,verify_closed)


def _confirm_absence(names,verify_closed):
    """Fresh read-only observation; does not assert who requested deletion."""
    from .install_inventory import services,SERVICES
    from .install_scm import require_vacant_registry_slot
    if (not isinstance(names,list) or any(not isinstance(n,str) or n not in SERVICES for n in names)
            or len(set(names))!=len(names)):
        raise SafetyError('Exact distinct installation service names required')
    if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    rows=services()
    if (not isinstance(rows,list) or len(rows)!=len(SERVICES)
            or any(not isinstance(r,dict) for r in rows) or [r.get('name') for r in rows]!=list(SERVICES)
            or any(type(r.get('exists')) is not bool for r in rows)):
        raise SafetyError('Incomplete service absence snapshot')
    for name in names:
        if next(row for row in rows if row['name']==name)['exists']:
            raise SafetyError('Service deletion is pending or the slot was recreated')
        require_vacant_registry_slot(name)
    if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    return dict(services=names,absence_verified=True,client_admission=False)
