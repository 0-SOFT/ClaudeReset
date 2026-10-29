"""Select a fixed recovery protocol from protected evidence, then recheck absence.

This internal coordinator never advances the main journal, removes payload files,
starts a service or grants client access. Each selected protocol obtains fresh
ownership evidence; selection alone authorizes no mutation.
"""
from .install_recovery_inputs import RecoveryInputs
from .install_service_receipts import ServiceReceipts
from .install_removal_receipts import RemovalReceipts
from .install_boundary_receipts import BoundaryReceipt
from .install_reservations import ReservationReceipt
from .install_boundary import _held_rules
from .install_empty_service_recovery import recover_empty_service_step
from .install_reserved_service_recovery import recover_reserved_services
from .install_registered_recovery import recover_registered_services
from .install_service_boundary_recovery import recover_removed_service_boundary
from .install_cleanup_observation import require_cleanup_absence
from .service_store import verify_paths
from .windows_pin import PinnedFile
from .backend_spec import document
from .safeio import SafetyError


def _reservation(journal):
    path=journal.directory/ReservationReceipt.filename
    try:path.lstat()
    except FileNotFoundError:return None
    with PinnedFile(path,limit=65536) as pin:value=document(pin.data)
    if not isinstance(value,dict):raise SafetyError('Invalid reservation recovery evidence')
    return ReservationReceipt(journal,value.get('keys')).validate(value)


def recover_service_step(store,generation,verify_closed):
    if not callable(verify_closed):raise SafetyError('Closed client-boundary verifier required')
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    closed()
    with RecoveryInputs(store,generation) as inputs:
        tx=store.journal.load();active=[e for e in tx['entries'] if e['state']!='undone']
        if tx['state']!='recovering' or not active or active[-1]['step']!='install_services':
            raise SafetyError('Exact ordered service recovery required')
        paths=[]
        names=('service-receipts.json','service-marker-receipts.json','boundary-receipt.json',
               'reservation-receipt.json','service-removal-receipts.json','pending-creation-cleanup.json',
               'service-reconciliation-log.json','boundary-reconciliation-log.json',
               'reservation-reconciliation-log.json','policy-binding-receipt.json')
        present=set()
        for name in names:
            path=store.journal.directory/name
            try:path.lstat()
            except FileNotFoundError:continue
            paths.append(path);present.add(name)
        verify_paths(paths,[])
        source=ServiceReceipts(store.journal).load();reservation=_reservation(store.journal)
        keys=[r.key.value() for r in _held_rules(store,inputs.payload)]
        boundary=BoundaryReceipt(store.journal,keys).load()
        if not source or not source['services']:
            route='empty';action=recover_empty_service_step
        elif boundary is None:
            raise SafetyError('Initial boundary history is required for recorded services')
        elif reservation is not None and reservation['state']!='removed':
            if present & {'service-removal-receipts.json','pending-creation-cleanup.json',
                          'service-reconciliation-log.json','boundary-reconciliation-log.json'}:
                raise SafetyError('Later cleanup evidence contradicts remaining reservations')
            route='reservations';action=recover_reserved_services
        else:
            removal=RemovalReceipts(store.journal).load()
            if removal is not None and removal['absence_verified']:
                route='boundary';action=recover_removed_service_boundary
            else:
                if boundary['state']!='committed' or 'boundary-reconciliation-log.json' in present:
                    raise SafetyError('Uncertain boundary cleanup requires completed service absence first')
                route='registrations';action=recover_registered_services
        if store.journal.load()!=tx:raise SafetyError('Recovery selection generation changed')
        closed()
    # Close inspection pins before the protocol acquires its own fresh scope.
    result=action(store,generation,verify_closed)
    if (not isinstance(result,dict) or result.get('services_recovered') is not True
            or result.get('client_admission') is not False):
        raise SafetyError('Service recovery did not confirm closed completion')
    def unchanged():
        closed()
        verify_paths(paths,[])
        if store.journal.load()!=tx or ServiceReceipts(store.journal).load()!=source:
            raise SafetyError('Service recovery changed the original transaction or creation history')
        current=BoundaryReceipt(store.journal,keys).load()
        if (boundary is None and current is not None
                or boundary is not None and (current is None or current['state']!='removed')):
            raise SafetyError('Initial boundary recovery remains incomplete')
        after=ReservationReceipt.require_removed_if_present(store.journal)
        if (after is None)!=(reservation is None) or after is not None and after['keys']!=reservation['keys']:
            raise SafetyError('Reservation identity changed during service recovery')
        return True
    unchanged()
    require_cleanup_absence(keys+([] if reservation is None else reservation['keys']),unchanged)
    unchanged()
    return dict(result,recovery_route=route,services_recovered=True,client_admission=False,
                payload_removed=False,journal_advanced=False)
