"""Fresh cleanup attempts for previously committed listener reservations."""
from .install_boundary_attempts import BoundaryAttempts
from .install_reservations import ReservationReceipt,_remove_pair
from .install_reservation_observation import inspect_reservation_pair,reservation_recovery_view
from .service_store import verify_paths
from .safeio import SafetyError
from .install_reservation_observation import reconcile_reservation_absence


class ReservationAttempts(BoundaryAttempts):
    filename='reservation-reconciliation-log.json'
    def __init__(self,receipt):
        if not isinstance(receipt,ReservationReceipt):raise SafetyError('Exact reservation receipt required')
        super().__init__(receipt)


def reconcile_committed_reservations(store,inputs,held,generation,verify_closed):
    receipt,source,observed=inspect_reservation_pair(store,inputs,held,generation,verify_closed)
    log=ReservationAttempts(receipt);log.context()
    def protected():
        paths=[receipt.path]
        try:log.path.lstat();paths.append(log.path)
        except FileNotFoundError:pass
        verify_paths(paths,[])
    protected();history=log.load();expected=history
    def checked():
        protected();inputs.report();held.verify()
        if (verify_closed(generation) is not True or receipt.load()!=source or log.load()!=expected):
            raise SafetyError('Reservation history or closed-boundary evidence changed')
        return True
    requested=False
    if observed['state']=='present':
        if (source['schema']==2 or history is not None and (history['absence_verified']
                or any(r['state']=='removal_committed' for r in history['attempts']))):
            raise SafetyError('Reservations appeared after known removal; no replacement adoption')
        identifier=log.begin()
        expected=dict(log.context(),attempts=[*([] if history is None else history['attempts']),
                      dict(id=identifier,state='remove_intent')],absence_verified=False)
        checked()
        _,current,snapshot=inspect_reservation_pair(store,inputs,held,generation,verify_closed)
        if current!=source or snapshot!=observed:raise SafetyError('Reservation pair changed before fresh attempt')
        with reservation_recovery_view(store,inputs,held,generation,verify_closed) as (engine,views,current_receipt,before,closed):
            if before!=source or current_receipt.keys!=receipt.keys:raise SafetyError('Reopened reservation identity differs')
            def guarded():
                closed();return checked()
            _remove_pair(engine,views,guarded)
        log.committed(identifier);expected['attempts'][-1]['state']='removal_committed';requested=True
    checked()
    _,current,absence=inspect_reservation_pair(store,inputs,held,generation,verify_closed)
    if current!=source or absence['state']!='absent':raise SafetyError('Reservation absence remains unconfirmed')
    checked();log.observe_absence(absence);receipt.confirm_absent(absence)
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    held.verify()
    return dict(reservations_absent=True,new_removal_transaction=requested,historical_attempts_replayed=False,
                client_admission=False)


def recover_service_reservations(store,inputs,held,generation,verify_closed):
    """Dispatch from inspected evidence, never from receipt-supplied rule keys."""
    _,source,observed=inspect_reservation_pair(store,inputs,held,generation,verify_closed)
    phase=source.get('previous_state',source['state'])
    if phase in ('committed','remove_intent'):
        return reconcile_committed_reservations(store,inputs,held,generation,verify_closed)
    if observed['state']!='absent':raise SafetyError('Uncertain reservation creation cannot authorize adoption')
    result=reconcile_reservation_absence(store,inputs,held,generation,verify_closed)
    return dict(reservations_absent=result['reservations_absent'],new_removal_transaction=False,
                historical_attempts_replayed=False,client_admission=False)
