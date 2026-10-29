"""Fresh attempts for uncertain removal of previously committed initial denies.

Never adopts a set after an unknown initial creation, nor replays an operation
known to have committed. Unknown attempts survive alongside fresh observations.
"""
from .install_boundary_confirmation import inspect_recovery_boundary
from .install_boundary_attempts import BoundaryAttempts
from .install_boundary import _held_rules
from .install_service_step import _require_complete_staging
from .install_reservations import ReservationReceipt
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .strict_wfp import Engine
from .service_store import verify_paths
from .safeio import SafetyError


def reconcile_committed_boundary(store,inputs,generation,verify_closed):
    receipt,source,observed=inspect_recovery_boundary(store,inputs,generation,verify_closed)
    log=BoundaryAttempts(receipt);log.context()
    def protected():
        paths=[receipt.path]
        try:log.path.lstat();paths.append(log.path)
        except FileNotFoundError:pass
        reservation=ReservationReceipt.require_removed_if_present(store.journal)
        if reservation is not None:paths.append(store.journal.directory/ReservationReceipt.filename)
        verify_paths(paths,[])
        return reservation
    reservation=protected();history=log.load();expected=history
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        inputs.report();_require_complete_staging(store,inputs.payload,inputs.configuration,inputs.runtime_signatures)
        if receipt.load()!=source or protected()!=reservation or log.load()!=expected:
            raise SafetyError('Boundary attempt or protected recovery evidence changed')
        return True
    def vacant():
        _confirm_absence(list(reversed(SERVICES)),closed)
        return True
    requested=False
    if observed['state']=='present':
        if (source['schema']==2 or history is not None and (history['absence_verified']
                or any(r['state']=='removal_committed' for r in history['attempts']))):
            raise SafetyError('Boundary appeared after known removal or absence; no replacement adoption')
        identifier=log.begin()
        expected=dict(log.context(),attempts=[*([] if history is None else history['attempts']),
                      dict(id=identifier,state='remove_intent')],absence_verified=False)
        vacant()
        _,current,snapshot=inspect_recovery_boundary(store,inputs,generation,verify_closed)
        if current!=source or snapshot!=observed:raise SafetyError('Boundary changed before fresh removal attempt')
        vacant()
        with Engine() as engine:engine.remove_recorded_denies(_held_rules(store,inputs.payload),vacant)
        # The API returned a successful transaction commit; record only that fact.
        log.committed(identifier);expected['attempts'][-1]['state']='removal_committed';requested=True
    vacant()
    _,current,absence=inspect_recovery_boundary(store,inputs,generation,verify_closed)
    if current!=source or absence['state']!='absent':raise SafetyError('Actual boundary absence remains unconfirmed')
    vacant();log.observe_absence(absence);receipt.confirm_absent(absence)
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    return dict(boundary_absent=True,new_removal_transaction=requested,historical_attempts_replayed=False,
                client_admission=False)
