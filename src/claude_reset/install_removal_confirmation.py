"""Confirm already requested removal after reopening, without SCM mutations.

No deletion replay, mutation of remaining services, or client admission.
Only the protected absence receipt is written; filters and payload remain held.
"""
from .install_service_attestation import _records
from .install_recovery_records import recovery_records
from .install_recovery_inputs import RecoveryInputs
from .install_service_step import _require_complete_staging
from .install_removal_receipts import RemovalReceipts
from .install_reservations import ReservationReceipt
from .install_boundary import _held_rules
from .install_boundary_receipts import BoundaryReceipt
from .install_scm_cleanup import _confirm_removal,_confirm_absence
from .service_store import verify_paths
from .safeio import SafetyError


def _confirm_recorded(store,inputs,generation,verify_closed,*,observed):
    """Recheck actual absence; durable requests alone never prove absence."""
    if not isinstance(inputs,RecoveryInputs) or not callable(verify_closed):
        raise SafetyError('Held recovery inputs and closed-boundary verifier required')

    def closed():
        if verify_closed(generation) is not True:
            raise SafetyError('Client boundary is not verified closed')
        return True

    def evidence():
        tx,source,markers=(recovery_records(store,generation,closed) if observed else _records(store,generation))
        if not observed and (tx['state']!='recovering' or any(row['state']!='disabled' for row in source['services'])):
            raise SafetyError('Completed registrations in ordered recovery required')
        inputs.report();_require_complete_staging(store,inputs.payload,inputs.configuration,inputs.runtime_signatures)
        reservation=ReservationReceipt.require_removed_if_present(store.journal)
        directory=store.journal.directory
        receipt=RemovalReceipts(store.journal).load()
        metadata=[directory/'boundary-receipt.json']
        if receipt is not None:metadata.append(directory/'service-removal-receipts.json')
        if reservation is not None:metadata.append(directory/ReservationReceipt.filename)
        verify_paths(metadata,[])
        keys=[rule.key.value() for rule in _held_rules(store,inputs.payload)]
        boundary=BoundaryReceipt(store.journal,keys).load()
        if boundary is None or boundary['state']!='committed':
            raise SafetyError('Initial deny boundary must remain committed')
        expected=[dict(spec=row['spec'],state='delete_requested') for row in reversed(source['services'])]
        if not observed and (receipt is None or receipt['services']!=expected):
            raise SafetyError('Complete durable deletion requests required; no replay permitted')
        return tx,source,markers,boundary,receipt,reservation

    closed();before=evidence()
    names=[row['name'] for row in reversed(before[1]['services'])]
    if observed:
        confirmed=_confirm_absence(names,closed)
    else:
        result=dict(services=[dict(name=name,deletion_requested=True,absence_verified=False,
                                  client_admission=False) for name in names],
                    absence_verified=False,client_admission=False)
        confirmed=_confirm_removal(result,closed)
    closed()
    if evidence()!=before:raise SafetyError('Removal evidence changed during absence inspection')
    receipt=RemovalReceipts(store.journal)
    if observed:receipt.confirm_observed(confirmed)
    else:receipt.confirm(confirmed)
    closed()
    result=dict(services_removed=len(confirmed['services']),absence_verified=True,
                deletion_replayed=False,client_admission=False)
    if observed:
        history=before[4]
        known=(history is not None and len(history['services'])==len(names)
               and all(row['state']=='delete_requested' for row in history['services']))
        result.update(completion_basis='observed_absence',deletion_outcome_known=known)
    return result



def confirm_recorded_removal(store,inputs,generation,verify_closed):
    """Every recorded request completed; independently confirm current absence."""
    return _confirm_recorded(store,inputs,generation,verify_closed,observed=False)


def reconcile_recorded_absence(store,inputs,generation,verify_closed):
    """Observe every owned slot absent, even when deletion history is incomplete.

    This never retries DeleteService or changes historical intents to success.
    Present/pending slots and incomplete ownership stay blocked.
    """
    return _confirm_recorded(store,inputs,generation,verify_closed,observed=True)
