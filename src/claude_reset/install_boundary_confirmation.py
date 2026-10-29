"""Observe absence after uncertain WFP operations; never replay mutations."""
from .install_recovery_inputs import RecoveryInputs
from .install_service_step import _require_complete_staging
from .install_service_receipts import ServiceReceipts
from .install_reservations import ReservationReceipt
from .install_boundary import _held_rules
from .install_boundary_receipts import BoundaryReceipt
from .install_boundary_observation import observe_initial_denies
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .strict_wfp import Engine
from .service_store import verify_paths
from .safeio import SafetyError


def inspect_recovery_boundary(store,inputs,generation,verify_closed):
    """Return a checked snapshot and its unchanged receipt; no metadata writes."""
    if not isinstance(inputs,RecoveryInputs) or not callable(verify_closed):
        raise SafetyError('Held recovery inputs and closed-boundary verifier required')
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    def vacant():
        _confirm_absence(list(reversed(SERVICES)),closed)
        return True
    def evidence():
        tx=ServiceReceipts(store.journal).transaction()
        active=[e for e in tx['entries'] if e['state']!='undone']
        if (tx['generation']!=generation or tx['state']!='recovering' or not active
                or active[-1]['step']!='install_services'):
            raise SafetyError('Boundary absence requires ordered matching recovery')
        inputs.report();_require_complete_staging(store,inputs.payload,inputs.configuration,inputs.runtime_signatures)
        reservation=ReservationReceipt.require_removed_if_present(store.journal)
        rules=_held_rules(store,inputs.payload);receipt=BoundaryReceipt(store.journal,[r.key.value() for r in rules])
        record=receipt.load()
        if record is None:raise SafetyError('Durable initial boundary intent required')
        paths=[receipt.path]
        if reservation is not None:paths.append(store.journal.directory/ReservationReceipt.filename)
        verify_paths(paths,[])
        return tx,reservation,record,rules,receipt
    vacant();before=evidence()
    with Engine() as engine:observed=observe_initial_denies(engine,before[3],vacant)
    vacant();after=evidence()
    if after[:3]!=before[:3]:raise SafetyError('Boundary recovery evidence changed during observation')
    return after[4],after[2],observed


def reconcile_boundary_absence(store,inputs,generation,verify_closed):
    receipt,before,observed=inspect_recovery_boundary(store,inputs,generation,verify_closed)
    if observed['state']!='absent':raise SafetyError('Initial denies remain present; no deletion replay')
    receipt.confirm_absent(observed)
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    return dict(boundary_absent=True,completion_basis='observed_absence',deletion_replayed=False,
                settings_changed=False,client_admission=False)
