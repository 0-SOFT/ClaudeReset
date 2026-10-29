"""Recover listener reservations before reopening service deletion evidence."""
from .install_recovery_inputs import RecoveryInputs
from .install_service_attestation import HeldAttestation
from .install_reservation_reconciliation import recover_service_reservations
from .install_registered_recovery import recover_registered_services
from .safeio import SafetyError


def recover_reserved_services(store,generation,verify_closed):
    if not callable(verify_closed):raise SafetyError('Closed client-boundary verifier required')
    with RecoveryInputs(store,generation) as inputs:
        with HeldAttestation(store,generation) as held:
            reservation=recover_service_reservations(store,inputs,held,generation,verify_closed)
    # Old handles and file pins are deliberately closed before the service
    # coordinator acquires fresh ownership evidence for its own operation.
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    result=recover_registered_services(store,generation,verify_closed)
    return dict(result,reservations_absent=True,
                new_reservation_removal_transaction=reservation['new_removal_transaction'])
