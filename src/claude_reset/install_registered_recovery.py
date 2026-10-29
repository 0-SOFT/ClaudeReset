"""Ordered internal recovery of recorded registrations after reopening.

This does not elevate, advance the installation journal, delete payload files or
grant clients access. Uncertain WFP outcomes and empty registration history need
their own recovery protocol. The real closed-boundary verifier is mandatory.
"""
from .install_recovery_inputs import RecoveryInputs
from .install_service_receipts import ServiceReceipts
from .install_creation_attestation import HeldPendingCreation
from .install_creation_cleanup import PendingCreationCleanup
from .install_remaining_attestation import HeldRemainingAttestation
from .install_reconciled_cleanup import ReconciledCleanup
from .install_boundary import _held_rules,_remove_backend_denies
from .install_boundary_receipts import BoundaryReceipt
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .safeio import SafetyError


def recover_registered_services(store,generation,verify_closed):
    if not callable(verify_closed):raise SafetyError('Closed client-boundary verifier required')
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    closed()
    with RecoveryInputs(store,generation) as inputs:
        source=ServiceReceipts(store.journal).load()
        if not source or not source['services']:
            raise SafetyError('Empty registration history requires separate boundary recovery')
        keys=[r.key.value() for r in _held_rules(store,inputs.payload)]
        boundary=BoundaryReceipt(store.journal,keys)
        before=boundary.load()
        if before is None or before['state']!='committed':
            raise SafetyError('Uncertain or completed boundary cleanup requires fresh WFP reconciliation')
        pending_requests=0
        if source['services'][-1]['state']=='intent':
            with HeldPendingCreation(store,generation,verify_closed) as pending:
                result=PendingCreationCleanup(store,inputs,pending,generation,verify_closed).run()
                pending_requests=int(result['new_deletion_request'])
        with HeldRemainingAttestation(store,generation,verify_closed) as remaining:
            result=ReconciledCleanup(store,inputs,remaining,generation,verify_closed).run()
        # Global fixed slots must be vacant, including slots never reached by
        # this partial registration. Do not remove denies beside a foreign slot.
        _confirm_absence(list(reversed(SERVICES)),closed)
        if boundary.load()!=before:raise SafetyError('Initial deny boundary changed during service recovery')
        removed=_remove_backend_denies(store,inputs.payload,generation,verify_closed)
        after=boundary.load()
        if (after!=dict(before,state='removed') or not isinstance(removed,dict)
                or removed!=dict(deny_filters_removed=16,client_admission=False)):
            raise SafetyError('Initial deny cleanup completion is unverified')
        closed()
        return dict(services_recovered=True,services_absent=4,
                    new_deletion_requests=pending_requests+result['new_deletion_requests'],
                    deny_filters_removed=16,client_admission=False)
