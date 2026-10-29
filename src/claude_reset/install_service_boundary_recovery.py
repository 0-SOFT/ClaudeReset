"""Resume only the boundary tail after all recorded services were removed."""
from .install_recovery_inputs import RecoveryInputs
from .install_recovery_records import recovery_records
from .install_removal_receipts import RemovalReceipts
from .install_boundary_receipts import BoundaryReceipt
from .install_boundary import _held_rules
from .install_boundary_reconciliation import reconcile_committed_boundary
from .install_boundary_confirmation import reconcile_boundary_absence
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .service_store import verify_paths
from .safeio import SafetyError


def recover_removed_service_boundary(store,generation,verify_closed):
    if not callable(verify_closed):raise SafetyError('Closed-boundary verifier required')
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    def evidence():
        records=recovery_records(store,generation,closed)
        receipt=RemovalReceipts(store.journal);verify_paths([receipt.path],[])
        removal=receipt.load()
        if removal is None or removal['absence_verified'] is not True:
            raise SafetyError('Boundary tail requires completed service absence evidence')
        _confirm_absence(list(reversed(SERVICES)),closed)
        return records,removal
    with RecoveryInputs(store,generation) as inputs:
        before=evidence()
        boundary=BoundaryReceipt(store.journal,[r.key.value() for r in _held_rules(store,inputs.payload)])
        record=boundary.load()
        if record is None:raise SafetyError('Recorded initial boundary required')
        phase=record.get('previous_state',record['state'])
        if phase in ('committed','remove_intent'):
            result=reconcile_committed_boundary(store,inputs,generation,verify_closed)
            requested=result['new_removal_transaction']
        elif phase=='removed':
            reconcile_boundary_absence(store,inputs,generation,verify_closed);requested=False
        else:raise SafetyError('Unknown initial creation is inconsistent with removed registrations')
        if evidence()!=before or boundary.load()['state']!='removed':
            raise SafetyError('Service recovery evidence changed during boundary reconciliation')
        closed()
        return dict(services_recovered=True,services_absent=4,new_deletion_requests=0,
                    deny_filters_absent=16,new_deny_removal_transaction=requested,client_admission=False)
