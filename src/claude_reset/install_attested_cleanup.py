"""Internal cleanup after reopening complete marked disabled registrations.

No elevation, service start, stop, adoption of legacy services, or client grant.
All query handles stay held until every deletion request is durably recorded.
Unknown outcomes still require separate reconciliation, not optimistic replay.
"""
from ctypes import wintypes as W
from .install_service_attestation import HeldAttestation,_records
from .install_recovery_inputs import RecoveryInputs
from .install_service_step import _require_complete_staging
from .install_scm import validate_snapshot,validate_spec
from .install_scm_cleanup import DELETE_ACCESS,_confirm_removal
from .install_removal_receipts import RemovalReceipts
from .install_reservations import ReservationReceipt
from .install_boundary import _held_rules
from .install_boundary_receipts import BoundaryReceipt
from .safeio import SafetyError


def _request_delete(held,spec,closed):
    if not isinstance(held,HeldAttestation):raise SafetyError('Held protected marker attestation required')
    spec=validate_spec(spec)
    held.verify_service(spec['name'])
    if closed() is not True:raise SafetyError('Client boundary is not verified closed')
    # The existing query handle keeps this SCM name bound to the inspected
    # object. Reopened handles are never presented as creation handles.
    reader=held.reader;handle=reader.api.OpenServiceW(reader.manager,spec['name'],DELETE_ACCESS)
    if not handle:raise SafetyError('Marked service cannot be opened for deletion')
    try:
        validate_snapshot(spec,reader.snapshot(handle,spec));held.verify_service(spec['name'])
        if closed() is not True:raise SafetyError('Client boundary is not verified closed')
        delete=reader.api.DeleteService;delete.argtypes=[W.HANDLE];delete.restype=W.BOOL
        if not delete(handle):raise SafetyError('Marked service deletion request failed')
    finally:reader.release_auxiliary(handle)


class AttestedCleanup:
    def __init__(self,store,inputs,held,generation,verify_closed):
        if (not isinstance(inputs,RecoveryInputs) or not isinstance(held,HeldAttestation)
                or held.store is not store or held.generation!=generation or not callable(verify_closed)):
            raise SafetyError('Matching held recovery inputs, attestation and closed-boundary verifier required')
        self.store,self.inputs,self.held=store,inputs,held
        self.generation,self.verifier=generation,verify_closed
        self.completed=[];self.result=None
        self._context()

    def closed(self):
        if self.verifier(self.generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True

    def _context(self):
        tx,source,markers=_records(self.store,self.generation)
        if (tx['state']!='recovering' or tx!=self.held.transaction
                or source!=self.held.source or markers!=self.held.markers):
            raise SafetyError('Marked cleanup recovery evidence changed')
        self.inputs.report()
        _require_complete_staging(self.store,self.inputs.payload,self.inputs.configuration,self.inputs.runtime_signatures)
        ReservationReceipt.require_removed_if_present(self.store.journal)
        keys=[rule.key.value() for rule in _held_rules(self.store,self.inputs.payload)]
        boundary=BoundaryReceipt(self.store.journal,keys).load()
        if boundary is None or boundary['state']!='committed':
            raise SafetyError('Initial deny boundary must remain committed during service cleanup')
        removal=RemovalReceipts(self.store.journal);record=removal.load()
        ordered=list(reversed(source['services']))
        confirmed=ordered[:len(self.completed)]
        if (self.completed!=[dict(name=row['name'],deletion_requested=True,
                                  absence_verified=False,client_admission=False) for row in confirmed]
                or ([] if record is None else record['services'])!=[
                    dict(spec=row['spec'],state='delete_requested') for row in confirmed]):
            raise SafetyError('Unknown deletion outcome cannot be resumed from receipts alone')
        if self.result is None and self.held.closed:raise SafetyError('Service query handles were released early')
        return ordered,removal

    def run(self):
        ordered,removal=self._context();self.closed()
        if self.result is None:
            for row in ordered[len(self.completed):]:
                # A refused boundary between services leaves a confirmed prefix
                # which only this same object may continue without replay.
                self.closed();self.held.verify_service(row['name'])
                removal.record('delete_intent',row['spec'])
                _request_delete(self.held,row['spec'],self.closed)
                removal.record('delete_requested',row['spec'])
                self.completed.append(dict(name=row['name'],deletion_requested=True,
                                           absence_verified=False,client_admission=False))
            self.result=dict(services=list(self.completed),absence_verified=False,client_admission=False)
        # Logical evidence revocation is not proof that all handles closed.
        self.closed();self.held.close()
        confirmed=_confirm_removal(self.result,self.closed)
        removal.confirm(confirmed)
        self.closed()
        return dict(services_removed=len(confirmed['services']),absence_verified=True,client_admission=False)
