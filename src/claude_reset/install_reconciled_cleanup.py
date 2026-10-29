"""Freshly attest and remove remaining objects without replaying old requests.

Each invocation has a separate durable attempt. Original uncertain history is
preserved; only actual complete absence can finish the service removal receipt.
No service start, stop, legacy adoption, WFP change, file removal or client grant.
"""
from copy import deepcopy
from .install_remaining_attestation import HeldRemainingAttestation
from .install_service_attestation import _records
from .install_recovery_records import recovery_records
from .install_recovery_inputs import RecoveryInputs
from .install_service_step import _require_complete_staging
from .install_removal_receipts import RemovalReceipts
from .install_reconciliation_log import ReconciliationLog
from .install_removal_confirmation import reconcile_recorded_absence
from .install_attested_cleanup import _request_delete
from .install_scm_cleanup import _confirm_absence
from .install_reservations import ReservationReceipt
from .install_boundary import _held_rules
from .install_boundary_receipts import BoundaryReceipt
from .service_store import verify_paths
from .safeio import SafetyError


class ReconciledCleanup:
    def __init__(self,store,inputs,held,generation,verify_closed):
        if (not isinstance(inputs,RecoveryInputs) or not isinstance(held,HeldRemainingAttestation)
                or held.store is not store or held.generation!=generation or not callable(verify_closed)):
            raise SafetyError('Matching remaining-service attestation and recovery inputs required')
        self.store,self.inputs,self.held=store,inputs,held
        self.generation,self.verifier=generation,verify_closed
        self.log=ReconciliationLog(store.journal,recovery_context=lambda:recovery_records(store,generation,self.closed))
        self.attempted=False;self.identifier=None;self.actions=[]
        self.closed();held.verify();self.initial=self._base()
        self.old_log=self.log.load()
        histories=[] if self.initial[2] is None else [self.initial[2]['services']]
        if self.old_log is not None:histories += [a['services'] for a in self.old_log['attempts']]
        if any(row['spec']['name'] not in held.absent for rows in histories for row in rows if row['state']=='delete_requested'):
            raise SafetyError('Previously confirmed deletion is not absent; no replay or replacement adoption')
        if held.items and ((self.initial[2] is not None and self.initial[2]['absence_verified'])
                or self.old_log is not None and any(a['state']=='complete' for a in self.old_log['attempts'])):
            raise SafetyError('A service appeared after completed absence; separate investigation required')

    def closed(self):
        if self.verifier(self.generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return self.held.require_closed()

    def _base(self):
        tx,source,markers=recovery_records(self.store,self.generation,self.closed)
        if tx!=self.held.transaction or source!=self.held.source or markers!=self.held.markers:
            raise SafetyError('Reconciled cleanup evidence changed')
        self.inputs.report();_require_complete_staging(self.store,self.inputs.payload,self.inputs.configuration,self.inputs.runtime_signatures)
        reservation=ReservationReceipt.require_removed_if_present(self.store.journal)
        boundary=BoundaryReceipt(self.store.journal,[r.key.value() for r in _held_rules(self.store,self.inputs.payload)]).load()
        if boundary is None or boundary['state']!='committed':raise SafetyError('Initial denies must remain committed')
        removal=RemovalReceipts(self.store.journal).load()
        paths=[self.store.journal.directory/BoundaryReceipt.filename]
        if reservation is not None:paths.append(self.store.journal.directory/ReservationReceipt.filename)
        if removal is not None:paths.append(RemovalReceipts(self.store.journal).path)
        try:self.log.path.lstat();paths.append(self.log.path)
        except FileNotFoundError:pass
        verify_paths(paths,[])
        return reservation,boundary,removal

    def _check_log(self,actions):
        current=self.log.load();old=[] if self.old_log is None else self.old_log['attempts']
        expected=dict(id=self.identifier,absent=list(self.held.absent),services=actions,state='running')
        if current is None or current['attempts']!=[*old,expected]:
            raise SafetyError('Reconciliation attempt changed or has uncertain in-memory progress')

    def _check(self,actions):
        self.closed()
        if self._base()!=self.initial:raise SafetyError('Cleanup boundary or original history changed')
        self._check_log(actions)

    def run(self):
        if self.attempted:raise SafetyError('A failed or completed attempt requires fresh attestation; no replay')
        self.attempted=True;self.closed();self.held.verify()
        if self._base()!=self.initial or self.log.load()!=self.old_log:
            raise SafetyError('Recovery evidence changed before attempt')
        self.identifier=self.log.begin(self.held.absent)
        for _,_,spec in reversed(self.held.items):
            self._check(self.actions)
            intent=dict(spec=deepcopy(spec),state='delete_intent')
            self.log.record(self.identifier,'delete_intent',spec)
            self._check([*self.actions,intent])
            _request_delete(self.held,spec,self.closed)
            self.log.record(self.identifier,'delete_requested',spec)
            self.actions.append(dict(spec=deepcopy(spec),state='delete_requested'))
        self._check(self.actions);self.held.close()
        reconcile_recorded_absence(self.store,self.inputs,self.generation,self.verifier)
        names=[row['name'] for row in reversed(self.held.source['services'])]
        observation=_confirm_absence(names,self.closed)
        self._check_log(self.actions);self.log.complete(self.identifier,observation);self.closed()
        return dict(services_absent=len(names),new_deletion_requests=len(self.actions),
                    historical_requests_replayed=False,absence_verified=True,client_admission=False)
