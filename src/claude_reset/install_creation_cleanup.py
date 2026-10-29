"""Internal pending-creation cleanup with held ownership and durable uncertainty."""
from ctypes import wintypes as W
from .install_creation_attestation import HeldPendingCreation,creation_records
from .install_creation_cleanup_receipt import CreationCleanupReceipt
from .install_removal_receipts import RemovalReceipts
from .install_creation_security import validate_pending_service
from .install_service_markers import creation_display,validate_creation_snapshot
from .install_recovery_inputs import RecoveryInputs
from .install_service_step import _require_complete_staging
from .install_reservations import ReservationReceipt
from .install_boundary_receipts import BoundaryReceipt
from .install_boundary import _held_rules
from .install_scm_cleanup import DELETE_ACCESS,_confirm_absence
from .service_store import verify_paths
from .safeio import SafetyError


def _request(held):
    if not isinstance(held,HeldPendingCreation) or held.handle is None:
        raise SafetyError('Held pending creation object required')
    held.verify();reader=held.reader;spec=held.spec
    handle=reader.api.OpenServiceW(reader.manager,spec['name'],DELETE_ACCESS)
    if not handle:raise SafetyError('Pending creation cannot be opened for deletion')
    try:
        actual=reader.snapshot(handle,spec)
        if held.marker['state']=='bound':validate_creation_snapshot(held.marker['marker'],spec,actual)
        else:
            validate_pending_service(spec,actual)
            if actual.get('display')!=creation_display(held.marker['marker'],spec):
                raise SafetyError('Pending creation deletion binding differs')
        held.verify();held.require_closed()
        delete=reader.api.DeleteService;delete.argtypes=[W.HANDLE];delete.restype=W.BOOL
        if not delete(handle):raise SafetyError('Pending creation deletion request failed')
    finally:reader.release_auxiliary(handle)


class PendingCreationCleanup:
    def __init__(self,store,inputs,held,generation,verify_closed):
        if (not isinstance(inputs,RecoveryInputs) or not isinstance(held,HeldPendingCreation)
                or held.store is not store or held.generation!=generation or not callable(verify_closed)):
            raise SafetyError('Matching pending creation and held recovery inputs required')
        self.store,self.inputs,self.held=store,inputs,held
        self.generation,self.verifier=generation,verify_closed
        self.receipt=CreationCleanupReceipt(store,generation);self.attempted=False
        self.closed();held.verify();self.initial=self._base();self.previous=self.receipt.load()
        if held.handle is not None and self.previous is not None and (self.previous['absence_verified']
                or any(r['state']=='delete_requested' for r in self.previous['attempts'])):
            raise SafetyError('Service present after accepted deletion or absence; no replacement adoption')
        removal=self.initial[2]
        if held.handle is not None and removal is not None and (removal['absence_verified'] or any(
                r['spec']['name']==held.spec['name'] and r['state']=='delete_requested' for r in removal['services'])):
            raise SafetyError('Original removal history contradicts the present pending service')

    def closed(self):
        if self.verifier(self.generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return self.held.require_closed()

    def _base(self):
        if creation_records(self.store,self.generation)!=(self.held.transaction,self.held.source,self.held.markers):
            raise SafetyError('Pending creation recovery evidence changed')
        self.inputs.report();_require_complete_staging(self.store,self.inputs.payload,self.inputs.configuration,self.inputs.runtime_signatures)
        reservation=ReservationReceipt.require_removed_if_present(self.store.journal)
        boundary=BoundaryReceipt(self.store.journal,[r.key.value() for r in _held_rules(self.store,self.inputs.payload)]).load()
        if boundary is None or boundary['state']!='committed':raise SafetyError('Initial denies must remain committed')
        paths=[self.store.journal.directory/BoundaryReceipt.filename]
        if reservation is not None:paths.append(self.store.journal.directory/ReservationReceipt.filename)
        removal=RemovalReceipts(self.store.journal).load()
        if removal is not None:paths.append(RemovalReceipts(self.store.journal).path)
        try:self.receipt.path.lstat();paths.append(self.receipt.path)
        except FileNotFoundError:pass
        verify_paths(paths,[])
        return reservation,boundary,removal

    def _check(self,expected):
        self.closed()
        if self._base()!=self.initial or self.receipt.load()!=expected:
            raise SafetyError('Pending creation cleanup boundary or history changed')

    def run(self):
        if self.attempted:raise SafetyError('Fresh attestation required after any pending cleanup attempt')
        self.attempted=True;self.held.verify();self._check(self.previous)
        requested=self.held.handle is not None;expected=self.previous
        if requested:
            identifier=self.receipt.begin()
            expected=dict(self.receipt.context(),attempts=[*([] if self.previous is None else self.previous['attempts']),
                          dict(id=identifier,state='delete_intent')],absence_verified=False)
            self._check(expected);_request(self.held)
            self.receipt.requested(identifier);expected['attempts'][-1]['state']='delete_requested'
        self._check(expected);self.held.close()
        observation=_confirm_absence([self.held.spec['name']],self.closed)
        self._check(expected);self.receipt.observe_absence(observation);self.closed()
        return dict(service=self.held.spec['name'],new_deletion_request=requested,
                    absence_verified=True,client_admission=False)
