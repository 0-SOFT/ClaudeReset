"""Internal disabled-service installation step; no public/elevating entry point.

The enclosing installer must authenticate the release and verify closed clients.
This coordinator never starts services or authorizes clients. Its recovery uses
only creation handles retained in this process, not journal-based SCM adoption.
"""
from .safeio import SafetyError
from .install_store import Store,Directory
from .install_stage import Staged
from .install_receipts import Receipts,identity
from .install_config_stage import ConfigurationReceipts
from .windows_pin import PinnedFile
from .service_store import program_files
from .install_scm import Native,HeldRegistrations,SERVICES,_register_disabled
from .install_service_receipts import ServiceReceipts
from .install_removal_receipts import RemovalReceipts
from .install_registry_bind import driver_preparation
from .install_service_markers import MarkerReceipts,service_preparation
from .install_boundary import _install_backend_denies,_remove_backend_denies,_held_rules
from .install_boundary_receipts import BoundaryReceipt
from .install_reservations import ReservationReceipt,_install_initial_reservations,_remove_initial_reservations
from .install_scm_cleanup import _rollback_held_registrations,_confirm_removal,_confirm_absence
from .install_created_verification import verify_created_bindings
from .install_runtime_stage import RuntimeSignatureReceipts


def _require_complete_staging(store,payload,configuration,runtime_signatures=None):
    """Check all held payload/configuration and recorded sidecars before WFP/SCM."""
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle or root.path!=program_files()/'ClaudeReset':
        raise SafetyError('Fixed held installation root required')
    groups=[(payload,Receipts),(configuration,ConfigurationReceipts)]
    signature_record=RuntimeSignatureReceipts(store.journal).load()
    if signature_record is not None or runtime_signatures is not None:
        if not isinstance(runtime_signatures,Staged):
            raise SafetyError('Recorded runtime signatures must remain held')
        groups.append((runtime_signatures,RuntimeSignatureReceipts))
    else:
        for name in RuntimeSignatureReceipts.names:
            try:(root.path/name).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Unrecorded runtime signature destination is occupied')
    for staged,kind in groups:
        record=kind(store.journal).load()
        if not record or set(staged.pins)!=set(kind.names) or len(record['files'])!=len(kind.names):
            raise SafetyError('Complete held staging and receipts required before service installation')
        for row in record['files']:
            pin=staged.pins[row['name']]
            if (not isinstance(pin,PinnedFile) or not pin.handle or pin.path!=root.path/row['name']
                    or row['state']!='complete' or row['sha256']!=pin.sha256
                    or row['identity']!=identity(pin.api,pin.handle)):
                raise SafetyError('Service installation input differs from completed staging')
            if kind is RuntimeSignatureReceipts and (not isinstance(pin.data,bytes) or len(pin.data)!=64):
                raise SafetyError('Exact detached runtime signature bytes required')


class DisabledServiceStep:
    def __init__(self,store,payload,configuration,generation,verify_closed,*,runtime_signatures=None):
        if (not isinstance(store,Store) or not isinstance(payload,Staged)
                or not isinstance(configuration,Staged) or not callable(verify_closed)):
            raise SafetyError('Held installation inputs and closed-client verifier required')
        self.store,self.payload,self.configuration=store,payload,configuration
        self.runtime_signatures=runtime_signatures
        self.generation,self.verifier=generation,verify_closed
        self.held=HeldRegistrations();self.native=None
        self.attempted=False;self.closed=False;self.deletion_result=None;self.deleted=[]
        self._context()

    def _context(self,*,recovering=False):
        if self.closed or not self.store.journal or not self.store.journal.lock:
            raise SafetyError('Open installation step and exclusive lock required')
        tx=ServiceReceipts(self.store.journal).transaction(writing=not recovering)
        if tx['generation']!=self.generation:raise SafetyError('Service step generation changed')
        if recovering and (tx['state']!='recovering'
                or not any(e['step']=='install_services' and e['state'] in ('intent','done') for e in tx['entries'])
                or any(e['step'] in ('verify_installed','fixture_acceptance') and e['state']!='undone' for e in tx['entries'])):
            raise SafetyError('Ordered service-step recovery required')
        return tx

    def verify_closed(self):
        if self.verifier(self.generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True

    def apply(self):
        self._context()
        if self.attempted:raise SafetyError('Service installation cannot be replayed')
        for name in ('boundary-receipt.json','reservation-receipt.json','service-receipts.json',
                     'service-removal-receipts.json','policy-binding-receipt.json',MarkerReceipts.filename,
                     'service-reconciliation-log.json','pending-creation-cleanup.json','boundary-reconciliation-log.json',
                     'reservation-reconciliation-log.json'):
            try:(self.store.journal.directory/name).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Existing service-step evidence requires separate recovery')
        _require_complete_staging(self.store,self.payload,self.configuration,self.runtime_signatures)
        self.verify_closed();self.attempted=True
        _install_backend_denies(self.store,self.payload,self.generation,self.verifier)
        receipts=ServiceReceipts(self.store.journal);receipts.begin()
        self.native=Native()
        prepare=driver_preparation(self.store,self.configuration.pins['Policy/Sandboxie.ini'],
                                   self.generation,self.verify_closed)
        mark=service_preparation(self.store,self.generation,self.verify_closed)
        for name in SERVICES:
            _register_disabled(self.native,name,receipts.record,self.verify_closed,
                               prepare_driver=prepare if name=='SbieDrv' else None,prepare_service=mark,prepare_creation=mark.begin,held=self.held)
        result=_install_initial_reservations(self.store,self.payload,self.configuration,
                                            self.generation,self.held,self.verifier)
        _require_complete_staging(self.store,self.payload,self.configuration,self.runtime_signatures)
        verify_created_bindings(self.store,self.generation,self.held,
                                self.configuration.pins['Policy/Sandboxie.ini'],self.verifier)
        from .install_prepared_boundary import verify_prepared_boundary
        verify_prepared_boundary(self.store,self.payload,self.configuration,self.generation,self.held,self.verifier,self.runtime_signatures)
        self.verify_closed()
        return dict(services_disabled=4,deny_filters=16,**result)

    def recover(self):
        self._context(recovering=True)
        if not self.attempted:raise SafetyError('Creation handles from this installation attempt required')
        self.verify_closed()
        path=self.store.journal.directory/ReservationReceipt.filename
        try:path.lstat();has_reservations=True
        except FileNotFoundError:has_reservations=False
        if has_reservations:
            # Unknown installation/removal outcomes are rejected by the primitive.
            try:ReservationReceipt.require_removed_if_present(self.store.journal)
            except SafetyError:
                _remove_initial_reservations(self.store,self.payload,self.configuration,
                                             self.generation,self.held,self.verifier)
        source=ServiceReceipts(self.store.journal).load()
        if source is not None and source['services']:
            removal=RemovalReceipts(self.store.journal);record=removal.load()
            if record is None or record['absence_verified'] is not True:
                if self.deletion_result is None:
                    # Only progress retained by this exact object can resume.
                    # An uncertain intent or a failed completion write cannot
                    # be promoted into successful deletion by journal readback.
                    removed=list(reversed(source['services']))[:len(self.deleted)]
                    expected=[dict(name=row['name'],deletion_requested=True,
                                   absence_verified=False,client_admission=False) for row in removed]
                    pending=self.held.pending_close_result()
                    confirmed=list(removed)
                    if pending is not None:
                        ordered=list(reversed(source['services']))
                        if len(removed)>=len(ordered):raise SafetyError('Unexpected pending service close')
                        row=ordered[len(removed)]
                        if pending!=dict(name=row['name'],deletion_requested=True,
                                         absence_verified=False,client_admission=False):
                            raise SafetyError('Pending close differs from the deletion sequence')
                        confirmed.append(row)
                    recorded=[] if record is None else record['services']
                    if (self.deleted!=expected or recorded!=[
                            dict(spec=row['spec'],state='delete_requested') for row in confirmed]):
                        raise SafetyError('Partial service deletion lacks confirmed in-memory progress')
                    remaining=source['services'][:len(source['services'])-len(self.deleted)]
                    if [s for _,_,s in self.held.items]!=[s['spec'] for s in remaining]:
                        raise SafetyError('Registration intent lacks matching held ownership')
                    self.deletion_result=_rollback_held_registrations(
                        self.held,removal.record,self.verify_closed,completed=self.deleted)
                removal.confirm(_confirm_removal(self.deletion_result,self.verify_closed))
            else:
                # An old receipt is not continuing proof that a slot is vacant.
                _confirm_absence([row['name'] for row in reversed(source['services'])],self.verify_closed)
        keys=[rule.key.value() for rule in _held_rules(self.store,self.payload)]
        boundary=BoundaryReceipt(self.store.journal,keys).load()
        if boundary is not None and boundary['state']!='removed':
            _remove_backend_denies(self.store,self.payload,self.generation,self.verifier)
        self.verify_closed()
        return dict(services_recovered=True,client_admission=False)

    def close(self):
        self.closed=True
        try:self.held.close()
        finally:
            if self.native is not None:self.native.close();self.native=None

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
