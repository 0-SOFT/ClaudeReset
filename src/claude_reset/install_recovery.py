"""Recover an unfinished fresh-install service/file sequence from held storage.

No public entry point, elevation, migration or installed-version uninstall.
The caller must reopen the protected store and provide actual scoped revocation
and closed-boundary verification. Bootstrap directories and audit evidence stay.
"""
from copy import deepcopy
from .safeio import SafetyError
from .install_store import Store,Directory
from .install_transaction import Transaction,validate,TERMINAL
from .install_service_recovery import recover_service_step
from .install_rollback import _rollback_installation_files
from .install_payload import FILES
from .install_configuration import FILES as CONFIG_FILES
from .install_runtime_signature import RUNTIME_SIDECARS
from .install_boundary import IMAGES
from .install_boundary_receipts import BoundaryReceipt
from .install_reservations import ReservationReceipt
from .install_cleanup_observation import require_cleanup_absence
from .strict_wfp import Identity,deny_rules

from .install_recovery_evidence import SERVICE_EVIDENCE,require_no_service_evidence

FILE_EVIDENCE=('stage-receipts.json','configuration-receipts.json','runtime-signature-receipts.json')


def _require_unstaged(store):
    """An earlier journal cannot conceal an unrecorded later operation."""
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:
        raise SafetyError('Held installation root required for early recovery')
    for name in (*FILE_EVIDENCE,*SERVICE_EVIDENCE):
        try:(store.journal.directory/name).lstat()
        except FileNotFoundError:continue
        raise SafetyError('Later installation evidence without durable staging intent')
    for name in sorted(set(FILES)|set(CONFIG_FILES)|RUNTIME_SIDECARS):
        try:(root.path/name).lstat()
        except FileNotFoundError:continue
        raise SafetyError('Occupied destination without durable staging intent')


class _Adapter:
    def __init__(self,store,value,revoke,verify):
        self.store=store;self.persisted=deepcopy(value);self.revoke=revoke;self.verify=verify
        self.services=None;self.files=None

    def current(self):
        if not self.store.journal or not self.store.journal.lock:
            raise SafetyError('Exclusive protected recovery lock is no longer held')
        if self.store.journal.load()!=self.persisted:
            raise SafetyError('Unfinished installation journal changed during recovery')

    def save(self,value):
        self.current();value=validate(value)
        if value['state']=='rolled_back_clients_closed':self.confirm_absence()
        self.store.journal.save(value)
        if self.store.journal.load()!=value:raise SafetyError('Recovery journal readback differs')
        self.persisted=deepcopy(value)

    def confirm_absence(self):
        self.current()
        if len(self.persisted['entries'])<3:_require_unstaged(self.store)
        if len(self.persisted['entries'])<=3:require_no_service_evidence(self.store.journal)
        root=self.store.directories['root']
        if not root.handle:raise SafetyError('Recovery installation root is no longer held')
        for name in sorted(set(FILES)|set(CONFIG_FILES)|RUNTIME_SIDECARS):
            try:(root.path/name).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Staged destination reappeared before recovery completion')
        if len(self.persisted['entries'])==4:
            keys=[v.key.value() for v in deny_rules([Identity('app',str(root.path/name)) for name in IMAGES])]
            boundary=BoundaryReceipt(self.store.journal,keys).load()
            if boundary is not None and boundary['state']!='removed':
                raise SafetyError('Initial boundary recovery is incomplete')
            reservation=ReservationReceipt.require_removed_if_present(self.store.journal)
            require_cleanup_absence(keys+([] if reservation is None else reservation['keys']),
                                    lambda:self.verify_closed(self.persisted['generation']))
        self.current()

    def revoke_owned(self,generation):
        # Still revoke after a failed intent write; never proceed to cleanup on
        # its uncertain durability. Transaction.recover enforces that ordering.
        self.revoke(generation)

    def verify_closed(self,generation):return self.verify(generation)

    def undo(self,step,generation):
        self.current()
        active=[e for e in self.persisted['entries'] if e['state']!='undone']
        if (self.persisted['state']!='recovering' or generation!=self.persisted['generation']
                or not active or active[-1]['step']!=step):
            raise SafetyError('Exact ordered recovery operation required')
        if step=='install_services':
            result=recover_service_step(self.store,generation,self.verify)
            if (not isinstance(result,dict) or result.get('services_recovered') is not True
                    or result.get('client_admission') is not False or result.get('journal_advanced') is not False):
                raise SafetyError('Service recovery completion is not confirmed')
            self.services=result
        elif step=='stage_protected_files':
            self.files=_rollback_installation_files(self.store,generation,self.verify)
        elif step=='inventory_backup':
            # Fresh-install inventory is read-only. Retain all audit metadata and
            # bootstrap directories; no historical network/backup restoration.
            pass
        else:raise SafetyError('Unsupported unfinished-install recovery operation')
        self.current()


def recover_unfinished_installation(store,generation,package_sha256,revoke_owned,verify_closed):
    if (not isinstance(store,Store) or not store.journal or not store.journal.lock
            or not callable(revoke_owned) or not callable(verify_closed)):
        raise SafetyError('Held protected store and scoped revocation callbacks required')
    value=store.journal.load()
    if value is None:raise SafetyError('Unfinished installation journal required')
    value=validate(value)
    if (value['generation']!=generation or value['package_sha256']!=package_sha256
            or value['state'] in TERMINAL or len(value['entries'])>4):
        raise SafetyError('Only the matching unfinished fresh service/file installation can be recovered')
    if len(value['entries'])<3:_require_unstaged(store)
    if len(value['entries'])<=3:require_no_service_evidence(store.journal)
    adapter=_Adapter(store,value,revoke_owned,verify_closed)
    result=Transaction.from_journal(adapter,value).recover()
    adapter.current()
    return dict(transaction=result,services=adapter.services,files=adapter.files,
                audit_evidence_retained=True,bootstrap_directories_retained=True,
                installed_version_uninstalled=False,client_admission=False)
