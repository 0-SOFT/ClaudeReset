"""Query-only evidence for the last interrupted CreateService operation.

No completion promotion, service/key mutation, start, deletion or client grant.
The atomic display binding is mandatory for every present pending service.
"""
from .install_service_attestation import NativeReader,RegistryReader
from .install_service_receipts import ServiceReceipts
from .install_service_markers import MarkerReceipts,VALUE,encoded,creation_display,validate_creation_snapshot
from .install_creation_security import validate_pending_service,validate_pending_key
from .install_registry import validate_security
from .install_store import Store,Directory
from .install_scm_cleanup import _confirm_absence
from .service_store import program_files,verify_paths
from .safeio import SafetyError


def creation_records(store,generation):
    if not isinstance(store,Store) or not store.journal or not store.journal.lock:
        raise SafetyError('Held protected creation recovery store required')
    tx=ServiceReceipts(store.journal).transaction()
    active=[row for row in tx['entries'] if row['state']!='undone']
    if tx['generation']!=generation or tx['state']!='recovering' or not active or active[-1]['step']!='install_services':
        raise SafetyError('Pending creation requires ordered service recovery')
    root=store.directories.get('root');installer=store.directories.get('Installer')
    if (not isinstance(root,Directory) or not root.handle or root.path!=program_files()/'ClaudeReset'
            or not isinstance(installer,Directory) or not installer.handle or installer.path!=root.path/'Installer'):
        raise SafetyError('Fixed held protected creation directories required')
    paths=[installer.path/name for name in ('install.lock','install-journal.json','service-receipts.json')]
    path=installer.path/MarkerReceipts.filename
    try:path.lstat();paths.append(path)
    except FileNotFoundError:pass
    verify_paths([root.path,installer.path,*paths],[root.path,installer.path])
    source=ServiceReceipts(store.journal).load();markers=MarkerReceipts(store.journal).load()
    rows=[] if markers is None else markers['services']
    if (not source or not source['services'] or source['services'][-1]['state']!='intent'
            or len(rows) not in (len(source['services'])-1,len(source['services']))
            or any(row['state']!='bound' for row in rows[:len(source['services'])-1])):
        raise SafetyError('Only the last creation may have incomplete ownership evidence')
    return tx,source,markers


class HeldPendingCreation:
    def __init__(self,store,generation,verify_closed):
        if not callable(verify_closed):raise SafetyError('Closed client-boundary verifier required')
        self.store,self.generation,self.verifier=store,generation,verify_closed
        self.reader=None;self.registry=None;self.handle=None;self.key=None;self.closed=False
        self.transaction,self.source,self.markers=creation_records(store,generation)
        self.spec=self.source['services'][-1]['spec']
        rows=[] if self.markers is None else self.markers['services']
        self.marker=rows[-1] if len(rows)==len(self.source['services']) else None
        try:
            self.require_closed();self.reader=NativeReader();self.registry=RegistryReader()
            self.handle=self.reader.open_optional(self.spec['name'])
            if self.handle is not None:
                if self.marker is None:raise SafetyError('Present service has no durable pre-creation binding')
                self.key=self.registry.open(self.spec['name'])
            self.verify()
        except BaseException:self.close();raise

    def require_closed(self):
        if self.verifier(self.generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True

    def verify(self):
        if self.closed:raise SafetyError('Pending creation query handles are closed')
        self.require_closed()
        if creation_records(self.store,self.generation)!=(self.transaction,self.source,self.markers):
            raise SafetyError('Pending creation metadata changed')
        if self.handle is None:
            _confirm_absence([self.spec['name']],self.require_closed)
        else:
            marker=self.marker['marker'];bound=self.marker['state']=='bound'
            def snapshot():
                actual=self.reader.snapshot(self.handle,self.spec)
                if bound:validate_creation_snapshot(marker,self.spec,actual)
                else:
                    validate_pending_service(self.spec,actual)
                    if actual.get('display')!=creation_display(marker,self.spec):
                        raise SafetyError('Pending creation display binding differs')
            snapshot()
            if self.registry.value(self.key,'SymbolicLinkValue') is not None:
                raise SafetyError('Pending service key is a symbolic link')
            security=self.registry.security(self.key)
            if bound:validate_security(security)
            else:validate_pending_key(security)
            value=self.registry.value(self.key,VALUE)
            expected=(3,encoded(marker,self.spec,self.generation,self.transaction['package_sha256']))
            if (bound or value is not None) and value!=expected:
                raise SafetyError('Pending service registry binding differs')
            snapshot()
        self.require_closed()
        return dict(service=self.spec['name'],service_present=self.handle is not None,
                    creation_binding_verified=self.handle is not None,
                    pending_creation_attested=True,may_delete=False,client_admission=False)

    def close(self):
        self.closed=True;failure=None
        if self.key is not None:
            try:self.registry.close_key(self.key)
            except Exception as error:failure=error
            else:self.key=None
        if self.handle is not None:
            try:self.reader.release(self.handle)
            except Exception as error:
                if failure is None:failure=error
            else:self.handle=None
        if self.reader is not None:
            try:self.reader.close()
            except Exception as error:
                if failure is None:failure=error
            else:
                if self.handle is None and self.key is None:self.reader=None
        if failure is not None:raise failure
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
