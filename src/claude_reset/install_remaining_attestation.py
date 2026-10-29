"""Hold remaining marked services and recheck an already absent reverse prefix.

Read-only evidence, never deletion authority or adoption of an unmarked service.
Pending deletion and non-prefix disappearance require a separate recovery path.
"""
from .install_service_attestation import HeldAttestation,NativeReader,RegistryReader,_records
from .install_scm_cleanup import _confirm_absence
from .install_recovery_records import recovery_records
from .safeio import SafetyError


class HeldRemainingAttestation(HeldAttestation):
    def __init__(self,store,generation,verify_closed):
        if not callable(verify_closed):raise SafetyError('Closed-boundary verifier required')
        self.store=store;self.generation=generation;self.verifier=verify_closed
        self.items=[];self.reader=None;self.registry=None;self.closed=False;self.absent=[]
        self.transaction,self.source,self.markers=recovery_records(store,generation,self.require_closed)
        try:
            self.require_closed();self.reader=NativeReader();self.registry=RegistryReader()
            for row in self.source['services']:
                handle=self.reader.open_optional(row['name'])
                if handle is None:
                    self.absent.append(row['name']);continue
                self.items.append((handle,None,dict(row['spec'])))
                if row['state']!='disabled':raise SafetyError('Interrupted creation reappeared after absence')
                if self.absent:raise SafetyError('Absent services are not a reverse cleanup prefix')
                key=self.registry.open(row['name'])
                self.items[-1]=(handle,key,dict(row['spec']))
            self.verify()
        except BaseException:self.close();raise

    def require_closed(self):
        if self.verifier(self.generation) is not True:
            raise SafetyError('Client boundary is not verified closed')
        return True

    def _verify_metadata(self):
        if self.closed:raise SafetyError('Remaining-service query handles are closed')
        self.require_closed();tx,source,markers=recovery_records(self.store,self.generation,self.require_closed)
        count=len(self.items)
        if (tx!=self.transaction or source!=self.source or markers!=self.markers
                or [spec for _,_,spec in self.items]!=[row['spec'] for row in source['services'][:count]]
                or self.absent!=[row['name'] for row in source['services'][count:]]):
            raise SafetyError('Remaining service generation or scope changed')
        if self.absent:_confirm_absence(list(reversed(self.absent)),self.require_closed)
        return tx

    def verify(self):
        result=super().verify()
        self.require_closed()
        result.update(observed_absent_services=list(self.absent),partial_recovery_evidence=True)
        return result
