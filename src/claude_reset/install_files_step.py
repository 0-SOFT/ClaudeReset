"""Hold payload, private configuration and optional runtime sidecars for later steps.

The enclosing adapter must authenticate the release and provide a real closed
boundary verifier. No public installation/elevation or client launch is exposed.
"""
from .backend_spec import document
from .broker_policy import inspect_local_roots
from .install_configuration import compile_configuration,FILES as CONFIGURATION_FILES
from .install_config_stage import _stage_configuration
from .install_payload import PinnedPayload, catalog,FILES
from .install_stage import _stage_payload
from .install_store import Store,Directory
from .install_rollback import _rollback_installation_files
from .install_runtime_signature import PinnedRuntimeSignatures,RUNTIME_SIDECARS
from .install_runtime_stage import RuntimeSignatureReceipts,_stage_runtime_signatures
from .safeio import SafetyError


class ProtectedFilesStep:
    def __init__(self,store,source,generation,verify_closed):
        if (not isinstance(store,Store) or not isinstance(source,PinnedPayload)
                or not callable(verify_closed)):
            raise SafetyError('Held store, payload and closed-boundary verifier required')
        self.store,self.source,self.generation,self.verifier=store,source,generation,verify_closed
        self.payload=None;self.configuration=None;self.attempted=False;self.closed=False
        self.runtime_signatures=None
        self._context()

    def _context(self,*,recovering=False):
        if self.closed or not self.store.journal or not self.store.journal.lock:
            raise SafetyError('Open files step and exclusive installation lock required')
        tx=self.store.journal.load()
        if (not tx or tx['generation']!=self.generation
                or tx['package_sha256']!=self.source.manifest_sha256):
            raise SafetyError('Files step does not match the installation generation')
        if recovering:
            stage=next((i for i,e in enumerate(tx['entries']) if e['step']=='stage_protected_files'),None)
            if (tx['state']!='recovering' or stage is None or tx['entries'][stage]['state']=='undone'
                    or any(e['state']!='undone' for e in tx['entries'][stage+1:])):
                raise SafetyError('Dependent steps must be recovered before staged files')
        elif (tx['state']!='applying' or not tx['entries']
                or tx['entries'][-1]!={'step':'stage_protected_files','state':'intent'}):
            raise SafetyError('Exact protected-files intent required')

    def verify_closed(self):
        if self.verifier(self.generation) is not True:
            raise SafetyError('Client boundary is not verified closed')

    def apply(self,spec_bytes,engine_bytes,local_roots,*,runtime_signatures=None):
        self._context()
        if self.attempted:raise SafetyError('Protected file staging cannot be replayed')
        self.source.report()
        if runtime_signatures is not None:
            if not isinstance(runtime_signatures,PinnedRuntimeSignatures):
                raise SafetyError('Held exact runtime signatures required')
            runtime_signatures.inspect(self.source)
        for name in ('stage-receipts.json','configuration-receipts.json',RuntimeSignatureReceipts.filename):
            try:(self.store.journal.directory/name).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Existing file evidence requires separate recovery')
        # Validate the entire private input before any payload file is created.
        roots=inspect_local_roots(local_roots)
        compile_configuration(spec_bytes,engine_bytes,
                              catalog(document(self.source.manifest.data)['payload']),roots)
        root=self.store.directories.get('root')
        if not isinstance(root,Directory) or not root.handle:raise SafetyError('Held root required')
        # Check private files too before starting payload copies. A conflict
        # must not strand a new partial payload beside another owner's policy.
        for name in sorted(set(FILES)|set(CONFIGURATION_FILES)|RUNTIME_SIDECARS):
            parent,leaf=name.rsplit('/',1);held=self.store.directories.get(parent)
            if (not isinstance(held,Directory) or not held.handle or held.path!=root.path/parent):
                raise SafetyError('All staging parents must match the held installation root')
            try:(held.path/leaf).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Occupied staging destination requires a separate ownership transaction')
        self.verify_closed();self.attempted=True
        self.payload=_stage_payload(self.store,self.source,self.generation,self.verifier)
        self.configuration=_stage_configuration(self.store,self.source,self.generation,
                                                spec_bytes,engine_bytes,roots,self.verifier)
        if runtime_signatures is not None:
            self.runtime_signatures=_stage_runtime_signatures(self.store,self.source,runtime_signatures,
                                                             self.generation,self.verifier)
        self.verify_closed()
        result=dict(payload_files=len(self.payload.pins),configuration_files=len(self.configuration.pins),
                    client_admission=False)
        if self.runtime_signatures is not None:result['runtime_signature_files']=len(self.runtime_signatures.pins)
        return result

    def _release_pins(self):
        for name in ('runtime_signatures','configuration','payload'):
            value=getattr(self,name)
            if value is not None:value.close();setattr(self,name,None)

    def recover(self):
        self._context(recovering=True)
        if not self.attempted:raise SafetyError('This object has no staging attempt to recover')
        self.verify_closed()
        # Journal ordering is checked before releasing file pins. The removal
        # primitive also checks WFP receipts and exact file ownership.
        self._release_pins()
        return _rollback_installation_files(self.store,self.generation,self.verifier)

    def close(self):
        self.closed=True
        self._release_pins()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
