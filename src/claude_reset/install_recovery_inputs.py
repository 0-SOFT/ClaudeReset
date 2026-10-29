"""Re-pin complete protected staging for recovery without writing any files."""
from .install_store import Store,Directory
from .install_stage import Staged
from .install_receipts import Receipts,identity
from .install_config_stage import ConfigurationReceipts
from .install_runtime_stage import RuntimeSignatureReceipts
from .install_service_step import _require_complete_staging
from .service_store import program_files,verify_paths
from .windows_pin import PinnedFile
from .safeio import SafetyError


class RecoveryInputs:
    def __init__(self,store,generation):
        self.payload=Staged();self.configuration=Staged();self.closed=False
        self.runtime_signatures=None
        try:
            if not isinstance(store,Store) or not store.journal or not store.journal.lock:
                raise SafetyError('Held recovery store required')
            tx=store.journal.load()
            active=[] if tx is None else [row for row in tx['entries'] if row['state']!='undone']
            if (not tx or tx['generation']!=generation or tx['state'] not in ('recovering','recovery_required')
                    or not active or active[-1]['step']!='install_services'):
                raise SafetyError('Complete inputs require the ordered service recovery step')
            root=store.directories.get('root');installer=store.directories.get('Installer')
            if (not isinstance(root,Directory) or not root.handle or root.path!=program_files()/'ClaudeReset'
                    or not isinstance(installer,Directory) or not installer.handle or installer.path!=root.path/'Installer'):
                raise SafetyError('Fixed held protected recovery directories required')
            metadata=[installer.path/name for name in ('install.lock','install-journal.json',
                      Receipts.filename,ConfigurationReceipts.filename)]
            verify_paths([root.path,installer.path,*metadata],[root.path,installer.path])
            groups=[(self.payload,Receipts,268435456),(self.configuration,ConfigurationReceipts,65536)]
            signature_path=installer.path/RuntimeSignatureReceipts.filename
            try:signature_path.lstat()
            except FileNotFoundError:pass
            else:
                verify_paths([signature_path],[])
                self.runtime_signatures=Staged()
                groups.append((self.runtime_signatures,RuntimeSignatureReceipts,64))
            for target,kind,limit in groups:
                record=kind(store.journal).load()
                if not record or len(record['files'])!=len(kind.names):
                    raise SafetyError('Complete staging receipts required for service recovery')
                for row in record['files']:
                    name=row['name'];parent=name.rsplit('/',1)[0];held=store.directories.get(parent)
                    if (row['state']!='complete' or not isinstance(held,Directory) or not held.handle
                            or held.path!=root.path/parent):
                        raise SafetyError('Complete held staging parent required')
                    path=root.path/name
                    verify_paths([held.path,path],[held.path])
                    pin=PinnedFile(path,expected_sha256=row['sha256'],limit=limit)
                    target.pins[name]=pin
                    if identity(pin.api,pin.handle)!=row['identity']:
                        raise SafetyError('Recovery input was replaced after staging')
            _require_complete_staging(store,self.payload,self.configuration,self.runtime_signatures)
            if store.journal.load()!=tx:raise SafetyError('Recovery generation changed while opening inputs')
        except BaseException:self.close();raise

    def report(self):
        if (self.closed or len(self.payload.pins)!=len(Receipts.names)
                or len(self.configuration.pins)!=len(ConfigurationReceipts.names)
                or any(not pin.handle for pin in [*self.payload.pins.values(),*self.configuration.pins.values()])):
            raise SafetyError('Recovery inputs are no longer held')
        result=dict(payload_files=23,configuration_files=3,settings_changed=False,
                    may_delete_services=False,client_admission=False)
        if self.runtime_signatures is not None:
            if (set(self.runtime_signatures.pins)!=RuntimeSignatureReceipts.names
                    or any(not pin.handle for pin in self.runtime_signatures.pins.values())):
                raise SafetyError('Runtime signature recovery inputs are no longer held')
            result['runtime_signature_files']=len(self.runtime_signatures.pins)
        return result
    def close(self):
        self.closed=True
        if self.runtime_signatures is not None:self.runtime_signatures.close()
        self.configuration.close();self.payload.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
