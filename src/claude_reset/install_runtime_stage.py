"""Journal owned runtime sidecars; no key installation, services or network grants."""
from .install_runtime_signature import PinnedRuntimeSignatures,RUNTIME_SIDECARS
from .install_payload import PinnedPayload
from .install_store import Store,Directory
from .install_stage import Staged
from .install_copy import _copy_pinned
from .install_receipts import Receipts
from .safeio import SafetyError


class RuntimeSignatureReceipts(Receipts):
    names=RUNTIME_SIDECARS
    filename='runtime-signature-receipts.json'


def _stage_runtime_signatures(store,payload,source,generation,verify_closed):
    if (not isinstance(store,Store) or not store.journal or not isinstance(payload,PinnedPayload)
            or not isinstance(source,PinnedRuntimeSignatures) or not callable(verify_closed)):
        raise SafetyError('Held runtime signature inputs and installation store required')
    tx=store.journal.load()
    if (not tx or tx['generation']!=generation or tx['package_sha256']!=payload.manifest_sha256
            or tx['state']!='applying' or not tx['entries']
            or tx['entries'][-1]!={'step':'stage_protected_files','state':'intent'}):
        raise SafetyError('Runtime signature staging requires exact durable file intent')
    source.inspect(payload)
    pins={name+'.sig':pin for name,pin in source.signatures.items()}
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:raise SafetyError('Held installation root required')
    targets={}
    for name in sorted(RUNTIME_SIDECARS):
        parent,leaf=name.rsplit('/',1);held=store.directories.get(parent)
        if not isinstance(held,Directory) or not held.handle or held.path!=root.path/parent:
            raise SafetyError('Runtime signature parent is not held')
        path=held.path/leaf
        try:path.lstat()
        except FileNotFoundError:pass
        else:raise SafetyError('Existing runtime signatures require separate ownership recovery')
        targets[name]=path
    def closed():
        if store.journal.load()!=tx:raise SafetyError('Runtime signature transaction changed')
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    receipts=RuntimeSignatureReceipts(store.journal);result=Staged()
    def created(handle):
        receipts.created(handle);closed()
    closed();receipts.begin()
    try:
        for name,path in targets.items():
            closed();receipts.intent(name,pins[name].sha256)
            result.pins[name]=_copy_pinned(pins[name],path,on_created=created)
            receipts.complete(result.pins[name]);closed()
        source.inspect(payload)
        closed()
        return result
    except BaseException:
        result.close();raise
