"""Stage held payload bytes only during the journalled file-copy step.

This is an internal installer primitive, not an installation entry point.
The adapter must authenticate the release and verify its closed client boundary
before recording stage_protected_files intent. No executables are started here.
"""
from .install_payload import PinnedPayload, FILES
from .install_store import Store, Directory
from .install_copy import _copy_pinned
from .safeio import SafetyError
from .install_receipts import Receipts, identity
from .windows_pin import PinnedFile


class Staged:
    def __init__(self):
        self.pins={}
    def close(self):
        for pin in reversed(list(self.pins.values())):pin.close()
        self.pins.clear()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def _stage_payload(store,payload,generation,verify_closed):
    if (not isinstance(store,Store) or not isinstance(payload,PinnedPayload) or not store.journal
            or not callable(verify_closed)):
        raise SafetyError('Held installer store and payload required')
    payload.report()
    state=store.journal.load()
    if (not state or state['generation']!=generation or state['package_sha256']!=payload.manifest_sha256
            or state['state']!='applying' or not state['entries']
            or state['entries'][-1]!={'step':'stage_protected_files','state':'intent'}):
        raise SafetyError('Payload staging does not match the durable installation intent')
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:
        raise SafetyError('Installation root is not held')
    # Check every parent before creating the first file. Paths come solely from
    # the compiled payload catalog, never from a package-provided destination.
    targets={}
    for name in sorted(FILES):
        parent,leaf=name.rsplit('/',1)
        held=store.directories.get(parent)
        if (not isinstance(held,Directory) or not held.handle
                or held.path!=root.path/parent):
            raise SafetyError('Payload parent is missing or does not match the held root')
        target=held.path/leaf
        try:target.lstat()
        except FileNotFoundError:pass
        else:raise SafetyError('Existing payload files require an ownership-aware upgrade')
        targets[name]=target
    result=Staged()
    receipts=Receipts(store.journal)
    def closed():
        if verify_closed(generation) is not True:
            raise SafetyError('Client boundary is not verified closed during payload staging')
    def created(handle):
        # Record the newly created empty file before a refusal can interrupt
        # the copy. Recovery must retain its exact identity, even with no bytes.
        receipts.created(handle)
        closed()
    closed()
    receipts.begin()
    try:
        for name,target in targets.items():
            closed()
            receipts.intent(name,payload.pins[name].sha256)
            result.pins[name]=_copy_pinned(payload.pins[name],target,on_created=created)
            receipts.complete(result.pins[name])
            closed()
        return result
    except BaseException:
        # Preserve partial files for the transaction's recovery operation.
        result.close();raise


def _inspect_staging(store,generation):
    """Read-only recovery evidence, never deletion authority or a network grant.

    An adapter must revoke and verify the client boundary before any rollback.
    Snapshot identities must be checked again on the actual mutation handle.
    """
    if not isinstance(store,Store) or not store.journal:
        raise SafetyError('Held installation store required')
    transaction=store.journal.load()
    if not transaction or transaction['generation']!=generation:
        raise SafetyError('Recovery generation differs')
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:raise SafetyError('Held root required')
    receipts=Receipts(store.journal).load()
    rows={} if receipts is None else {row['name']:row for row in receipts['files']}
    result=[]
    for name in sorted(FILES):
        parent,leaf=name.rsplit('/',1)
        held=store.directories.get(parent)
        if not isinstance(held,Directory) or not held.handle or held.path!=root.path/parent:
            raise SafetyError('Recovery parent differs')
        path=held.path/leaf;row=rows.get(name)
        try:path.lstat()
        except FileNotFoundError:status='missing'
        else:
            if row is None or row['identity'] is None:status='unrecorded'
            else:
                try:
                    with PinnedFile(path) as pin:
                        if identity(pin.api,pin.handle)!=row['identity']:status='replaced'
                        elif pin.sha256==row['sha256']:status='owned_complete'
                        elif row['state']=='created':status='owned_partial'
                        else:status='changed'
                except (OSError,SafetyError):status='unverifiable'
        result.append({'name':name,'status':status})
    return {'generation':generation,'files':result,'client_admission':False,
            'mutation_authorized':False}
