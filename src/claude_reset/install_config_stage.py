"""Stage compiled private configuration in new protected files; never reload it."""
import hashlib
import msvcrt
import os
from .install_configuration import compile_configuration,FILES
from .install_receipts import Receipts
from .install_store import Store,Directory
from .install_payload import PinnedPayload,catalog
from .install_stage import Staged
from .backend_spec import document
from .safeio import SafetyError
from .windows_pin import PinnedFile
from .broker_policy import inspect_local_roots


class ConfigurationReceipts(Receipts):
    names=FILES
    filename='configuration-receipts.json'


def _stage_configuration(store,payload,generation,spec_bytes,engine_bytes,local_roots,verify_closed):
    if not isinstance(store,Store) or not isinstance(payload,PinnedPayload) or not store.journal:
        raise SafetyError('Held store and release payload required')
    payload.report()
    transaction=store.journal.load()
    if (not transaction or transaction['generation']!=generation
            or transaction['package_sha256']!=payload.manifest_sha256
            or transaction['state']!='applying' or not transaction['entries']
            or transaction['entries'][-1]!={'step':'stage_protected_files','state':'intent'}):
        raise SafetyError('Private staging requires matching durable intent')
    value=catalog(document(payload.manifest.data)['payload'])
    plan=compile_configuration(spec_bytes,engine_bytes,value,inspect_local_roots(local_roots))
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle:raise SafetyError('Held root required')
    targets={}
    for name,data in plan.files():
        parent,leaf=name.rsplit('/',1);held=store.directories.get(parent)
        if not isinstance(held,Directory) or not held.handle or held.path!=root.path/parent:
            raise SafetyError('Configuration parent is not held')
        path=held.path/leaf
        try:path.lstat()
        except FileNotFoundError:pass
        else:raise SafetyError('Existing configuration requires a separate update transaction')
        targets[name]=(path,data)
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    receipts=ConfigurationReceipts(store.journal);receipts.begin();result=Staged()
    try:
        for name,(path,data) in sorted(targets.items()):
            if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
            digest=hashlib.sha256(data).hexdigest();receipts.intent(name,digest)
            with path.open('xb') as stream:
                receipts.created(msvcrt.get_osfhandle(stream.fileno()))
                if verify_closed(generation) is not True:
                    raise SafetyError('Client boundary is not verified closed before configuration write')
                if stream.write(data)!=len(data):raise SafetyError('Incomplete private configuration write')
                stream.flush();os.fsync(stream.fileno())
            pin=PinnedFile(path,expected_sha256=digest,limit=max(1,len(data)))
            result.pins[name]=pin;receipts.complete(pin)
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return result
    except BaseException:result.close();raise
