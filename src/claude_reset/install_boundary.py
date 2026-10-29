"""Initial backend denies from held staged payload, no endpoints or client permits."""
from .install_store import Store,Directory
from .install_stage import Staged
from .install_receipts import Receipts,identity
from .windows_pin import PinnedFile
from .service_store import program_files
from .strict_wfp import Engine,Identity,deny_rules
from .safeio import SafetyError
from .install_boundary_receipts import BoundaryReceipt

IMAGES=('Backend/ClaudeResetBackend.exe','Runtime/ClaudeResetRuntime.exe',
        'Engine/engine.exe','Gateway/ClaudeResetGateway.exe')


def _install_backend_denies(store,staged,generation,verify_closed):
    """Caller must authenticate the release before entering installation intent.

    This step installs only backend-image denies. Client driver policy, listener
    reservations, signatures and actual closed-client verification remain other
    required parts of the installation; no permit is compiled here.
    """
    if not isinstance(store,Store) or not store.journal or not isinstance(staged,Staged):
        raise SafetyError('Held installation and staged payload required')
    tx=store.journal.load()
    if (not tx or tx['generation']!=generation or tx['state']!='applying' or not tx['entries']
            or tx['entries'][-1]!=dict(step='install_services',state='intent')):
        raise SafetyError('Initial boundary requires durable installation intent')
    rules=_held_rules(store,staged)
    keys=[rule.key.value() for rule in rules]
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    receipt=BoundaryReceipt(store.journal,keys);receipt.record('intent')
    with Engine() as engine:
        engine.install_new_denies(rules,lambda:verify_closed(generation))
    receipt.record('committed')
    return dict(deny_filters=len(keys),client_admission=False)


def _held_rules(store,staged):
    root=store.directories.get('root')
    if not isinstance(root,Directory) or not root.handle or root.path!=program_files()/'ClaudeReset':
        raise SafetyError('Fixed protected installation root required')
    records=Receipts(store.journal).load()
    if not records:raise SafetyError('Completed payload receipts required')
    rows={row['name']:row for row in records['files']};identities=[]
    for name in IMAGES:
        pin=staged.pins.get(name);row=rows.get(name)
        if (not isinstance(pin,PinnedFile) or not pin.handle or pin.path!=root.path/name
                or not row or row['state']!='complete' or row['sha256']!=pin.sha256
                or row['identity']!=identity(pin.api,pin.handle)):
            raise SafetyError('Backend deny target differs from staged payload')
        identities.append(Identity('app',str(pin.path)))
    return deny_rules(identities)


def _remove_backend_denies(store,staged,generation,verify_closed):
    from .install_inventory import services,SERVICES
    from .install_scm import require_vacant_registry_slot
    if not isinstance(store,Store) or not store.journal or not isinstance(staged,Staged):
        raise SafetyError('Held installation and staged payload required')
    try:(store.journal.directory/'boundary-reconciliation-log.json').lstat()
    except FileNotFoundError:pass
    else:raise SafetyError('Boundary attempt history requires its reconciliation protocol')
    tx=store.journal.load()
    if not tx or tx['generation']!=generation or tx['state']!='recovering':
        raise SafetyError('Boundary cleanup requires matching recovery generation')
    from .install_reservations import ReservationReceipt
    ReservationReceipt.require_removed_if_present(store.journal)
    rules=_held_rules(store,staged);keys=[rule.key.value() for rule in rules]
    def closed():
        if verify_closed(generation) is not True:return False
        rows=services()
        if (not isinstance(rows,list) or len(rows)!=len(SERVICES)
                or any(not isinstance(r,dict) for r in rows)
                or [r.get('name') for r in rows]!=list(SERVICES)
                or any(r.get('exists') is not False for r in rows)):
            raise SafetyError('All installation service slots must be absent before deny cleanup')
        for name in SERVICES:require_vacant_registry_slot(name)
        return True
    if not closed():raise SafetyError('Client boundary is not verified closed')
    receipt=BoundaryReceipt(store.journal,keys);receipt.recover_record('remove_intent')
    with Engine() as engine:engine.remove_recorded_denies(rules,closed)
    receipt.recover_record('removed')
    return dict(deny_filters_removed=len(keys),client_admission=False)
