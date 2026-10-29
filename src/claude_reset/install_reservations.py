"""Coordinate both owned listener reservations in one fresh WFP transaction."""
import ctypes as C
from ctypes import wintypes as W
from contextlib import ExitStack
from .gateway_reservation import Reservation,LAYERS,SUB
from .strict_wfp import Engine
from . import wfp
from .wfp_security import Descriptor
from .install_boundary_receipts import BoundaryReceipt
from .safeio import SafetyError


class ReservationReceipt(BoundaryReceipt):
    filename='reservation-receipt.json'


def _validate_pair(engine,views):
    if not isinstance(engine,Engine) or not engine.handle or engine.dynamic is not False or engine._transaction is not False:
        raise SafetyError('Idle persistent WFP parent session required')
    if (not isinstance(views,list) or len(views)!=2 or any(not isinstance(v,Reservation) for v in views)
            or [v.service for v in views]!=['ClaudeResetBackend','ClaudeResetGateway']
            or any(getattr(v,'_borrowed_engine',None) is not engine or v._borrowed_closed for v in views)
            or views[0].port==views[1].port):
        raise SafetyError('Exact distinct backend and gateway reservations required')


def _install_pair(engine,views,verify_closed):
    _validate_pair(engine,views)
    if verify_closed() is not True:raise SafetyError('Closed boundary and vacant ports required')
    if views[0].existing_sublayer():raise SafetyError('Existing reservation sublayer cannot be adopted')
    engine._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],engine.handle,0);engine._transaction=True
    try:
        views[0].ensure_sublayer()
        for view in views:
            for layer in LAYERS:
                for allow in (False,True):
                    if view.verified(layer,allow):raise SafetyError('Reservation key is already occupied')
                    f,keep=view.native(layer,allow);identifier=C.c_uint64()
                    with Descriptor() as security:
                        engine._call('FwpmFilterAdd0',[W.HANDLE,C.POINTER(wfp.FILTER),C.c_void_p,C.POINTER(C.c_uint64)],
                            engine.handle,C.byref(f),security.pointer,C.byref(identifier))
                    if not view.verified(layer,allow):raise SafetyError('New listener reservation readback failed')
        if verify_closed() is not True:raise SafetyError('Listener boundary changed before commit')
        engine._call('FwpmTransactionCommit0',[W.HANDLE],engine.handle);engine._transaction=False
    except BaseException:
        engine._call('FwpmTransactionAbort0',[W.HANDLE],engine.handle);engine._transaction=False;raise


def _remove_pair(engine,views,verify_closed):
    _validate_pair(engine,views)
    filters=[view.native(layer,allow)[0] for view in views for layer in LAYERS for allow in (False,True)]
    keys={f.filterKey.value() for f in filters}
    def exact():
        if (not views[0].existing_sublayer() or views[0].own_keys()!=keys
                or not all(v.verified(layer,allow) for v in views for layer in LAYERS for allow in (False,True))):
            raise SafetyError('Recorded reservations changed or have additional filters')
    if verify_closed() is not True:raise SafetyError('Closed listener boundary required')
    exact()
    engine._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],engine.handle,0);engine._transaction=True
    try:
        exact()
        for f in filters:
            engine._call('FwpmFilterDeleteByKey0',[W.HANDLE,C.POINTER(wfp.GUID)],engine.handle,C.byref(f.filterKey))
        engine._call('FwpmSubLayerDeleteByKey0',[W.HANDLE,C.POINTER(wfp.GUID)],engine.handle,C.byref(SUB))
        if views[0].existing_sublayer() or any(v.verified(layer,allow) for v in views for layer in LAYERS for allow in (False,True)):
            raise SafetyError('Listener reservation removal readback failed')
        if verify_closed() is not True:raise SafetyError('Listener boundary changed before removal commit')
        engine._call('FwpmTransactionCommit0',[W.HANDLE],engine.handle);engine._transaction=False
    except BaseException:
        engine._call('FwpmTransactionAbort0',[W.HANDLE],engine.handle);engine._transaction=False;raise


def _installation_inputs(store,staged,configuration,generation,held,*,attested=False,runtime_signatures=None):
    from .install_store import Store
    from .install_stage import Staged
    from .install_scm import HeldRegistrations,SERVICES,validate_snapshot,validate_spec
    from .install_service_receipts import ServiceReceipts
    from .install_binding_receipts import BindingReceipt
    from .install_config_stage import ConfigurationReceipts
    from .install_receipts import identity
    from .install_boundary import _held_rules
    from .windows_pin import PinnedFile
    from .backend_spec import decode
    from .install_service_attestation import HeldAttestation
    if (not isinstance(store,Store) or not store.journal or not isinstance(staged,Staged)
            or not isinstance(configuration,Staged)
            or not isinstance(held,HeldAttestation if attested else HeldRegistrations)):
        raise SafetyError('Held installation, payload, configuration and services required')
    tx=store.journal.load()
    if not tx or tx['generation']!=generation:raise SafetyError('Reservation generation differs')
    if attested:
        from .install_service_step import _require_complete_staging
        if held.store is not store or held.generation!=generation:
            raise SafetyError('Attested reservation recovery belongs to another store')
        _require_complete_staging(store,staged,configuration,runtime_signatures)
    rules=_held_rules(store,staged);root=store.directories['root'].path
    config_rows=ConfigurationReceipts(store.journal).load()
    if not config_rows:raise SafetyError('Private configuration receipts required')
    for row in config_rows['files']:
        pin=configuration.pins.get(row['name'])
        if (not isinstance(pin,PinnedFile) or not pin.handle or pin.path!=root/row['name']
                or row['state']!='complete' or row['sha256']!=pin.sha256
                or row['identity']!=identity(pin.api,pin.handle)):
            raise SafetyError('Reservation configuration changed after staging')
    if len(config_rows['files'])!=3:raise SafetyError('Complete private configuration required')
    spec=decode(configuration.pins['Backend/backend.json'].data)
    for field,path in [('engine_sha256','Engine/engine.exe'),('runtime_sha256','Runtime/ClaudeResetRuntime.exe'),
                       ('gateway_sha256','Gateway/ClaudeResetGateway.exe')]:
        if spec[field]!=staged.pins[path].sha256:raise SafetyError('Reservation images differ from backend specification')
    policy=BindingReceipt(store.journal,configuration.pins['Policy/Sandboxie.ini']).load()
    if policy is None or policy['state']!='bound':raise SafetyError('Driver policy is not bound')
    boundary=BoundaryReceipt(store.journal,[rule.key.value() for rule in rules]).load()
    if boundary is None or boundary['state']!='committed':raise SafetyError('Initial deny boundary is not committed')
    def services_closed():
        records=ServiceReceipts(store.journal).load()
        if (not records or len(records['services'])!=4 or any(r['state']!='disabled' for r in records['services'])
                or len(held.items)!=4 or [spec['name'] for _,_,spec in held.items]!=list(SERVICES)):
            raise SafetyError('Four held disabled registrations required')
        if attested:
            held.verify()
            if [expected for _,_,expected in held.items]!=[record['spec'] for record in records['services']]:
                raise SafetyError('Attested service records differ')
            return True
        for (native,handle,expected),record in zip(held.items,records['services']):
            validate_spec(expected)
            if expected!=record['spec']:raise SafetyError('Held registration differs from durable receipt')
            native.require_created(handle,expected['name']);validate_snapshot(expected,native.snapshot(handle,expected))
        return True
    services_closed()
    return root,spec,rules,services_closed


def _install_initial_reservations(store,staged,configuration,generation,held,verify_closed):
    return _initial_reservations(store,staged,configuration,generation,held,verify_closed,removing=False)


def _remove_initial_reservations(store,staged,configuration,generation,held,verify_closed):
    return _initial_reservations(store,staged,configuration,generation,held,verify_closed,removing=True)


def _remove_attested_initial_reservations(store,staged,configuration,generation,held,verify_closed,*,runtime_signatures=None):
    """Removal only, using completed protected generation markers, never adoption."""
    return _initial_reservations(store,staged,configuration,generation,held,verify_closed,
                                 removing=True,attested=True,runtime_signatures=runtime_signatures)


def _initial_reservations(store,staged,configuration,generation,held,verify_closed,*,removing,attested=False,runtime_signatures=None):
    from .install_service_receipts import ServiceReceipts
    from .service_store import verify_image
    from .tcp_inventory import listeners
    if attested and not removing:raise SafetyError('Reopened service evidence cannot install reservations')
    root,spec,rules,services_closed=_installation_inputs(store,staged,configuration,generation,held,
        attested=attested,runtime_signatures=runtime_signatures)
    try:(store.journal.directory/'reservation-reconciliation-log.json').lstat()
    except FileNotFoundError:pass
    else:raise SafetyError('Reservation attempt history requires its reconciliation protocol')
    tx=ServiceReceipts(store.journal).transaction(writing=not removing)
    if removing and tx['state']!='recovering':raise SafetyError('Reservation cleanup requires recovery')
    targets=[(root/'Engine/engine.exe','ClaudeResetBackend',spec['backend_port']),
             (root/'Gateway/ClaudeResetGateway.exe','ClaudeResetGateway',spec['gateway_port'])]
    for path,service,_ in targets:verify_image(path,service)
    with Engine() as engine,ExitStack() as stack:
        views=[stack.enter_context(Reservation(path,service,port,engine=engine)) for path,service,port in targets]
        def closed():
            if verify_closed(generation) is not True:return False
            services_closed()
            if listeners([port for _,_,port in targets]):raise SafetyError('Dedicated reservation ports are occupied')
            if not engine.existing_sublayer() or not all(engine.exists_verified(rule) for rule in rules):
                raise SafetyError('Initial backend denies changed before reservation')
            return True
        if not closed():raise SafetyError('Reservation requires closed clients')
        keys=[view.native(layer,allow)[0].filterKey.value() for view in views for layer in LAYERS for allow in (False,True)]
        receipt=ReservationReceipt(store.journal,keys)
        if removing:
            receipt.recover_record('remove_intent')
            _remove_pair(engine,views,closed)
            receipt.recover_record('removed')
        else:
            receipt.record('intent')
            _install_pair(engine,views,closed)
            receipt.record('committed')
    return {('reservation_filters_removed' if removing else 'reservation_filters'):16,'client_admission':False}
