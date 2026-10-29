"""Query-only complete pair observation before any service cleanup."""
from ctypes import wintypes as W
from contextlib import ExitStack,contextmanager
from .install_reservations import _validate_pair,_installation_inputs,ReservationReceipt
from .install_recovery_inputs import RecoveryInputs
from .gateway_reservation import Reservation,LAYERS
from .strict_wfp import Engine
from .install_boundary_observation import READ_ONLY
from .service_store import verify_image,verify_paths
from .tcp_inventory import listeners
from .safeio import SafetyError


def observe_pair(engine,views,verify_closed):
    _validate_pair(engine,views)
    keys=[v.native(layer,allow)[0].filterKey.value() for v in views for layer in LAYERS for allow in (False,True)]
    if len(keys)!=16 or len(set(keys))!=16:raise SafetyError('Exact distinct reservation identities required')
    def closed():
        if not callable(verify_closed) or verify_closed() is not True:raise SafetyError('Closed listener boundary required')
    closed();engine._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],engine.handle,READ_ONLY)
    engine._transaction=True
    try:
        closed();layer=views[0].existing_sublayer();actual=views[0].own_keys()
        present=[v.verified(layer,allow) for v in views for layer in LAYERS for allow in (False,True)]
        if type(layer) is not bool or type(actual) is not set or any(type(v) is not bool for v in present):
            raise SafetyError('Incomplete reservation observation')
        if layer and actual==set(keys) and all(present):state='present'
        elif not layer and not actual and not any(present):state='absent'
        else:raise SafetyError('Reservation pair is partial or has additional objects')
        closed()
    finally:
        engine._call('FwpmTransactionAbort0',[W.HANDLE],engine.handle);engine._transaction=False
    closed()
    return dict(keys=keys,state=state,transaction_consistent=True,settings_changed=False,client_admission=False)


@contextmanager
def reservation_recovery_view(store,inputs,held,generation,verify_closed):
    if not isinstance(inputs,RecoveryInputs) or not callable(verify_closed):
        raise SafetyError('Held recovery inputs and closed-boundary verifier required')
    inputs.report()
    root,spec,rules,services_closed=_installation_inputs(store,inputs.payload,inputs.configuration,generation,held,attested=True,
            runtime_signatures=inputs.runtime_signatures)
    transaction=store.journal.load()
    active=[e for e in transaction['entries'] if e['state']!='undone']
    if transaction['state']!='recovering' or not active or active[-1]['step']!='install_services':
        raise SafetyError('Reservation observation requires ordered recovery')
    targets=[(root/'Engine/engine.exe','ClaudeResetBackend',spec['backend_port']),
             (root/'Gateway/ClaudeResetGateway.exe','ClaudeResetGateway',spec['gateway_port'])]
    for path,service,_ in targets:verify_image(path,service)
    with Engine() as engine,ExitStack() as stack:
        views=[stack.enter_context(Reservation(path,service,port,engine=engine)) for path,service,port in targets]
        keys=[v.native(layer,allow)[0].filterKey.value() for v in views for layer in LAYERS for allow in (False,True)]
        receipt=ReservationReceipt(store.journal,keys);before=receipt.load()
        if before is None:raise SafetyError('Durable reservation intent required')
        metadata=[receipt.path,store.journal.directory/'policy-binding-receipt.json',
                  store.journal.directory/'boundary-receipt.json']
        def closed():
            if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
            inputs.report()
            current=_installation_inputs(store,inputs.payload,inputs.configuration,generation,held,attested=True,
            runtime_signatures=inputs.runtime_signatures)
            if current[:3]!=(root,spec,rules):raise SafetyError('Reservation installation inputs changed')
            verify_paths(metadata,[])
            if store.journal.load()!=transaction or receipt.load()!=before:
                raise SafetyError('Reservation recovery metadata changed')
            if listeners([port for _,_,port in targets]):raise SafetyError('Dedicated reservation ports are occupied')
            if (not engine.existing_sublayer() or engine.own_keys()!={r.key.value() for r in rules}
                    or not all(engine.exists_verified(rule) for rule in rules)):
                raise SafetyError('Exact initial backend denies must remain present')
            return True
        closed()
        yield engine,views,receipt,before,closed
        closed()
    inputs.report();current=_installation_inputs(store,inputs.payload,inputs.configuration,generation,held,attested=True,
            runtime_signatures=inputs.runtime_signatures)
    verify_paths(metadata,[])
    if (current[:3]!=(root,spec,rules) or store.journal.load()!=transaction or receipt.load()!=before
            or verify_closed(generation) is not True):
        raise SafetyError('Reservation evidence changed while closing the query session')


def inspect_reservation_pair(store,inputs,held,generation,verify_closed):
    with reservation_recovery_view(store,inputs,held,generation,verify_closed) as (engine,views,receipt,before,closed):
        observed=observe_pair(engine,views,closed)
    return receipt,before,observed


def reconcile_reservation_absence(store,inputs,held,generation,verify_closed):
    receipt,before,observed=inspect_reservation_pair(store,inputs,held,generation,verify_closed)
    if observed['state']!='absent':raise SafetyError('Reservations remain present; no deletion replay')
    receipt.confirm_absent(observed)
    if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
    held.verify()
    return dict(reservations_absent=True,deletion_replayed=False,client_admission=False)
