"""Read back the complete initial WFP boundary before service-step completion.

Services remain disabled. This is not installed driver or client acceptance.
The two WFP sublayers are checked in one read-only transaction; SCM, file and
registry observations are sequential, not atomic with BFE.
"""
from contextlib import ExitStack
from .safeio import SafetyError
from .install_reservations import _installation_inputs,ReservationReceipt
from .install_reservation_observation import observe_pair
from .gateway_reservation import Reservation,LAYERS
from .strict_wfp import Engine
from .install_boundary_receipts import BoundaryReceipt
from .install_created_verification import verify_created_bindings
from .service_store import verify_image
from .tcp_inventory import listeners


def verify_prepared_boundary(store,payload,configuration,generation,held,verify_closed,runtime_signatures=None):
    from .install_service_step import _require_complete_staging
    _require_complete_staging(store,payload,configuration,runtime_signatures)
    root,spec,rules,services_closed=_installation_inputs(store,payload,configuration,generation,held)
    transaction=store.journal.load()
    if (transaction['state']!='applying' or transaction['entries'][-1]!=dict(step='install_services',state='intent')):
        raise SafetyError('Final initial-boundary verification requires registration intent')
    targets=[(root/'Engine/engine.exe','ClaudeResetBackend',spec['backend_port']),
             (root/'Gateway/ClaudeResetGateway.exe','ClaudeResetGateway',spec['gateway_port'])]
    for path,name,_ in targets:verify_image(path,name)
    deny=BoundaryReceipt(store.journal,[rule.key.value() for rule in rules]);deny_before=deny.load()
    if deny_before is None or deny_before['state']!='committed':raise SafetyError('Committed initial denies required')
    def stable():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        _require_complete_staging(store,payload,configuration,runtime_signatures)
        if store.journal.load()!=transaction or deny.load()!=deny_before:
            raise SafetyError('Prepared installation evidence changed')
        services_closed()
        verify_created_bindings(store,generation,held,configuration.pins['Policy/Sandboxie.ini'],verify_closed)
        occupied=listeners([port for _,_,port in targets])
        if type(occupied) is not list or occupied:
            raise SafetyError('Prepared listener ports are occupied or unverified')
        return True
    stable()
    with Engine() as engine,ExitStack() as stack:
        views=[stack.enter_context(Reservation(path,name,port,engine=engine)) for path,name,port in targets]
        keys=[v.native(layer,allow)[0].filterKey.value() for v in views for layer in LAYERS for allow in (False,True)]
        receipt=ReservationReceipt(store.journal,keys);before=receipt.load()
        if before is None or before['state']!='committed':raise SafetyError('Committed exact listener reservations required')
        def closed():
            stable()
            if receipt.load()!=before:raise SafetyError('Prepared listener evidence changed')
            if (engine.existing_sublayer() is not True or engine.own_keys()!=set(deny.keys)
                    or not all(engine.exists_verified(rule) is True for rule in rules)):
                raise SafetyError('Prepared initial deny set differs')
            return True
        observed=observe_pair(engine,views,closed)
        if observed['state']!='present':raise SafetyError('Prepared listener reservations are absent')
    stable()
    if receipt.load()!=before:raise SafetyError('Prepared listener evidence changed while closing inspection')
    return dict(deny_filters_verified=16,reservation_filters_verified=16,wfp_snapshot_consistent=True,
                services_started=False,client_admission=False)
