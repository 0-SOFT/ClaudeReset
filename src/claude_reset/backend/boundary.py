"""Provider-independent, service-bound backend rules; clients get no permits here."""
from contextlib import ExitStack
from pathlib import Path
import ipaddress
from ..errors import SafetyError
from ..network.strict_wfp import Identity, ServiceRule, PERMIT, deny_rules, Engine
from ..network.gateway_reservation import Reservation, LAYERS as RESERVATION_LAYERS
from .. import config


def layout(root):
    root = Path(root)
    return {'engine':root/'Engine/engine.exe', 'engine_config':root/'Engine/engine.json',
            'gateway':root/'Gateway/ClaudeResetGateway.exe', 'gateway_config':root/'Gateway/gateway.json',
            'runtime':root/'Runtime/ClaudeResetRuntime.exe', 'backend':root/'Backend/ClaudeResetBackend.exe',
            'spec':root/'Backend/backend.json', 'temp':root/'RuntimeTemp'}


def rules(root, *, peer_address, peer_port, backend_port, gateway_port):
    try:
        peer=ipaddress.ip_address(peer_address)
        if peer.version!=4 or not peer.is_global or str(peer)!=peer_address:
            raise ValueError()
    except ValueError:
        raise SafetyError('A literal public IPv4 tunnel peer is required') from None
    if (type(peer_port) is not int or not 1<=peer_port<=65535
            or any(type(p) is not int or not 1024<=p<49152 for p in (backend_port,gateway_port))
            or backend_port==gateway_port):
        raise SafetyError('Dedicated distinct backend and gateway ports are required')
    paths=layout(root)
    images={name:Identity('app',str(paths[name])) for name in ('engine','gateway','runtime','backend')}
    for ident in images.values():
        ident.validate()
    closed=deny_rules(list(images.values()))
    opened=[
        ServiceRule(images['engine'],'connect_v4',PERMIT,peer_address,peer_port,False,config.BACKEND_SERVICE),
        ServiceRule(images['engine'],'recv_v4',PERMIT,config.LOOPBACK,backend_port,False,config.BACKEND_SERVICE),
        ServiceRule(images['gateway'],'connect_v4',PERMIT,config.LOOPBACK,backend_port,False,config.GATEWAY_SERVICE),
        ServiceRule(images['gateway'],'recv_v4',PERMIT,config.LOOPBACK,gateway_port,False,config.GATEWAY_SERVICE),
        ServiceRule(images['runtime'],'connect_v4',PERMIT,config.LOOPBACK,gateway_port,False,config.BACKEND_SERVICE),
    ]
    return closed,opened


def verify_installed(root, spec, *, active_lease=False, engine=None, reservation=None, expected=None):
    """Read the exact backend and reservation sets in one BFE snapshot.

    The active phase expects this generation's five dynamic permits as well as
    persistent denies. This is a read-only observation, not lease ownership or
    installed driver/client acceptance; lifetime checks remain with the caller.
    engine and reservation open the BFE sessions (Engine, Reservation) and expected gives the rules (rules).
    """
    if type(active_lease) is not bool:
        raise SafetyError('Explicit backend lease phase required')
    engine,reservation=engine or Engine,reservation or Reservation
    ports={k:spec[k] for k in ('peer_address','peer_port','backend_port','gateway_port')}
    closed,opened=(expected or rules)(root,**ports)
    expected=closed+opened if active_lease else closed
    keys={rule.key.value() for rule in expected}
    if len(keys)!=len(expected):
        raise SafetyError('Backend rule identities overlap')
    paths=layout(root)
    with engine() as reader, ExitStack() as stack:
        views=[stack.enter_context(reservation(paths[name],service,port,engine=reader))
               for name,service,port in [('engine',config.BACKEND_SERVICE,spec['backend_port']),
                                        ('gateway',config.GATEWAY_SERVICE,spec['gateway_port'])]]
        reservation_keys={view.native(layer,allow)[0].filterKey.value()
                          for view in views for layer in RESERVATION_LAYERS for allow in (False,True)}
        if len(reservation_keys)!=16:
            raise SafetyError('Reservation rule identities overlap')
        # A read-only snapshot: no filters or sublayers can be changed here.
        with reader.transaction(read_only=True):
            actual=reader.own_keys()
            if (reader.existing_sublayer() is not True or type(actual) is not set or actual!=keys
                    or not all(reader.exists_verified(rule) is True for rule in expected)):
                raise SafetyError('Exact backend boundary is missing, changed or has additional rules')
            actual=views[0].own_keys()
            if type(actual) is not set or actual!=reservation_keys:
                raise SafetyError('Exact listener reservation set differs')
            for view in views:
                if (view.existing_sublayer() is not True
                        or not all(view.verified(layer,allow) is True
                                   for layer in RESERVATION_LAYERS for allow in (False,True))):
                    raise SafetyError('Service listener reservation is missing or changed')
    return opened
