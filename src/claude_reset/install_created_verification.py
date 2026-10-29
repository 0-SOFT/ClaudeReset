"""Query final bindings while original disabled-service creation handles are held.

This does not start services or replace signed installed runtime acceptance.
The enclosing step holds staged files and verifies the actual closed boundary.
"""
from .safeio import SafetyError
from .install_scm import HeldRegistrations,SERVICES
from .install_service_attestation import RegistryReader
from .install_service_receipts import ServiceReceipts
from .install_service_markers import MarkerReceipts,VALUE,encoded,validate_creation_snapshot
from .install_binding_receipts import BindingReceipt
from . import install_registry as registry


def verify_created_bindings(store,generation,held,policy,verify_closed):
    if not isinstance(held,HeldRegistrations) or not callable(verify_closed):
        raise SafetyError('Original registrations and closed boundary verifier required')
    services=ServiceReceipts(store.journal);markers=MarkerReceipts(store.journal)
    tx=services.transaction(writing=True)
    source=services.load();owners=markers.load();binding=BindingReceipt(store.journal,policy)
    bound=binding.load()
    if (tx['generation']!=generation or not source or not owners
            or len(source['services'])!=4 or len(owners['services'])!=4
            or [spec['name'] for _,_,spec in held.items]!=list(SERVICES)
            or any(row['state']!='disabled' for row in source['services'])
            or any(row['state']!='bound' for row in owners['services'])
            or bound is None or bound['state']!='bound'):
        raise SafetyError('Complete creation and policy binding evidence required')

    originals=tuple((native,handle,dict(spec)) for native,handle,spec in held.items)

    def unchanged():
        if verify_closed(generation) is not True:
            raise SafetyError('Client boundary is not verified closed')
        if tuple(held.items)!=originals:
            raise SafetyError('Creation handles changed during verification')
        for native,handle,spec in originals:native.require_created(handle,spec['name'])
        if (services.transaction(writing=True)!=tx or services.load()!=source
                or markers.load()!=owners or binding.load()!=bound):
            raise SafetyError('Creation verification evidence changed')
        binding.staged()
        return True

    unchanged();reader=RegistryReader()
    for (native,handle,spec),row,owner in zip(held.items,source['services'],owners['services']):
        unchanged()
        if spec!=row['spec']:raise SafetyError('Held service differs from creation receipt')
        native.require_created(handle,spec['name'])
        validate_creation_snapshot(owner['marker'],spec,native.snapshot(handle,spec))
        key=reader.open(spec['name'])
        try:
            if reader.value(key,'SymbolicLinkValue') is not None:
                raise SafetyError('Created service registry key is a link')
            registry.validate_security(reader.security(key))
            data=encoded(owner['marker'],spec,tx['generation'],tx['package_sha256'])
            if reader.value(key,VALUE)!=(3,data):
                raise SafetyError('Created service ownership marker changed')
            if spec['name']=='SbieDrv':
                actual=reader.value(key,'IniPath')
                if actual is None or registry.decode_string(*actual)!=registry.expected_path():
                    raise SafetyError('Created driver policy binding changed')
            native.require_created(handle,spec['name'])
            validate_creation_snapshot(owner['marker'],spec,native.snapshot(handle,spec))
            unchanged()
        finally:reader.close_key(key)
    unchanged()
    return dict(disabled_bindings_verified=4,driver_started=False,client_admission=False)
