"""Reserve only a Claude gateway TCP port for its exact service image and SID.

Persistent bind and receive rules prevent a different listener replacing a dead
controller. No default firewall policy, interface, route or DNS is changed.
Installation is separate from authorizing clients to use the gateway.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import uuid
from ..windows import wfp
from ..windows.service_identity import service_descriptor
from ..windows.wfp_session import APP_ID, SECURITY_DESCRIPTOR, Session, blob, condition_blob, condition_u32
from ..errors import SafetyError
from .. import config

NS = uuid.UUID('6ef4230b-dc85-4fb8-9d93-34d274553a8a')
SUB = wfp.GUID.of(uuid.uuid5(NS, 'gateway-port-v1'))
MARK = b'ClaudeReset-Gateway-Reservation-v1'
WEIGHT = 61100
PORT = wfp.GUID.of('0c1ba1af-5765-453f-af22-a8f791ac775b')
PROTOCOL = wfp.GUID.of('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7')
USER = wfp.GUID.of('af043a0a-b34d-4f86-979c-c90371af6e66')
LAYERS = ('1247d66d-0b60-4a15-8d44-7155d0f53a0c', '55a650e1-5f0a-4eca-a653-88f53b26aa8c',
          'e1cd9fe7-f4b5-4273-96c0-592e487b8650', 'a3b42c97-9f04-4672-b87e-cee9c483257f')


class Reservation(Session):
    """Port reservation filters of one service. With engine=..., a view that borrows an open parent session."""

    def __init__(self, executable, service, port, *, engine=None, descriptor=None):
        # descriptor is the service's security descriptor (read from the service manager unless given).
        self.executable=Path(executable)
        expected = {config.GATEWAY_SERVICE:'ClaudeResetGateway.exe',config.GATEWAY_FIXTURE_SERVICE:'ClaudeResetGateway.exe',
                    config.BACKEND_SERVICE:'engine.exe',config.BACKEND_FIXTURE_SERVICE:'engine.exe'}.get(service)
        if not expected or not self.executable.is_absolute() or self.executable.name!=expected or not self.executable.is_file():
            raise SafetyError('An exact existing gateway image is required')
        if type(port) is not int or not 1024<=port<49152:
            raise SafetyError('Use one dedicated non-ephemeral gateway port')
        self.descriptor=service_descriptor(service) if descriptor is None else descriptor
        self.service,self.port=service,port
        self.slot=f'{service}:{port}'
        self.borrowed=engine is not None
        super().__init__(borrow=engine)

    def existing_sublayer(self):
        """Read only; never create a missing reservation during runtime checks."""
        return self.owned_sublayer(SUB, MARK, (WEIGHT,), changed='Gateway reservation sublayer changed')

    def own_keys(self):
        return self.filter_keys(SUB)

    def ensure_sublayer(self):
        if self.existing_sublayer():
            return
        self.add_sublayer(SUB, 'ClaudeReset gateway port', MARK, WEIGHT)
        if not self.existing_sublayer():
            raise SafetyError('New gateway sublayer readback failed')

    def native(self, layer, allow):
        keep=[]
        conditions=(wfp.CONDITION*(4 if allow else 2))()
        for c,field,dtype,value in zip(conditions,(PORT,PROTOCOL),(2,1),(self.port,6)):
            condition_u32(c,field,dtype,value)
        if allow:
            condition_blob(conditions[2],wfp.FIELD_APP_ID,APP_ID,self.app_id(self.executable),keep)
            condition_blob(conditions[3],USER,SECURITY_DESCRIPTOR,self.descriptor,keep)
        key=wfp.GUID.of(uuid.uuid5(NS,f'{self.slot}:{layer}:{allow}'))
        mark=MARK+hashlib.sha256((self.slot+str(self.executable)).encode()+self.descriptor).digest()
        keep.append(conditions)
        f=wfp.FILTER(filterKey=key,displayData=wfp.DISPLAY('ClaudeReset reserved gateway port',None),flags=1,
                     providerData=blob(mark,keep),layerKey=wfp.GUID.of(layer),subLayerKey=SUB,
                     numFilterConditions=len(conditions),filterCondition=conditions)
        f.weight.type,f.weight.value.u8=1,15 if allow else 1
        f.action.type=wfp.FWP_ACTION_PERMIT if allow else wfp.FWP_ACTION_BLOCK
        return f,keep

    def verified(self, layer, allow):
        wanted,keep=self.native(layer,allow)
        return self.matches(wanted,label='Gateway reservation')

    def install(self):
        if self.borrowed:
            raise SafetyError('Borrowed reservation requires a coordinated transaction')
        from ..backend.service_store import verify_image
        verify_image(self.executable,self.service)
        self.ensure_sublayer()
        with self.transaction():
            for layer in LAYERS:
                for allow in (False,True):
                    if self.verified(layer,allow):
                        continue
                    f,keep=self.native(layer,allow)
                    self.add_filter(f)
                    if not self.verified(layer,allow):
                        raise SafetyError('Gateway filter missing after installation')

    def remove_fixture(self):
        if self.borrowed:
            raise SafetyError('Borrowed reservation cannot run fixture cleanup')
        if self.service!=config.GATEWAY_FIXTURE_SERVICE:
            raise SafetyError('Fixture cleanup cannot remove production reservations')
        for layer in LAYERS:
            for allow in (False,True):
                if self.verified(layer,allow):
                    f,keep=self.native(layer,allow)
                    self.delete_filter(f.filterKey)
