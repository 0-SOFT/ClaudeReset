"""Durable policy-binding evidence tied to the staged file and service intent."""
from copy import deepcopy
import json
import os
import uuid
from .backend_spec import document
from .install_config_stage import ConfigurationReceipts
from .install_receipts import identity
from .install_service_receipts import ServiceReceipts
from .windows_pin import PinnedFile
from .safeio import SafetyError


class BindingReceipt:
    def __init__(self,journal,policy):
        self.journal=journal;self.policy=policy
        self.path=journal.directory/'policy-binding-receipt.json'

    def transaction(self,writing=False):
        value=ServiceReceipts(self.journal).transaction(writing=writing)
        if writing:
            services=ServiceReceipts(self.journal).load()
            if (not services or len(services['services'])!=4
                    or services['services'][-1]['name']!='SbieDrv'
                    or services['services'][-1]['state']!='intent'):
                raise SafetyError('Policy binding requires the pending new driver registration')
        return value

    def staged(self):
        pin=self.policy
        if not isinstance(pin,PinnedFile) or not pin.handle:raise SafetyError('Held staged policy required')
        value=ConfigurationReceipts(self.journal).load()
        if not value:raise SafetyError('Configuration receipts required')
        rows=[row for row in value['files'] if row['name']=='Policy/Sandboxie.ini']
        if (len(rows)!=1 or rows[0]['state']!='complete' or rows[0]['sha256']!=pin.sha256
                or rows[0]['identity']!=identity(pin.api,pin.handle)):
            raise SafetyError('Policy does not match the completed configuration receipt')
        return rows[0]

    def validate(self,value):
        tx=self.transaction()
        if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','policy','state'}
                or type(value['schema']) is not int or value['schema']!=1
                or any(value[k]!=tx[k] for k in ('generation','package_sha256'))
                or value['state'] not in ('intent','bound') or value['policy']!=self.staged()):
            raise SafetyError('Invalid policy binding receipt')
        return deepcopy(value)

    def load(self):
        self.transaction()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def record(self,state,digest):
        tx=self.transaction(writing=True);row=self.staged()
        if digest!=row['sha256']:raise SafetyError('Binding digest differs from staged policy')
        old=self.load()
        if state=='intent':
            if old is not None:raise SafetyError('Existing policy binding requires separate recovery')
            value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],policy=row,state=state)
        elif state=='bound':
            if not old or old['state']!='intent':raise SafetyError('Binding completion requires durable intent')
            value=dict(old,state=state)
        else:raise SafetyError('Unknown binding receipt transition')
        value=self.validate(value)
        temporary=self.journal.directory/('binding-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Cannot persist policy binding receipt')
        if self.load()!=value:raise SafetyError('Policy binding receipt readback differs')
