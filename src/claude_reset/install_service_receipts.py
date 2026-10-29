"""Durable evidence of disabled registrations, not authority to adopt/delete SCM names."""
from copy import deepcopy
import json
import os
import uuid
from .backend_spec import document
from .safeio import SafetyError
from .windows_pin import PinnedFile
from .install_inventory import SERVICES
from .install_scm import specification


def validate(value,transaction):
    if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','services'}
            or type(value['schema']) is not int or value['schema']!=1
            or any(value[k]!=transaction[k] for k in ('generation','package_sha256'))):
        raise SafetyError('Invalid service receipt identity')
    rows=value['services']
    if not isinstance(rows,list) or len(rows)>len(SERVICES):raise SafetyError('Invalid service receipt sequence')
    for index,row in enumerate(rows):
        expected=specification(SERVICES[index])
        if (not isinstance(row,dict) or set(row)!={'name','state','spec'}
                or row['name']!=SERVICES[index] or row['state'] not in ('intent','disabled')
                or index<len(rows)-1 and row['state']!='disabled'
                or not isinstance(row['spec'],dict) or set(row['spec'])!=set(expected)
                or any(type(row['spec'][k]) is not type(v) or row['spec'][k]!=v for k,v in expected.items())):
            raise SafetyError('Service receipt differs from fixed disabled specification')
    return deepcopy(value)


class ServiceReceipts:
    def __init__(self,journal):
        self.journal=journal;self.path=journal.directory/'service-receipts.json'

    def transaction(self,*,writing=False):
        if not self.journal.lock:raise SafetyError('Installation lock required')
        value=self.journal.load()
        if value is None:raise SafetyError('Installation journal required')
        if writing and (value['state']!='applying' or not value['entries']
                or value['entries'][-1]!={'step':'install_services','state':'intent'}):
            raise SafetyError('Service registration requires durable install_services intent')
        return value

    def load(self):
        transaction=self.transaction()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return validate(document(pin.data),transaction)

    def save(self,value):
        value=validate(value,self.transaction(writing=True))
        temporary=self.journal.directory/('services-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Cannot commit service receipt')
        if self.load()!=value:raise SafetyError('Service receipt readback differs')

    def begin(self):
        if self.load() is not None:raise SafetyError('Existing service receipts require separate recovery')
        value=self.transaction(writing=True)
        self.save(dict(schema=1,generation=value['generation'],package_sha256=value['package_sha256'],services=[]))

    def record(self,state,spec):
        if not isinstance(spec,dict):raise SafetyError('Invalid service receipt specification')
        value=self.load()
        if value is None:raise SafetyError('Service receipts not initialized')
        if state=='intent':value['services'].append(dict(name=spec.get('name'),state=state,spec=deepcopy(spec)))
        elif state=='disabled':
            if (not value['services'] or value['services'][-1]['state']!='intent'
                    or value['services'][-1]['spec']!=spec):
                raise SafetyError('Disabled confirmation requires matching intent')
            value['services'][-1]['state']='disabled'
        else:raise SafetyError('Unknown service receipt transition')
        self.save(value)
