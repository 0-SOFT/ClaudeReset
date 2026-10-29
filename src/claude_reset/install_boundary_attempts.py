"""Bounded durable attempts for cleanup of a previously committed deny set."""
from copy import deepcopy
import hashlib,json,os,re,uuid
from .install_boundary_receipts import BoundaryReceipt
from .install_service_receipts import ServiceReceipts
from .windows_pin import PinnedFile
from .backend_spec import document
from .safeio import SafetyError


class BoundaryAttempts:
    filename='boundary-reconciliation-log.json'
    def __init__(self,receipt):
        if not isinstance(receipt,BoundaryReceipt):raise SafetyError('Exact protected boundary receipt required')
        self.receipt=receipt;self.journal=receipt.journal;self.path=self.journal.directory/self.filename

    def context(self):
        tx=ServiceReceipts(self.journal).transaction();source=self.receipt.load()
        active=[e for e in tx['entries'] if e['state']!='undone']
        if tx['state']!='recovering' or not active or active[-1]['step']!='install_services' or source is None:
            raise SafetyError('Ordered boundary recovery required')
        if source['schema']==2:
            source=dict(source,schema=1,state=source['previous_state'])
            del source['previous_state'];del source['completion_basis']
        if source['state'] not in ('committed','remove_intent'):
            raise SafetyError('An uncertain initial commit cannot authorize deny deletion')
        digest=hashlib.sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],source_sha256=digest)

    def validate(self,value):
        context=self.context()
        if (not isinstance(value,dict) or set(value)!=set(context)|{'attempts','absence_verified'}
                or type(value['schema']) is not int or any(value[k]!=v for k,v in context.items())
                or type(value['absence_verified']) is not bool or not isinstance(value['attempts'],list)
                or len(value['attempts'])>16):raise SafetyError('Invalid boundary reconciliation history')
        ids=set()
        for row in value['attempts']:
            if (not isinstance(row,dict) or set(row)!={'id','state'} or not isinstance(row['id'],str)
                    or not re.fullmatch('[a-f0-9]{32}',row['id']) or row['id'] in ids
                    or row['state'] not in ('remove_intent','removal_committed')):
                raise SafetyError('Invalid boundary reconciliation attempt')
            ids.add(row['id'])
        if any(r['state']=='removal_committed' for r in value['attempts'][:-1]):
            raise SafetyError('Known committed boundary removal cannot be replayed')
        return deepcopy(value)

    def load(self):
        self.context()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def save(self,value):
        value=self.validate(value);temporary=self.journal.directory/('boundary-attempt-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode());stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Boundary attempt durability is unknown')
        if self.load()!=value:raise SafetyError('Boundary attempt readback differs')

    def begin(self):
        value=self.load()
        if value is None:value=dict(self.context(),attempts=[],absence_verified=False)
        if value['absence_verified'] or any(r['state']=='removal_committed' for r in value['attempts']):
            raise SafetyError('Completed boundary removal or absence cannot be replayed')
        identifier=uuid.uuid4().hex;value['attempts'].append(dict(id=identifier,state='remove_intent'))
        self.save(value);return identifier

    def committed(self,identifier):
        value=self.load()
        if (not value or value['absence_verified'] or not value['attempts']
                or value['attempts'][-1]!=dict(id=identifier,state='remove_intent')):
            raise SafetyError('Current boundary removal intent required')
        value['attempts'][-1]['state']='removal_committed';self.save(value)

    def observe_absence(self,observation):
        if (not isinstance(observation,dict) or observation!=dict(keys=self.receipt.keys,state='absent',
                transaction_consistent=True,settings_changed=False,client_admission=False)
                or observation['transaction_consistent'] is not True or observation['settings_changed'] is not False
                or observation['client_admission'] is not False):
            raise SafetyError('Fresh complete boundary absence required')
        value=self.load()
        if value is None:value=dict(self.context(),attempts=[],absence_verified=False)
        value['absence_verified']=True;self.save(value)
