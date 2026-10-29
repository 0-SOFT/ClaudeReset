"""Bounded append-only attempt history for fresh service cleanup reconciliation."""
from copy import deepcopy
import hashlib,json,os,re,uuid
from .install_service_receipts import ServiceReceipts
from .install_scm import validate_spec
from .windows_pin import PinnedFile
from .backend_spec import document
from .safeio import SafetyError


class ReconciliationLog:
    filename='service-reconciliation-log.json'
    def __init__(self,journal,*,recovery_context=None):
        self.journal=journal;self.path=journal.directory/self.filename;self.recovery_context=recovery_context

    def context(self):
        source=ServiceReceipts(self.journal);tx=source.transaction();record=source.load()
        if self.recovery_context is not None:
            checked=self.recovery_context()
            if checked[:2]!=(tx,record):raise SafetyError('Recovery context differs from journal')
        active=[row for row in tx['entries'] if row['state']!='undone']
        if (tx['state']!='recovering' or not active or active[-1]['step']!='install_services'
                or not record or not record['services']
                or self.recovery_context is None and any(r['state']!='disabled' for r in record['services'])):
            raise SafetyError('Reconciliation requires completed registrations in ordered recovery')
        digest=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return tx,record['services'],digest

    def validate(self,value):
        tx,source,digest=self.context()
        if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','source_sha256','attempts'}
                or type(value['schema']) is not int or value['schema']!=1
                or any(value[k]!=tx[k] for k in ('generation','package_sha256')) or value['source_sha256']!=digest
                or not isinstance(value['attempts'],list) or not 1<=len(value['attempts'])<=16):
            raise SafetyError('Invalid service reconciliation history')
        ids=set();names=[r['name'] for r in source]
        for attempt in value['attempts']:
            if (not isinstance(attempt,dict) or set(attempt)!={'id','absent','services','state'}
                    or not isinstance(attempt['id'],str) or not re.fullmatch('[a-f0-9]{32}',attempt['id'])
                    or attempt['id'] in ids or attempt['state'] not in ('running','complete')
                    or not isinstance(attempt['absent'],list) or len(attempt['absent'])>len(names)
                    or attempt['absent']!=names[len(names)-len(attempt['absent']):]
                    or not isinstance(attempt['services'],list)):
                raise SafetyError('Invalid reconciliation attempt identity or absent scope')
            ids.add(attempt['id']);remaining=list(reversed(source[:len(names)-len(attempt['absent'])]))
            if len(attempt['services'])>len(remaining):raise SafetyError('Reconciliation action exceeds remaining scope')
            for index,row in enumerate(attempt['services']):
                if (not isinstance(row,dict) or set(row)!={'spec','state'} or row['spec']!=remaining[index]['spec']
                        or row['state'] not in ('delete_intent','delete_requested')
                        or index<len(attempt['services'])-1 and row['state']!='delete_requested'):
                    raise SafetyError('Reconciliation action order differs')
                validate_spec(row['spec'])
            if attempt['state']=='complete' and (len(attempt['services'])!=len(remaining)
                    or any(r['state']!='delete_requested' for r in attempt['services'])):
                raise SafetyError('Incomplete reconciliation attempt cannot complete')
        return deepcopy(value)

    def load(self):
        self.context()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def save(self,value):
        value=self.validate(value);data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        if len(data)>65536:raise SafetyError('Reconciliation history exceeds bounded size')
        temporary=self.journal.directory/('reconciliation-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Reconciliation history durability is unknown')
        if self.load()!=value:raise SafetyError('Reconciliation history readback differs')

    def begin(self,absent):
        tx,_,digest=self.context();value=self.load()
        if value is None:value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],source_sha256=digest,attempts=[])
        identifier=uuid.uuid4().hex
        value['attempts'].append(dict(id=identifier,absent=list(absent),services=[],state='running'))
        self.save(value);return identifier

    def record(self,identifier,state,spec):
        value=self.load()
        if not value or value['attempts'][-1]['id']!=identifier or value['attempts'][-1]['state']!='running':
            raise SafetyError('Only the current running reconciliation attempt may record actions')
        rows=value['attempts'][-1]['services']
        if state=='delete_intent':rows.append(dict(spec=deepcopy(spec),state=state))
        elif state=='delete_requested':
            if not rows or rows[-1]!=dict(spec=spec,state='delete_intent'):
                raise SafetyError('Matching reconciliation intent required')
            rows[-1]['state']=state
        else:raise SafetyError('Unknown reconciliation action')
        self.save(value)

    def complete(self,identifier,observation):
        value=self.load();_,source,_=self.context()
        if (not value or value['attempts'][-1]['id']!=identifier or value['attempts'][-1]['state']!='running'
                or not isinstance(observation,dict) or set(observation)!={'services','absence_verified','client_admission'}
                or observation['services']!=[r['name'] for r in reversed(source)]
                or observation['absence_verified'] is not True or observation['client_admission'] is not False):
            raise SafetyError('Exact fresh complete absence required to finish reconciliation')
        value['attempts'][-1]['state']='complete';self.save(value)
