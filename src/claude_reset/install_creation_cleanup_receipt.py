"""Durable history of pending-creation cleanup, never installation completion.

The caller must independently establish current ownership before a request and
fresh SCM/registry absence before observation. This file grants no SCM authority.
"""
from copy import deepcopy
import hashlib,json,os,re,uuid
from .install_creation_attestation import creation_records
from .windows_pin import PinnedFile
from .backend_spec import document
from .safeio import SafetyError


class CreationCleanupReceipt:
    filename='pending-creation-cleanup.json'

    def __init__(self,store,generation):
        self.store,self.generation=store,generation
        self.path=store.journal.directory/self.filename

    def context(self):
        tx,source,markers=creation_records(self.store,self.generation)
        digest=hashlib.sha256(json.dumps([source,markers],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],
                    evidence_sha256=digest,service=source['services'][-1]['name'])

    def validate(self,value):
        context=self.context()
        if (not isinstance(value,dict) or set(value)!=set(context)|{'attempts','absence_verified'}
                or type(value['schema']) is not int or any(value[k]!=v for k,v in context.items())
                or type(value['absence_verified']) is not bool or not isinstance(value['attempts'],list)
                or len(value['attempts'])>16):
            raise SafetyError('Invalid pending creation cleanup receipt')
        ids=set()
        for attempt in value['attempts']:
            if (not isinstance(attempt,dict) or set(attempt)!={'id','state'}
                    or not isinstance(attempt['id'],str) or not re.fullmatch('[a-f0-9]{32}',attempt['id'])
                    or attempt['id'] in ids or attempt['state'] not in ('delete_intent','delete_requested')):
                raise SafetyError('Invalid pending creation cleanup attempt')
            ids.add(attempt['id'])
        # A known accepted request cannot be issued again, even after restart.
        if any(r['state']=='delete_requested' for r in value['attempts'][:-1]):
            raise SafetyError('Pending creation deletion request was replayed')
        return deepcopy(value)

    def load(self):
        self.context()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def save(self,value):
        value=self.validate(value);data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        temporary=self.store.journal.directory/('creation-cleanup-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        if not self.store.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Pending creation cleanup durability is unknown')
        if self.load()!=value:raise SafetyError('Pending creation cleanup readback differs')

    def begin(self):
        value=self.load()
        if value is None:value=dict(self.context(),attempts=[],absence_verified=False)
        if value['absence_verified'] or any(r['state']=='delete_requested' for r in value['attempts']):
            raise SafetyError('Observed absence or accepted request cannot be replayed')
        identifier=uuid.uuid4().hex
        value['attempts'].append(dict(id=identifier,state='delete_intent'))
        self.save(value);return identifier

    def requested(self,identifier):
        value=self.load()
        if (not value or value['absence_verified'] or not value['attempts']
                or value['attempts'][-1]!=dict(id=identifier,state='delete_intent')):
            raise SafetyError('Current pending creation deletion intent required')
        value['attempts'][-1]['state']='delete_requested';self.save(value)

    def observe_absence(self,observation):
        context=self.context()
        if (not isinstance(observation,dict) or set(observation)!={'services','absence_verified','client_admission'}
                or observation['services']!=[context['service']] or observation['absence_verified'] is not True
                or observation['client_admission'] is not False):
            raise SafetyError('Exact fresh pending creation absence required')
        value=self.load()
        if value is None:value=dict(context,attempts=[],absence_verified=False)
        value['absence_verified']=True;self.save(value)
