"""Prepare durable ownership evidence for newly created disabled services only.

No adoption, deletion, start, elevation or cross-process mutation authority.
The protected journal and registry must remain outside untrusted write access.
An administrator who can replace both is outside this ownership protocol.
"""
from copy import deepcopy
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
import re
import secrets
import uuid
from . import install_registry as registry
from .install_registry_bind import Native as RegistryWriter,ACCESS
from .install_scm import Native as Services,validate_spec,validate_snapshot
from .install_service_receipts import ServiceReceipts
from .install_inventory import SERVICES
from .backend_spec import document
from .windows_pin import PinnedFile
from .safeio import SafetyError

VALUE='ClaudeResetOwnerV1'


def encoded(marker,spec,generation,package_sha256):
    spec=validate_spec(spec)
    fields={'schema','generation','package_sha256','service','nonce','spec_sha256'}
    if (not isinstance(marker,dict) or set(marker)!=fields
            or type(marker['schema']) is not int or marker['schema']!=1
            or marker['service']!=spec['name'] or marker['generation']!=generation
            or marker['package_sha256']!=package_sha256):
        raise SafetyError('Service ownership marker identity differs')
    for key,size in [('generation',32),('package_sha256',64),('nonce',64),('spec_sha256',64)]:
        if not isinstance(marker[key],str) or not re.fullmatch('[a-f0-9]{%d}'%size,marker[key]):
            raise SafetyError('Invalid service ownership marker field')
    digest=hashlib.sha256(json.dumps(spec,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if marker['spec_sha256']!=digest:raise SafetyError('Service ownership specification differs')
    data=json.dumps(marker,sort_keys=True,separators=(',',':')).encode('utf-8')
    if len(data)>520:raise SafetyError('Service ownership marker exceeds fixed bound')
    return data


def creation_display(marker,spec):
    """Fixed display binding, persisted by the same SCM call as creation."""
    if not isinstance(marker,dict):raise SafetyError('Creation marker required')
    encoded(marker,spec,marker.get('generation'),marker.get('package_sha256'))
    return 'ClaudeReset '+spec['name']+' ['+marker['nonce']+']'


def validate_creation_snapshot(marker,spec,actual):
    validate_snapshot(spec,actual)
    if actual.get('display')!=creation_display(marker,spec):
        raise SafetyError('Service creation binding differs')


class MarkerReceipts:
    filename='service-marker-receipts.json'
    def __init__(self,journal):
        self.journal=journal;self.path=journal.directory/self.filename

    def context(self,writing=False):
        source=ServiceReceipts(self.journal)
        tx=source.transaction(writing=writing);records=source.load()
        if records is None:raise SafetyError('Service registration receipts required for markers')
        return tx,records['services']

    def validate(self,value):
        tx,services=self.context()
        if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','services'}
                or type(value['schema']) is not int or value['schema']!=1
                or any(value[k]!=tx[k] for k in ('generation','package_sha256'))
                or not isinstance(value['services'],list) or len(value['services'])>len(services)):
            raise SafetyError('Invalid service marker receipt')
        nonces=set()
        for index,row in enumerate(value['services']):
            if (not isinstance(row,dict) or set(row)!={'marker','state'}
                    or row['state'] not in ('intent','bound')
                    or index<len(value['services'])-1 and row['state']!='bound'):
                raise SafetyError('Invalid service marker sequence')
            encoded(row['marker'],services[index]['spec'],tx['generation'],tx['package_sha256'])
            if row['marker']['nonce'] in nonces:raise SafetyError('Service ownership nonce was reused')
            nonces.add(row['marker']['nonce'])
        return deepcopy(value)

    def load(self):
        self.context()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def save(self,value):
        self.context(writing=True);value=self.validate(value)
        temporary=self.journal.directory/('service-marker-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Service marker receipt durability is unknown')
        if self.load()!=value:raise SafetyError('Service marker receipt readback differs')

    def begin(self,spec):
        spec=validate_spec(spec);tx,services=self.context(writing=True)
        if not services or services[-1]!=dict(name=spec['name'],state='intent',spec=spec):
            raise SafetyError('Ownership marker requires pending new service intent')
        value=self.load()
        if value is None:value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],services=[])
        if len(value['services'])!=len(services)-1:
            raise SafetyError('Existing or missing service marker requires separate recovery')
        marker=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],
                    service=spec['name'],nonce=secrets.token_hex(32),
                    spec_sha256=hashlib.sha256(json.dumps(spec,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        value['services'].append(dict(marker=marker,state='intent'));self.save(value)
        return marker

    def pending(self,spec):
        spec=validate_spec(spec);tx,services=self.context();value=self.load()
        if (not value or not services or services[-1]!=dict(name=spec['name'],state='intent',spec=spec)
                or len(value['services'])!=len(services) or value['services'][-1]['state']!='intent'):
            raise SafetyError('Durable pre-creation marker intent required')
        return deepcopy(value['services'][-1]['marker'])

    def complete(self,marker):
        tx,services=self.context(writing=True);value=self.load()
        if (not value or not services or services[-1]['state']!='intent'
                or len(value['services'])!=len(services)
                or value['services'][-1]!=dict(marker=marker,state='intent')):
            raise SafetyError('Exact pending service marker required')
        value['services'][-1]['state']='bound';self.save(value)


class Native(RegistryWriter):
    def open(self,name):
        if name not in SERVICES:raise SafetyError('Unknown service marker registry slot')
        key=registry.KEY.rsplit('\\',1)[0]+'\\'+name;handle=W.HANDLE()
        if self.api.RegOpenKeyExW(W.HANDLE(-2147483646),key,8,ACCESS,C.byref(handle)):
            raise SafetyError('New service marker key cannot be opened')
        return handle

    def write_marker(self,handle,data):
        if not isinstance(data,bytes) or not 1<=len(data)<=520:
            raise SafetyError('Bounded encoded service marker required')
        buffer=C.create_string_buffer(data)
        if self.api.RegSetValueExW(handle,VALUE,0,3,buffer,len(data)):
            raise SafetyError('Cannot write new service ownership marker')


def _mark_created_service(writer,services,handle,spec,receipts,verify_closed):
    spec=validate_spec(spec)
    if not isinstance(services,Services) or not isinstance(receipts,MarkerReceipts):
        raise SafetyError('Original registration and protected marker receipts required')
    services.require_created(handle,spec['name'])
    marker=receipts.pending(spec)
    validate_creation_snapshot(marker,spec,services.snapshot(handle,spec))
    def closed():
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
    closed();key=writer.open(spec['name'])
    try:
        if writer.value(key,'SymbolicLinkValue') is not None or writer.value(key,VALUE) is not None:
            raise SafetyError('Existing registry marker or link cannot be adopted')
        data=encoded(marker,spec,marker['generation'],marker['package_sha256'])
        closed();writer.protect(key)
        closed();writer.write_marker(key,data);writer.flush(key)
        registry.validate_security(writer.security(key))
        if writer.value(key,VALUE)!=(3,data):raise SafetyError('Service marker readback differs')
        services.require_created(handle,spec['name'])
        validate_creation_snapshot(marker,spec,services.snapshot(handle,spec))
        closed();receipts.complete(marker)
        return dict(marker_bound=True,service=spec['name'],client_admission=False,may_delete=False)
    finally:writer.close_key(key)


def service_preparation(store,generation,verify_closed):
    """Fixed registration hook, invoked only while creation handles are held."""
    from .install_store import Store
    if not isinstance(store,Store) or not store.journal or not store.journal.lock:
        raise SafetyError('Held installation store required for service markers')
    def prepare(services,handle,spec):
        tx=store.journal.load()
        if not tx or tx['generation']!=generation:raise SafetyError('Service marker generation changed')
        return _mark_created_service(Native(),services,handle,spec,MarkerReceipts(store.journal),verify_closed)
    def begin(spec):
        tx=store.journal.load()
        if not tx or tx['generation']!=generation:raise SafetyError('Service marker generation changed')
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        return MarkerReceipts(store.journal).begin(spec)
    prepare.begin=begin
    return prepare
