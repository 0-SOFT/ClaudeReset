"""Durable staging receipts under the existing exclusive installation lock.

Receipts distinguish an incomplete owned copy from an unrecorded collision.
They are not package authentication or permission to remove installed files.
"""
from copy import deepcopy
import ctypes as C
from ctypes import wintypes as W
import json
import os
import re
import uuid
from .backend_spec import document
from .install_payload import FILES
from .install_store import Information
from .safeio import SafetyError
from .windows_pin import PinnedFile


def identity(api,handle):
    query=api.GetFileInformationByHandle
    query.argtypes=[W.HANDLE,C.POINTER(Information)];query.restype=W.BOOL
    info=Information()
    if (not query(handle,C.byref(info)) or info.attributes&0x410 or info.links!=1):
        raise SafetyError('Staged file identity is not a single regular file')
    return [info.volume,info.index_high,info.index_low,
            info.creation.dwHighDateTime,info.creation.dwLowDateTime]


def validate(value,*,names=FILES):
    if (not isinstance(value,dict) or set(value)!={'schema','generation','package_sha256','files'}
            or type(value['schema']) is not int or value['schema']!=1):
        raise SafetyError('Invalid staging receipt')
    for key,length in [('generation',32),('package_sha256',64)]:
        if not isinstance(value[key],str) or not re.fullmatch('[a-f0-9]{%d}'%length,value[key]):
            raise SafetyError('Invalid receipt generation')
    rows=value['files']
    if not isinstance(rows,list) or len(rows)>len(names):raise SafetyError('Invalid receipt files')
    for i,row in enumerate(rows):
        if (not isinstance(row,dict) or set(row)!={'name','sha256','state','identity'}
                or row['name']!=sorted(names)[i]
                or not isinstance(row['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',row['sha256'])
                or row['state'] not in ('intent','created','complete')
                or i<len(rows)-1 and row['state']!='complete'):
            raise SafetyError('Invalid receipt sequence')
        ident=row['identity']
        if row['state']=='intent':
            if ident is not None:raise SafetyError('Intent must not assert ownership')
        elif (not isinstance(ident,list) or len(ident)!=5
                or any(type(v) is not int or not 0<=v<=0xffffffff for v in ident)):
            raise SafetyError('Invalid receipt file identity')
    return deepcopy(value)


class Receipts:
    names=FILES
    filename='stage-receipts.json'
    def __init__(self,journal):
        self.journal=journal
        self.path=journal.directory/self.filename

    def load(self):
        if not self.journal.lock:raise SafetyError('Installation lock is not held')
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:value=validate(document(pin.data),names=self.names)
        transaction=self.journal.load()
        if transaction is None or any(value[k]!=transaction[k] for k in ('generation','package_sha256')):
            raise SafetyError('Receipt does not belong to the installation journal')
        return value

    def _save(self,value):
        value=validate(value,names=self.names)
        if not self.journal.lock:raise SafetyError('Installation lock is not held')
        transaction=self.journal.load()
        if transaction is None or any(value[k]!=transaction[k] for k in ('generation','package_sha256')):
            raise SafetyError('Receipt does not belong to the installation journal')
        temporary=self.journal.directory/('receipt-'+uuid.uuid4().hex+'.tmp')
        data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush();os.fsync(stream.fileno())
        from .install_metadata_commit import replace_metadata
        replace_metadata(self.journal,temporary,self.path,data)
        if self.load()!=value:raise SafetyError('Staging receipt readback differs')

    def begin(self):
        if self.load() is not None:raise SafetyError('Existing staging receipts require recovery')
        transaction=self.journal.load()
        if not transaction:raise SafetyError('Installation journal required')
        self._save(dict(schema=1,generation=transaction['generation'],
            package_sha256=transaction['package_sha256'],files=[]))

    def intent(self,name,digest):
        value=self.load()
        if value is None:raise SafetyError('Staging receipts were not initialized')
        value['files'].append(dict(name=name,sha256=digest,state='intent',identity=None))
        self._save(value)

    def created(self,handle):
        value=self.load()
        if not value or not value['files'] or value['files'][-1]['state']!='intent':
            raise SafetyError('Creation requires a pending receipt')
        value['files'][-1].update(state='created',identity=identity(self.journal.api,handle))
        self._save(value)

    def complete(self,pin):
        value=self.load()
        if not value or not value['files']:raise SafetyError('Creation receipt required')
        row=value['files'][-1]
        if (row['state']!='created' or row['sha256']!=pin.sha256
                or row['identity']!=identity(pin.api,pin.handle)):
            raise SafetyError('Completed copy identity differs from creation receipt')
        row['state']='complete';self._save(value)
