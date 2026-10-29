"""Durable current-registration cleanup, distinct from cross-process adoption."""
from copy import deepcopy
import json
import os
import uuid
from .backend_spec import document
from .install_service_receipts import ServiceReceipts
from .install_scm import validate_spec
from .windows_pin import PinnedFile
from .safeio import SafetyError


class RemovalReceipts:
    def __init__(self,journal):
        self.journal=journal;self.path=journal.directory/'service-removal-receipts.json'

    def context(self):
        from .install_reservations import ReservationReceipt
        ReservationReceipt.require_removed_if_present(self.journal)
        source=ServiceReceipts(self.journal)
        tx=source.transaction()
        if (tx['state']!='recovering' or not any(e['step']=='install_services'
                and e['state'] in ('intent','done') for e in tx['entries'])
                or any(e['step'] in ('verify_installed','fixture_acceptance') and e['state']!='undone' for e in tx['entries'])):
            raise SafetyError('Service cleanup requires its ordered recovery step')
        records=source.load()
        if records is None:raise SafetyError('Registration receipts required')
        return tx,list(reversed(records['services']))

    def validate(self,value):
        tx,source=self.context()
        observed=isinstance(value,dict) and value.get('schema')==2
        fields={'schema','generation','package_sha256','services','absence_verified'}
        if observed:fields.add('completion_basis')
        if (not isinstance(value,dict) or set(value)!=fields
                or type(value['schema']) is not int or value['schema'] not in (1,2)
                or any(value[k]!=tx[k] for k in ('generation','package_sha256'))
                or type(value['absence_verified']) is not bool or not isinstance(value['services'],list)
                or len(value['services'])>len(source)):
            raise SafetyError('Invalid service removal receipt')
        for index,row in enumerate(value['services']):
            if (not isinstance(row,dict) or set(row)!={'spec','state'} or row['spec']!=source[index]['spec']
                    or row['state'] not in ('delete_intent','delete_requested')
                    or index<len(value['services'])-1 and row['state']!='delete_requested'):
                raise SafetyError('Service removal order differs from registration')
            validate_spec(row['spec'])
        if observed:
            if (value['completion_basis']!='observed_absence' or value['absence_verified'] is not True or not source):
                raise SafetyError('Observed absence requires recorded services and explicit observation basis')
        elif value['absence_verified'] and (len(value['services'])!=len(source)
                or any(r['state']!='delete_requested' for r in value['services'])):
            raise SafetyError('Incomplete service removal cannot be verified')
        return deepcopy(value)

    def load(self):
        self.context()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def save(self,value):
        value=self.validate(value)
        temporary=self.journal.directory/('removal-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Cannot persist service removal receipt')
        if self.load()!=value:raise SafetyError('Service removal readback differs')

    def record(self,state,spec):
        tx,_=self.context();value=self.load()
        if value is None:value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],services=[],absence_verified=False)
        if value['absence_verified']:raise SafetyError('Completed service removal cannot be replayed')
        if state=='delete_intent':value['services'].append(dict(spec=deepcopy(spec),state=state))
        elif state=='delete_requested':
            if not value['services'] or value['services'][-1]!=dict(spec=spec,state='delete_intent'):
                raise SafetyError('Deletion requires durable matching intent')
            value['services'][-1]['state']=state
        else:raise SafetyError('Unknown service removal transition')
        self.save(value)

    def confirm(self,result):
        value=self.load();_,source=self.context()
        if (value is None or value['schema']!=1 or not isinstance(result,dict)
                or set(result)!={'services','absence_verified','client_admission'}
                or result['absence_verified'] is not True or result['client_admission'] is not False
                or result['services']!=[row['name'] for row in source]):
            raise SafetyError('Complete exact service absence result required')
        value['absence_verified']=True;self.save(value)


    def confirm_observed(self,result):
        """Persist actual absence without inventing a successful DeleteService result."""
        value=self.load();tx,source=self.context()
        if (not source or not isinstance(result,dict) or set(result)!={'services','absence_verified','client_admission'}
                or result['absence_verified'] is not True or result['client_admission'] is not False
                or result['services']!=[row['name'] for row in source]):
            raise SafetyError('Complete exact observed absence required')
        # Keep all recorded states; absent history is never invented as success.
        if value is None:value=dict(generation=tx['generation'],package_sha256=tx['package_sha256'],services=[])
        self.save(dict(value,schema=2,absence_verified=True,completion_basis='observed_absence'))
