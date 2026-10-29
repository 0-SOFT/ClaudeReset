"""Durable intent for the initial deny-only WFP transaction."""
from copy import deepcopy
import json
import os
import re
import uuid
from .backend_spec import document
from .install_service_receipts import ServiceReceipts
from .windows_pin import PinnedFile
from .safeio import SafetyError


class BoundaryReceipt:
    filename='boundary-receipt.json'
    @classmethod
    def require_removed_if_present(cls,journal):
        """Ordering gate only; receipt-supplied keys never authorize WFP deletion."""
        path=journal.directory/cls.filename
        try:path.lstat()
        except FileNotFoundError:return
        with PinnedFile(path,limit=65536) as pin:value=document(pin.data)
        if not isinstance(value,dict):raise SafetyError('Invalid boundary recovery evidence')
        receipt=cls(journal,value.get('keys'))
        value=receipt.validate(value)
        if value['state']!='removed':
            raise SafetyError('Recorded boundary must be removed before dependent cleanup')
        return value

    def __init__(self,journal,keys):
        if (not isinstance(keys,list) or len(keys)!=16
                or any(not isinstance(k,str) or not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',k) for k in keys)
                or len(set(keys))!=16):raise SafetyError('Exact initial backend filter keys required')
        self.journal=journal;self.keys=list(keys);self.path=journal.directory/self.filename

    def validate(self,value):
        tx=ServiceReceipts(self.journal).transaction()
        observed=isinstance(value,dict) and value.get('schema')==2
        fields={'schema','generation','package_sha256','keys','state'}
        if observed:fields|={'previous_state','completion_basis'}
        if (not isinstance(value,dict) or set(value)!=fields
                or type(value['schema']) is not int or value['schema'] not in (1,2)
                or any(value[k]!=tx[k] for k in ('generation','package_sha256'))
                or value['keys']!=self.keys or value['state'] not in ('intent','committed','remove_intent','removed')):
            raise SafetyError('Initial boundary receipt differs')
        if observed and (value['state']!='removed' or value['completion_basis']!='observed_absence'
                or value['previous_state'] not in ('intent','committed','remove_intent','removed')):
            raise SafetyError('Observed boundary absence must preserve its previous phase')
        return deepcopy(value)

    def load(self):
        ServiceReceipts(self.journal).transaction()
        try:self.path.lstat()
        except FileNotFoundError:return None
        with PinnedFile(self.path,limit=65536) as pin:return self.validate(document(pin.data))

    def record(self,state):
        tx=ServiceReceipts(self.journal).transaction(writing=True);old=self.load()
        if state=='intent':
            if old is not None:raise SafetyError('Existing boundary attempt requires separate recovery')
            value=dict(schema=1,generation=tx['generation'],package_sha256=tx['package_sha256'],keys=self.keys,state=state)
        elif state=='committed':
            if old is None or old['state']!='intent':raise SafetyError('WFP commit requires durable intent')
            value=dict(old,state=state)
        else:raise SafetyError('Unknown initial boundary transition')
        self.save(value)

    def recover_record(self,state):
        tx=ServiceReceipts(self.journal).transaction();old=self.load()
        if (tx['state']!='recovering' or not any(e['step']=='install_services' and e['state'] in ('intent','done') for e in tx['entries'])
                or any(e['step'] in ('verify_installed','fixture_acceptance') and e['state']!='undone' for e in tx['entries'])):
            raise SafetyError('Boundary removal requires ordered service recovery')
        required={'remove_intent':'committed','removed':'remove_intent'}.get(state)
        if required is None or old is None or old['state']!=required:
            raise SafetyError('Unconfirmed boundary creation cannot authorize removal')
        self.save(dict(old,state=state))

    def confirm_absent(self,observation):
        tx=ServiceReceipts(self.journal).transaction();old=self.load()
        active=[e for e in tx['entries'] if e['state']!='undone']
        if (tx['state']!='recovering' or not active or active[-1]['step']!='install_services' or old is None
                or not isinstance(observation,dict) or observation!=dict(keys=self.keys,state='absent',
                    transaction_consistent=True,settings_changed=False,client_admission=False)
                or observation['transaction_consistent'] is not True or observation['settings_changed'] is not False
                or observation['client_admission'] is not False):
            raise SafetyError('Exact fresh boundary absence in ordered recovery required')
        self.save(dict(old,schema=2,state='removed',completion_basis='observed_absence',
                       previous_state=old.get('previous_state',old['state'])))

    def save(self,value):
        value=self.validate(value)
        temporary=self.journal.directory/('boundary-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        if not self.journal.api.MoveFileExW(str(temporary),str(self.path),1|8):
            raise SafetyError('Cannot persist initial boundary receipt')
        if self.load()!=value:raise SafetyError('Initial boundary receipt readback differs')
