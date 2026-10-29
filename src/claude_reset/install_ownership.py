"""Exact ownership matching for future upgrade/repair; no service control.

The caller must read the record from administrator-owned, protected storage.
A matching name or path alone is never an ownership proof. These comparisons
do not authorize unloading a busy driver or reopening client traffic.
"""
import re
from pathlib import Path
from .install_payload import catalog
from .install_inventory import SERVICES
from .safeio import SafetyError


def record(value):
    if (not isinstance(value,dict) or set(value)!={'schema','product','generation','version','package_sha256','files'}
            or type(value['schema']) is not int or value['schema']!=1 or value['product']!='ClaudeReset'):
        raise SafetyError('Invalid protected ownership record')
    for key,pattern in [('generation','[a-f0-9]{32}'),('package_sha256','[a-f0-9]{64}'),
                        ('version',r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')]:
        if not isinstance(value[key],str) or not re.fullmatch(pattern,value[key]):
            raise SafetyError('Invalid installation identity')
    catalog(value['files'])
    return value


def configurations(root):
    root=Path(root)
    return {
        'ClaudeResetBackend':{'image':'Backend/ClaudeResetBackend.exe','binary':'"'+str(root/'Backend/ClaudeResetBackend.exe')+'" --service','type':16,'start':3,'account':'LocalSystem'},
        'ClaudeResetGateway':{'image':'Gateway/ClaudeResetGateway.exe','binary':'"'+str(root/'Gateway/ClaudeResetGateway.exe')+'" --service','type':16,'start':3,'account':'LocalSystem'},
        'SbieSvc':{'image':'Sandboxie/x64/SbieSvc.exe','binary':'"'+str(root/'Sandboxie/x64/SbieSvc.exe')+'"','type':16,'start':3,'account':'LocalSystem'},
        'SbieDrv':{'image':'Sandboxie/x64/SbieDrv.sys','binary':'\\??\\'+str(root/'Sandboxie/x64/SbieDrv.sys'),'type':1,'start':3,'account':''},
    }


def assess(value, rows, file_hashes, root):
    """Compare a previously authenticated record with a fresh fixed-slot snapshot.

    A result with all matches is only an ownership comparison. Token, service
    DACL/SID type, policy, signatures, driver users and current clients still
    require their own checks before a privileged adapter may mutate anything.
    """
    value=record(value)
    if (not isinstance(rows,list) or len(rows)!=len(SERVICES)
            or any(not isinstance(row,dict) for row in rows)
            or [row.get('name') for row in rows]!=list(SERVICES)
            or not isinstance(file_hashes,dict)):
        raise SafetyError('Incomplete ownership inventory')
    expected=configurations(root); mismatches=[]; busy=[]
    for row in rows:
        name=row['name']; wanted=expected[name]
        if row.get('exists') is not True:
            mismatches.append({'resource':name,'reason':'missing_service'})
            continue
        if any(type(row.get(k)) is not type(wanted[k]) or row[k]!=wanted[k]
               for k in ('binary','type','start','account')):
            mismatches.append({'resource':name,'reason':'service_configuration_changed'})
        if (type(row.get('state')) is not int or row['state']!=1
                or type(row.get('pid')) is not int or row['pid']!=0):
            busy.append(name)
    for name,metadata in value['files'].items():
        if file_hashes.get(name)!=metadata['sha256']:
            mismatches.append({'resource':name,'reason':'file_missing_or_changed'})
    for name in file_hashes.keys()-value['files'].keys():
        mismatches.append({'resource':name,'reason':'unrecorded_file'})
    return {'schema':1,'generation':value['generation'],'ownership_fields_match':not mismatches,
            'mismatches':mismatches,'busy_services':busy,'may_mutate':False,
            'driver_unload_authorized':False,'client_admission':False,
            'limits':['Record authentication and protected ACL checks are required separately.',
                      'Matched fields do not establish service SID/DACL, signature or policy acceptance.',
                      'A busy or mismatched installation is never forcibly stopped or adopted.']}
