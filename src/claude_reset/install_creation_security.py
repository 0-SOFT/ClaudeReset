"""Read-only checks for a disabled, stopped creation that never became ready.

These checks are only prerequisites for a separate ownership-bound cleanup.
They cannot attest an installed/runnable service or authorize client admission.
Completed service/key security validators remain stricter and unchanged.
"""
from .install_scm import validate_spec
from .service_store import OWNERS
from .safeio import SafetyError


def _rules(row,flags):
    if (not isinstance(row,dict) or not isinstance(row.get('owner'),str) or row['owner'] not in OWNERS
            or row.get('dacl_present') is not True or row.get('dacl_null') is not False
            or not isinstance(row.get('rules'),list) or not row['rules']):
        raise SafetyError('Pending creation has untrusted owner or unavailable security')
    for rule in row['rules']:
        if (not isinstance(rule,dict) or set(rule)!={'sid','mask','type','flags'}
                or not isinstance(rule['sid'],str) or type(rule['mask']) is not int or not 0<=rule['mask']<=0xFFFFFFFF
                or type(rule['type']) is not int or rule['type']!=0
                or type(rule['flags']) is not int or rule['flags'] not in flags):
            raise SafetyError('Unsupported pending-creation permission')
    return row['rules']


def validate_pending_service(spec,actual):
    spec=validate_spec(spec)
    if not isinstance(actual,dict):raise SafetyError('Pending service configuration unavailable')
    for key in ('name','binary','type','start','error','account','group','dependencies'):
        if type(actual.get(key)) is not type(spec[key]) or actual[key]!=spec[key]:
            raise SafetyError('Pending creation specification differs: '+key)
    if (type(actual.get('state')) is not int or actual['state']!=1
            or type(actual.get('pid')) is not int or actual['pid']!=0
            or type(actual.get('sid_type')) is not int or actual['sid_type'] not in (0,spec['sid_type'])):
        raise SafetyError('Pending service must be stopped and have an initial or final SID type')
    rights={sid:0 for sid in OWNERS}
    for rule in _rules(actual,{0}):
        if rule['sid'] in rights:rights[rule['sid']]|=rule['mask']
        # Documented default read/interrogate/enumerate/user-defined-control
        # rights are tolerated ONLY for this Disabled/Stopped cleanup check.
        elif rule['mask'] & ~0x2018D:
            raise SafetyError('Untrusted principal can alter or start pending service')
    if rights['S-1-5-32-544']&0xF01FF!=0xF01FF or rights['S-1-5-18']&0x20005!=0x20005:
        raise SafetyError('Pending service administrative control is incomplete')
    return True


def validate_pending_key(actual):
    if not isinstance(actual,dict) or type(actual.get('protected')) is not bool:
        raise SafetyError('Pending service key inheritance state unavailable')
    rights={sid:0 for sid in OWNERS}
    for rule in _rules(actual,{0,2,16,18}):
        if rule['sid'] in rights:rights[rule['sid']]|=rule['mask']
        elif rule['mask'] & ~0x20019:
            raise SafetyError('Untrusted principal can modify pending service registry key')
    if any(mask&0xF003F!=0xF003F for mask in rights.values()):
        raise SafetyError('Pending registry key administrative control is incomplete')
    return True
