"""Provider-independent, strict configuration for the native gateway service.

This describes a pinned local process, not proof that that process implements the
user's tunnel. It does not install a service, change networking or authorize apps.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import PureWindowsPath
import re
from .safeio import SafetyError

KEYS=frozenset(('schema','protocol','backend_port','listen_port','engine_pid',
    'engine_start_utc_ticks','engine_path','engine_sha256','engine_config_path','engine_config_sha256',
    'generation','controller_pid','controller_start_utc_ticks','controller_path','controller_sha256'))


def local_path(value):
    if (not isinstance(value,str) or not re.match(r'\A[A-Za-z]:\\',value)
            or len(value)>32760 or any(c in value for c in '\r\n\0/') or ':' in value[2:]
            or any(part in ('.','..') or part.endswith((' ','.')) for part in value[3:].split('\\'))
            or any(re.match(r'(?i)\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\Z)', part) for part in value[3:].split('\\'))
            or str(PureWindowsPath(value)).casefold()!=value.casefold()):
        raise SafetyError('A canonical local absolute file path is required')
    if not PureWindowsPath(value).name:
        raise SafetyError('A file path is required')
    return value


def validate(profile):
    if not isinstance(profile,dict) or set(profile)!=KEYS:
        raise SafetyError('Gateway schema contains missing or unknown keys')
    for key,low,high in [('schema',2,2),('backend_port',1024,49151),('listen_port',1024,49151),
                         ('engine_pid',1,2147483647),('engine_start_utc_ticks',1,3155378975999999999),
                         ('controller_pid',1,2147483647),('controller_start_utc_ticks',1,3155378975999999999)]:
        if type(profile[key]) is not int or not low<=profile[key]<=high:
            raise SafetyError('Invalid gateway integer: '+key)
    if profile['protocol'] not in ('http','socks5') or profile['listen_port']==profile['backend_port']:
        raise SafetyError('Use HTTP CONNECT or SOCKS5 on a distinct local port')
    if (profile['controller_pid']==profile['engine_pid'] or not isinstance(profile['generation'],str)
            or not re.fullmatch('[a-f0-9]{32}',profile['generation'])):
        raise SafetyError('Distinct process generations and a fresh session identifier are required')
    for key in ('engine_path','engine_config_path','controller_path'):local_path(profile[key])
    if PureWindowsPath(profile['controller_path']).name != 'ClaudeResetRuntime.exe':
        raise SafetyError('The dedicated runtime controller is required')
    for key in ('engine_sha256','engine_config_sha256','controller_sha256'):
        if not isinstance(profile[key],str) or not re.fullmatch('[a-f0-9]{64}',profile[key]):
            raise SafetyError('An exact SHA-256 is required')
    return dict(profile)


def decode(data):
    if not isinstance(data,bytes) or len(data)>16384:
        raise SafetyError('Gateway configuration size limit exceeded')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise SafetyError('Duplicate gateway configuration key')
            result[key]=value
        return result
    try:return validate(json.loads(data.decode('utf-8-sig'),object_pairs_hook=unique))
    except (UnicodeError,ValueError,TypeError):raise SafetyError('Invalid gateway configuration') from None


def encode(profile):
    return json.dumps(validate(profile),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def installation_plan(profile, image_sha256):
    data=encode(profile)
    if not isinstance(image_sha256,str) or not re.fullmatch('[a-f0-9]{64}',image_sha256):
        raise SafetyError('An exact gateway build hash is required')
    return {'schema':1,'service':'ClaudeResetGateway','status':'prepared_not_installed',
            'backend_service':'ClaudeResetBackend','backend_token_user':'S-1-5-18',
            'backend_service_installed_verified':False,
            'config_sha256':hashlib.sha256(data).hexdigest(),'image_sha256':image_sha256,
            'listen_port':profile['listen_port'],'protocol':profile['protocol'],
            'requires_administrator':True,'client_network_opened':False,
            'backend_tunnel_attested':False,'full_tunnel_verified':False,
            'steps':['validate_and_lock_reviewed_inputs','create_protected_service_store',
                     'create_dedicated_service_sid','create_dedicated_backend_service_sid',
                     'verify_backend_endpoint_denies_before_start','reserve_exact_tcp_port',
                     'read_back_service_acl_and_reservation','start_and_probe_service',
                     'keep_clients_closed_until_broker_and_client_acceptance'],
            'rollback':'stop_owned_service_keep_client_denies_remove_only_verified_owned_objects'}
