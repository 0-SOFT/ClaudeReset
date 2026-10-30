"""Provider-independent, strict configuration for the native gateway service.

This describes a pinned local process, not proof that that process implements the
user's tunnel. It does not install a service, change networking or authorize apps.
"""
from __future__ import annotations
import json
from pathlib import PureWindowsPath
import re
from ..errors import SafetyError
from ..model.records import GatewayProfile, exact
from ..safeio import local_path



def validate(profile):
    if not exact(profile, GatewayProfile):
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
    for key in ('engine_path','engine_config_path','controller_path'):
        local_path(profile[key])
    if PureWindowsPath(profile['controller_path']).name != 'ClaudeResetRuntime.exe':
        raise SafetyError('The dedicated runtime controller is required')
    for key in ('engine_sha256','engine_config_sha256','controller_sha256'):
        if not isinstance(profile[key],str) or not re.fullmatch('[a-f0-9]{64}',profile[key]):
            raise SafetyError('An exact SHA-256 is required')
    return dict(profile)


def encode(profile):
    return json.dumps(validate(profile),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
