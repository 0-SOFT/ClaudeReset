"""Validate a narrow sing-box tunnel configuration without provider names.

This is static validation only. A controller must also bind these exact bytes to
a reviewed running engine and enforce its destinations before admitting clients.
Unknown features are rejected, rather than assumed not to add another route.
"""
from __future__ import annotations
import base64
import hashlib
import ipaddress
import json
import re
import uuid
from .safeio import SafetyError

UTLS_FINGERPRINTS = frozenset(('chrome','chrome_psk','chrome_psk_shuffle','chrome_padding_psk_shuffle',
    'chrome_pq','chrome_pq_psk','firefox','edge','safari','360','qq','ios','android','random','randomized'))


def _keys(value,required,optional=()):
    if not isinstance(value,dict) or not set(required)<=set(value)<=set(required)|set(optional):
        raise SafetyError('Unsupported tunnel configuration shape')


def _text(value,limit):
    return isinstance(value,str) and 0<len(value)<=limit and not any(ord(c)<32 or ord(c)==127 for c in value)


def inspect_sing_box(config):
    _keys(config,('log','inbounds','outbounds','route'),('experimental',))
    if config['log']!={'disabled':True} or config['log']['disabled'] is not True:raise SafetyError('Engine logging must be disabled')
    if not isinstance(config['inbounds'],list) or len(config['inbounds'])!=1 or not isinstance(config['outbounds'],list) or len(config['outbounds'])!=1:
        raise SafetyError('Exactly one inbound and one encrypted outbound are supported')
    inbound=config['inbounds'][0];outbound=config['outbounds'][0]
    _keys(inbound,('type','tag','listen','listen_port'))
    if inbound['type'] not in ('http','socks','mixed') or inbound['listen']!='127.0.0.1' or type(inbound['listen_port']) is not int or not 1024<=inbound['listen_port']<49152 or not _text(inbound['tag'],64):
        raise SafetyError('One dedicated IPv4 loopback proxy is required')
    _keys(outbound,('type','tag','server','server_port','uuid','tls'),('transport','flow'))
    if outbound['type']!='vless' or not _text(outbound['tag'],64) or config['route']!={'final':outbound['tag']}:
        raise SafetyError('The only final route must be the selected encrypted outbound')
    try:
        address=ipaddress.ip_address(outbound['server'])
        if address.version!=4 or not address.is_global or str(address)!=outbound['server']:raise ValueError()
        if type(outbound['server_port']) is not int or not 1<=outbound['server_port']<=65535:raise ValueError()
        if str(uuid.UUID(outbound['uuid']))!=outbound['uuid'].lower():raise ValueError()
    except (ValueError,TypeError,AttributeError):raise SafetyError('A literal public peer and valid credentials are required') from None
    if outbound.get('flow','') not in ('','xtls-rprx-vision'):raise SafetyError('Unsupported VLESS flow')
    tls=outbound['tls'];_keys(tls,('enabled','server_name','reality','utls'))
    if tls['enabled'] is not True or not _text(tls['server_name'],253) or not re.fullmatch(r'[A-Za-z0-9.-]+',tls['server_name']):
        raise SafetyError('Verified TLS with an explicit server name is required')
    reality=tls['reality'];_keys(reality,('enabled','public_key','short_id'))
    try:
        key=reality['public_key']
        if reality['enabled'] is not True or not isinstance(key,str) or not re.fullmatch('[A-Za-z0-9_-]{43}',key):raise ValueError()
        decoded=base64.urlsafe_b64decode(key+'=')
        if len(decoded)!=32 or base64.urlsafe_b64encode(decoded).decode().rstrip('=')!=key:raise ValueError()
        if not isinstance(reality['short_id'],str) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}',reality['short_id']):raise ValueError()
    except (ValueError,TypeError):raise SafetyError('Invalid pinned Reality identity') from None
    if 'utls' in tls:
        _keys(tls['utls'],('enabled','fingerprint'))
        if (tls['utls']['enabled'] is not True or not isinstance(tls['utls']['fingerprint'],str)
                or tls['utls']['fingerprint'] not in UTLS_FINGERPRINTS):raise SafetyError('Invalid uTLS settings')
    if 'transport' in outbound:
        _keys(outbound['transport'],('type','service_name'))
        if outbound['transport']['type']!='grpc' or not _text(outbound['transport']['service_name'],256):raise SafetyError('Only the reviewed gRPC transport subset is supported')
    if 'experimental' in config:
        _keys(config['experimental'],('clash_api',));api=config['experimental']['clash_api']
        _keys(api,('external_controller','secret'))
        match=re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})',api['external_controller']) if isinstance(api['external_controller'],str) else None
        if not match or not 1024<=int(match[1])<49152 or int(match[1])==inbound['listen_port'] or not _text(api['secret'],512):
            raise SafetyError('Controller must be authenticated on a separate loopback port')
    # No peer address, UUID, key, service name or controller secret in the result.
    return {'schema':1,'status':'supported_static_configuration','passed':True,
        'adapter':'sing_box_vless_reality_v1','inbound_protocol':inbound['type'],
        'config_sha256':hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'single_encrypted_route':True,'runtime_engine_verified':False,
        'client_network_opened':False,'full_tunnel_verified':False}
