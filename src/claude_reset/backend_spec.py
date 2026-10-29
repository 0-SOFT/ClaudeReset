"""Strict, inactive installation inputs for the owned backend service.

Imported hashes are claims. Only the engine catalog compiled into the runtime
can authorize engine bytes; no path or command is accepted from this document.
"""
import hashlib
import ipaddress
import json
import re
from .backend_attestation import inspect_sing_box
from .compatibility import DEPENDENCIES
from .safeio import SafetyError

ENGINES = DEPENDENCIES['sing-box']['windows_amd64_images']
KEYS = {'schema', 'profile_id', 'engine_version', 'engine_sha256',
        'engine_config_sha256', 'runtime_sha256', 'gateway_sha256',
        'peer_address', 'peer_port', 'backend_port', 'gateway_port', 'expected_exit_ips'}


def document(data, limit=65536):
    if not isinstance(data, bytes) or len(data) > limit:
        raise SafetyError('Backend document size limit exceeded')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise SafetyError('Invalid backend document') from None


def public_address(value, *, ipv4=False):
    try:
        address = ipaddress.ip_address(value) if isinstance(value, str) else None
        if (address is None or not address.is_global or str(address) != value
                or '%' in value or (ipv4 and address.version != 4)):
            raise ValueError()
    except ValueError:
        raise SafetyError('A canonical public IP address is required') from None
    return value


def validate(spec):
    if not isinstance(spec, dict) or set(spec) != KEYS or type(spec['schema']) is not int or spec['schema'] != 1:
        raise SafetyError('Unsupported backend service schema')
    if not isinstance(spec['profile_id'], str) or not re.fullmatch('[a-f0-9]{32}', spec['profile_id']):
        raise SafetyError('Exact profile identity required')
    for key in ('engine_sha256', 'engine_config_sha256', 'runtime_sha256', 'gateway_sha256'):
        if not isinstance(spec[key], str) or not re.fullmatch('[a-f0-9]{64}', spec[key]):
            raise SafetyError('Exact backend artifact hashes required')
    if not isinstance(spec['engine_version'], str) or ENGINES.get(spec['engine_version']) != spec['engine_sha256']:
        raise SafetyError('Engine is absent from the verified build catalog')
    public_address(spec['peer_address'], ipv4=True)
    if (type(spec['peer_port']) is not int or not 1 <= spec['peer_port'] <= 65535
            or any(type(spec[k]) is not int or not 1024 <= spec[k] < 49152 for k in ('backend_port', 'gateway_port'))
            or spec['backend_port'] == spec['gateway_port']):
        raise SafetyError('Invalid dedicated backend ports')
    exits = spec['expected_exit_ips']
    if not isinstance(exits, list) or not 1 <= len(exits) <= 16:
        raise SafetyError('Explicit expected tunnel exits required')
    for value in exits: public_address(value)
    if len(set(exits)) != len(exits): raise SafetyError('Duplicate tunnel exits')
    return {**spec, 'expected_exit_ips': list(exits)}


def bind_config(spec, data):
    """Bind exact on-disk bytes and all allowed endpoints before any launch."""
    spec = validate(spec)
    config = document(data)
    inspect_sing_box(config)
    if 'experimental' in config:
        raise SafetyError('Service controller listeners are not supported')
    inbound, outbound = config['inbounds'][0], config['outbounds'][0]
    if (hashlib.sha256(data).hexdigest() != spec['engine_config_sha256']
            or inbound['listen_port'] != spec['backend_port']
            or outbound['server'] != spec['peer_address']
            or outbound['server_port'] != spec['peer_port']):
        raise SafetyError('Engine configuration differs from the protected service specification')
    return 'socks5' if inbound['type'] == 'socks' else 'http'


def decode(data):
    return validate(document(data, 16384))
