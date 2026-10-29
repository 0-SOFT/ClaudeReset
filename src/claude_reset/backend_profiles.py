"""Encrypted, inactive tunnel profiles. Import never selects or starts a route."""
from __future__ import annotations
import json
from pathlib import Path
import re
import uuid
from .backend_attestation import inspect_sing_box
from .gateway_profile import local_path
from .safeio import SafetyError, atomic_bytes, guarded, local_volume
from .windows import DPAPI

LIMIT = 65536
KEYS = {'schema', 'adapter', 'engine_path', 'engine_sha256', 'engine_version', 'config'}


def decode(data):
    if not isinstance(data, bytes) or len(data) > LIMIT:
        raise SafetyError('Backend profile size limit exceeded')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        profile = json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique)
        return validate(profile)
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise SafetyError('Invalid backend profile') from None


def validate(profile):
    if not isinstance(profile, dict) or set(profile) != KEYS:
        raise SafetyError('Missing or unsupported backend profile fields')
    if type(profile['schema']) is not int or profile['schema'] != 1 or profile['adapter'] != 'sing_box_vless_reality_v1':
        raise SafetyError('Unsupported backend adapter or schema')
    local_path(profile['engine_path'])
    if not isinstance(profile['engine_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', profile['engine_sha256']):
        raise SafetyError('Exact engine SHA-256 required')
    if not isinstance(profile['engine_version'], str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', profile['engine_version']):
        raise SafetyError('Exact stable engine version required')
    try: inspect_sing_box(profile['config'])
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise SafetyError('Invalid tunnel configuration') from None
    return profile


def summary(identifier, profile):
    result = inspect_sing_box(profile['config'])
    # These are claims bound to imported bytes, not executable/runtime acceptance.
    return {'schema': 1, 'profile_id': identifier, 'status': 'imported_inactive',
        'adapter': profile['adapter'], 'declared_engine_version': profile['engine_version'],
        'declared_engine_sha256': profile['engine_sha256'], 'config_sha256': result['config_sha256'],
        'engine_build_verified': False, 'runtime_engine_verified': False,
        'selected': False, 'client_network_opened': False, 'full_tunnel_verified': False}


def import_profile(paths, file, *, crypto=None):
    # Reject remote paths before opening: importing must not itself contact SMB.
    file = Path(file)
    local_path(str(file))
    local_volume(file)
    file = guarded(file, file.parent)
    with file.open('rb') as stream: profile = decode(stream.read(LIMIT + 1))
    payload = json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(payload) > LIMIT: raise SafetyError('Backend profile size limit exceeded')
    identifier = uuid.uuid4().hex
    root = paths.state / 'backend-profiles'
    atomic_bytes(root / (identifier + '.dpapi'), (crypto or DPAPI()).encrypt(payload), paths.state)
    return summary(identifier, profile)


def load(paths, identifier, *, crypto=None):
    if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
        raise SafetyError('Invalid backend profile ID')
    file = guarded(paths.state / 'backend-profiles' / (identifier + '.dpapi'), paths.state)
    with file.open('rb') as stream: encrypted = stream.read(LIMIT * 2 + 1)
    if len(encrypted) > LIMIT * 2: raise SafetyError('Encrypted backend size limit exceeded')
    return decode((crypto or DPAPI()).decrypt(encrypted))


def status(paths, identifier, *, crypto=None):
    return summary(identifier, load(paths, identifier, crypto=crypto))


def catalog(paths, *, crypto=None):
    root = guarded(paths.state / 'backend-profiles', paths.state)
    rows = []
    if root.exists():
        identifiers = []
        for count, file in enumerate(root.iterdir()):
            if count >= 1024: raise SafetyError('Backend profile inventory limit exceeded')
            if re.fullmatch('[a-f0-9]{32}[.]dpapi', file.name): identifiers.append(file.stem)
        for identifier in sorted(identifiers):
            try: rows.append(status(paths, identifier, crypto=crypto))
            except (SafetyError, OSError):
                rows.append({'profile_id':identifier,'status':'unreadable_or_invalid',
                             'selected':False,'client_network_opened':False})
    return {'schema':1,'profiles':rows,'selected_profile':None,'client_admission':False,
            'status':'inactive_inventory','network_requests':0}
