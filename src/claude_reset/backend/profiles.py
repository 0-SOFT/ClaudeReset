"""Encrypted, inactive tunnel profiles. Import never selects or starts a route."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..errors import SafetyError
from ..model.ids import new_id
from ..model.jsonc import strict_loads
from ..model.records import EngineProfile, exact
from ..model.status import Backend
from ..safeio import atomic_bytes, guarded, local_path, local_volume
from ..windows.dpapi import DPAPI
from .attestation import inspect_sing_box

__all__ = ['LIMIT', 'catalog', 'decode', 'import_profile', 'load', 'status', 'summary']

LIMIT = 65536


def decode(data):
    profile = strict_loads(data, limit=LIMIT, too_large='Backend profile size limit exceeded',
                           invalid='Invalid backend profile', encoding='utf-8-sig')
    try:
        return validate(profile)
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise SafetyError('Invalid backend profile') from None


def validate(profile):
    if not exact(profile, EngineProfile):
        raise SafetyError('Missing or unsupported backend profile fields')
    if type(profile['schema']) is not int or profile['schema'] != 1 or profile['adapter'] != 'sing_box_vless_reality_v1':
        raise SafetyError('Unsupported backend adapter or schema')
    local_path(profile['engine_path'])
    if not isinstance(profile['engine_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', profile['engine_sha256']):
        raise SafetyError('Exact engine SHA-256 required')
    if not isinstance(profile['engine_version'], str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', profile['engine_version']):
        raise SafetyError('Exact stable engine version required')
    try:
        inspect_sing_box(profile['config'])
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise SafetyError('Invalid tunnel configuration') from None
    return profile


def summary(identifier, profile):
    result = inspect_sing_box(profile['config'])
    # These are claims bound to imported bytes, not executable/runtime acceptance.
    return {'schema': 1, 'profile_id': identifier, 'status': Backend.IMPORTED_INACTIVE,
        'adapter': profile['adapter'], 'declared_engine_version': profile['engine_version'],
        'declared_engine_sha256': profile['engine_sha256'], 'config_sha256': result['config_sha256'],
        'engine_build_verified': False, 'runtime_engine_verified': False,
        'selected': False, 'client_network_opened': False, 'full_tunnel_verified': False}


def import_profile(paths, file, *, crypto=DPAPI()):
    # Reject remote paths before opening: importing must not itself contact SMB.
    file = Path(file)
    local_path(str(file))
    local_volume(file)
    file = guarded(file, file.parent)
    with file.open('rb') as stream:
        profile = decode(stream.read(LIMIT + 1))
    payload = json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(payload) > LIMIT:
        raise SafetyError('Backend profile size limit exceeded')
    identifier = new_id()
    root = paths.state / 'backend-profiles'
    atomic_bytes(root / (identifier + '.dpapi'), crypto.encrypt(payload), paths.state)
    return summary(identifier, profile)


def load(paths, identifier, *, crypto=DPAPI()):
    if not isinstance(identifier, str) or not re.fullmatch('[a-f0-9]{32}', identifier):
        raise SafetyError('Invalid backend profile ID')
    file = guarded(paths.state / 'backend-profiles' / (identifier + '.dpapi'), paths.state)
    with file.open('rb') as stream:
        encrypted = stream.read(LIMIT * 2 + 1)
    if len(encrypted) > LIMIT * 2:
        raise SafetyError('Encrypted backend size limit exceeded')
    return decode(crypto.decrypt(encrypted))


def status(paths, identifier, *, crypto=DPAPI()):
    return summary(identifier, load(paths, identifier, crypto=crypto))


def catalog(paths, *, crypto=DPAPI()):
    root = guarded(paths.state / 'backend-profiles', paths.state)
    rows = []
    if root.exists():
        identifiers = []
        for count, file in enumerate(root.iterdir()):
            if count >= 1024:
                raise SafetyError('Backend profile inventory limit exceeded')
            if re.fullmatch('[a-f0-9]{32}[.]dpapi', file.name):
                identifiers.append(file.stem)
        for identifier in sorted(identifiers):
            try:
                rows.append(status(paths, identifier, crypto=crypto))
            except (SafetyError, OSError):
                rows.append({'profile_id':identifier,'status':Backend.UNREADABLE_OR_INVALID,
                             'selected':False,'client_network_opened':False})
    return {'schema':1,'profiles':rows,'selected_profile':None,'client_admission':False,
            'status':Backend.INACTIVE_INVENTORY,'network_requests':0}
