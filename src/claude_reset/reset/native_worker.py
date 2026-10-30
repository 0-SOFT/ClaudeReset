"""Short-lived package-identity worker; IPC is authenticated by user DPAPI."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .. import layout
from ..errors import SafetyError, error_kind
from ..safeio import atomic_bytes, guarded
from ..windows.cng import KEY_PATTERN, Provider, package_identity, selftest
from ..windows.dpapi import DPAPI

__all__ = ['FAMILY', 'main']

FAMILY = 'Claude_pzs8sxrjxfjjc'


def dispatch(request):
    if request.get('schema') != 1 or request.get('family') != FAMILY or package_identity() != FAMILY:
        raise SafetyError('Native worker package identity mismatch')
    if not time.time() < request.get('expires', 0) <= time.time() + 120:
        raise SafetyError('Native request expired')
    if request.get('operation') == 'selftest':
        return selftest(FAMILY)
    with Provider() as provider:
        if request.get('operation') == 'inventory':
            keys = []
            unknown = 0
            for name, algorithm, flags in provider.names():
                if not name.startswith('Claude-HwKey-'):
                    continue
                match = KEY_PATTERN.fullmatch(name)
                if not match or algorithm not in ('ECDSA', 'ECDSA_P256') or flags & 0x20:
                    unknown += 1
                    continue
                keys.append({'name': name, 'account': match[1], 'generation': int(match[2] or 0),
                             'public_digest': provider.public_digest(name)})
            return {'keys': sorted(keys, key=lambda x: x['name']), 'unknown_application_keys': unknown}
        if request.get('operation') == 'delete':
            provider.delete_selected(request['name'], request['public_digest'])
            return {'deleted_key_absent': True}
    raise SafetyError('Unsupported native operation')


def main(request_path):
    path = Path(request_path)
    # Only this tool's unique IPC subdirectory; never accept arbitrary output paths.
    root = layout.ipc_home()
    guarded(path, root)
    if path.name != 'request.dpapi' or not re.fullmatch('[a-f0-9]{32}', path.parent.name):
        raise SafetyError('Invalid native IPC path')
    if path.stat().st_size > 65536:
        raise SafetyError('Native request too large')
    crypto = DPAPI()
    request = json.loads(crypto.decrypt(path.read_bytes()))
    try:
        result = {'ok': True, 'payload': dispatch(request)}
    except Exception as exc:
        result = {'ok': False, 'error_type': error_kind(exc)}
    result['nonce'] = request.get('nonce')
    atomic_bytes(path.parent / 'response.dpapi', crypto.encrypt(json.dumps(result).encode()), root)
    return 0 if result['ok'] else 1
