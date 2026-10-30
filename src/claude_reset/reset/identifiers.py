"""Run-scoped HMAC comparisons; raw identifiers never enter a report or journal."""
from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
from pathlib import Path
from ..model import jsonc
from ..errors import SafetyError
from ..safeio import guarded
from .. import layout
from ..model.status import Identifier


def targets(plan, paths):
    result = []
    for action in plan.actions:
        target = Path(action.target)
        if action.kind == 'reset_code':
            for file in [target / layout.CODE_CONFIG] + ([layout.code_config(paths)] if target == layout.code_home(paths) else []):
                for field in ('userID', 'machineID', 'summonSidKey'):
                    result.append((file, field, 'code'))
        elif action.component == 'desktop' and target.name == 'ant-did':
            result.append((target, 'file', 'desktop'))
    return result


def value(path, field):
    guarded(path, path.parent)
    if not path.exists():
        return None
    if path.stat().st_size > 20_000_000:
        raise SafetyError('Identifier source size limit exceeded')
    if field == 'file':
        return path.read_bytes()
    obj = jsonc.read(path, path.parent)
    result = obj.get(field)
    if result is None:
        return None
    if not isinstance(result, str):
        raise SafetyError('Unknown identifier schema')
    return result.encode('utf-8')


def digest(key, content):
    return hmac.new(key, content, hashlib.sha256).hexdigest() if content is not None else None


def baseline(plan, paths):
    key = secrets.token_bytes(32)
    return {'schema': 1, 'key': base64.b64encode(key).decode('ascii'),
            'values': [digest(key, value(path, field)) for path, field, _ in targets(plan, paths)]}


def compare(plan, paths, before):
    if before.get('schema') != 1:
        raise SafetyError('Unknown identifier comparison schema')
    try:
        key = base64.b64decode(before['key'], validate=True)
    except (KeyError, ValueError, TypeError):
        raise SafetyError('Invalid comparison key') from None
    items = targets(plan, paths)
    if len(key) != 32 or len(items) != len(before.get('values', [])):
        raise SafetyError('Comparison does not match the run scope')
    results = []
    for (path, field, component), old in zip(items, before['values']):
        current = digest(key, value(path, field))
        if old is None:
            status = Identifier.NEW_VALUE_OBSERVED_NO_OLD_BASELINE if current else Identifier.NOT_OBSERVED
        elif current is None:
            status = Identifier.OLD_VALUE_REMOVED_NEW_VALUE_NOT_OBSERVED
        else:
            status = Identifier.UNCHANGED if hmac.compare_digest(old, current) else Identifier.CHANGED
        results.append({'component': component, 'field': 'installation_id' if field == 'file' else field, 'status': status})
    return {'run': plan.id, 'scope': 'known local identifier fields only', 'comparisons': results,
            'account_and_organization_verified': False, 'desktop_key_verified': False,
            'ready_for_new_account': False}
