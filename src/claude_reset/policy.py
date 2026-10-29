"""A saved policy approves exact discovered scopes, never future unknown paths."""
from __future__ import annotations
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from .discovery import Selection
from .planner import build_plan
from .safeio import SafetyError, guarded, atomic_bytes
from .windows import DPAPI


def catalog(plan):
    result = []
    if plan.inventory is None:
        raise SafetyError('A complete inventory is required to save policy')
    for profile in plan.inventory.profiles:
        if profile.source == 'managed_chrome':
            continue  # Tool-created output is never a future deletion target.
        result.append((profile.component, profile.path, profile.source, profile.selected))
        if profile.component == 'vscode':
            named = guarded(Path(profile.path) / 'profiles', Path(profile.path))
            if named.exists():
                for child in named.iterdir():
                    if child.is_dir():
                        result.append(('vscode-named', str(guarded(child, named)), profile.source, profile.selected))
    return sorted(result)


def save_policy(path: Path, plan, *, consent_id, crypto=None):
    if consent_id != plan.id or plan.blockers or not plan.actions:
        raise SafetyError('A reviewed, unblocked plan is required to save policy')
    selection = asdict(plan.selection)
    selection['profiles'] = [p.path for p in plan.inventory.profiles if p.selected]
    obj = {'schema': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
           'components': plan.components, 'selection': selection, 'catalog': catalog(plan),
           'versions': plan.versions, 'automatic_local_reset': True,
           'server_confirmation': 'required_for_each_run'}
    crypto = crypto or DPAPI()
    data = crypto.encrypt(json.dumps(obj, ensure_ascii=False).encode('utf-8'))
    if json.loads(crypto.decrypt(data)) != json.loads(json.dumps(obj)):
        raise SafetyError('Policy encryption verification failed')
    atomic_bytes(path, data, path.parent)


def policy_plan(paths, path: Path, *, crypto=None, platform_state=None, env=None):
    guarded(path, path.parent)
    if path.stat().st_size > 4_000_000:
        raise SafetyError('Policy size limit exceeded')
    try:
        obj = json.loads((crypto or DPAPI()).decrypt(path.read_bytes()))
        if obj['schema'] != 1 or obj['automatic_local_reset'] is not True or obj['server_confirmation'] != 'required_for_each_run':
            raise ValueError()
        selection = Selection(**obj['selection'])
        plan = build_plan(paths, obj['components'], selection=selection, platform_state=platform_state, env=env)
        if json.loads(json.dumps(catalog(plan))) != obj['catalog']:
            plan.blockers.append('Discovered profiles changed since policy approval; review and save a new policy')
        if plan.versions != obj['versions']:
            plan.blockers.append('Client versions changed since policy approval')
        return plan
    except (KeyError, TypeError, ValueError, OSError):
        raise SafetyError('Saved policy cannot be read safely') from None
