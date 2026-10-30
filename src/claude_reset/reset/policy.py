"""A saved policy approves exact discovered scopes, never future unknown paths."""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from ..errors import SafetyError
from ..model.ids import utc_now
from ..model.notes import Note
from ..model.reset import Selection
from ..safeio import atomic_bytes, guarded
from ..windows.dpapi import DPAPI
from .planner import build_plan

__all__ = ['policy_plan', 'save_policy']


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


def save_policy(path: Path, plan, *, consent_id, crypto=DPAPI()):
    if consent_id != plan.id or plan.blockers or not plan.actions:
        raise SafetyError('A reviewed, unblocked plan is required to save policy')
    selection = asdict(plan.selection)
    selection['profiles'] = [p.path for p in plan.inventory.profiles if p.selected]
    obj = {'schema': 1, 'created_utc': utc_now(),
           'components': list(plan.components), 'selection': selection, 'catalog': catalog(plan),
           'versions': plan.versions, 'automatic_local_reset': True,
           'server_confirmation': 'required_for_each_run'}
    data = crypto.encrypt(json.dumps(obj, ensure_ascii=False).encode('utf-8'))
    if json.loads(crypto.decrypt(data)) != json.loads(json.dumps(obj)):
        raise SafetyError('Policy encryption verification failed')
    atomic_bytes(path, data, path.parent)


def policy_plan(paths, path: Path, *, crypto=DPAPI(), platform_state=None, env=os.environ):
    guarded(path, path.parent)
    if path.stat().st_size > 4_000_000:
        raise SafetyError('Policy size limit exceeded')
    try:
        obj = json.loads(crypto.decrypt(path.read_bytes()))
        if obj['schema'] != 1 or obj['automatic_local_reset'] is not True or obj['server_confirmation'] != 'required_for_each_run':
            raise ValueError()
        selection = Selection(**obj['selection'])
        plan = build_plan(paths, obj['components'], selection=selection, platform_state=platform_state, env=env)
        if json.loads(json.dumps(catalog(plan))) != obj['catalog']:
            plan = plan.with_blockers(Note('plan.policy_profiles_changed'))
        if plan.versions != obj['versions']:
            plan = plan.with_blockers(Note('plan.policy_versions_changed'))
        return plan
    except (KeyError, TypeError, ValueError, OSError):
        raise SafetyError('Saved policy cannot be read safely') from None
