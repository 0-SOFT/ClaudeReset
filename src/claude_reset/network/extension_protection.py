"""Exclude exact installed Claude extension binaries through the removal receipt."""

from ..model import jsonc
from . import l1_settings
from ..elevation import launch
from ..errors import SafetyError
from ..safeio import atomic_bytes, atomic_json, guarded
from .strict_wfp import Engine, Identity, deny_rules, relay_permits
from ..windows.system import DPAPI
from .. import config
from .. import layout
from .l1_common import task_state


def remove_owned_settings(paths, *, crypto=None):
    path = guarded(paths.roaming / 'Code/User/settings.json', paths.roaming)
    if not path.exists():
        return
    settings = jsonc.read(path, path.parent)
    env_key = config.VSCODE_ENVIRONMENT
    wrapper_key = config.VSCODE_WRAPPER
    env = settings.get(env_key)
    remaining = ([item for item in env if item not in [
        {'name': name, 'value': value} for name, value in l1_settings.OWNED_ENV]]
        if isinstance(env, list) else env)
    wrapper_owned = settings.get(wrapper_key) == str(l1_settings.runner_path())
    if remaining == env and not wrapper_owned:
        return
    backup = layout.controller(paths) / 'vscode-settings-exclude-before.dpapi'
    if not backup.exists():
        atomic_bytes(backup, (crypto or DPAPI()).encrypt(path.read_bytes()), paths.state)
    if remaining != env:
        jsonc.set_property(path, path.parent, env_key, remaining)
    if wrapper_owned:
        jsonc.set_property(path, path.parent, wrapper_key, '')


def remove_exact_filters(paths, *, engine_factory=Engine, idle=None):
    idle = idle or (lambda: task_state() in ('Ready', 'Disabled', 'Missing'))
    root = guarded(layout.vscode_extensions(paths), paths.home)
    targets = []
    if root.exists():
        for path in sorted(root.glob(layout.EXTENSION_CLI)):
            path = guarded(path, root)
            if path.is_file():
                targets.append(Identity('app', str(path)))
    rules = deny_rules(targets)
    with engine_factory() as engine:
        if not idle():
            raise SafetyError('Controller must be stopped before extension exclusion')
        before = engine.own_keys()
        # A remaining dynamic permit means the old controller is not closed.
        if before.intersection(r.key.value() for r in relay_permits(targets, config.RELAY_PORT)):
            raise SafetyError('Extension relay permits remain')
        selected = [r for r in rules if r.key.value() in before]
        for rule in selected:
            rule.validate()
            if not engine.exists_verified(rule):
                raise SafetyError('Extension filter readback failed')
        with engine.transaction():
            for rule in selected:
                if not engine.exists_verified(rule):
                    raise SafetyError('Extension filter changed')
                engine.delete_filter(rule.key)
            expected = before - {r.key.value() for r in selected}
            if engine.own_keys() != expected or not idle():
                raise SafetyError('Extension removal readback failed')
    return len(selected)


def remove_filters(paths, report_path, *, request_id=None, remove=None):
    """Elevated child: remove the extension's filters and write the receipt; remove is remove_exact_filters."""
    from ..elevation.request import admit_child, child_event
    result = dict(schema=1, finished=False, scope='installed_vscode_extension')
    result.update(admit_child(paths, 'remove', request_id))
    try:
        result['filters_removed'] = (remove or remove_exact_filters)(paths)
        result['removed'] = True
    except Exception:
        result['removed'] = False
        result['error'] = 'extension_filter_removal_failed'
    result['finished'] = True
    child_event(paths, {k: result[k] for k in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def exclude(paths, *, dispatch=None, remove_settings=remove_owned_settings):
    """Leave the extension unprotected: its filters through UAC, then the project settings this program set.
    dispatch shows the UAC prompt (launch.dispatch_request unless given)."""
    from ..elevation.request import execute
    dispatch = dispatch or launch.dispatch_request
    receipt = execute(paths, 'remove', lambda request: dispatch(request, exclude_extension=True))
    if receipt.get('passed') is True:
        remove_settings(paths)
    return receipt
