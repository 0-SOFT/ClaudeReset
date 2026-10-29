"""Exclude exact installed Claude extension binaries through the removal receipt."""
import ctypes

from . import jsonc, l1_settings, strict_guard, wfp
from .safeio import SafetyError, atomic_bytes, atomic_json, guarded
from .strict_wfp import Engine, Identity, deny_rules, relay_permits
from .windows import DPAPI


def remove_owned_settings(paths, *, crypto=None):
    path = guarded(paths.roaming / 'Code/User/settings.json', paths.roaming)
    if not path.exists():
        return
    settings = jsonc.read(path, path.parent)
    env_key = 'claudeCode.environmentVariables'
    wrapper_key = 'claudeCode.claudeProcessWrapper'
    env = settings.get(env_key)
    remaining = ([item for item in env if item not in [
        {'name': name, 'value': value} for name, value in l1_settings.OWNED_ENV]]
        if isinstance(env, list) else env)
    wrapper_owned = settings.get(wrapper_key) == str(l1_settings.runner_path())
    if remaining == env and not wrapper_owned:
        return
    backup = strict_guard.directory(paths) / 'vscode-settings-exclude-before.dpapi'
    if not backup.exists():
        atomic_bytes(backup, (crypto or DPAPI()).encrypt(path.read_bytes()), paths.state)
    if remaining != env:
        jsonc.set_property(path, path.parent, env_key, remaining)
    if wrapper_owned:
        jsonc.set_property(path, path.parent, wrapper_key, '')


def remove_exact_filters(paths, *, engine_factory=Engine, idle=None):
    from .l1_install import task_state
    idle = idle or (lambda: task_state() in ('Ready', 'Disabled', 'Missing'))
    root = guarded(paths.home / '.vscode/extensions', paths.home)
    targets = []
    if root.exists():
        for path in sorted(root.glob('anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe')):
            path = guarded(path, root)
            if path.is_file():
                targets.append(Identity('app', str(path)))
    rules = deny_rules(targets)
    with engine_factory() as engine:
        if not idle():
            raise SafetyError('Controller must be stopped before extension exclusion')
        before = engine.own_keys()
        # A remaining dynamic permit means the old controller is not closed.
        if before.intersection(r.key.value() for r in relay_permits(targets, strict_guard.GATE_PORT)):
            raise SafetyError('Extension relay permits remain')
        selected = [r for r in rules if r.key.value() in before]
        for rule in selected:
            rule.validate()
            if not engine.exists_verified(rule):
                raise SafetyError('Extension filter readback failed')
        engine._call('FwpmTransactionBegin0', [wfp.wintypes.HANDLE, wfp.wintypes.DWORD], engine.handle, 0)
        try:
            for rule in selected:
                if not engine.exists_verified(rule):
                    raise SafetyError('Extension filter changed')
                engine._call('FwpmFilterDeleteByKey0', [wfp.wintypes.HANDLE, ctypes.POINTER(wfp.GUID)],
                             engine.handle, ctypes.byref(rule.key))
            expected = before - {r.key.value() for r in selected}
            if engine.own_keys() != expected or not idle():
                raise SafetyError('Extension removal readback failed')
            engine._call('FwpmTransactionCommit0', [wfp.wintypes.HANDLE], engine.handle)
        except BaseException:
            engine._call('FwpmTransactionAbort0', [wfp.wintypes.HANDLE], engine.handle)
            raise
    return len(selected)


def remove_filters(paths, report_path, *, request_id=None):
    from .uac_request import admit_child, child_event
    result = dict(schema=1, finished=False, scope='installed_vscode_extension')
    result.update(admit_child(paths, 'remove', request_id))
    try:
        result['filters_removed'] = remove_exact_filters(paths)
        result['removed'] = True
    except Exception:
        result['removed'] = False
        result['error'] = 'extension_filter_removal_failed'
    result['finished'] = True
    child_event(paths, {k: result[k] for k in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def exclude(paths):
    from .uac_request import execute
    receipt = execute(paths, 'remove', lambda request: strict_guard.dispatch_request(request, exclude_extension=True))
    if receipt.get('passed') is True:
        remove_owned_settings(paths)
    return receipt
