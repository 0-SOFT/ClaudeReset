"""Where the local backend is installed and whether it is in its reviewed state.

The backend task's working folder, its worker status, profile and engine configuration are read here; the
reviewed versions of the clients the protection covers are listed here too."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .. import config, layout
from ..errors import SafetyError, error_kind
from ..model.compatibility import REVIEWED_STANDALONE_CLI
from ..model.ids import utc_now
from ..model.notes import Note
from ..model.status import Network
from ..safeio import guarded, read_json
from ..windows import packages, tasks
from ..windows.dpapi import DPAPI
from ..windows.packages import current_package, split_command_line

__all__ = ['BOUNDARIES', 'Guard', 'REVIEWED_STANDALONE_CLI', 'check_engine_and_config', 'check_listeners',
           'check_proxy_config', 'check_worker', 'guard_from_task', 'in_package', 'live_state', 'locate_guard',
           'read_worker_state', 'same_path', 'sha256', 'status', 'worker_probe', 'worker_state']


BOUNDARIES = (
    Note('guard.boundary.shared_apps'),
    Note('guard.boundary.static'),
    Note('guard.boundary.filters'),
)


@dataclass(frozen=True)
class Guard:
    base: Path
    python: Path
    task: dict

    @property
    def work(self) -> Path:
        return self.base.parent


def sha256(path: Path) -> str:
    with open(path, 'rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def same_path(a, b) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def live_state(pids) -> dict:
    return packages.live_state(pids, ports=(config.BACKEND_PORT, config.BACKEND_API_PORT),
                               owned_package=config.OWNED_PACKAGE_NAME, desktop_family=config.DESKTOP_PACKAGE[0])


def worker_probe(proxy, launch=''):
    """The package probe for one run: the proxy to test and an optional launch command."""
    return packages.worker_probe(proxy, zip(('backend', 'controller', 'gate'), config.OWN_PORTS), launch)


def in_package(package: tuple[str, str], script: str, timeout=45.0) -> dict:
    """Run a probe inside the package; its answer may hold only the probe's keys."""
    return packages.run_in_package(package, script, root=layout.ipc_home(), keys=packages.WORKER_KEYS, timeout=timeout)


def guard_from_task(task: dict) -> Guard:
    """The installed logon task is the only accepted pointer to the guard files."""
    actions = task.get('actions') or []
    if len(actions) != 1:
        raise SafetyError('Unexpected local proxy task actions', code='guard_task_actions')
    python = Path(actions[0].get('execute') or '')
    arguments = split_command_line(actions[0].get('arguments') or '')
    if python.name.lower() != config.PYTHONW or len(arguments) != 1 or Path(arguments[0]).name.lower() != config.BACKEND_WORKER:
        raise SafetyError('Unexpected local proxy task actions', code='guard_task_actions')
    script = Path(arguments[0])
    if not script.is_absolute():
        raise SafetyError('Unexpected local proxy task actions', code='guard_task_actions')
    guarded(script, Path(script.anchor))
    return Guard(script.parent, python, {k: task.get(k) for k in ('state', 'enabled', 'run_level')})


def locate_guard() -> Guard | None:
    task = tasks.describe(config.BACKEND_TASK)
    return guard_from_task(task) if task else None


def check_proxy_config(cfg: dict) -> dict:
    """Shape of the decrypted engine config. Server, credentials and keys are never returned."""
    outbounds = cfg.get('outbounds') or []
    api = (cfg.get('experimental') or {}).get('clash_api') or {}
    result = {
        'single_snow_outbound': [o.get('tag') for o in outbounds] == [config.ENGINE_ROUTE_TAG],
        'no_direct_fallback': cfg.get('route') == {'final': config.ENGINE_ROUTE_TAG} and not any(o.get('type') in ('direct', 'block', 'selector', 'urltest') for o in outbounds),
        'loopback_inbound_only': cfg.get('inbounds') == [{'type': 'http', 'tag': 'claude-loopback', 'listen': config.LOOPBACK, 'listen_port': config.BACKEND_PORT}],
        'controller_loopback': api.get('external_controller') == f'{config.LOOPBACK}:{config.BACKEND_API_PORT}' and bool(api.get('secret')),
        'engine_log_disabled': cfg.get('log') == {'disabled': True},
    }
    result['passed'] = all(result.values())
    return result


def check_listeners(listeners: list, engine_pid) -> dict:
    ports = {}
    for row in listeners:
        ports.setdefault(int(row['port']), []).append(row)
    exposed = [r for r in listeners if r.get('address') != config.LOOPBACK]
    foreign = [r for r in listeners if r.get('pid') != engine_pid]
    return {'proxy_listening': config.BACKEND_PORT in ports, 'controller_listening': config.BACKEND_API_PORT in ports,
            'loopback_only': not exposed, 'owned_by_engine': bool(listeners) and not foreign,
            'passed': config.BACKEND_PORT in ports and config.BACKEND_API_PORT in ports and not exposed and not foreign}


def check_worker(guard: Guard, state: dict, live: dict) -> dict:
    by_pid = {p['pid']: p for p in live.get('processes') or []}
    worker, engine = by_pid.get(state.get('worker_pid')), by_pid.get(state.get('engine_pid'))
    boot = live['boot']
    profile = read_json(guard.base / layout.BACKEND_PROFILE, guard.base)
    result = {
        'state_running': state.get('state') == 'running',
        'worker_alive': bool(worker) and str(guard.base / config.BACKEND_WORKER).casefold() in (worker.get('command') or '').casefold(),
        'engine_child_of_worker': bool(worker and engine) and engine.get('parent') == worker['pid'] and same_path(engine.get('path') or '', profile['engine_path']),
        'started_after_boot': bool(worker) and worker['created'] > boot,
    }
    result['passed'] = all(result.values())
    return result


def check_engine_and_config(guard: Guard, *, crypto=DPAPI()) -> dict:
    profile = read_json(guard.base / layout.BACKEND_PROFILE, guard.base)
    engine = guarded(Path(profile['engine_path']), guard.base / 'engine')
    result = {'engine_reviewed': engine.is_file() and sha256(engine) == profile['engine_sha256'], 'proxy_url': profile.get('proxy_url') == config.BACKEND_URL}
    sealed = guarded(guard.base / layout.BACKEND_ENGINE_CONFIG, guard.base)
    plain = crypto.decrypt(sealed.read_bytes())
    try:
        result['config_reviewed'] = hashlib.sha256(plain).hexdigest() == profile['config_sha256']
        result.update(check_proxy_config(json.loads(plain)))
    finally:
        del plain
    result['passed'] = all(v for k, v in result.items() if k != 'passed')
    return result


def status(paths) -> dict:
    """Read-only, no network requests: is the installed guard in its reviewed state?"""
    report = {'schema': 1, 'utc': utc_now(), 'scope': 'claude_only_local_guard',
              'network_requests': 0, 'settings_changed': False, 'router_contacted': False, 'boundaries': BOUNDARIES}
    guard = locate_guard()
    if not guard:
        return {**report, 'installed': False, 'status': Network.NOT_INSTALLED, 'passed': False,
                'findings': [Note('guard.finding.not_installed', task=config.BACKEND_TASK)]}
    blocking, review = [], []

    def section(check):
        try:
            return check()
        except (OSError, SafetyError, ValueError, KeyError, TypeError) as exc:
            return {'passed': False, 'error_type': error_kind(exc)}
    state = worker_state(guard.base) or {}
    live = live_state([state.get('worker_pid'), state.get('engine_pid')])
    report.update(installed=True, task=guard.task, program_package=current_package())
    if not guard.task.get('enabled'):
        blocking.append(Note('guard.finding.task_disabled'))
    if guard.task.get('run_level') != 'Limited':
        review.append(Note('guard.finding.task_rights'))
    report['worker'] = section(lambda: check_worker(guard, state, live))
    if not report['worker']['passed']:
        blocking.append(Note('guard.finding.worker'))
    report['listener'] = check_listeners(live.get('listeners') or [], state.get('engine_pid'))
    if not report['listener']['passed']:
        blocking.append(Note('guard.finding.listener'))
    report['proxy_config'] = section(lambda: check_engine_and_config(guard))
    if not report['proxy_config']['passed']:
        blocking.append(Note('guard.finding.config'))
    report['packages'] = {'owned_registered': live.get('owned_package') == config.OWNED_PACKAGE[0],
                          'desktop_installed': bool((live.get('desktop') or {}).get('version'))}
    if not report['packages']['owned_registered']:
        blocking.append(Note('guard.finding.package'))
    variables = live.get('proxy_variables') or {}
    report['ordinary_scope'] = {'wininet_proxy_enabled': bool((live.get('wininet') or {}).get('proxy_enable')),
                                'wininet_auto_config': bool((live.get('wininet') or {}).get('auto_config')),
                                'global_proxy_variables': sorted(k for k, v in variables.items() if v)}
    if any(report['ordinary_scope'].values()):
        review.append(Note('guard.finding.shared_proxy'))
    report.update(findings=blocking + review, blocking=bool(blocking), passed=not blocking,
                  status=Network.PROTECTION_DEGRADED if blocking else Network.STATIC_CHECKS_PASSED_REVIEW_NEEDED if review else Network.STATIC_CHECKS_PASSED)
    return report


def read_worker_state(base: Path) -> dict:
    """What the backend worker last wrote about itself; raises when it is missing or unreadable."""
    return read_json(base / layout.BACKEND_STATUS, base)


def worker_state(base: Path) -> dict | None:
    """What the backend worker last wrote about itself, or None when nothing readable is there."""
    try:
        state = read_worker_state(base)
    except (OSError, ValueError, SafetyError):
        return None
    return state if isinstance(state, dict) else None
