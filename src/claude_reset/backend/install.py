"""Install the loopback backend from tracked files and an owner-supplied tunnel profile; remove it again.

Layout under ~/.claude-reset/backend: the pinned engine, a worker generated from the tracked template,
the DPAPI-sealed runtime config, profile.json and the logon task config.BACKEND_TASK (the name the
controller already looks for). Runs as the user without elevation; it touches no firewall rule, client,
proxy setting or route. The tunnel profile uses the format of examples/backend.example.json and is read
from a local file the owner places on this PC: it is never stored in git and never printed.
"""
import hashlib
import json
import secrets
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from .. import config, layout
from ..elevation.claims import serialized
from ..errors import SafetyError, error_info
from ..model.status import Backend, Measurement
from ..network import connections, remote_backend
from ..safeio import atomic_bytes
from ..windows import tasks, tcp
from ..windows.dpapi import DPAPI
from ..windows.powershell import run_process
from . import location as backend_location
from . import profiles as backend_profiles
from .attestation import inspect_sing_box

__all__ = ['PLACEHOLDER', 'ROOT', 'acquire_engine', 'base_directory', 'build_runtime_config', 'install', 'load_lock',
           'port_in_use', 'preconditions', 'prepare', 'remove']

ROOT = layout.PROGRAM_DIR
LOCK = ROOT / 'third_party/sources/sing-box-lock.json'
TEMPLATE = ROOT / 'packaging/backend' / config.BACKEND_WORKER
PLACEHOLDER = '__CLAUDE_RESET_SRC__'
ARCHIVE_LIMIT = 200_000_000


def base_directory(paths):
    return layout.tool_home(paths) / 'backend'


def load_lock():
    return json.loads(LOCK.read_text('utf-8'))


def build_runtime_config(profile_config, secret=None):   # None: a fresh random secret for each config
    """The exact shape backend_location.check_proxy_config accepts, around the owner's single validated outbound."""
    inspect_sing_box(profile_config)
    outbound = dict(profile_config['outbounds'][0], tag=config.ENGINE_ROUTE_TAG)
    runtime = {'log': {'disabled': True},
               'inbounds': [{'type': 'http', 'tag': 'claude-loopback', 'listen': config.LOOPBACK, 'listen_port': config.BACKEND_PORT}],
               'outbounds': [outbound], 'route': {'final': config.ENGINE_ROUTE_TAG},
               'experimental': {'clash_api': {'external_controller': f'{config.LOOPBACK}:{config.BACKEND_API_PORT}',
                                              'secret': secret or secrets.token_hex(16)}}}
    inspect_sing_box(runtime)
    return runtime


def render_worker(template_text, source_directory):
    if PLACEHOLDER not in template_text:
        raise SafetyError('The worker template has no source placeholder')
    return template_text.replace(PLACEHOLDER, str(source_directory))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def acquire_engine(target, lock, *, archive=None, opener=urllib.request.urlopen):
    """Pinned official engine archive -> target. Returns the path of the verified executable.

    `archive` is a local copy for an offline install; otherwise the pinned URL is downloaded. The archive
    length and SHA-256 and the executable SHA-256 must all match the lock; names are checked before extraction.
    """
    target.mkdir(parents=True, exist_ok=True)
    local = Path(archive) if archive else target.parent / ('download-' + lock['asset'])
    if not archive:
        digest, size = hashlib.sha256(), 0
        with opener(lock['url'], timeout=60) as source, open(local, 'wb') as destination:
            while block := source.read(1 << 20):
                size += len(block)
                if size > lock['bytes']:
                    raise SafetyError('Download exceeds the pinned length')
                digest.update(block)
                destination.write(block)
    try:
        if local.stat().st_size != lock['bytes'] or sha256_file(local) != lock['sha256']:
            raise SafetyError('Engine archive differs from the pinned release')
        with zipfile.ZipFile(local) as bundle:
            names = bundle.namelist()
            if len(names) != len(set(names)) or sum(i.file_size for i in bundle.infolist()) > ARCHIVE_LIMIT:
                raise SafetyError('Unexpected engine archive structure')
            for info in bundle.infolist():
                name = PurePosixPath(info.filename)
                if name.is_absolute() or '..' in name.parts or ':' in info.filename or '\\' in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SafetyError('Unsafe path in the engine archive')
            bundle.extractall(target)
        executable = target / PurePosixPath(next(n for n in names if n.endswith('/sing-box.exe')))
        if sha256_file(executable) != lock['executable_sha256']:
            raise SafetyError('Engine executable differs from the pinned hash')
        return executable
    finally:
        if not archive:
            local.unlink(missing_ok=True)


def task_exists(runner=run_process):
    return tasks.exists(config.BACKEND_TASK, runner)


def register_task(pythonw, worker, runner=run_process, name=config.BACKEND_TASK):
    tasks.register_logon_task(name, pythonw, f'"{worker}"', worker.parent,
                              'Claude-only loopback tunnel backend; no router, interface or system proxy changes.', runner)


def port_in_use(port):
    """Whether something listens on this loopback port."""
    return tcp.listening(config.LOOPBACK, port)


def preconditions(paths, *, runner=run_process, port_busy=port_in_use):
    """Reasons not to install, found before anything is written."""
    errors = []
    if getattr(sys, 'frozen', False):
        errors.append('frozen_build: the backend worker needs the Python interpreter; install from the source tree')
    if task_exists(runner):
        errors.append('task_exists: the backend task is already registered; it is never overwritten')
    for port in (config.BACKEND_PORT, config.BACKEND_API_PORT):
        if port_busy(port):
            errors.append(f'port_{port}_in_use')
    base = base_directory(paths)
    if base.exists() and any(base.iterdir()):
        errors.append('directory_not_empty: ' + str(base))
    if not TEMPLATE.is_file() or not LOCK.is_file():
        errors.append('tracked_files_missing')
    return errors


def prepare(paths, profile_file, *, archive=None, opener=urllib.request.urlopen, crypto=DPAPI()):
    """Write the engine, worker, sealed config and profile.json; no task, no process."""
    profile = backend_profiles.decode(Path(profile_file).read_bytes())
    lock = load_lock()
    if profile['engine_sha256'] != lock['executable_sha256']:
        raise SafetyError(f"The profile must name the pinned engine {lock['version']} (engine_sha256 {lock['executable_sha256']})")
    runtime = build_runtime_config(profile['config'])
    base = base_directory(paths)
    base.mkdir(parents=True, exist_ok=True)
    executable = acquire_engine(base / 'engine', lock, archive=archive, opener=opener)
    plain = json.dumps(runtime, sort_keys=True, separators=(',', ':')).encode()
    atomic_bytes(base / layout.BACKEND_ENGINE_CONFIG, crypto.encrypt(plain), base)
    meta = {'schema': 1, 'engine_path': str(executable), 'engine_sha256': lock['executable_sha256'],
            'config_file': str(base / layout.BACKEND_ENGINE_CONFIG), 'config_sha256': hashlib.sha256(plain).hexdigest(),
            'proxy_url': config.BACKEND_URL, 'api_url': config.loopback_url(config.BACKEND_API_PORT),
            'credentials_at_rest': 'dpapi_current_user', 'plaintext_config_written': False, 'source': 'backend_install'}
    atomic_bytes(base / layout.BACKEND_PROFILE, json.dumps(meta, indent=2).encode(), base)
    worker = base / config.BACKEND_WORKER
    atomic_bytes(worker, render_worker(TEMPLATE.read_text('utf-8'), ROOT / 'src').encode('utf-8'), base)
    return base, worker


def wait_for_worker(base, seconds=40, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + seconds
    status = {}
    while clock() < deadline:
        status = backend_location.worker_state(base) or {}
        if status.get('state') in ('running', 'failed'):
            break
        sleep(.5)
    return status


@serialized('backend_install', completed={Backend.INSTALLED, Backend.NOT_STARTED, Backend.NOT_INSTALLED}, nested=True)
def install(paths, profile_file, *, archive=None, runner=run_process, opener=urllib.request.urlopen,
            measure=connections.measure, wait=wait_for_worker, crypto=DPAPI(),
            pythonw=Path(sys.executable).with_name(config.PYTHONW), install_remote=remote_backend.install,
            port_busy=port_in_use):
    result = {'schema': 1, 'finished': False, 'action': 'backend_install', 'elevation_used': False,
              'firewall_changed': False, 'clients_changed': False, 'raw_addresses_saved': False}
    try:
        try:
            adapter = json.loads(Path(profile_file).read_bytes().decode('utf-8-sig')).get('adapter')
        except (OSError, ValueError, AttributeError):
            adapter = None
        if adapter in remote_backend.ADAPTERS.values():
            return install_remote(paths, profile_file)
        errors = preconditions(paths, runner=runner, port_busy=port_busy)
        if errors:
            result.update(status=Backend.NOT_STARTED, reasons=errors, finished=True)
            return result
        base, worker = prepare(paths, profile_file, archive=archive, opener=opener, crypto=crypto)
        result['prepared'] = True
        interpreter = Path(pythonw)
        if not interpreter.is_file():
            raise SafetyError('pythonw.exe was not found next to the interpreter')
        register_task(interpreter, worker, runner)
        result['task_registered'] = True
        tasks.start(config.BACKEND_TASK, runner)
        status = wait(base)
        result['worker_state'] = status.get('state')
        if status.get('state') != 'running':
            raise SafetyError('The backend worker did not reach the running state' + (': ' + status['error_type'] if status.get('error_type') else ''))
        guard = backend_location.locate_guard()
        result['static_check'] = bool(guard) and bool(backend_location.check_engine_and_config(guard).get('passed'))
        measured = measure(config.BACKEND_URL)
        # The address itself is never returned: the owner compares it with the expected exit outside the log.
        result['exit_measured'] = measured.get('status') == Measurement.MEASURED
        result['exit_address_family'] = measured.get('address_family')
        result['status'] = Backend.INSTALLED if result['static_check'] and result['exit_measured'] else Backend.INSTALLED_NEEDS_ATTENTION
    except Exception as exc:
        result.update(status=Backend.FAILED, error=error_info(exc))
    result['finished'] = True
    return result


@serialized('backend_remove', completed={Backend.REMOVED}, nested=True)
def remove(paths, *, runner=run_process, port_busy=port_in_use, sleep=time.sleep):
    """Stop the worker normally, unregister the task and delete only files this installer created."""
    result = {'schema': 1, 'finished': False, 'action': 'backend_remove'}
    base = base_directory(paths)
    try:
        if port_busy(config.RELAY_PORT):
            raise SafetyError('The L1 relay is listening: stop the controller first, or protected clients lose their network')
        status = backend_location.worker_state(base) or {}
        if status.get('state') == 'running' and isinstance(status.get('instance'), str):
            atomic_bytes(base / 'stop-request.json', json.dumps({'instance': status['instance']}).encode(), base)
            for _ in range(40):
                latest = backend_location.worker_state(base)
                if latest is not None and latest.get('state') != 'running':
                    break
                sleep(.25)
        if task_exists(runner):
            tasks.unregister(config.BACKEND_TASK, runner)
        for name in (config.BACKEND_WORKER, layout.BACKEND_PROFILE, layout.BACKEND_ENGINE_CONFIG, layout.BACKEND_STATUS, 'worker.lock', 'stop-request.json', 'worker-status.tmp'):
            (base / name).unlink(missing_ok=True)
        engine = base / 'engine'
        if engine.is_dir():
            shutil.rmtree(engine)
        if base.is_dir() and not any(base.iterdir()):
            base.rmdir()
        result['status'] = Backend.REMOVED if not task_exists(runner) and not base.exists() else Backend.REMOVED_WITH_LEFTOVERS
    except Exception as exc:
        result.update(status=Backend.FAILED, error=error_info(exc))
    result['finished'] = True
    return result
