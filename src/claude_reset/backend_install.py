"""Install the loopback backend from tracked files and an owner-supplied tunnel profile; remove it again.

Layout under ~/.claude-reset/backend: the pinned engine, a worker generated from the tracked template,
the DPAPI-sealed runtime config, profile.json and the logon task `ClaudeReset-SnowProxy` (the name the
controller already looks for). Runs as the user without elevation; it touches no firewall rule, client,
proxy setting or route. The tunnel profile uses the format of examples/backend.example.json and is read
from a local file the owner places on this PC: it is never stored in git and never printed.
"""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from . import backend_profiles, netguard
from .backend_attestation import inspect_sing_box
from .safeio import SafetyError, atomic_bytes
from .windows import DPAPI
from .uac_request import serialized

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'third_party/sources/sing-box-lock.json'
TEMPLATE = ROOT / 'packaging/backend/proxy_worker.py'
TAG = 'snow-only'            # opaque tag the controller's config check expects; not a provider name
PLACEHOLDER = '__CLAUDE_RESET_SRC__'
NO_WINDOW = 0x08000000
ARCHIVE_LIMIT = 200_000_000


def base_directory(paths):
    return paths.home / '.claude-reset' / 'backend'


def load_lock():
    return json.loads(LOCK.read_text('utf-8'))


def build_runtime_config(profile_config, secret=None):
    """The exact shape netguard.check_proxy_config accepts, around the owner's single validated outbound."""
    inspect_sing_box(profile_config)
    outbound = dict(profile_config['outbounds'][0], tag=TAG)
    runtime = {'log': {'disabled': True},
               'inbounds': [{'type': 'http', 'tag': 'claude-loopback', 'listen': netguard.PROXY_HOST, 'listen_port': netguard.PROXY_PORT}],
               'outbounds': [outbound], 'route': {'final': TAG},
               'experimental': {'clash_api': {'external_controller': f'{netguard.PROXY_HOST}:{netguard.CONTROLLER_PORT}',
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


def powershell(script, runner=subprocess.run, timeout=60):
    executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = runner([str(executable), '-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop"; ' + script],
                    capture_output=True, text=True, timeout=timeout, creationflags=NO_WINDOW)
    return result.returncode, (result.stdout or '').strip(), ' '.join((result.stderr or '').split())[:300]


def task_exists(runner=subprocess.run):
    code, out, _ = powershell(f"if (Get-ScheduledTask -TaskName {netguard.psq(netguard.TASK_NAME)} -ErrorAction SilentlyContinue) {{ 'yes' }}; exit 0", runner)
    return code == 0 and out == 'yes'


def register_task(pythonw, worker, runner=subprocess.run, name=netguard.TASK_NAME):
    script = f'''
$name = {netguard.psq(name)}
if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {{ throw 'Task already exists; no overwrite' }}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute {netguard.psq(pythonw)} -Argument {netguard.psq(f'"{worker}"')} -WorkingDirectory {netguard.psq(worker.parent)}
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Claude-only loopback tunnel backend; no router, interface or system proxy changes.' | Out-Null
exit 0'''
    code, _, error = powershell(script, runner)
    if code:
        raise SafetyError('Task registration was refused: ' + (error or 'no details'))


def preconditions(paths, *, runner=subprocess.run, port_busy=None):
    """Reasons not to install, found before anything is written."""
    from . import l1_mechanism
    busy = port_busy or (lambda port: l1_mechanism.connect('127.0.0.1', port, .3) == 'connected')
    errors = []
    if getattr(sys, 'frozen', False):
        errors.append('frozen_build: the backend worker needs the Python interpreter; install from the source tree')
    if task_exists(runner):
        errors.append('task_exists: the backend task is already registered; it is never overwritten')
    for port in (netguard.PROXY_PORT, netguard.CONTROLLER_PORT):
        if busy(port):
            errors.append(f'port_{port}_in_use')
    base = base_directory(paths)
    if base.exists() and any(base.iterdir()):
        errors.append('directory_not_empty: ' + str(base))
    if not TEMPLATE.is_file() or not LOCK.is_file():
        errors.append('tracked_files_missing')
    return errors


def prepare(paths, profile_file, *, archive=None, opener=urllib.request.urlopen, crypto=None):
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
    atomic_bytes(base / 'snow-config.dpapi', (crypto or DPAPI()).encrypt(plain), base)
    meta = {'schema': 1, 'engine_path': str(executable), 'engine_sha256': lock['executable_sha256'],
            'config_file': str(base / 'snow-config.dpapi'), 'config_sha256': hashlib.sha256(plain).hexdigest(),
            'proxy_url': netguard.PROXY_URL, 'api_url': f'http://{netguard.PROXY_HOST}:{netguard.CONTROLLER_PORT}',
            'credentials_at_rest': 'dpapi_current_user', 'plaintext_config_written': False, 'source': 'backend_install'}
    atomic_bytes(base / 'profile.json', json.dumps(meta, indent=2).encode(), base)
    worker = base / 'proxy_worker.py'
    atomic_bytes(worker, render_worker(TEMPLATE.read_text('utf-8'), ROOT / 'src').encode('utf-8'), base)
    return base, worker


def wait_for_worker(base, seconds=40, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + seconds
    status = {}
    while clock() < deadline:
        try:
            status = json.loads((base / 'worker-status.json').read_text('utf-8-sig'))
        except (OSError, ValueError):
            status = {}
        if status.get('state') in ('running', 'failed'):
            break
        sleep(.5)
    return status


@serialized('backend_install', completed={'installed', 'not_started', 'not_installed'}, nested=True)
def install(paths, profile_file, *, archive=None, runner=subprocess.run, opener=urllib.request.urlopen,
            measure=None, wait=wait_for_worker, crypto=None, pythonw=None):
    result = {'schema': 1, 'finished': False, 'action': 'backend_install', 'elevation_used': False,
              'firewall_changed': False, 'clients_changed': False, 'raw_addresses_saved': False}
    try:
        from . import remote_backend
        try:
            adapter = json.loads(Path(profile_file).read_bytes().decode('utf-8-sig')).get('adapter')
        except (OSError, ValueError, AttributeError):
            adapter = None
        if adapter in remote_backend.ADAPTERS.values():
            return remote_backend.install(paths, profile_file)
        errors = preconditions(paths, runner=runner)
        if errors:
            result.update(status='not_started', reasons=errors, finished=True)
            return result
        base, worker = prepare(paths, profile_file, archive=archive, opener=opener, crypto=crypto)
        result['prepared'] = True
        interpreter = Path(pythonw or Path(sys.executable).with_name('pythonw.exe'))
        if not interpreter.is_file():
            raise SafetyError('pythonw.exe was not found next to the interpreter')
        register_task(interpreter, worker, runner)
        result['task_registered'] = True
        code, _, error = powershell(f"Start-ScheduledTask -TaskName {netguard.psq(netguard.TASK_NAME)}; exit 0", runner)
        if code:
            raise SafetyError('Task start was refused: ' + error)
        status = wait(base)
        result['worker_state'] = status.get('state')
        if status.get('state') != 'running':
            raise SafetyError('The backend worker did not reach the running state' + (': ' + status['error_type'] if status.get('error_type') else ''))
        guard = netguard.locate_guard()
        result['static_check'] = bool(guard) and bool(netguard.check_engine_and_config(guard).get('passed'))
        from . import connections
        measured = (measure or connections.measure)(netguard.PROXY_URL)
        # The address itself is never returned: the owner compares it with the expected exit outside the log.
        result['exit_measured'] = measured.get('status') == 'measured'
        result['exit_address_family'] = measured.get('address_family')
        result['status'] = 'installed' if result['static_check'] and result['exit_measured'] else 'installed_needs_attention'
    except BaseException as exc:
        result.update(status='failed', error=type(exc).__name__ + ': ' + str(exc)[:200])
    result['finished'] = True
    return result


@serialized('backend_remove', completed={'removed'}, nested=True)
def remove(paths, *, runner=subprocess.run, port_busy=None, sleep=time.sleep):
    """Stop the worker normally, unregister the task and delete only files this installer created."""
    from . import l1_mechanism
    result = {'schema': 1, 'finished': False, 'action': 'backend_remove'}
    base = base_directory(paths)
    try:
        busy = port_busy or (lambda port: l1_mechanism.connect('127.0.0.1', port, .3) == 'connected')
        if busy(25082):
            raise SafetyError('The L1 relay is listening: stop the controller first, or protected clients lose their network')
        status = {}
        try:
            status = json.loads((base / 'worker-status.json').read_text('utf-8-sig'))
        except (OSError, ValueError):
            pass
        if status.get('state') == 'running' and isinstance(status.get('instance'), str):
            atomic_bytes(base / 'stop-request.json', json.dumps({'instance': status['instance']}).encode(), base)
            for _ in range(40):
                try:
                    if json.loads((base / 'worker-status.json').read_text('utf-8-sig')).get('state') != 'running':
                        break
                except (OSError, ValueError):
                    pass
                sleep(.25)
        if task_exists(runner):
            code, _, error = powershell(f"Unregister-ScheduledTask -TaskName {netguard.psq(netguard.TASK_NAME)} -Confirm:$false; exit 0", runner)
            if code:
                raise SafetyError('Task removal was refused: ' + error)
        for name in ('proxy_worker.py', 'profile.json', 'snow-config.dpapi', 'worker-status.json', 'worker.lock', 'stop-request.json', 'worker-status.tmp'):
            (base / name).unlink(missing_ok=True)
        engine = base / 'engine'
        if engine.is_dir():
            shutil.rmtree(engine)
        if base.is_dir() and not any(base.iterdir()):
            base.rmdir()
        result['status'] = 'removed' if not task_exists(runner) and not base.exists() else 'removed_with_leftovers'
    except BaseException as exc:
        result.update(status='failed', error=type(exc).__name__ + ': ' + str(exc)[:200])
    result['finished'] = True
    return result
