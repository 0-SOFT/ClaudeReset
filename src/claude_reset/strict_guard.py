"""Windows default-deny gate for the reviewed local snow backend.

The relay owns both its listening socket and the dynamic WFP permit session.
Its death closes connections and removes permits; persistent deny rules remain.
"""
from __future__ import annotations
import ctypes
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from . import connections, l1_consent, l1_monitor, netguard, remote_backend
from .strict_wfp import Engine, Identity, Rule, PERMIT, deny_rules, relay_permits
from .safeio import SafetyError, atomic_json, guarded
from .windows import DPAPI, ps_json
from .uac_request import serialized

GATE_PORT = 25082
GATE_URL = f'http://127.0.0.1:{GATE_PORT}'
RUNNER_NAME = 'ClaudeResetRun.exe'


def directory(paths):
    return guarded(paths.state / 'strict-guard', paths.state)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def cli_state(paths):
    """Standalone CLI facts for the status report. The hash is information, never a gate:
    a deny by exact path blocks only direct network, so a new or unreviewed version fails
    closed (offline unless it honours the proxy variables) instead of stopping the controller."""
    cli = paths.home / '.local/bin/claude.exe'
    if not cli.is_file():
        return {'present': False, 'reviewed_hash': None}
    return {'present': True, 'reviewed_hash': netguard.sha256(cli) == netguard.REVIEWED_STANDALONE_CLI}


def identities(paths):
    """Cheap enough to call every controller cycle: it hashes nothing."""
    result = [Identity('package', value[0]) for value in (netguard.DESKTOP_PACKAGE, netguard.OWNED_PACKAGE)]
    cli = paths.home / '.local/bin/claude.exe'
    if cli.is_file():
        result.append(Identity('app', str(cli)))
    # Claude Code's own native binary in the shared editor: an exact Claude image,
    # not Code.exe. Every installed extension version is covered; a version
    # installed while the controller runs is adopted by adopt_new_identities.
    extensions = paths.home / '.vscode/extensions'
    if extensions.is_dir() and not (directory(paths) / 'exclude-vscode-extension.flag').exists():
        for exe in sorted(extensions.glob('anthropic.claude-code-*-win32-x64/resources/native-binary/claude.exe')):
            if exe.is_file():
                result.append(Identity('app', str(exe)))
    return result


def adopt_new_identities(paths, targets, lease, state):
    """Cover a Claude image that appeared after start (an extension update): deny first, then permit.

    Returns the new target list. Any failure is recorded in the status and never stops the
    controller; a new image left without a deny stays visible as `adopt_error` until the next start.
    """
    try:
        fresh = [identity for identity in identities(paths) if identity not in targets]
        if not fresh:
            return targets
        with Engine() as permanent:
            permanent.install(deny_rules(fresh))
        lease.install(relay_permits(fresh, GATE_PORT))
    except Exception as exc:
        state['adopt_error'] = type(exc).__name__
        return targets
    state.pop('adopt_error', None)
    state['adopted'] = state.get('adopted', []) + [identity.value for identity in fresh]
    return targets + fresh


def backend(paths):
    """Read only the installed, hash-reviewed snow configuration; never infer a route."""
    guard = netguard.locate_guard()
    if not guard or not netguard.status(paths).get('passed'):
        raise SafetyError('The existing snow backend must pass its static checks')
    meta = netguard.read_json(guard.base / 'profile.json', guard.base)
    config = json.loads(DPAPI().decrypt((guard.base / 'snow-config.dpapi').read_bytes()))
    from .backend_attestation import inspect_sing_box
    inspect_sing_box(config)
    outbound = config['outbounds'][0]
    tls = outbound.get('tls') or {}
    if (outbound.get('type') != 'vless' or not tls.get('enabled') or tls.get('insecure')
            or not (tls.get('reality') or {}).get('enabled') or not (tls.get('reality') or {}).get('public_key')
            or ipaddress.ip_address(outbound['server']).version != 4 or not ipaddress.ip_address(outbound['server']).is_global
            or type(outbound['server_port']) is not int or not 1 <= outbound['server_port'] <= 65535):
        raise SafetyError('Strict backend requires the reviewed literal IPv4 VLESS Reality peer')
    state = netguard.read_json(guard.base / 'worker-status.json', guard.base)
    return guard, meta, config, state


def plan(paths):
    targets = identities(paths)
    remote = remote_backend.load(paths)
    if remote is None:
        backend(paths)
    saved = connections.load(paths)
    return {'schema': 1, 'status': 'strict_plan_prepared', 'passed': True,
            'scope': [t.kind + ':' + (t.value if t.kind == 'package' else 'reviewed_standalone_claude' if t.value.endswith('claude.exe') and '.local' in t.value else 'claude_code_extension_binary') for t in targets],
            'persistent_default_denies': len(deny_rules(targets)), 'relay_url': GATE_URL,
            'tunnel_identity': remote_backend.backend_kind(remote) if remote else 'installed_reviewed_snow_vless_reality',
            'expected_exit_profile_present': saved is not None,
            'production_open_supported': False, 'full_tunnel_verified': False,
            'blocking_requirement': 'delegated_dns_and_ipc_isolation',
            'opens_network': False, 'router_changed': False, 'ordinary_applications_changed': False,
            'limits': ['Общие Chrome/VS Code вне защищённой области',
                       'Входящие подключения к защищённым приложениям запрещаются, включая локальные callbacks',
                       'Обнаружен обход через DNS-службу; открытие доступа клиентам отключено до изоляции служб/IPC',
                       'Прозрачный туннель роутера не допускается этим backend']}


def peer_is_engine(stream, engine_pid):
    """Attribute this exact established backend socket before forwarding any bytes."""
    local = stream.getsockname()[1]
    remote = stream.getpeername()[1]
    result = ps_json(f'''@{{pids=@(Get-NetTCPConnection -State Established -LocalAddress '127.0.0.1' -LocalPort {remote} -RemoteAddress '127.0.0.1' -RemotePort {local} -ErrorAction SilentlyContinue | ForEach-Object {{[int]$_.OwningProcess}})}} | ConvertTo-Json -Compress''')
    return (result or {}).get('pids') == [engine_pid]


def create_transport(proxy, verify_peer, *, port=GATE_PORT):
    """The gateway is independent of the provider; backend attestation is separate."""
    from .tunnel_transport import ConnectRelay
    return ConnectRelay(proxy, verify_peer, port=port)


class Relay:
    def __init__(self, upstream, verify_peer, *, port=GATE_PORT):
        self.upstream, self.verify_peer = upstream, verify_peer
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name == 'nt':
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.listener.bind(('127.0.0.1', port))
        self.listener.listen(32)
        self.listener.settimeout(.5)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.clients = set()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(64)

    def serve(self):
        while not self.stopped.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(False):
                client.close()
                continue
            with self.lock:
                if self.stopped.is_set():
                    client.close()
                    self.slots.release()
                    break
                self.clients.add(client)
            threading.Thread(target=self._pipe, args=(client,), daemon=True).start()

    def _pipe(self, client):
        upstream = None
        try:
            upstream = socket.create_connection(self.upstream, timeout=5)
            # The listener could have been replaced after a process crash. A
            # port check alone is insufficient: verify the accepted socket PID.
            if not self.verify_peer(upstream):
                return
            with self.lock:
                if self.stopped.is_set():
                    return
                self.clients.add(upstream)
            client.settimeout(5)
            while not self.stopped.is_set():
                readable, _, _ = select.select([client, upstream], [], [], .5)
                for source in readable:
                    data = source.recv(32768)
                    if not data or self.stopped.is_set():
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, SafetyError, ValueError):
            pass  # No direct retry, redirect, or alternate upstream.
        finally:
            with self.lock:
                for stream in (client, upstream):
                    if stream is not None:
                        self.clients.discard(stream)
                        stream.close()
            self.slots.release()

    def close(self):
        self.stopped.set()
        self.listener.close()
        with self.lock:
            for stream in tuple(self.clients):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()
            self.clients.clear()


def configure_future_clients(paths):
    """Point only the Desktop proxy policy at the relay; create it when absent.

    The shared ~/.claude/settings.json is never written: it is read by every
    Claude Code including the unprotected shared editor, and a stopped relay
    would break them. Protected standalone CLI runs get the proxy per launch.
    """
    import winreg
    changes = []
    for label, hive in [('user', winreg.HKEY_CURRENT_USER), ('machine', winreg.HKEY_LOCAL_MACHINE)]:
        with winreg.CreateKeyEx(hive, r'SOFTWARE\Policies\Claude', 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
            try:
                value, kind = winreg.QueryValueEx(key, 'egressProxyUrl')
            except FileNotFoundError:
                value, kind = None, winreg.REG_SZ
            if value is not None and (value not in (netguard.PROXY_URL, GATE_URL) or kind != winreg.REG_SZ):
                raise SafetyError('Desktop proxy policy changed; refusing to overwrite it')
            winreg.SetValueEx(key, 'egressProxyUrl', 0, winreg.REG_SZ, GATE_URL)
            changes.append(label + '_desktop_proxy')
    return changes


def serve(paths, report_path, *, request_id=None):
    """Admit one exact start before any controller effects or status overwrite."""
    from .admission import locked
    from .controller_admission import consume
    from .uac_request import child_event, admission_denied
    from .controller_process import generation
    import msvcrt
    folder = directory(paths)
    lockfile = mutex = None
    request = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    try:
        with locked(paths):
            folder.mkdir(parents=True, exist_ok=True)
            lockfile = open(folder / 'controller.lock', 'a+b')
            try:
                lockfile.seek(0)
                msvcrt.locking(lockfile.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                lockfile.close()
                lockfile = None
                raise SafetyError('Strict controller is already running') from None
            mutex = kernel.CreateMutexW(None, False, 'Global\\ClaudeReset.StrictGate.v1')
            if not mutex or kernel.WaitForSingleObject(mutex, 0) not in (0, 0x80):
                if mutex:
                    kernel.CloseHandle(mutex)
                    mutex = None
                raise SafetyError('Another strict controller owns the Windows boundary')
            request = consume(paths, request_id)
            state = {'schema': 1, 'instance': uuid.uuid4().hex, 'pid': os.getpid(),
                     'process_created': generation(os.getpid()), 'state': 'preparing',
                     'passed': False, 'full_tunnel_verified': False, 'router_changed': False,
                     'ordinary_applications_changed': False, 'utc': stamp(), **request}
            # Publish while still admitted: a subsequent claim can identify and
            # stop this exact process before changing resources.
            atomic_json(folder / 'status.json', state, folder)
        result = _serve_admitted(paths, report_path, folder, state)
        child_event(paths, request, 'finish')
        return result
    except (OSError, SafetyError) as exc:
        if request is None:
            try:
                admission_denied(paths, 'start', request_id,
                                 verified_identity=getattr(exc, 'verified_identity', None))
            except (OSError, SafetyError):
                pass
        raise
    finally:
        if lockfile is not None:
            lockfile.seek(0)
            msvcrt.locking(lockfile.fileno(), msvcrt.LK_UNLCK, 1)
            lockfile.close()
        if mutex:
            kernel.ReleaseMutex(mutex)
            kernel.CloseHandle(mutex)


def _serve_admitted(paths, report_path, folder, state):
    lease = relay = None
    def publish():
        state['utc'] = stamp()
        atomic_json(folder / 'status.json', state, folder)
        atomic_json(report_path, state, report_path.parent)
        atomic_json(folder / ('uac-' + state['request_id'] + '.json'), state, folder)
    def closing():
        try:
            return netguard.read_json(folder / 'close.request', folder).get('instance') == state['instance']
        except FileNotFoundError:
            return False
    try:
        targets = identities(paths)
        remote = remote_backend.load(paths)
        if remote is not None:
            state['backend'] = remote_backend.backend_kind(remote)
            reach = remote_backend.reachable(remote)
            if reach['status'] != 'reachable':
                # Nothing is blocked because of an exit that does not answer: this is the first-install rule.
                state.update(state='blocked_exit_unreachable', reason=reach.get('reason'))
                publish()
                return state
        state['phase'] = 'install_client_boundary'
        with Engine() as permanent:
            permanent.ensure_sublayer()
            permanent.install(deny_rules(targets))
        state.update(state='direct_sockets_blocked', persistent_boundary=True, standalone_cli=cli_state(paths))
        publish()
        # No client permission exists while checking or preparing the backend.
        state['phase'] = 'verify_backend'
        guard = worker = None
        if remote is None:
            guard, meta, config, worker = backend(paths)
            outbound = config['outbounds'][0]
            engine_identity = Identity('app', str(Path(meta['engine_path'])))
            endpoint = Rule(engine_identity, 'connect_v4', PERMIT, outbound['server'], outbound['server_port'], True)
            engine_denies = [Rule(engine_identity, 'connect_' + family) for family in ('v4', 'v6')]
            state['phase'] = 'pin_engine_endpoint'
            with Engine() as permanent:
                permanent.install(engine_denies + [endpoint])
            state['engine_endpoint_pinned'] = True
        saved = connections.load(paths)
        if saved is None:
            state.update(state='blocked_profile_required', reason='Configure trusted expected exit addresses first')
            publish()
            return state
        if saved['local_proxy'] not in (netguard.PROXY_URL, GATE_URL) or saved['router_proxy'] is not None:
            raise SafetyError('Only the reviewed local snow backend is eligible for this gate')
        relay = None

        def start_relay(instance):
            if (folder / 'measure-destinations.flag').exists():
                instance.measure = folder / 'destinations.jsonl'
            if not (folder / 'allow-telemetry.flag').exists():
                from .tunnel_transport import TELEMETRY_SUFFIXES
                instance.deny = TELEMETRY_SUFFIXES
                state['telemetry_denied'] = list(TELEMETRY_SUFFIXES)
            threading.Thread(target=instance.serve, daemon=True).start()
        if remote is not None:
            # The exit is measured through the real relay, the only path clients will have.
            relay = remote_backend.make_relay(remote, port=GATE_PORT)
            start_relay(relay)
            test_profile = dict(saved, local_proxy=GATE_URL)
        else:
            test_profile = dict(saved, local_proxy=netguard.PROXY_URL)
        if not connections.check(test_profile)['passed']:
            state.update(state='blocked_exit_mismatch')
            publish()
            return state
        state['phase'] = 'verify_delegated_traffic_coverage'
        from .brokered_dns import coverage_gate
        coverage = coverage_gate()
        state['coverage'] = coverage
        accepted = l1_consent.admits(coverage, l1_consent.load(folder))
        if accepted and not coverage['passed']:
            state['level'] = 'L1_owner_accepted_limits'
        if not accepted:
            state.update(state='direct_sockets_blocked_coverage_incomplete', full_tunnel_verified=False)
            publish()
            return state
        if relay is None:
            relay = create_transport(netguard.PROXY_URL, lambda stream: peer_is_engine(stream, worker['engine_pid']))
            start_relay(relay)
        # Verify actual forwarding before permits, using the separate diagnostic process.
        if not connections.check(dict(saved, local_proxy=GATE_URL))['passed']:
            raise SafetyError('Relay verification failed; Claude stays blocked')
        changes = configure_future_clients(paths)
        if closing() or connections.load(paths) != saved:
            state['state'] = 'blocked_close_requested'
            return state
        lease = Engine(dynamic=True)
        lease.install(relay_permits(targets, GATE_PORT))
        state.update(state='relay_open', passed=True, proxy_url=GATE_URL, clients_configured=changes,
                     live_permit_session=True, restart_existing_clients_required=True)
        publish()
        expected_profile = saved
        failures = 0
        while True:
            reason = None
            if closing():
                reason = 'close_requested'
            elif connections.load(paths) != expected_profile:
                reason = 'profile_changed'
            else:
                try:
                    if remote is None:
                        latest = netguard.read_json(guard.base / 'worker-status.json', guard.base)
                        if latest.get('instance') != worker.get('instance') or latest.get('engine_pid') != worker.get('engine_pid') or latest.get('state') != 'running':
                            reason = 'backend_changed'
                        elif not netguard.check_engine_and_config(guard).get('passed'):
                            reason = 'backend_config_failed'
                    if reason is None:
                        failures, reason = l1_monitor.probe_verdict(connections.check(dict(saved, local_proxy=GATE_URL)), failures)
                except (OSError, ValueError, KeyError, SafetyError):
                    failures, reason = l1_monitor.monitor_error(failures)
            if reason:
                state['stop_reason'] = reason
                break
            before = len(targets)
            targets = adopt_new_identities(paths, targets, lease, state)
            if len(targets) != before or 'adopt_error' in state:
                publish()
            # Polling detects operational failure; prevention of direct traffic
            # comes from the permanent endpoint pin and the client deny rules.
            time.sleep(5)
    except Exception as exc:
        state.update(state='blocked_error' if state.get('persistent_boundary') else 'installation_failed_protection_unknown', error_type=type(exc).__name__)
        state.setdefault('stop_reason', 'exception')
        if isinstance(exc, SafetyError):
            state['error_reason'] = str(exc)
    finally:
        if lease:
            lease.close()  # revoke permissions before closing streams
        if relay:
            relay.close()
        if state['state'] == 'relay_open':
            state['state'] = 'blocked_controller_stopped'
        state.update(passed=False, live_permit_session=False, finished=True)
        publish()
        l1_monitor.record_exit(folder, state)
    return state


def l1_accept(paths, confirmed):
    """Record the owner's acceptance of exactly the boundaries open right now."""
    from .brokered_dns import coverage_gate
    coverage = coverage_gate()
    open_now = l1_consent.required(coverage)
    if confirmed is not True:
        return {'status': 'l1_acceptance_not_recorded', 'passed': False, 'open_boundaries': open_now,
                'next': 'repeat with --confirm-l1-limits after reading every listed boundary'}
    folder = directory(paths)
    folder.mkdir(parents=True, exist_ok=True)
    saved = l1_consent.record(folder, coverage)
    return {'status': 'l1_acceptance_recorded', 'passed': True, 'accepted': saved['accepted'],
            'opens_network': False, 'full_tunnel_verified': False}


def l1_revoke(paths):
    return {'status': 'l1_acceptance_revoked' if l1_consent.revoke(directory(paths)) else 'l1_acceptance_remains', 'passed': True}


def l1_status(paths):
    saved = l1_consent.load(directory(paths))
    return {'status': 'l1_acceptance_present' if saved else 'l1_acceptance_absent', 'passed': False,
            'accepted': saved['accepted'] if saved else [], 'utc': saved['utc'] if saved else None}


def remove(paths, report_path, *, request_id=None):
    """Elevated: delete every filter in the owned sublayer, the sublayer, and our proxy policy values."""
    from . import wfp
    import winreg
    folder = directory(paths)
    result = {'schema': 1, 'finished': False, 'utc': stamp()}
    from .uac_request import admit_child, child_event
    result.update(admit_child(paths, 'remove', request_id))
    try:
        state = netguard.read_json(folder / 'status.json', folder) if (folder / 'status.json').exists() else {}
        if state.get('state') == 'relay_open':
            raise SafetyError('Stop the controller first; permits must be revoked before removal')
        with Engine() as engine:
            if engine.existing_sublayer():
                keys = sorted(engine.own_keys())
                engine._call('FwpmTransactionBegin0', [wfp.wintypes.HANDLE, wfp.wintypes.DWORD], engine.handle, 0)
                try:
                    for value in keys:
                        key = wfp.GUID.of(value)
                        engine._call('FwpmFilterDeleteByKey0', [wfp.wintypes.HANDLE, ctypes.POINTER(wfp.GUID)], engine.handle, ctypes.byref(key))
                    from .strict_wfp import SUBKEY
                    sub = SUBKEY
                    engine._call('FwpmSubLayerDeleteByKey0', [wfp.wintypes.HANDLE, ctypes.POINTER(wfp.GUID)], engine.handle, ctypes.byref(sub))
                    engine._call('FwpmTransactionCommit0', [wfp.wintypes.HANDLE], engine.handle)
                except BaseException:
                    engine._call('FwpmTransactionAbort0', [wfp.wintypes.HANDLE], engine.handle)
                    raise
                result['filters_removed'] = len(keys)
            result['sublayer_present_after'] = engine.existing_sublayer()
            result['filters_remaining_after'] = len(engine.own_keys())
            if result['sublayer_present_after'] or result['filters_remaining_after']:
                raise SafetyError('Strict boundary remains after removal')
        removed = []
        for label, hive in [('user', winreg.HKEY_CURRENT_USER), ('machine', winreg.HKEY_LOCAL_MACHINE)]:
            try:
                with winreg.OpenKey(hive, r'SOFTWARE\Policies\Claude', 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                    value, kind = winreg.QueryValueEx(key, 'egressProxyUrl')
                    if value == GATE_URL and kind == winreg.REG_SZ:
                        winreg.DeleteValue(key, 'egressProxyUrl')
                        removed.append(label + '_desktop_proxy')
            except FileNotFoundError:
                pass
        result['policy_values_removed'] = removed
        remaining = []
        for label, hive in [('user', winreg.HKEY_CURRENT_USER), ('machine', winreg.HKEY_LOCAL_MACHINE)]:
            try:
                with winreg.OpenKey(hive, r'SOFTWARE\Policies\Claude', 0, winreg.KEY_READ) as key:
                    value, kind = winreg.QueryValueEx(key, 'egressProxyUrl')
                    if value == GATE_URL and kind == winreg.REG_SZ:
                        remaining.append(label + '_desktop_proxy')
            except FileNotFoundError:
                pass
        result['policy_values_remaining_after'] = remaining
        if remaining:
            raise SafetyError('Claude proxy policy remains after removal')
        result['removed'] = True
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
    result['finished'] = True
    child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def elevated_remove(paths):
    return gui_elevated(paths, 'remove')


TASK_NAME = 'ClaudeReset L1 Controller'


def autostart_directory():
    return Path(os.environ['ProgramFiles']) / 'ClaudeReset-L1'


def _task_xml(executable, report, user):
    from xml.sax.saxutils import escape
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(user)}</UserId><Delay>PT1M</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="A"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Hidden>true</Hidden></Settings>
  <Actions Context="A"><Exec><Command>{escape(str(executable))}</Command><Arguments>--strict-guard-serve --report "{escape(str(report))}"</Arguments></Exec></Actions>
</Task>
'''


ASIDE = '.old-'


def swap_in(temporary, destination):
    """Put a new file in place even if the old one is a running program.

    A running image cannot be overwritten or deleted, but Windows lets it be renamed; the new file then
    takes the name and the old one is cleared later. This is what lets an update be installed while the
    controller or a wrapper started by an open Claude Code session is still running."""
    try:
        os.replace(temporary, destination)
    except PermissionError:
        os.replace(destination, destination.with_name(destination.name + ASIDE + str(int(time.time()))))
        os.replace(temporary, destination)


def clear_asides(folder):
    """Delete renamed-away old files that are no longer running; the rest wait for the next call."""
    for old in folder.glob('*' + ASIDE + '*'):
        try:
            old.unlink()
        except OSError:
            pass


def remove_file(path):
    try:
        path.unlink(missing_ok=True)
    except PermissionError:
        os.replace(path, path.with_name(path.name + ASIDE + str(int(time.time()))))


def autostart_install(paths, report_path, *, request_id=None):
    """Elevated: copy the frozen program into Program Files and register the logon task."""
    import shutil
    import tempfile
    result = {'schema': 1, 'finished': False, 'utc': stamp()}
    from .uac_request import admit_child, child_event
    result.update(admit_child(paths, 'autostart', request_id))
    try:
        if not getattr(sys, 'frozen', False):
            raise SafetyError('Autostart needs the frozen ClaudeReset.exe')
        target = autostart_directory()
        target.mkdir(exist_ok=True)
        if os.path.islink(target) or (os.lstat(target).st_file_attributes & 0x400):
            raise SafetyError('Autostart folder is a reparse point')
        clear_asides(target)
        executable = target / 'ClaudeReset.exe'
        temporary = target / 'ClaudeReset.exe.new'
        shutil.copyfile(sys.executable, temporary)
        swap_in(temporary, executable)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        # The wrapper that starts Claude inside the package; absent in a build without it.
        runner = Path(sys.executable).with_name(RUNNER_NAME)
        if runner.is_file():
            temporary = target / (RUNNER_NAME + '.new')
            shutil.copyfile(runner, temporary)
            swap_in(temporary, target / RUNNER_NAME)
            result['runner_sha256'] = hashlib.sha256((target / RUNNER_NAME).read_bytes()).hexdigest()
        user = os.environ['USERDOMAIN'] + '\\' + os.environ['USERNAME']
        report = directory(paths) / 'autostart-report.json'
        with tempfile.TemporaryDirectory() as folder:
            xml = Path(folder) / 'task.xml'
            expected_xml = _task_xml(executable, report, user)
            xml.write_text(expected_xml, encoding='utf-16')
            created = subprocess.run(['schtasks', '/Create', '/TN', TASK_NAME, '/XML', str(xml), '/F'],
                                     capture_output=True, text=True, creationflags=0x08000000)
        if created.returncode != 0:
            raise SafetyError('Task registration failed')
        definition = autostart_task_definition(expected_xml)
        result.update(registered=definition == 'matching', definition_state=definition,
                      executable_sha256=digest, task=TASK_NAME)
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
    result['finished'] = True
    child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def autostart_task_definition(expected_xml):
    """Conservative definition snapshot, never process-exit or replay authority.

    Only namespace/attribute ordering and formatting whitespace are normalized.
    Scheduler-added defaults remain a mismatch until explicitly supported.
    """
    from xml.etree import ElementTree as ET

    def tree(xml):
        if not isinstance(xml, str) or len(xml) > 65536 or '<!DOCTYPE' in xml.upper():
            raise ValueError('Task definition unavailable')
        def node(element):
            return (element.tag, sorted(element.attrib.items()),
                    element.text if element.text and element.text.strip() else '',
                    element.tail if element.tail and element.tail.strip() else '',
                    tuple(node(child) for child in element))
        return node(ET.fromstring(xml))

    try:
        row = ps_json(r'''
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
        $service = New-Object -ComObject 'Schedule.Service';
        $service.Connect();
        $task = $service.GetFolder('\').GetTask('ClaudeReset L1 Controller');
        @{xml=$task.Xml} | ConvertTo-Json -Compress
        ''')
        if isinstance(row, dict):
            return 'matching' if tree(row.get('xml')) == tree(expected_xml) else 'different'
    except (OSError, ValueError, TypeError, RecursionError, ET.ParseError, SafetyError):
        pass
    return 'unknown'


def autostart_task_state():
    """Exact task lookup; CLI failure and localized text never prove absence."""
    try:
        row = ps_json(r'''
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new();
        $service = New-Object -ComObject 'Schedule.Service';
        $service.Connect();
        $folder = $service.GetFolder('\');
        try {
            $task = $folder.GetTask('ClaudeReset L1 Controller');
            if ($null -eq $task) { $state = 'unknown' }
            else { $state = 'present' }
        } catch {
            $failure = $_.Exception;
            while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
            $state = 'unknown';
            if (($failure -is [System.Runtime.InteropServices.COMException]) -and
                ($failure.ErrorCode -eq -2147024894)) { $state = 'absent' }
        }
        @{state=$state} | ConvertTo-Json -Compress
        ''')
        if isinstance(row, dict) and row.get('state') in ('present', 'absent', 'unknown'):
            return row['state']
    except (OSError, ValueError, TypeError, SafetyError):
        pass
    return 'unknown'


def autostart_remove(paths, report_path, *, request_id=None):
    """Elevated: unregister the logon task and delete only the program copy this feature installed."""
    result = {'schema': 1, 'finished': False, 'utc': stamp()}
    from .uac_request import admit_child, child_event
    result.update(admit_child(paths, 'autostart-off', request_id))
    try:
        subprocess.run(['schtasks', '/Delete', '/TN', TASK_NAME, '/F'], capture_output=True, text=True, creationflags=0x08000000)
        state = autostart_task_state()
        result['task_state_after'] = state
        result['task_present_after'] = {'present': True, 'absent': False, 'unknown': None}[state]
        target = autostart_directory()
        executable = target / 'ClaudeReset.exe'
        result['program_removed'] = False
        if state != 'absent':
            raise SafetyError('Task absence was not verified')
        if executable.is_file():
            remove_file(executable)
        remove_file(target / RUNNER_NAME)
        clear_asides(target)
        if target.is_dir() and not any(target.iterdir()):
            target.rmdir()
        result['program_removed'] = (not executable.exists() and
                                     not (target / RUNNER_NAME).exists() and
                                     not any(target.glob('*' + ASIDE + '*')))
    except BaseException as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
    result['finished'] = True
    child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


def elevated_autostart(paths, enable=True):
    return gui_elevated(paths, 'autostart' if enable else 'autostart-off')


def status(paths):
    folder = directory(paths)
    path = folder / 'status.json'
    if not path.exists():
        return {'status': 'strict_not_installed', 'passed': False}
    row = netguard.read_json(path, folder)
    # A status file is not a live WFP attestation. Never authorize from this file.
    return {'status': 'strict_controller_last_report', 'last_report': row,
            'passed': False, 'requires_live_verification': True}


def probe(paths):
    rows = []
    script = netguard.WORKER_PROBE.replace('__PROXY__', GATE_URL).replace('__LAUNCH__', '')
    for package in (netguard.DESKTOP_PACKAGE, netguard.OWNED_PACKAGE):
        result = netguard.in_package(package, script)
        boundary = result.get('family') == package[0] and all(result.get('tcp_' + k) == '10013' for k in ('v4', 'v6', 'backend', 'controller'))
        mode = ('relay_open' if result.get('tcp_gate') == 'connected' and result.get('proxy_https') == '200'
                else 'closed' if result.get('tcp_gate') == '10013' else 'unverified')
        rows.append({'package': package[0], 'boundary_passed': boundary, 'mode': mode, 'results': result})
    passed = all(r['boundary_passed'] and r['mode'] != 'unverified' for r in rows)
    return {'status': 'strict_scoped_probe_passed' if passed else 'strict_scoped_probe_failed',
            'passed': passed, 'packages': rows, 'full_tunnel_verified': False,
            'router_changed': False, 'ordinary_applications_changed': False,
            'limits': ['Проба пакетов подтверждает указанную границу TCP; все IPC/гостевые сценарии отдельно не аттестованы']}


def inspect(paths):
    targets = identities(paths)
    _, meta, config, _ = backend(paths)
    out = config['outbounds'][0]
    engine = Identity('app', str(Path(meta['engine_path'])))
    rules = deny_rules(targets) + [Rule(engine, 'connect_' + f) for f in ('v4', 'v6')]
    rules += [Rule(engine, 'connect_v4', PERMIT, out['server'], out['server_port'], True)]
    with Engine() as reader:
        verified = sum(reader.exists_verified(r) for r in rules)
        expected = {r.key.value() for r in rules}
        dynamic = {r.key.value() for r in relay_permits(targets, GATE_PORT)}
        actual = reader.own_keys()
        unexpected = actual - expected - dynamic
    return {'status': 'strict_windows_boundary_inspected', 'passed': verified == len(rules) and not unexpected,
            'persistent_rules_expected': len(rules), 'persistent_rules_verified': verified,
            'active_permit_count': len(actual & dynamic), 'unexpected_rule_count': len(unexpected),
            'settings_changed': False, 'full_tunnel_verified': False}


@serialized('strict_close', completed=set(), nested=True,
            nested_completed={'strict_close_requested'})
def request_close(paths):
    # Wait on the exact process generation, not just the relay or task state.
    # Standalone close retains ownership for subsequent reconciliation.
    folder = directory(paths)
    from .controller_process import close_and_wait
    exited = close_and_wait(folder, netguard.read_json, atomic_json, stamp())
    return {'status': 'strict_close_requested' if exited else 'controller_not_stopped',
            'passed': exited, 'process_exited': exited, 'filters_removed': False}


def live_launch_gate(paths, profile):
    folder = directory(paths)
    try:
        state = netguard.read_json(folder / 'status.json', folder)
    except FileNotFoundError:
        return {'status': 'blocked_strict_controller_required', 'passed': False}
    if state.get('state') != 'relay_open' or type(state.get('pid')) is not int:
        return {'status': 'blocked_strict_controller_closed', 'passed': False}
    pid = state['pid']
    live = ps_json(f'''$p=Get-CimInstance Win32_Process -Filter 'ProcessId={pid}';
      @{{image=[string]$p.ExecutablePath; command=[string]$p.CommandLine;
         owners=@(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort {GATE_PORT} -ErrorAction SilentlyContinue |
                   ForEach-Object {{[int]$_.OwningProcess}})}} | ConvertTo-Json -Compress''')
    expected = {os.path.normcase(sys.executable)}
    if not getattr(sys, 'frozen', False):
        expected.add(os.path.normcase(str(Path(sys.executable).with_name('pythonw.exe'))))
    if (not live or live.get('owners') != [pid] or os.path.normcase(live.get('image') or '') not in expected
            or '--strict-guard-serve' not in (live.get('command') or '')):
        return {'status': 'blocked_strict_controller_identity', 'passed': False}
    result = connections.check(dict(profile, local_proxy=GATE_URL))
    result['proxy_url'] = GATE_URL
    result['status'] = 'live_relay_verified_package_probe_required' if result['passed'] else 'blocked_relay_probe'
    return result


def elevated_start(paths):
    return gui_elevated(paths, 'start')


def dispatch_request(request, *, executable=None, exclude_extension=False):
    """Dispatch a persisted claim, optionally using the newly built frozen program."""
    flags = {'start': '--strict-guard-serve', 'remove': '--strict-guard-remove-serve',
             'autostart': '--strict-guard-autostart-serve',
             'autostart-off': '--strict-guard-autostart-off-serve',
             'package-register': '--l1-package-register-serve',
             'package-remove': '--l1-package-remove-serve',
             'filters': '--network-guard-filters'}
    arguments = [flags[request.operation], '--report', request.receipt,
                 '--state-root', request.state_root, '--uac-request-id', request.request_id]
    if exclude_extension:
        if request.operation != 'remove':
            raise SafetyError('Extension exclusion requires a removal receipt')
        arguments.append('--exclude-vscode-extension')
    frozen_program = executable is not None
    executable = str(executable) if frozen_program else sys.executable
    if not frozen_program and not getattr(sys, 'frozen', False):
        arguments.insert(0, str(Path(__file__).resolve().parents[1] / 'launcher.py'))
        windowless = Path(executable).with_name('pythonw.exe')
        if not windowless.is_file():
            raise SafetyError('Windowless Python is required')
        executable = str(windowless)
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                  ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    return shell.ShellExecuteW(None, 'runas', executable, subprocess.list2cmdline(arguments), None, 0) or 0


def gui_elevated(paths, operation):
    from .uac_request import execute
    if operation == 'start':
        plan(paths)
    return execute(paths, operation, dispatch_request)
