"""Portable test of the Windows boundary L1 relies on, with no tunnel and no real client.

On a disposable sublayer it denies the ClaudeReset.NetworkIsolation package, opens a loopback relay
whose "backend" is a plain local forwarder, and checks from inside the package that
  - before a permit every direct and loopback connection is refused (10013), the closed gate included;
  - with the relay permit only the gate answers and HTTPS through it works;
  - after the permit is revoked everything is refused again;
while an ordinary process keeps its direct access (positive control).
Everything it adds is deleted by exact key. Needs one elevation, the registered package, and free
loopback ports 25080/25082 (so it refuses to run beside a production controller).
"""
import ctypes
import json
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from ctypes import wintypes as W
from datetime import datetime, timezone
from pathlib import Path

CLOSED = '10013'
DIRECT_KEYS = ('v4', 'v6', 'backend', 'controller')
CONTROL_HOST = ('1.1.1.1', 443)


def blocked(probe):
    return all(probe.get('tcp_' + key) == CLOSED for key in DIRECT_KEYS)


def verdict(control, before, opened, after):
    """'mechanism_passed' only when every expectation holds; each failed one is named."""
    failures = []
    if control.get('loopback_direct') != 'connected':
        failures.append('control_loopback_not_reachable')
    if not blocked(before) or before.get('tcp_gate') != CLOSED:
        failures.append('package_not_closed_before_permit')
    if not blocked(opened):
        failures.append('permit_opened_more_than_the_gate')
    if opened.get('tcp_gate') != 'connected':
        failures.append('gate_not_reachable_with_permit')
    if opened.get('proxy_https') != '200':
        failures.append('https_through_relay_failed')
    if not blocked(after) or after.get('tcp_gate') != CLOSED:
        failures.append('package_not_closed_after_revoke')
    internet = control.get('internet_direct')
    return {'verdict': 'mechanism_passed' if not failures else 'mechanism_failed', 'failures': failures,
            'internet_control': internet if internet else 'not_measured'}


def connect(host, port, timeout=2.0):
    try:
        socket.create_connection((host, port), timeout).close()
        return 'connected'
    except OSError as exc:
        return type(exc).__name__


class DirectBackend:
    """Stand-in for a tunnel: an HTTP CONNECT proxy that forwards straight to the destination."""
    def __init__(self, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.listener.bind(('127.0.0.1', port))
        self.listener.listen(16)
        self.listener.settimeout(.3)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.connections = []
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def serve(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client):
        upstream = None
        try:
            client.settimeout(8)
            header = b''
            while not header.endswith(b'\r\n\r\n') and len(header) < 4096:
                chunk = client.recv(1)
                if not chunk:
                    return
                header += chunk
            fields = header.split(b'\r\n', 1)[0].split(b' ')
            if len(fields) != 3 or fields[0] != b'CONNECT':
                client.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                return
            host, _, port = fields[1].decode('ascii').rpartition(':')
            upstream = socket.create_connection((host.strip('[]'), int(port)), timeout=8)
            self.connections.append(fields[1].decode('ascii'))
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            while not self.stopped.is_set():
                readable, _, _ = select.select([client, upstream], [], [], .5)
                for source in readable:
                    data = source.recv(32768)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except (OSError, ValueError, UnicodeError):
            pass
        finally:
            for stream in (client, upstream):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(3)


def precondition_errors():
    """Reasons not to start, found without elevation."""
    from . import package_isolation
    from .safeio import SafetyError
    errors = []
    try:
        if not package_isolation.accepted(package_isolation.installed()):
            errors.append('package_not_registered: run --l1-package-register first')
    except (OSError, ValueError, subprocess.SubprocessError, SafetyError):
        errors.append('package_state_unknown: registration could not be verified')
    for port, name in ((25080, 'backend'), (25082, 'gate')):
        if connect('127.0.0.1', port, .3) == 'connected':
            errors.append(f'port_{port}_in_use: a {name} is already listening; this test would disturb it')
    return errors


def run(report: Path):
    from . import netguard, strict_guard, strict_wfp, wfp
    from .safeio import SafetyError
    from .strict_wfp import Identity, deny_rules, relay_permits
    sublayer = wfp.GUID.of(uuid.uuid5(strict_wfp.NAMESPACE, 'l1-mechanism-test-v1'))
    strict_wfp.SUBKEY = sublayer
    strict_wfp.SUBWEIGHT = 61200

    class Engine(strict_wfp.Engine):
        # BFE may store a new sublayer with its weight raised by one; only this disposable one accepts the shift.
        def existing_sublayer(self):
            last = None
            for weight in (61200, 61201, 61202):
                strict_wfp.SUBWEIGHT = weight
                try:
                    return strict_wfp.Engine.existing_sublayer(self)
                except SafetyError as exc:
                    last = exc
            raise last

    state = {'schema': 1, 'finished': False, 'utc': datetime.now(timezone.utc).isoformat(), 'steps': {},
             'windows_build': sys.getwindowsversion().build}

    def save():
        report.write_text(json.dumps(state, indent=1), 'utf-8')
    owned = Identity('package', netguard.OWNED_PACKAGE[0])
    backend = relay = lease = None
    added = []
    probe = netguard.WORKER_PROBE.replace('__PROXY__', strict_guard.GATE_URL).replace('__LAUNCH__', '')
    try:
        backend = DirectBackend(netguard.PROXY_PORT).start()
        rules = deny_rules([owned])
        with Engine() as engine:
            engine.ensure_sublayer()
            added = [r for r in rules if not engine.exists_verified(r)]
            engine.install(rules)
        state['steps']['deny_installed'] = {'rules': len(rules), 'added_by_this_run': len(added)}
        save()
        before = netguard.in_package(netguard.OWNED_PACKAGE, probe)
        state['steps']['package_before_permit'] = before
        save()
        relay = strict_guard.create_transport(f'http://127.0.0.1:{backend.port}', lambda stream: True, port=strict_guard.GATE_PORT)
        threading.Thread(target=relay.serve, daemon=True).start()
        time.sleep(.5)
        control = {'loopback_direct': connect('127.0.0.1', strict_guard.GATE_PORT),
                   'internet_direct': connect(*CONTROL_HOST, 4)}
        state['steps']['ordinary_control'] = control
        lease = Engine(dynamic=True)
        lease.install(relay_permits([owned], strict_guard.GATE_PORT))
        opened = netguard.in_package(netguard.OWNED_PACKAGE, probe)
        state['steps']['package_with_permit'] = opened
        state['steps']['backend_saw'] = list(backend.connections)[:5]
        lease.close()
        lease = None
        time.sleep(1)
        after = netguard.in_package(netguard.OWNED_PACKAGE, probe)
        state['steps']['package_after_revoke'] = after
        state.update(verdict(control, before, opened, after))
    except BaseException as exc:
        state.update(verdict='error', error=type(exc).__name__ + ': ' + str(exc)[:200])
    finally:
        cleanup = {}
        try:
            if lease:
                lease.close()
            if relay:
                relay.close()
            if backend:
                backend.close()
            cleanup['processes_closed'] = True
        except BaseException as exc:
            cleanup['processes_error'] = type(exc).__name__
        try:
            with Engine() as engine:
                for rule in added:
                    if engine.exists_verified(rule):
                        engine._call('FwpmFilterDeleteByKey0', [W.HANDLE, ctypes.POINTER(wfp.GUID)], engine.handle, ctypes.byref(rule.key))
                cleanup['own_filters_left'] = sum(engine.exists_verified(r) for r in added)
                engine._call('FwpmSubLayerDeleteByKey0', [W.HANDLE, ctypes.POINTER(wfp.GUID)], engine.handle,
                             ctypes.byref(sublayer), allowed=(0x80320007,))
                cleanup['test_sublayer_left'] = bool(engine.existing_sublayer())
        except BaseException as exc:
            cleanup['filters_error'] = type(exc).__name__ + ': ' + str(exc)[:120]
        state['cleanup'] = cleanup
        state['finished'] = True
        save()
    return state
