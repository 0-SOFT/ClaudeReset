"""The L1 controller: one admitted process blocks the clients' direct sockets, checks the backend and the exit,
then relays the clients through itself until it has to stop.

The relay owns both its listening socket and the dynamic WFP permit session.
Its death closes connections and removes permits; persistent deny rules remain.
"""
from __future__ import annotations

import msvcrt
import os
from pathlib import Path
import threading
import time

from . import connections, controller_process, controller_status, gate_rules, l1_consent, l1_monitor
from . import remote_backend
from .. import config
from .. import layout
from ..backend import location as backend_location
from ..elevation import launch
from ..elevation import request as uac
from ..elevation.admission import consume
from ..elevation.claims import serialized
from ..elevation.locks import locked
from ..errors import SafetyError, error_info
from ..model.status import Measurement, Network
from ..safeio import atomic_json, read_json
from ..windows import mutex, policy
from ..windows.system import ps_json
from ..windows.wfp import GUID
from .relay import Relay
from .strict_wfp import Engine, Identity, Rule, PERMIT, deny_rules, relay_permits
from .tunnel_transport import TELEMETRY_SUFFIXES, ConnectRelay
from ..model.ids import new_id, utc_now
from .probe import Probe

__all__ = ['Controller', 'configure_future_clients', 'create_transport', 'elevated', 'elevated_remove',
           'elevated_start', 'peer_is_engine', 'remove', 'request_close', 'run_admitted', 'serve', 'stamp']

# One controller for the whole computer, whichever user or session starts it.
MUTEX = 'Global\\ClaudeReset.StrictGate.v1'



def peer_is_engine(stream, engine_pid):
    """Attribute this exact established backend socket before forwarding any bytes."""
    local = stream.getsockname()[1]
    remote = stream.getpeername()[1]
    result = ps_json(f'''@{{pids=@(Get-NetTCPConnection -State Established -LocalAddress '{config.LOOPBACK}' '''
                     f'''-LocalPort {remote} -RemoteAddress '{config.LOOPBACK}' -RemotePort {local} '''
                     '''-ErrorAction SilentlyContinue | ForEach-Object {[int]$_.OwningProcess})} '''
                     '''| ConvertTo-Json -Compress''')
    return (result or {}).get('pids') == [engine_pid]


def create_transport(proxy, verify_peer, *, port=config.RELAY_PORT):
    """The gateway is independent of the provider; backend attestation is separate."""
    return ConnectRelay(proxy, verify_peer, port=port)


def configure_future_clients(paths):
    """Point only the Desktop proxy policy at the relay; create it when absent.

    The shared ~/.claude/settings.json is never written: it is read by every
    Claude Code including the unprotected shared editor, and a stopped relay
    would break them. Protected standalone CLI runs get the proxy per launch.
    """
    changes = []
    for label, hive in policy.HIVES:
        if not policy.replace_string(hive, config.DESKTOP_POLICY_KEY, config.DESKTOP_PROXY_VALUE, config.RELAY_URL,
                                     (config.BACKEND_URL, config.RELAY_URL)):
            raise SafetyError('Desktop proxy policy changed; refusing to overwrite it')
        changes.append(label + '_desktop_proxy')
    return changes


def serve(paths, report_path, *, request_id=None, engine=Engine, probe=None):
    """Admit one exact start before any controller effects or status overwrite."""
    folder = layout.controller(paths)
    lockfile = held = None
    request = None
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
            held = mutex.hold(MUTEX)
            if held is None:
                raise SafetyError('Another strict controller owns the Windows boundary')
            request = consume(paths, request_id)
            state = {'schema': 1, 'instance': new_id(), 'pid': os.getpid(),
                     'process_created': controller_process.generation(os.getpid()), 'state': 'preparing',
                     'passed': False, 'full_tunnel_verified': False, 'router_changed': False,
                     'ordinary_applications_changed': False, 'utc': utc_now(), **request}
            # Publish while still admitted: a subsequent claim can identify and
            # stop this exact process before changing resources.
            controller_status.write(folder, state)
        result = run_admitted(paths, report_path, folder, state, engine=engine, probe=probe)
        uac.child_event(paths, request, 'finish')
        return result
    except (OSError, SafetyError) as exc:
        if request is None:
            try:
                uac.admission_denied(paths, 'start', request_id,
                                     verified_identity=getattr(exc, 'verified_identity', None))
            except (OSError, SafetyError):
                pass
        raise
    finally:
        if lockfile is not None:
            lockfile.seek(0)
            msvcrt.locking(lockfile.fileno(), msvcrt.LK_UNLCK, 1)
            lockfile.close()
        if held is not None:
            held.release()


class Controller:
    """One admitted run of the L1 controller.

    It blocks the clients' direct sockets, verifies the backend and the exit, opens the relay to the clients and
    watches until it has to stop. Each phase publishes its state; a phase that stops the run returns False.
    """

    def __init__(self, paths: layout.Paths, report_path: Path, folder: Path, state: dict, *,
                 engine: type = Engine, probe: Probe | None = None) -> None:
        self.paths, self.report_path, self.folder, self.state = paths, report_path, folder, state
        # The WFP engine and the network checks: the platform's own unless a test gives doubles.
        self.engine, self.probe = engine, probe or Probe()
        self.lease = self.relay = None
        self.targets = self.remote = self.saved = None
        self.guard = self.worker = None

    def publish(self) -> None:
        state, folder = self.state, self.folder
        state['utc'] = utc_now()
        controller_status.write(folder, state)
        atomic_json(self.report_path, state, self.report_path.parent)
        atomic_json(folder / ('uac-' + state['request_id'] + '.json'), state, folder)

    def closing(self) -> bool:
        try:
            return read_json(self.folder / 'close.request', self.folder).get('instance') == self.state['instance']
        except FileNotFoundError:
            return False

    def start_relay(self, instance: Relay) -> None:
        if (self.folder / 'measure-destinations.flag').exists():
            instance.measure = self.folder / 'destinations.jsonl'
        if not (self.folder / 'allow-telemetry.flag').exists():
            instance.deny = TELEMETRY_SUFFIXES
            self.state['telemetry_denied'] = list(TELEMETRY_SUFFIXES)
        threading.Thread(target=instance.serve, daemon=True).start()

    def block_clients(self) -> bool:
        state = self.state
        self.targets = gate_rules.identities(self.paths)
        self.remote = remote_backend.load(self.paths)
        if self.remote is not None:
            state['backend'] = remote_backend.backend_kind(self.remote)
            reach = self.probe.reachable(self.remote)
            if reach['status'] != Measurement.REACHABLE:
                # Nothing is blocked because of an exit that does not answer: this is the first-install rule.
                state.update(state='blocked_exit_unreachable', reason=reach.get('reason'))
                self.publish()
                return False
        state['phase'] = 'install_client_boundary'
        with self.engine() as permanent:
            permanent.ensure_sublayer()
            permanent.install(deny_rules(self.targets))
        state.update(state='direct_sockets_blocked', persistent_boundary=True,
                     standalone_cli=gate_rules.cli_state(self.paths))
        self.publish()
        return True

    def pin_backend(self) -> bool:
        # No client permission exists while checking or preparing the backend.
        self.state['phase'] = 'verify_backend'
        if self.remote is None:
            self.guard, meta, engine_config, self.worker = gate_rules.backend(self.paths)
            outbound = engine_config['outbounds'][0]
            engine_identity = Identity('app', str(Path(meta['engine_path'])))
            endpoint = Rule(engine_identity, 'connect_v4', PERMIT, outbound['server'], outbound['server_port'], True)
            engine_denies = [Rule(engine_identity, 'connect_' + family) for family in ('v4', 'v6')]
            self.state['phase'] = 'pin_engine_endpoint'
            with self.engine() as permanent:
                permanent.install(engine_denies + [endpoint])
            self.state['engine_endpoint_pinned'] = True
        return True

    def check_exit(self) -> bool:
        state = self.state
        saved = connections.load(self.paths)
        if saved is None:
            state.update(state='blocked_profile_required', reason='Configure trusted expected exit addresses first')
            self.publish()
            return False
        if saved['local_proxy'] not in (config.BACKEND_URL, config.RELAY_URL) or saved['router_proxy'] is not None:
            raise SafetyError('Only the reviewed local backend is eligible for this gate')
        self.saved = saved
        if self.remote is not None:
            # The exit is measured through the real relay, the only path clients will have.
            self.relay = remote_backend.make_relay(self.remote, port=config.RELAY_PORT)
            self.start_relay(self.relay)
            test_profile = dict(saved, local_proxy=config.RELAY_URL)
        else:
            test_profile = dict(saved, local_proxy=config.BACKEND_URL)
        if not self.probe.check(test_profile)['passed']:
            state.update(state='blocked_exit_mismatch')
            self.publish()
            return False
        return True

    def check_coverage(self) -> bool:
        state = self.state
        state['phase'] = 'verify_delegated_traffic_coverage'
        coverage = self.probe.coverage()
        state['coverage'] = coverage
        accepted = l1_consent.admits(coverage, l1_consent.load(self.folder))
        if accepted and not coverage['passed']:
            state['level'] = 'L1_owner_accepted_limits'
        if not accepted:
            state.update(state='direct_sockets_blocked_coverage_incomplete', full_tunnel_verified=False)
            self.publish()
            return False
        return True

    def open_relay(self) -> bool:
        if self.relay is None:
            worker = self.worker
            self.relay = create_transport(config.BACKEND_URL,
                                          lambda stream: peer_is_engine(stream, worker['engine_pid']))
            self.start_relay(self.relay)
        # Verify actual forwarding before permits, using the separate diagnostic process.
        if not self.probe.check(dict(self.saved, local_proxy=config.RELAY_URL))['passed']:
            raise SafetyError('Relay verification failed; Claude stays blocked')
        changes = configure_future_clients(self.paths)
        if self.closing() or connections.load(self.paths) != self.saved:
            self.state['state'] = 'blocked_close_requested'
            return False
        self.lease = self.engine(dynamic=True)
        self.lease.install(relay_permits(self.targets, config.RELAY_PORT))
        self.state.update(state='relay_open', passed=True, proxy_url=config.RELAY_URL, clients_configured=changes,
                          live_permit_session=True, restart_existing_clients_required=True)
        self.publish()
        return True

    def stop_reason(self, failures: int) -> tuple[int, str | None]:
        """(failures, reason): why the relay must close now, or None while everything still holds."""
        if self.closing():
            return failures, 'close_requested'
        if connections.load(self.paths) != self.saved:
            return failures, 'profile_changed'
        reason = None
        try:
            if self.remote is None:
                guard, worker = self.guard, self.worker
                latest = backend_location.read_worker_state(guard.base)
                if (latest.get('instance') != worker.get('instance')
                        or latest.get('engine_pid') != worker.get('engine_pid')
                        or latest.get('state') != 'running'):
                    reason = 'backend_changed'
                elif not backend_location.check_engine_and_config(guard).get('passed'):
                    reason = 'backend_config_failed'
            if reason is None:
                checked = self.probe.check(dict(self.saved, local_proxy=config.RELAY_URL))
                failures, reason = l1_monitor.probe_verdict(checked, failures)
        except (OSError, ValueError, KeyError, SafetyError):
            failures, reason = l1_monitor.monitor_error(failures)
        return failures, reason

    def watch(self) -> None:
        failures = 0
        while True:
            failures, reason = self.stop_reason(failures)
            if reason:
                self.state['stop_reason'] = reason
                break
            before = len(self.targets)
            self.targets = gate_rules.adopt_new_identities(self.paths, self.targets, self.lease, self.state)
            if len(self.targets) != before or 'adopt_error' in self.state:
                self.publish()
            # Polling detects operational failure; prevention of direct traffic
            # comes from the permanent endpoint pin and the client deny rules.
            time.sleep(5)

    def run(self) -> dict:
        state = self.state
        try:
            if (self.block_clients() and self.pin_backend() and self.check_exit() and self.check_coverage()
                    and self.open_relay()):
                self.watch()
        except Exception as exc:
            failed = 'blocked_error' if state.get('persistent_boundary') else 'installation_failed_protection_unknown'
            state.update(state=failed, error_type=type(exc).__name__)
            state.setdefault('stop_reason', 'exception')
            if isinstance(exc, SafetyError):
                state['error_reason'] = str(exc)
        finally:
            if self.lease:
                self.lease.close()  # revoke permissions before closing streams
            if self.relay:
                self.relay.close()
            if state['state'] == 'relay_open':
                state['state'] = 'blocked_controller_stopped'
            state.update(passed=False, live_permit_session=False, finished=True)
            self.publish()
            l1_monitor.record_exit(self.folder, state)
        return state


def run_admitted(paths, report_path, folder, state, *, engine=Engine, probe=None):
    return Controller(paths, report_path, folder, state, engine=engine, probe=probe).run()


def remove(paths, report_path, *, request_id=None, engine=Engine):
    """Elevated: delete every filter in the owned sublayer, the sublayer, and our proxy policy values."""
    folder = layout.controller(paths)
    result = {'schema': 1, 'finished': False, 'utc': utc_now()}
    result.update(uac.admit_child(paths, 'remove', request_id))
    try:
        state = controller_status.read(folder) if controller_status.exists(folder) else {}
        if state.get('state') == 'relay_open':
            raise SafetyError('Stop the controller first; permits must be revoked before removal')
        with engine() as session:
            if session.existing_sublayer():
                keys = sorted(session.own_keys())
                session.remove_owned([GUID.of(value) for value in keys])
                result['filters_removed'] = len(keys)
            result['sublayer_present_after'] = session.existing_sublayer()
            result['filters_remaining_after'] = len(session.own_keys())
            if result['sublayer_present_after'] or result['filters_remaining_after']:
                raise SafetyError('Strict boundary remains after removal')
        result['policy_values_removed'] = [
            label + '_desktop_proxy' for label, hive in policy.HIVES
            if policy.delete_string(hive, config.DESKTOP_POLICY_KEY, config.DESKTOP_PROXY_VALUE, config.RELAY_URL)]
        remaining = [label + '_desktop_proxy' for label, hive in policy.HIVES
                     if policy.holds_string(hive, config.DESKTOP_POLICY_KEY, config.DESKTOP_PROXY_VALUE,
                                            config.RELAY_URL)]
        result['policy_values_remaining_after'] = remaining
        if remaining:
            raise SafetyError('Claude proxy policy remains after removal')
        result['removed'] = True
    except Exception as exc:
        result['error'] = error_info(exc)
    result['finished'] = True
    uac.child_event(paths, {key: result[key] for key in ('request_id', 'operation', 'state_root')}, 'finish')
    atomic_json(report_path, result, report_path.parent)
    return result


@serialized('strict_close', completed=set(), nested=True,
            nested_completed={Network.STRICT_CLOSE_REQUESTED})
def request_close(paths):
    # Wait on the exact process generation, not just the relay or task state.
    # Standalone close retains ownership for subsequent reconciliation.
    folder = layout.controller(paths)
    exited = controller_process.close_and_wait(folder, read_json, atomic_json, utc_now())
    return {'status': Network.STRICT_CLOSE_REQUESTED if exited else Network.CONTROLLER_NOT_STOPPED,
            'passed': exited, 'process_exited': exited, 'filters_removed': False}


def elevated(paths, operation, *, dispatch=None):
    """Carry out one elevated operation through a persisted claim and wait for its receipt.

    dispatch shows the UAC prompt for the prepared request (launch.dispatch_request when not given)."""
    if operation == 'start':
        gate_rules.plan(paths)
    return uac.execute(paths, operation, dispatch or launch.dispatch_request)


def elevated_start(paths, *, dispatch=None):
    return elevated(paths, 'start', dispatch=dispatch)


def elevated_remove(paths, *, dispatch=None):
    return elevated(paths, 'remove', dispatch=dispatch)
