"""Detect resolver delegation with a loopback-only DNS sink, never external DNS.

The sink answers only fresh random .invalid names created by this invocation.
Failure/busy port is not evidence of containment. This probe cannot certify all IPC.
"""
from __future__ import annotations
import socket
import threading
from ..backend import location as backend_location
from ..windows.system import ps_json
from .. import config
from ..windows import packages
from ..model.status import Network
from ..model.ids import new_id


def probe():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        server.bind((config.LOOPBACK, 53))
    except OSError:
        server.close()
        return {'status': Network.LOCAL_DNS_PROBE_UNAVAILABLE, 'passed': False, 'external_dns_requests': 0}
    server.settimeout(.2)
    names = [new_id() for _ in range(3)]
    questions = [(bytes([len(name)]) + name.encode('ascii') + b'\x07invalid\0\x00\x01\x00\x01') for name in names]
    counts = [0, 0, 0]
    finished = threading.Event()
    def receive():
        while not finished.is_set():
            try:
                data, peer = server.recvfrom(4096)
                if len(data) < 12 or data[12:] not in questions:
                    continue  # Never answer or log an unrelated query.
                index = questions.index(data[12:])
                counts[index] += 1
                response = data[:2] + b'\x81\x83' + data[4:6] + b'\0\0\0\0\0\0' + data[12:]
                server.sendto(response, peer)
            except socket.timeout:
                continue
            except OSError:
                return
    thread = threading.Thread(target=receive, daemon=True)
    thread.start()
    try:
        ps_json(packages.dns_probe(names[0], config.LOOPBACK))
        rows = []
        for index, package in enumerate((config.DESKTOP_PACKAGE, config.OWNED_PACKAGE), 1):
            result = backend_location.in_package(package, packages.dns_probe(names[index], config.LOOPBACK), timeout=25)
            rows.append({'package': package[0], 'identity_matches': result.get('family') == package[0],
                         'dns_packets_received': counts[index]})
        passed = counts[0] > 0 and all(r['identity_matches'] and r['dns_packets_received'] == 0 for r in rows)
        return {'status': Network.DNS_PROBE_CONTAINED if passed else Network.BROKERED_DNS_NOT_CONTAINED,
                'passed': passed, 'ordinary_control_packets': counts[0], 'packages': rows,
                'external_dns_requests': 0, 'system_dns_changed': False}
    finally:
        finished.set()
        server.close()
        thread.join(1)


def coverage_gate(*, measure=probe):
    """AppContainer and driver boundaries are verified only in disposable fixtures.

    Do not turn a successful socket/exit measurement into authority to open the
    real clients. Existing full-trust clients and Cowork have not been migrated.
    measure is the brokered DNS probe.
    """
    dns = measure()
    return {'passed': False, 'status': Network.BLOCKED_INCOMPLETE_BROKER_ISOLATION, 'dns': dns,
            'delegated_ipc_verified': False, 'cowork_guest_after_new_boundary_verified': False,
            'appcontainer_fixture_only': True, 'driver_boundary_fixture_only': True,
            'production_clients_migrated': False,
            'driver_production_open_supported': False,
            'helper_process_thread_boundary_verified': False,
            'helper_bootstrap_before_execution_verified': False,
            'helper_token_integrity_verified': False,
            'remaining_boundaries': ['controller_lifetime_lease', 'complete_ipc_boundary',
                                     'control_files_and_broker_integrity', 'working_client_compatibility',
                                     'cowork_guest_boundary', 'local_network_metadata',
                                     'helper_process_thread_access', 'helper_bootstrap_before_execution',
                                     'helper_token_integrity'],
            'full_pc_file_access_required': True}
