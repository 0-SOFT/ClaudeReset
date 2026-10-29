"""Detect resolver delegation with a loopback-only DNS sink, never external DNS.

The sink answers only fresh random .invalid names created by this invocation.
Failure/busy port is not evidence of containment. This probe cannot certify all IPC.
"""
from __future__ import annotations
import json
import socket
import threading
import uuid
from . import netguard
from .windows import ps_json


def probe():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        server.bind(('127.0.0.1', 53))
    except OSError:
        server.close()
        return {'status': 'local_dns_probe_unavailable', 'passed': False, 'external_dns_requests': 0}
    server.settimeout(.2)
    names = [uuid.uuid4().hex for _ in range(3)]
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
    def script(name):
        return ("$r=@{};try{$r.family=[Windows.ApplicationModel.Package,Windows.ApplicationModel,ContentType=WindowsRuntime]::Current.Id.FamilyName}catch{$r.family='ordinary'};"
                "try{Resolve-DnsName -Name '" + name + ".invalid' -Server 127.0.0.1 -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Out-Null;$r.proxy_https='resolved'}catch{$r.proxy_https='dns_error'};"
                "$r | ConvertTo-Json -Compress")
    try:
        ps_json(script(names[0]))
        rows = []
        for index, package in enumerate((netguard.DESKTOP_PACKAGE, netguard.OWNED_PACKAGE), 1):
            result = netguard.in_package(package, script(names[index]), timeout=25)
            rows.append({'package': package[0], 'identity_matches': result.get('family') == package[0],
                         'dns_packets_received': counts[index]})
        passed = counts[0] > 0 and all(r['identity_matches'] and r['dns_packets_received'] == 0 for r in rows)
        return {'status': 'dns_probe_contained' if passed else 'brokered_dns_not_contained',
                'passed': passed, 'ordinary_control_packets': counts[0], 'packages': rows,
                'external_dns_requests': 0, 'system_dns_changed': False}
    finally:
        finished.set()
        server.close()
        thread.join(1)


def coverage_gate():
    """AppContainer and driver boundaries are verified only in disposable fixtures.

    Do not turn a successful socket/exit measurement into authority to open the
    real clients. Existing full-trust clients and Cowork have not been migrated.
    """
    dns = probe()
    return {'passed': False, 'status': 'blocked_incomplete_broker_isolation', 'dns': dns,
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
