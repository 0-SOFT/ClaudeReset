"""Read current process tokens and Cowork presence; never authorize from a snapshot."""
from __future__ import annotations
import os
from ..backend import location as backend_location
from ..windows.system import ps_json
from .. import config
from .. import layout
from ..model import clients
from ..windows import packages
from ..windows.process import compute_systems, token_facts
from ..model.status import Network


def local_metadata_probe(*, run_in=None):
    """What each package sees of this PC's network adapters; run_in runs a probe inside a package
    (backend_location.in_package)."""
    run_in = run_in or backend_location.in_package
    rows = []
    for package in (config.DESKTOP_PACKAGE, config.OWNED_PACKAGE):
        try:
            value = run_in(package, packages.LOCAL_METADATA_PROBE)
            count = value.get('non_loopback_adapters', '')
            rows.append({'identity_matches': value.get('family') == package[0],
                         'location_status': value.get('location_status', 'unavailable'),
                         'non_loopback_adapters_visible': int(count) if count.isdigit() else None})
        except Exception as exc:
            rows.append({'identity_matches': False, 'error_type': type(exc).__name__})
    return {'packages': rows, 'network_requests': 0, 'coordinates_requested': False,
            'ip_or_mac_addresses_read': False, 'permission_prompt_requested': False,
            'settings_changed': False,
            'limits': ['A Windows socket filter does not hide network-adapter metadata',
                       'Location permission state is not an IP geolocation measurement']}


def summarize(rows, hcs):
    scoped = [r for r in rows if r.get('scoped')]
    unreadable = sum(r.get('token_read_failed', False) for r in scoped)
    contained = sum(r.get('appcontainer') is True and r.get('capability_count') == 0 for r in scoped)
    escapes = sum(bool(r.get('descendant')) and not r.get('protected_identity') for r in scoped)
    return {'status': Network.ISOLATION_AUDIT_COMPLETED, 'passed': False, 'full_tunnel_verified': False,
            'read_only': True, 'network_requests': 0, 'processes_changed': False,
            'protected_processes_observed': len(scoped), 'no_capability_appcontainer_processes': contained,
            'full_trust_or_unverified_processes': len(scoped) - contained,
            'unreadable_protected_tokens': unreadable, 'descendants_without_protected_identity': escapes,
            'claude_processes_outside_protected_scope': sum(not r.get('scoped') for r in rows),
            'cowork_service_observed': any(r.get('kind', '').lower() == clients.ProcessKind.COWORK_SERVICE for r in rows),
            'cowork_service_within_protected_scope': any(r.get('kind', '').lower() == clients.ProcessKind.COWORK_SERVICE for r in scoped),
            'cowork': hcs,
            'full_pc_file_access_required': True,
            'blockers': ['DNS and system-service delegation are not contained for current clients',
                         'Cowork guest coverage after the new boundary is not verified',
                         'Local network-adapter metadata remains visible or unverified'],
            'limits': ['This is a process snapshot, not proof of future children or all IPC',
                       'A missing or stopped Cowork VM is not a passing guest-network test']}


# Image names compared without case: 'claude.exe' covers Claude Desktop and the Claude Code CLI.
CLAUDE_IMAGES = clients.image_names(clients.owners('desktop') | {clients.ProcessKind.CODE_CLI})
AUDITED_IMAGES = CLAUDE_IMAGES | clients.image_names({clients.ProcessKind.EDITOR, clients.CHROME_IMAGE})


def audit(paths):
    census = ps_json("@{rows=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)} | ConvertTo-Json -Depth 4 -Compress")
    records = {r['ProcessId']: r for r in (census or {}).get('rows', [])}
    tokens, protected = {}, set()
    families = (config.DESKTOP_PACKAGE[0], config.OWNED_PACKAGE[0])
    standalone = os.path.normcase(str(layout.standalone_cli(paths)))
    for pid, record in records.items():
        if str(record.get('Name', '')).lower() not in AUDITED_IMAGES:
            continue
        value = tokens[pid] = token_facts(pid)
        if value.get('package') in families or os.path.normcase(record.get('ExecutablePath') or '') == standalone:
            protected.add(pid)
    descendants = set(protected)
    for _ in records:
        extra = {pid for pid, r in records.items() if r['ParentProcessId'] in descendants} - descendants
        if not extra:
            break
        descendants |= extra
    selected = descendants | {pid for pid, r in records.items() if str(r.get('Name', '')).lower() in CLAUDE_IMAGES}
    rows = []
    for pid in selected:
        value = tokens[pid] if pid in tokens else token_facts(pid)
        rows.append(dict(value, kind=records[pid]['Name'], scoped=pid in descendants, descendant=pid not in protected,
                         protected_identity=value.get('package') in families or pid in protected))
    hcs = {'inventory_verified': False, 'guest_verified': False, 'running_guests': None}
    try:
        systems = compute_systems()
        if systems is not None:
            if isinstance(systems, list) and all(isinstance(s, dict) for s in systems):
                guests = [s for s in systems if 'cowork' in str(s.get('Owner', '')).lower()]
                hcs.update(inventory_verified=True, running_guests=sum(s.get('State') == 'Running' for s in guests), observed_guests=len(guests))
        else:
            hcs['reason'] = 'elevated_inventory_required_or_unavailable'
    except (OSError, ValueError):
        hcs['reason'] = 'inventory_unavailable'
    result = summarize(rows, hcs)
    result['local_metadata'] = local_metadata_probe()
    return result
