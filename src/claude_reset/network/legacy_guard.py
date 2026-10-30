"""Legacy commands of the 0.3.x local guard, kept with their behaviour: the opt-in probe, guarded launch and
the elevated filter inspection. Where the backend is and whether it is reviewed lives in backend_location.

The guard itself (loopback proxy task, scoped WFP filters, owned package identity)
is installed outside the program. Nothing here changes filters, proxy settings, routes,
DNS, firewall profiles or the router, and ordinary applications are never targeted.
"""
from __future__ import annotations
import urllib.error
import urllib.request
from ..errors import SafetyError
from .. import config
from ..windows import packages
from ..windows.packages import current_package
from ..windows.wfp import Inspection
from ..model.status import Elevation, Network
from ..model.notes import Note
from ..backend import location as backend_location
from . import controller_status
from .. import layout
from ..model.ids import utc_now

# Builds whose network and permission code was reviewed together with the guard.
# Claude Code settings in the dedicated editor: every proxy variable points at the backend.


def package_probe(package: tuple[str, str]) -> dict:
    row = {'package': package[0]}
    try:
        result = backend_location.in_package(package, backend_location.worker_probe(config.BACKEND_URL))
    except SafetyError as exc:
        return {**row, 'passed': False, 'error': str(exc)}
    row.update(identity_verified=result.get('family') == package[0],
               direct_tcp={'v4': result.get('tcp_v4'), 'v6': result.get('tcp_v6')},
               proxy_https=result.get('proxy_https'))
    row['passed'] = row['identity_verified'] and row['direct_tcp'] == {'v4': '10013',
                                                                       'v6': '10013'} and row['proxy_https'] == '200'
    return row


def https_status(url: str, proxy: str | None, timeout=12) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy} if proxy else {}))
    request = urllib.request.Request(url, headers={'User-Agent': 'ClaudeReset network-guard'})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096)
            return {'http_status': response.status, 'body': body}
    except urllib.error.HTTPError as exc:
        return {'http_status': exc.code}
    except Exception as exc:
        return {'error_type': type(exc).__name__}


def probe(paths, *, ordinary_control=False) -> dict:
    """Scoped probes only by default; an ordinary outbound control is separate."""
    if paths is not None:
        from .gate_rules import probe as strict_probe
        if controller_status.exists(layout.controller(paths)):
            return strict_probe(paths)
    guard = backend_location.locate_guard()
    if not guard:
        raise SafetyError('Local Claude network guard is not installed', code='guard_not_installed')
    preflight = backend_location.status(paths)
    if not preflight.get('passed'):
        return {'status': Network.GUARD_PREFLIGHT_FAILED, 'passed': False, 'network_requests': 0,
                'settings_changed': False, 'full_tunnel_verified': False}
    trace = https_status('https://claude.ai/cdn-cgi/trace', config.BACKEND_URL)
    fields = dict(x.split('=', 1) for x in trace.pop('body', b'').decode('ascii', 'replace').splitlines() if '=' in x)
    exit_trace = {**trace, 'loc': fields.get('loc'), 'colo': fields.get('colo')}
    own = current_package()
    if own:
        # Inside a guarded package this process is itself denied direct egress.
        ordinary = {'status': Network.NOT_APPLICABLE_PROGRAM_RUNS_IN_PACKAGE, 'package': own}
    elif ordinary_control:
        ordinary = https_status('https://example.com/', None)
        ordinary.pop('body', None)
    else:
        ordinary = {'status': Network.NOT_REQUESTED_ONLY_SCOPED_PROBES}
    packages = [package_probe(config.DESKTOP_PACKAGE), package_probe(config.OWNED_PACKAGE)]
    passed = all(p['passed'] for p in packages) and exit_trace.get('http_status') == 200
    return {'schema': 1, 'utc': utc_now(), 'scope': 'claude_only_local_guard',
            'program_package': own, 'packages': packages, 'snow_exit': exit_trace, 'ordinary_direct_control': ordinary,
            'raw_addresses_saved': False, 'settings_changed': False, 'router_contacted': False, 'passed': passed,
            'full_tunnel_verified': False,
            'status': Network.DIRECT_EGRESS_DENIED_PROXY_WORKING if passed else Network.GUARD_PROBE_FAILED,
            'limits': [Note('guard.limit.probe'), Note('guard.limit.earlier'), *backend_location.BOUNDARIES[:2]]}


def guarded_launch(paths, target: str) -> dict:
    """Keep the legacy entry point closed until installed release acceptance.

    Diagnostic probes and user-writable legacy status are not client admission
    authority. This compatibility command deliberately performs no launch or probe.
    """
    if target not in ('chrome', 'vscode'):
        raise SafetyError('Unknown guarded launch target', code='launch_target_unknown')
    return {'target': target, 'scope': 'dedicated_claude_profile',
            'status': Network.BLOCKED_INSTALLED_ACCEPTANCE_REQUIRED, 'passed': False,
            'client_admission': False, 'process_started': False, 'network_requests': 0,
            'settings_changed': False, 'ordinary_profiles_targeted': False,
            'current_sessions_closed': False, 'router_changed': False,
            'functional_acceptance_pending': True,
            'reason': 'Working-client launch requires the installed boundary and full release acceptance; diagnostic '
                      'probes cannot authorize it.'}


def filters() -> dict:
    """Administrative read of the ten owned WFP filters (run elevated)."""
    from ..windows.wfp_session import inspect_owned_filters
    return {'schema': 1, 'utc': utc_now(), **inspect_owned_filters()}


def filter_receipt(paths, request_id, *, inspect=None):
    """Read-only child result with exact identity, including inspection errors."""
    from ..elevation.request import admit_child, child_event
    identity = admit_child(paths, 'filters', request_id)
    try:
        result = (inspect or filters)()
    except Exception as exc:
        result = {'status': Network.INSPECTION_FAILED, 'error_type': type(exc).__name__, 'passed': False}
    child_event(paths, identity, 'finish')
    return {**result, **identity, 'schema': 1, 'finished': True,
            'read_only': True, 'filters_changed': False}


def elevated_filters(paths, timeout=120, *, dispatch=None) -> dict:
    """Serialize UAC inspection and expose only a bounded public summary.

    dispatch shows the UAC prompt for the prepared request (launch.dispatch_request when not given)."""
    from ..elevation import launch, request as uac_request
    dispatch = dispatch or launch.dispatch_request
    requests = []
    def recorded(request):
        requests.append(request)
        return dispatch(request)
    result = uac_request.execute(paths, 'filters', recorded, wait_seconds=timeout)
    # Completion means the read finished, not that L1 is installed or accepted.
    result.update(passed=False, read_only=True, filters_changed=False)
    if result['status'] == Elevation.INSPECTION_FINISHED:
        row = uac_request.read_receipt(requests[0])
        statuses = {Inspection.ADMINISTRATOR_REQUIRED, Inspection.ENGINE_UNAVAILABLE, Inspection.OWNED_FILTERS_VERIFIED,
                    Inspection.OWNED_FILTERS_INCOMPLETE, Network.INSPECTION_FAILED}
        result['inspection_status'] = (row.get('status') if row and row.get('status') in statuses
                                       else Network.INSPECTION_FAILED)
        result['filters_verified'] = bool(row and row.get('status') == Inspection.OWNED_FILTERS_VERIFIED
                                          and row.get('passed') is True)
    return result
