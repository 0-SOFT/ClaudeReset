"""What the L1 gate blocks and lets through: the protected Claude images, the reviewed backend they may reach
through the relay, the plan shown before anything changes and the probe that the rules hold."""
from __future__ import annotations

import ipaddress
import json

from . import connections, remote_backend
from .. import config
from .. import layout
from ..backend import location as backend_location
from ..backend.attestation import inspect_sing_box
from ..errors import SafetyError
from ..model.notes import Note
from ..model.status import Network
from ..safeio import read_json
from ..windows.system import DPAPI
from .strict_wfp import Engine, Identity, deny_rules, relay_permits

__all__ = ['adopt_new_identities', 'backend', 'cli_state', 'identities', 'plan', 'probe']


def cli_state(paths):
    """Standalone CLI facts for the status report. The hash is information, never a gate:
    a deny by exact path blocks only direct network, so a new or unreviewed version fails
    closed (offline unless it honours the proxy variables) instead of stopping the controller."""
    cli = paths.home / '.local/bin/claude.exe'
    if not cli.is_file():
        return {'present': False, 'reviewed_hash': None}
    return {'present': True, 'reviewed_hash': backend_location.sha256(cli) == backend_location.REVIEWED_STANDALONE_CLI}


def identities(paths):
    """Cheap enough to call every controller cycle: it hashes nothing."""
    result = [Identity('package', value[0]) for value in (config.DESKTOP_PACKAGE, config.OWNED_PACKAGE)]
    cli = paths.home / '.local/bin/claude.exe'
    if cli.is_file():
        result.append(Identity('app', str(cli)))
    # Claude Code's own native binary in the shared editor: an exact Claude image,
    # not Code.exe. Every installed extension version is covered; a version
    # installed while the controller runs is adopted by adopt_new_identities.
    extensions = layout.vscode_extensions(paths)
    if extensions.is_dir() and not (layout.controller(paths) / layout.EXTENSION_EXCLUDED_FLAG).exists():
        for exe in sorted(extensions.glob(layout.EXTENSION_CLI)):
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
        lease.install(relay_permits(fresh, config.RELAY_PORT))
    except Exception as exc:
        state['adopt_error'] = type(exc).__name__
        return targets
    state.pop('adopt_error', None)
    state['adopted'] = state.get('adopted', []) + [identity.value for identity in fresh]
    return targets + fresh


def backend(paths):
    """Read only the installed, hash-reviewed engine configuration; never infer a route."""
    guard = backend_location.locate_guard()
    if not guard or not backend_location.status(paths).get('passed'):
        raise SafetyError('The existing local backend must pass its static checks')
    meta = read_json(guard.base / layout.BACKEND_PROFILE, guard.base)
    engine_config = json.loads(DPAPI().decrypt((guard.base / layout.BACKEND_ENGINE_CONFIG).read_bytes()))
    inspect_sing_box(engine_config)
    outbound = engine_config['outbounds'][0]
    tls = outbound.get('tls') or {}
    if (outbound.get('type') != 'vless' or not tls.get('enabled') or tls.get('insecure')
            or not (tls.get('reality') or {}).get('enabled') or not (tls.get('reality') or {}).get('public_key')
            or ipaddress.ip_address(outbound['server']).version != 4
            or not ipaddress.ip_address(outbound['server']).is_global
            or type(outbound['server_port']) is not int or not 1 <= outbound['server_port'] <= 65535):
        raise SafetyError('Strict backend requires the reviewed literal IPv4 VLESS Reality peer')
    state = backend_location.read_worker_state(guard.base)
    return guard, meta, engine_config, state


def plan(paths):
    targets = identities(paths)
    remote = remote_backend.load(paths)
    if remote is None:
        backend(paths)
    saved = connections.load(paths)
    return {'schema': 1, 'status': Network.STRICT_PLAN_PREPARED, 'passed': True,
            'scope': [t.kind + ':' + (t.value if t.kind == 'package'
                                      else 'reviewed_standalone_claude' if t.value.endswith('claude.exe')
                                      and '.local' in t.value else 'claude_code_extension_binary') for t in targets],
            'persistent_default_denies': len(deny_rules(targets)), 'relay_url': config.RELAY_URL,
            'tunnel_identity': remote_backend.backend_kind(remote) if remote else config.LOCAL_BACKEND_IDENTITY,
            'expected_exit_profile_present': saved is not None,
            'production_open_supported': False, 'full_tunnel_verified': False,
            'blocking_requirement': 'delegated_dns_and_ipc_isolation',
            'opens_network': False, 'router_changed': False, 'ordinary_applications_changed': False,
            'limits': [Note('strict.limit.shared_apps'),
                       Note('strict.limit.inbound'),
                       Note('strict.limit.dns'),
                       Note('strict.limit.router')]}


def probe(paths):
    rows = []
    script = backend_location.worker_probe(config.RELAY_URL)
    for package in (config.DESKTOP_PACKAGE, config.OWNED_PACKAGE):
        result = backend_location.in_package(package, script)
        sealed = all(result.get('tcp_' + k) == '10013' for k in ('v4', 'v6', 'backend', 'controller'))
        boundary = result.get('family') == package[0] and sealed
        mode = ('relay_open' if result.get('tcp_gate') == 'connected' and result.get('proxy_https') == '200'
                else 'closed' if result.get('tcp_gate') == '10013' else 'unverified')
        rows.append({'package': package[0], 'boundary_passed': boundary, 'mode': mode, 'results': result})
    passed = all(r['boundary_passed'] and r['mode'] != 'unverified' for r in rows)
    return {'status': Network.STRICT_SCOPED_PROBE_PASSED if passed else Network.STRICT_SCOPED_PROBE_FAILED,
            'passed': passed, 'packages': rows, 'full_tunnel_verified': False,
            'router_changed': False, 'ordinary_applications_changed': False,
            'limits': [Note('strict.limit.probe_scope')]}
