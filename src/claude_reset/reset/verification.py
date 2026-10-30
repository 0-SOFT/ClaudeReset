"""Explicit acceptance evidence; a manual checklist is never a measured result."""
from __future__ import annotations
import re
from types import MappingProxyType
from ..errors import SafetyError
from ..safeio import atomic_json
from .. import layout
from ..model.records import exact

TESTS = MappingProxyType({
    'T-01': 'Inventory, versions, authentication and restoration sources',
    'T-02': 'State and database verification with synthetic network denial; no physical disconnect',
    'T-03': 'Launch without login in every selected client',
    'T-04': 'Expected new account and fresh generated identifiers',
    'T-05': 'Desktop key and account registration',
    'T-06': 'Normal client restart without restoring old state; reboot excluded',
    'T-07': 'Bridges, project context and external accounts',
    'T-08': 'CLI, extension host, Desktop and website telemetry',
    'T-09': 'Time zones, languages, headers and permissions',
    'T-10': 'Client network routes, IPv4, IPv6, UDP, DNS, WebRTC',
    'T-11': 'Functional proxy refusal, exit mismatch and no direct fallback on synthetic fixtures',
    'T-12': 'Claimed installations and environments',
    'T-13': 'Failure and recovery without loss or false readiness',
})
SCENARIOS = ('desktop_chat', 'cowork', 'chrome_site', 'chrome_bridge', 'code_cli',
             'vscode_extension', 'remote_control', 'mcp_local', 'wsl', 'docker', 'ssh')
PROTOCOLS = ('ipv4_tcp', 'ipv6_tcp', 'udp_quic', 'dns', 'webrtc_stun_turn')
FAILURES = ('tunnel_absent', 'tunnel_interrupted', 'windows_start', 'wake_up',
            'network_reconnect', 'dns_change', 'ipv6_change', 'adapter_added', 'client_update')
FUNCTIONAL_FAILURES = ('proxy_unreachable', 'exit_mismatch', 'unsupported_backend', 'client_update')
EXCLUDED = ('physical_network_disconnect', 'windows_reboot', 'power_cut', 'sleep_wake_stress', 'physical_adapter_switch')


def _require_run_id(run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid verification run ID')


def template(run_id, components, *, schema=2):
    _require_run_id(run_id)
    if type(schema) is not int or schema not in (1, 2):
        raise SafetyError('Unknown verification schema')
    if (not isinstance(components, list) or not 1 <= len(components) <= 4
            or any(not isinstance(c, str) or c not in ('code', 'vscode', 'desktop', 'chrome') for c in components)
            or len(set(components)) != len(components)):
        raise SafetyError('Invalid verification component scope')
    result = {'schema': schema, 'run': run_id, 'components': list(components),
            'checks': {test: 'not_verified' for test in TESTS},
            'server': {'sessions': 'not_verified', 'code_tokens': 'not_verified',
                       'devices_pairings': 'not_verified', 'cloud_memory': 'not_verified'},
            'network': {s: {p: 'not_verified' for p in PROTOCOLS} for s in SCENARIOS},
            'failure_tests': {f: 'not_verified' for f in (FAILURES if schema == 1 else FUNCTIONAL_FAILURES)}}
    if schema == 2:
        result['excluded_by_owner'] = list(EXCLUDED)
        result['network']['chrome_bridge'] = {p: 'not_applicable' for p in PROTOCOLS}
    return result


def summarize(evidence):
    # Accept only closed vocabularies: no arbitrary HAR, tokens, account IDs or text.
    try:
        schema = evidence['schema']
        if type(schema) is not int or schema not in (1, 2):
            raise ValueError()
        expected = template(evidence['run'], evidence['components'], schema=schema)
        if not exact(evidence, expected):
            raise ValueError()
        if schema == 2 and evidence['excluded_by_owner'] != expected['excluded_by_owner']:
            raise ValueError()
        if not isinstance(evidence['components'], list) or not evidence['components'] or any(
                c not in ('code', 'vscode', 'desktop', 'chrome') for c in evidence['components']):
            raise ValueError()
        values = []
        def inspect(actual, shape):
            if not exact(actual, shape):
                raise ValueError()
            for key, value in shape.items():
                if isinstance(value, dict):
                    inspect(actual[key], value)
                elif actual[key] not in ('not_verified', 'user_reported_pass', 'failed', 'not_applicable'):
                    raise ValueError()
                else:
                    values.append(actual[key])
        for field in ('checks', 'server', 'network', 'failure_tests'):
            inspect(evidence[field], expected[field])
        return {'run': evidence['run'], 'components': evidence['components'],
                'source': 'manual_evidence_not_independently_verified',
                'failed': values.count('failed'), 'not_verified': values.count('not_verified'),
                'user_reported_pass': values.count('user_reported_pass'),
                'excluded_by_owner': list(EXCLUDED) if schema == 2 else [],
                'ready_for_new_account': False, 'full_tunnel_verified': False}
    except (KeyError, ValueError, TypeError, AttributeError):
        raise SafetyError('Verification evidence has an unknown schema or contains unsupported fields') from None


def _private_scope(paths, run_id, crypto=None):
    """Read only scope from a private journal while the caller holds its lock."""
    from .execution import Executor
    # Validate before constructing any path, even when no journal exists.
    _require_run_id(run_id)
    run = layout.run_folder(paths, layout.RUNS, run_id)
    journal = Executor(paths, crypto).read_private(run / layout.JOURNAL_FILE)
    if (not isinstance(journal, dict) or type(journal.get('schema')) is not int
            or journal['schema'] != 1 or not isinstance(journal.get('plan'), dict)
            or journal['plan'].get('id') != run_id):
        raise SafetyError('Invalid private verification scope')
    return template(run_id, journal['plan'].get('components'))['components']


def template_for_run(paths, run_id, crypto=None):
    from .execution import operation_lock
    with operation_lock(paths):
        return template(run_id, _private_scope(paths, run_id, crypto))


def save_evidence(paths, evidence, crypto=None):
    from .execution import operation_lock
    summary = summarize(evidence)
    with operation_lock(paths):
        components = _private_scope(paths, evidence['run'], crypto)
        if components != evidence['components']:
            raise SafetyError('Verification scope does not match this run')
        run = layout.run_folder(paths, layout.RUNS, evidence['run'])
        atomic_json(run / 'acceptance.json', evidence, paths.state)
        atomic_json(run / 'acceptance-summary.json', summary, paths.state)
    return summary
