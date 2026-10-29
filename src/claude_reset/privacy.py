"""Read-only, value-minimized privacy inventory; never a wire-capture verdict."""
from __future__ import annotations
from datetime import datetime, timezone
import os
import stat
from pathlib import Path
from . import jsonc
from .safeio import SafetyError, guarded, tree_entries
from .windows_environment import folded

FLAGS = ('DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING',
         'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'DO_NOT_TRACK')
OTEL_FLAGS = ('CLAUDE_CODE_ENABLE_TELEMETRY', 'OTEL_SDK_DISABLED',
              'OTEL_METRICS_EXPORTER', 'OTEL_LOGS_EXPORTER', 'OTEL_TRACES_EXPORTER',
              'OTEL_EXPORTER_OTLP_ENDPOINT', 'OTEL_EXPORTER_OTLP_HEADERS',
              'OTEL_EXPORTER_OTLP_PROTOCOL', 'OTEL_EXPORTER_OTLP_METRICS_ENDPOINT',
              'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT', 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT',
              'OTEL_RESOURCE_ATTRIBUTES', 'OTEL_SERVICE_NAME')
CONTEXT_FIELDS = {
    'device': ('arch', 'boot_time', 'brand', 'family', 'model', 'memory_size',
               'free_memory', 'processor_count', 'processor_frequency', 'cpu_description',
               'screen_density', 'screen_resolution'),
    'os': ('name', 'version', 'build', 'kernel_version'),
    'app': ('app_name', 'app_version', 'app_build', 'app_start_time', 'app_memory',
            'free_memory', 'build_type', 'app_arch'),
    'browser': ('name', 'version'),
    'gpu': ('name', 'vendor_name', 'memory_size'),
    'gpu_1': ('name', 'active', 'id', 'vendor_id', 'driver_version', 'type'),
    'gpu_2': ('name', 'active', 'id', 'vendor_id', 'driver_version', 'type'),
    'culture': ('locale', 'timezone'),
    'runtime': ('name', 'version'),
    'node': ('name', 'type', 'version'),
    'chrome': ('name', 'type', 'version'),
}


def flag_states(env):
    if not isinstance(env, dict):
        raise SafetyError('Privacy environment has an unknown schema')
    env=folded(env)
    # Never serialize arbitrary environment values, even for known variable names.
    return {name: ('unset' if name not in env else 'empty' if env[name] == ''
                   else 'set_nonempty' if isinstance(env[name], str) else 'invalid_type')
            for name in FLAGS}


def otel_configuration(env):
    """Presence only; exporter endpoints/headers and custom variable names are private."""
    if not isinstance(env, dict) or any(not isinstance(name, str) for name in env):
        raise SafetyError('OpenTelemetry environment has an unknown schema')
    env=folded(env)
    recognized = {name: ('unset' if name not in env else 'empty' if env[name] == ''
                        else 'set_nonempty' if isinstance(env[name], str) else 'invalid_type')
                  for name in OTEL_FLAGS}
    unknown = [name for name in env if name.startswith('OTEL_') and name not in OTEL_FLAGS]
    return {'known_variable_states': recognized,
            'other_otel_variable_count': len(unknown),
            'configuration_present': any(name in env for name in OTEL_FLAGS) or bool(unknown),
            'effective_client_environment': 'not_verified',
            'exporter_enabled': 'not_verified', 'transmission': 'not_verified'}


def cli_settings(profile):
    obj = jsonc.read(profile / 'settings.json', profile)
    local = jsonc.read(profile / 'settings.local.json', profile)
    return {'settings_present': (profile / 'settings.json').exists(),
            'configured_environment': flag_states(obj.get('env', {})),
            'local_settings_present': (profile / 'settings.local.json').exists(),
            'configured_local_environment': flag_states(local.get('env', {})),
            'opentelemetry': {'settings': otel_configuration(obj.get('env', {})),
                              'local_settings': otel_configuration(local.get('env', {}))},
            'effective_child_environment': 'not_verified',
            'transmission': 'not_verified'}


def vscode_settings(profile):
    obj = jsonc.read(profile / 'settings.json', profile)
    value = obj.get('telemetry.telemetryLevel')
    variables = obj.get('claudeCode.environmentVariables', [])
    if not isinstance(variables, list):
        raise SafetyError('Extension environment has an unknown schema')
    env = {}
    for entry in variables:
        if not isinstance(entry, dict) or not isinstance(entry.get('name'), str):
            raise SafetyError('Extension environment has an unknown schema')
        name=entry['name'].upper()
        if name in FLAGS or name in OTEL_FLAGS or name.startswith('OTEL_'):
            if name in env:
                raise SafetyError('Duplicate privacy environment variable')
            env[name] = entry.get('value')
    return {'configured_editor_level': value if value in ('off', 'crash', 'error', 'all') else
            'unset' if value is None else 'unrecognized',
            'extension_environment': flag_states(env),
            'opentelemetry': otel_configuration(env),
            'extension_host_gate': 'configured_off_not_runtime_verified' if value == 'off' else 'not_verified',
            'child_cli_gate': 'independent_of_editor_setting',
            'transmission': 'not_verified'}


def desktop_context(profile):
    path = guarded(profile / 'sentry/scope_v3.json', profile)
    present = path.exists()
    obj = jsonc.read(path, profile) if present else {}
    scope = obj.get('scope', {})
    event = obj.get('event', {})
    if not all(isinstance(x, dict) and isinstance(x.get('contexts', {}), dict) for x in (scope, event)):
        raise SafetyError('Desktop diagnostic context has an unknown schema')
    fields = {}
    for category, allowed in CONTEXT_FIELDS.items():
        data = [x.get('contexts', {}).get(category, {}) for x in (scope, event)]
        if not all(isinstance(x, dict) for x in data):
            raise SafetyError('Desktop diagnostic context has an unknown schema')
        fields[category] = [name for name in allowed if any(name in x for x in data)]
    queue = guarded(profile / 'sentry/queue', profile)
    count = 0
    if queue.exists():
        entries = 0
        for item, info in tree_entries(queue, profile):
            if item == queue:
                if not stat.S_ISDIR(info.st_mode):
                    raise SafetyError('Diagnostic queue has an unknown storage layout')
                continue
            entries += 1
            if entries > 10000:
                raise SafetyError('Diagnostic queue inventory limit exceeded')
            if stat.S_ISREG(info.st_mode):
                count += 1
            elif not stat.S_ISDIR(info.st_mode):
                raise SafetyError('Diagnostic queue has an unknown storage entry')
    return {'local_context': 'present' if present else 'absent_at_observation',
            'context_field_names': fields,
            'user_context_present': bool(scope.get('user') or event.get('user')) if present else 'not_verified',
            'queue_storage_file_count': count, 'queued_event_count': 'not_verified',
            'queue_age_and_origin': 'not_verified',
            'transmission': 'not_verified', 'supported_opt_out': 'not_verified'}


def audit(paths, profiles=None, env=None):
    """Inspect explicit profile roots or the three standard local profiles only.

    No application is started; no account storage, request body or secret is exported.
    The caller environment is distinct from the environment of an existing client.
    """
    paths.validate()
    if profiles is None:
        profiles = [('code', paths.home / '.claude'), ('vscode', paths.roaming / 'Code/User')]
        desktop = paths.local / 'Claude-Data/claude_pzs8sxrjxfjjc'
        if desktop.exists():
            profiles.append(('desktop', desktop))
    readers = {'code': cli_settings, 'vscode': vscode_settings, 'desktop': desktop_context}
    results = []
    for component, root in profiles:
        if component not in readers:
            continue
        root = Path(root)
        if not root.is_absolute():
            raise SafetyError('Privacy profile path must be absolute')
        guarded(root, root, allow_root=True)
        results.append({'component': component, **readers[component](root)})
    return {'schema': 1, 'observed_utc': datetime.now(timezone.utc).isoformat(),
            'source': 'local_configuration_and_context', 'profiles': results,
            'caller_environment': flag_states(dict(os.environ) if env is None else env),
            'caller_opentelemetry': otel_configuration(dict(os.environ) if env is None else env),
            'caller_is_client_environment': False,
            'website': {'account_consent': 'manual_check_required', 'transmission': 'not_verified'},
            'limitations': ['profile_settings_can_be_overridden', 'editor_opt_out_does_not_disable_child_cli',
                            'local_context_does_not_prove_transmission', 'empty_queue_does_not_prove_no_events',
                            'no_universal_desktop_or_website_switch', 'no_client_wire_capture'],
            'settings_changed': False, 'network_requests': 0,
            'telemetry_fully_disabled': False, 'ready_for_new_account': False}
