import json

import pytest
from test_reset import paths

from claude_reset.privacy.inventory import audit, cli_settings, desktop_context, otel_configuration, vscode_settings
from claude_reset.safeio import SafetyError


def write(root, name, obj):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding='utf-8')
    return path


def test_privacy_audit_never_echoes_environment_or_context_values(paths):
    code = paths.home / '.claude'
    editor = paths.roaming / 'Code/User'
    desktop = paths.local / 'Claude-Data/claude_pzs8sxrjxfjjc'
    write(code, 'settings.json', {'env': {'DISABLE_ERROR_REPORTING': 'SECRET', 'ANTHROPIC_API_KEY': 'SECRET'}})
    write(editor, 'settings.json', {'telemetry.telemetryLevel': 'off', 'claudeCode.environmentVariables':
          [{'name': 'ANTHROPIC_AUTH_TOKEN', 'value': 'SECRET'}]})
    write(desktop, 'sentry/scope_v3.json', {'scope': {'contexts': {'os': {'name': 'SECRET'},
          'device': {'model': 'SECRET', 'privateField': 'SECRET'}}, 'user': {'id': 'SECRET'}}})
    before = {p: p.read_bytes() for base in (code, editor, desktop) for p in base.rglob('*') if p.is_file()}
    result = audit(paths, env={'DISABLE_TELEMETRY': 'SECRET', 'PASSWORD': 'SECRET'})
    assert 'SECRET' not in json.dumps(result)
    assert 'privateField' not in json.dumps(result)
    assert result['profiles'][1]['child_cli_gate'] == 'independent_of_editor_setting'
    assert result['profiles'][2]['context_field_names']['os'] == ['name']
    assert not result['telemetry_fully_disabled'] and result['network_requests'] == 0
    assert all(p.read_bytes() == value for p, value in before.items())


def test_missing_configuration_is_not_opt_out_or_effective_environment(paths):
    result = audit(paths, env={})
    assert result['profiles'][0]['configured_environment']['DISABLE_TELEMETRY'] == 'unset'
    assert result['profiles'][0]['effective_child_environment'] == 'not_verified'
    assert not result['caller_is_client_environment']


@pytest.mark.parametrize('value', ['SECRET', {'token': 'SECRET'}, ['SECRET']])
def test_unrecognized_editor_level_is_not_exported(paths, value):
    root = paths.roaming / 'Code/User'
    write(root, 'settings.json', {'telemetry.telemetryLevel': value})
    assert vscode_settings(root)['configured_editor_level'] == 'unrecognized'


def test_duplicate_and_malformed_configuration_fail_closed(paths):
    root = paths.home / '.claude'
    write(root, 'settings.json', {'env': []})
    with pytest.raises(SafetyError):
        cli_settings(root)
    (root/'settings.json').write_text('{"env":{},"env":{"DISABLE_TELEMETRY":"1"}}')
    with pytest.raises(SafetyError):
        cli_settings(root)
    editor = paths.roaming / 'Code/User'
    write(editor, 'settings.json', {'claudeCode.environmentVariables':
          [{'name': 'DISABLE_TELEMETRY', 'value': '1'}, {'name': 'DISABLE_TELEMETRY', 'value': ''}]})
    with pytest.raises(SafetyError):
        vscode_settings(editor)


def test_queue_presence_is_not_proof_of_sending_or_old_origin(paths):
    root = paths.local / 'fixture-desktop'
    write(root, 'sentry/scope_v3.json', {'scope': {}})
    write(root, 'sentry/queue/event.json', {'token': 'SECRET'})
    result = desktop_context(root)
    assert result['queue_storage_file_count'] == 1
    assert result['queued_event_count'] == 'not_verified'
    assert result['queue_age_and_origin'] == 'not_verified'
    assert result['transmission'] == 'not_verified'
    assert 'SECRET' not in json.dumps(result)


def test_queue_is_inventoried_without_context_and_without_opening_event_files(paths,monkeypatch):
    from pathlib import Path
    root=paths.local/'fixture-desktop'
    event=write(root,'sentry/queue/SECRET-name.json',{'token':'SECRET-value'})
    nested=write(root,'sentry/queue/nested/event.json',{'token':'SECRET-value'})
    before={p:p.read_bytes() for p in (event,nested)}
    def forbidden(*args,**kwargs):pytest.fail('Queue event contents must not be opened')
    with monkeypatch.context() as patch:
        patch.setattr(Path,'read_bytes',forbidden)
        patch.setattr(Path,'read_text',forbidden)
        result=desktop_context(root)
    assert result['local_context'] == 'absent_at_observation'
    assert result['queue_storage_file_count'] == 2
    assert result['user_context_present'] == 'not_verified'
    assert result['queued_event_count'] == result['queue_age_and_origin'] == result['transmission'] == 'not_verified'
    assert 'SECRET' not in json.dumps(result)
    assert all(p.read_bytes() == value for p,value in before.items())


def test_missing_context_and_queue_do_not_certify_no_events(paths):
    result=desktop_context(paths.local/'missing-desktop')
    assert result['queue_storage_file_count'] == 0
    assert result['local_context'] == 'absent_at_observation'
    assert result['queued_event_count'] == result['transmission'] == 'not_verified'


def test_queue_file_is_not_misreported_as_empty_directory(paths):
    root=paths.local/'fixture-desktop'
    write(root,'sentry/queue',{'token':'SECRET'})
    with pytest.raises(SafetyError,match='storage layout'):desktop_context(root)


def test_queue_directory_enumeration_is_bounded_even_without_events(paths,monkeypatch):
    from claude_reset.privacy import inventory as privacy
    root=paths.local/'fixture-desktop';queue=root/'sentry/queue'
    queue.mkdir(parents=True);info=queue.stat();visited=[]
    def entries(*args):
        yield queue,info
        for index in range(20000):
            visited.append(index);yield queue/str(index),info
    monkeypatch.setattr(privacy,'tree_entries',entries)
    with pytest.raises(SafetyError,match='inventory limit'):desktop_context(root)
    assert len(visited) == 10001


def test_local_privacy_override_is_reported_separately_and_without_values(paths):
    root=paths.home/'.claude'
    first=write(root,'settings.json',{'env':{'DISABLE_TELEMETRY':'SECRET'}})
    second=write(root,'settings.local.json',{'env':{'disable_telemetry':''}})
    before={p:p.read_bytes() for p in (first,second)}
    result=cli_settings(root)
    assert result['settings_present'] and result['local_settings_present']
    assert result['configured_environment']['DISABLE_TELEMETRY'] == 'set_nonempty'
    assert result['configured_local_environment']['DISABLE_TELEMETRY'] == 'empty'
    assert result['effective_child_environment'] == result['transmission'] == 'not_verified'
    assert 'SECRET' not in json.dumps(result)
    assert all(p.read_bytes() == value for p,value in before.items())


def test_explicit_profiles_do_not_scan_other_users_or_unselected_roots(paths):
    root = paths.home / 'selected'
    write(root, 'settings.json', {'env': {'DISABLE_TELEMETRY': '1'}})
    result = audit(paths, [('code', root)], env={})
    assert len(result['profiles']) == 1
    assert result['profiles'][0]['configured_environment']['DISABLE_TELEMETRY'] == 'set_nonempty'
    with pytest.raises(SafetyError):
        audit(paths, [('code', 'relative')], env={})


def test_unsafe_report_path_returns_failure_without_secondary_traceback(paths, monkeypatch, capsys):
    from claude_reset.cli import main
    monkeypatch.setattr('claude_reset.cli.Paths.current', lambda: paths)
    assert main(['--privacy-audit', '--report', '../SECRET/report.json']) == 1
    output = capsys.readouterr()
    assert 'Traceback' not in output.err and 'SECRET' not in output.err
    assert 'Report could not be written safely' in output.err


def test_desktop_event_context_is_reported_without_values(paths):
    root = paths.local / 'fixture-desktop'
    write(root, 'sentry/scope_v3.json', {'scope': {}, 'event': {'contexts':
          {'culture': {'timezone': 'SECRET', 'locale': 'SECRET'}, 'gpu_1': {'name': 'SECRET'}}}})
    result = desktop_context(root)
    assert result['context_field_names']['culture'] == ['locale', 'timezone']
    assert result['context_field_names']['gpu_1'] == ['name']
    assert 'SECRET' not in json.dumps(result)


def test_otel_sources_are_separate_and_never_export_secrets(paths):
    code = paths.home / '.claude'
    editor = paths.roaming / 'Code/User'
    write(code, 'settings.json', {'env': {'OTEL_EXPORTER_OTLP_HEADERS': 'SECRET'}})
    write(code, 'settings.local.json', {'env': {'OTEL_EXPORTER_OTLP_ENDPOINT': 'SECRET'}})
    write(editor, 'settings.json', {'claudeCode.environmentVariables': [
        {'name': 'CLAUDE_CODE_ENABLE_TELEMETRY', 'value': '0'},
        {'name': 'OTEL_PRIVATE_SECRET', 'value': 'SECRET'}]})
    result = audit(paths, env={'OTEL_RESOURCE_ATTRIBUTES': 'SECRET'})
    assert 'SECRET' not in json.dumps(result)
    code_result, editor_result = result['profiles'][:2]
    assert code_result['opentelemetry']['settings']['configuration_present']
    assert code_result['opentelemetry']['local_settings']['configuration_present']
    assert editor_result['opentelemetry']['other_otel_variable_count'] == 1
    assert editor_result['opentelemetry']['exporter_enabled'] == 'not_verified'
    assert result['caller_opentelemetry']['configuration_present']
    assert not result['caller_is_client_environment']


@pytest.mark.parametrize('value', ['0', 'false', '1', 'console', 'SECRET', '', None, ['SECRET']])
def test_otel_presence_never_claims_runtime_enablement(value):
    result = otel_configuration({'OTEL_METRICS_EXPORTER': value})
    assert result['configuration_present']
    assert result['exporter_enabled'] == result['transmission'] == 'not_verified'
    assert 'SECRET' not in json.dumps(result)


def test_otel_absence_and_duplicate_extension_variables(paths):
    assert not otel_configuration({})['configuration_present']
    root = paths.roaming / 'Code/User'
    write(root, 'settings.json', {'claudeCode.environmentVariables': [
        {'name': 'OTEL_EXPORTER_OTLP_HEADERS', 'value': 'SECRET'},
        {'name': 'OTEL_EXPORTER_OTLP_HEADERS', 'value': ''}]})
    with pytest.raises(SafetyError):
        vscode_settings(root)
    with pytest.raises(SafetyError):
        otel_configuration([])


