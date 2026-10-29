from types import SimpleNamespace

import pytest

from test_reset import paths
from claude_reset import strict_guard as guard, uac_request as uac


@pytest.mark.parametrize('change, expected', [
    (lambda xml: xml, 'matching'),
    (lambda xml: xml.replace('\n', ''), 'matching'),
    (lambda xml: xml.replace('--strict-guard-serve', '--other'), 'different'),
    (lambda xml: xml.replace('HighestAvailable', 'LeastPrivilege'), 'different'),
    (lambda xml: xml.replace('IgnoreNew', 'Parallel'), 'different'),
    (lambda xml: xml.replace('controller.exe', 'foreign.exe'), 'different'),
    (lambda xml: xml.replace('<Delay>PT1M</Delay>', ''), 'different'),
    (lambda xml: '<Task/>', 'different'),
    (lambda xml: '<broken', 'unknown'),
    (lambda xml: None, 'unknown'),
    (lambda xml: '<!DOCTYPE Task><Task/>', 'unknown'),
    (lambda xml: 'x' * 65537, 'unknown'),
])
def test_exact_definition_snapshot(monkeypatch, change, expected):
    xml = guard._task_xml('controller.exe', 'report.json', 'fixture-user')
    monkeypatch.setattr(guard, 'ps_json', lambda script: {'xml': change(xml)})
    assert guard.autostart_task_definition(xml) == expected


@pytest.mark.parametrize('failure', [False, True])
def test_definition_adapter_uses_exact_fake_com_lookup(monkeypatch, failure):
    from claude_reset.windows import ps_json
    xml = guard._task_xml('controller.exe', 'report.json', 'fixture-user')
    fixture = '''
    function New-Object {
        param($ComObject)
        if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM' }
        $fake = [pscustomobject]@{};
        $fake | Add-Member ScriptMethod Connect {};
        $fake | Add-Member ScriptMethod GetFolder {
            param($path)
            if ($path -ne '\\') { throw 'unexpected folder' }
            return $this
        };
        $fake | Add-Member ScriptMethod GetTask {
            param($name)
            if ($name -ne 'ClaudeReset L1 Controller') { throw 'unexpected task' }
            if ($fail) { throw 'fixture unavailable' }
            return [pscustomobject]@{Xml=$expected}
        };
        return $fake
    }
    '''
    def run(script):
        return ps_json("$expected='" + xml.replace("'", "''") + "'; $fail=$"
                       + str(failure).lower() + ';' + fixture + script)
    monkeypatch.setattr(guard, 'ps_json', run)
    assert guard.autostart_task_definition(xml) == ('unknown' if failure else 'matching')


@pytest.mark.parametrize('definition', ['matching', 'different', 'unknown'])
def test_install_does_not_accept_task_name_alone(paths, tmp_path, monkeypatch, definition):
    source = tmp_path / 'source.exe'
    source.write_bytes(b'fixture')
    monkeypatch.setattr(guard.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(guard.sys, 'executable', str(source))
    monkeypatch.setenv('USERDOMAIN', 'fixture')
    monkeypatch.setenv('USERNAME', 'user')
    monkeypatch.setattr(guard, 'autostart_directory', lambda: tmp_path / 'installed')
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        assert '/Create' in argv
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(guard.subprocess, 'run', run)
    def inspect(xml):
        assert '--strict-guard-serve' in xml
        assert str(tmp_path / 'installed' / 'ClaudeReset.exe') in xml
        return definition
    monkeypatch.setattr(guard, 'autostart_task_definition', inspect)
    request = uac.prepare(paths, 'autostart')
    result = guard.autostart_install(paths, tmp_path / 'report.json', request_id=request.request_id)
    assert result['registered'] is (definition == 'matching')
    assert result['definition_state'] == definition
    assert len(calls) == 1
    assert uac.blocked(paths)


@pytest.mark.parametrize('query_code', [1, 5, 1722])
def test_failed_query_preserves_all_installed_files(paths, tmp_path, monkeypatch, query_code):
    target = tmp_path / 'installed'
    target.mkdir()
    names = ['ClaudeReset.exe', guard.RUNNER_NAME, 'ClaudeReset.exe.old-1']
    for name in names:
        (target / name).write_bytes(b'fixture')
    monkeypatch.setattr(guard, 'autostart_directory', lambda: target)
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=query_code))
    monkeypatch.setattr(guard, 'ps_json', lambda *a: {'state': 'unknown'})
    request = uac.prepare(paths, 'autostart-off')
    result = guard.autostart_remove(paths, tmp_path / 'report.json', request_id=request.request_id)
    assert all((target / name).read_bytes() == b'fixture' for name in names)
    assert result['task_present_after'] is None
    assert result['program_removed'] is False
    assert uac.blocked(paths)


@pytest.mark.parametrize('row, expected', [
    ({'state': 'present'}, 'present'), ({'state': 'absent'}, 'absent'),
    ({'state': 'unknown'}, 'unknown'), (None, 'unknown'),
    ({}, 'unknown'), ({'state': False}, 'unknown'),
    ({'state': 'ERROR: task not found'}, 'unknown'),
])
def test_structured_task_observation(monkeypatch, row, expected):
    monkeypatch.setattr(guard, 'ps_json', lambda script: row)
    assert guard.autostart_task_state() == expected


@pytest.mark.parametrize('error', [OSError(), ValueError(), guard.SafetyError('private')])
def test_failed_task_observation_is_unknown(monkeypatch, error):
    def fail(script):
        raise error
    monkeypatch.setattr(guard, 'ps_json', fail)
    assert guard.autostart_task_state() == 'unknown'


@pytest.mark.parametrize('stage, code, expected', [
    ('task', 0, 'present'), ('task', -2147024894, 'absent'),
    ('task', -2147024891, 'unknown'), ('task', -2147023174, 'unknown'),
    ('connect', -2147024894, 'unknown'), ('folder', -2147024894, 'unknown'),
])
def test_powershell_exact_lookup_with_fake_com(monkeypatch, stage, code, expected):
    from claude_reset.windows import ps_json
    # Execute the actual adapter, replacing COM construction before it can run.
    fixture = '''
    function New-Object {
        param($ComObject)
        if ($ComObject -ne 'Schedule.Service') { throw 'unexpected COM' }
        $fake = [pscustomobject]@{};
        $fake | Add-Member ScriptMethod Connect {
            if ($stage -eq 'connect') { throw [System.Runtime.InteropServices.COMException]::new('fixture', $code) }
        };
        $fake | Add-Member ScriptMethod GetFolder {
            param($path)
            if ($path -ne '\\') { throw 'unexpected folder' }
            if ($stage -eq 'folder') { throw [System.Runtime.InteropServices.COMException]::new('fixture', $code) }
            return $this
        };
        $fake | Add-Member ScriptMethod GetTask {
            param($name)
            if ($name -ne 'ClaudeReset L1 Controller') { throw 'unexpected task' }
            if ($code -ne 0) { throw [System.Runtime.InteropServices.COMException]::new('arbitrary localized text', $code) }
            return [pscustomobject]@{Name=$name}
        };
        return $fake
    }
    '''
    def run(script):
        return ps_json(f"$stage='{stage}'; $code={code}; " + fixture + script)
    monkeypatch.setattr(guard, 'ps_json', run)
    assert guard.autostart_task_state() == expected


@pytest.mark.parametrize('state', ['present', 'absent'])
@pytest.mark.parametrize('has_executable', [True, False])
def test_removal_requires_absent_and_checks_runner(paths, tmp_path, monkeypatch, state, has_executable):
    target = tmp_path / 'installed'
    target.mkdir()
    names = [guard.RUNNER_NAME, 'ClaudeReset.exe.old-1']
    if has_executable:
        names.append('ClaudeReset.exe')
    for name in names:
        (target / name).write_bytes(b'fixture')
    monkeypatch.setattr(guard, 'autostart_directory', lambda: target)
    monkeypatch.setattr(guard.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1))
    monkeypatch.setattr(guard, 'ps_json', lambda script: {'state': state})
    request = uac.prepare(paths, 'autostart-off')
    result = guard.autostart_remove(paths, tmp_path / 'report.json', request_id=request.request_id)
    assert result['program_removed'] is (state == 'absent')
    assert result['task_present_after'] is (state == 'present')
    for name in names:
        assert (target / name).exists() is (state == 'present')
    assert uac.blocked(paths)
