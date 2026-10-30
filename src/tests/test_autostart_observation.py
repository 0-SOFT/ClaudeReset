import sys

import pytest
from scripted import Strict
from test_reset import paths

from claude_reset import config
from claude_reset.elevation import claims
from claude_reset.elevation import request as uac
from claude_reset.errors import SafetyError
from claude_reset.network import autostart
from claude_reset.windows import tasks


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
def test_exact_definition_snapshot(change, expected):
    xml = autostart.task_xml('controller.exe', 'report.json', 'fixture-user')
    scheduler = Strict(xml=lambda name: tasks.xml(name, query=lambda script: {'xml': change(xml)}))
    assert autostart.task_definition(xml, scheduler=scheduler) == expected


@pytest.mark.parametrize('failure', [False, True])
def test_definition_adapter_uses_exact_fake_com_lookup(failure):
    from claude_reset.windows.powershell import ps_json
    xml = autostart.task_xml('controller.exe', 'report.json', 'fixture-user')
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
    scheduler = Strict(xml=lambda name: tasks.xml(name, query=run))
    assert autostart.task_definition(xml, scheduler=scheduler) == ('unknown' if failure else 'matching')


@pytest.mark.parametrize('definition', ['matching', 'different', 'unknown'])
def test_install_does_not_accept_task_name_alone(paths, tmp_path, monkeypatch, definition):
    source = tmp_path / 'source.exe'
    source.write_bytes(b'fixture')
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(source))
    monkeypatch.setenv('USERDOMAIN', 'fixture')
    monkeypatch.setenv('USERNAME', 'user')
    created = []
    def registered(name):
        return {'matching': created[-1], 'different': '<Task/>', 'unknown': None}[definition]
    scheduler = Strict(create=lambda name, xml: created.append(xml), xml=registered)
    request = uac.prepare(paths, 'autostart')
    result = autostart.install(paths, tmp_path / 'report.json', request_id=request.request_id, scheduler=scheduler,
                               folder=tmp_path / 'installed')
    assert result['registered'] is (definition == 'matching')
    assert result['definition_state'] == definition
    assert len(created) == 1 and '--strict-guard-serve' in created[0]
    assert str(tmp_path / 'installed' / 'ClaudeReset.exe') in created[0]
    assert claims.blocked(paths)


def test_failed_query_preserves_all_installed_files(paths, tmp_path):
    target = tmp_path / 'installed'
    target.mkdir()
    names = ['ClaudeReset.exe', config.RUNNER_EXE, 'ClaudeReset.exe.old-1']
    for name in names:
        (target / name).write_bytes(b'fixture')
    request = uac.prepare(paths, 'autostart-off')
    result = autostart.remove(paths, tmp_path / 'report.json', request_id=request.request_id,
                              scheduler=Strict(delete=None, lookup='unknown'), folder=target)
    assert all((target / name).read_bytes() == b'fixture' for name in names)
    assert result['task_present_after'] is None
    assert result['program_removed'] is False
    assert claims.blocked(paths)


@pytest.mark.parametrize('row, expected', [
    ({'state': 'present'}, 'present'), ({'state': 'absent'}, 'absent'),
    ({'state': 'unknown'}, 'unknown'), (None, 'unknown'),
    ({}, 'unknown'), ({'state': False}, 'unknown'),
    ({'state': 'ERROR: task not found'}, 'unknown'),
])
def test_structured_task_observation(row, expected):
    assert tasks.lookup(config.CONTROLLER_TASK, query=lambda script: row) == expected


@pytest.mark.parametrize('error', [OSError(), ValueError(), SafetyError('private')])
def test_failed_task_observation_is_unknown(error):
    def fail(script):
        raise error
    assert tasks.lookup(config.CONTROLLER_TASK, query=fail) == 'unknown'


@pytest.mark.parametrize('stage, code, expected', [
    ('task', 0, 'present'), ('task', -2147024894, 'absent'),
    ('task', -2147024891, 'unknown'), ('task', -2147023174, 'unknown'),
    ('connect', -2147024894, 'unknown'), ('folder', -2147024894, 'unknown'),
])
def test_powershell_exact_lookup_with_fake_com(stage, code, expected):
    from claude_reset.windows.powershell import ps_json
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
    scheduler = Strict(lookup=lambda name: tasks.lookup(name, query=run))
    assert autostart.task_state(scheduler=scheduler) == expected


@pytest.mark.parametrize('state', ['present', 'absent'])
@pytest.mark.parametrize('has_executable', [True, False])
def test_removal_requires_absent_and_checks_runner(paths, tmp_path, state, has_executable):
    target = tmp_path / 'installed'
    target.mkdir()
    names = [config.RUNNER_EXE, 'ClaudeReset.exe.old-1']
    if has_executable:
        names.append('ClaudeReset.exe')
    for name in names:
        (target / name).write_bytes(b'fixture')
    request = uac.prepare(paths, 'autostart-off')
    result = autostart.remove(paths, tmp_path / 'report.json', request_id=request.request_id,
                              scheduler=Strict(delete=None, lookup=state), folder=target)
    assert result['program_removed'] is (state == 'absent')
    assert result['task_present_after'] is (state == 'present')
    for name in names:
        assert (target / name).exists() is (state == 'present')
    assert claims.blocked(paths)
