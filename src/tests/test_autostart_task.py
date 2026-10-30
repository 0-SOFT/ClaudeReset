import xml.etree.ElementTree as ET

from claude_reset.network import autostart

NS = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'


def test_task_xml_is_well_formed_and_scoped():
    text = autostart.task_xml(r'C:\Program Files\ClaudeReset-L1\ClaudeReset.exe', r'C:\x\a&b\report.json', r'PC\user<1>')
    root = ET.fromstring(text.replace('encoding="UTF-16"', 'encoding="UTF-8"'))
    assert root.find(f'.//{NS}RunLevel').text == 'HighestAvailable'
    assert root.find(f'.//{NS}LogonTrigger/{NS}UserId').text == r'PC\user<1>'
    command = root.find(f'.//{NS}Exec/{NS}Command').text
    assert command == r'C:\Program Files\ClaudeReset-L1\ClaudeReset.exe'
    assert root.find(f'.//{NS}Exec/{NS}Arguments').text.startswith('--strict-guard-serve --report ')
    assert root.find(f'.//{NS}ExecutionTimeLimit').text == 'PT0S'


def test_autostart_requires_frozen_program(tmp_path):
    import json
    from types import SimpleNamespace
    from claude_reset.elevation import request as uac
    paths = SimpleNamespace(state=tmp_path, local=tmp_path / 'local')
    request = uac.prepare(paths, 'autostart')
    result = autostart.install(paths, tmp_path / 'r.json', request_id=request.request_id)
    assert 'frozen' in result['error'] and json.loads((tmp_path / 'r.json').read_text())['finished'] is True
