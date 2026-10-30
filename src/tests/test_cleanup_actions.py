import json
import pytest
from claude_reset.windows import cleanup_actions as ca
from claude_reset.safeio import SafetyError
from functools import partial
from claude_reset.model import clients


def test_credential_scope_matches_ps1_without_passwords(monkeypatch):
    text = ('Target: LegacyGeneric:target=Claude-token\nЦель: anthropic/login\n'
            'Target: unrelated\nTarget: notclaude\nUser: secret-user\n')
    monkeypatch.setattr(ca, 'ps_json', lambda _: {'text': text})
    assert ca.credential_names() == ('LegacyGeneric:target=Claude-token', 'anthropic/login')
    scripts = []
    monkeypatch.setattr(ca, 'ps_json', scripts.append)
    ca.delete_credential("Claude-a'b")
    assert "'Claude-a''b'" in scripts[0] and '$LASTEXITCODE' in scripts[0]
    with pytest.raises(SafetyError):
        ca.delete_credential('unrelated')
    assert len(scripts) == 1


@pytest.mark.parametrize('action,status', [(partial(ca.resolve_processes, clients.CLOSABLE_APPS), 'process_stop_requested'),
                                          (ca.resolve_service, 'cowork_service_stopped')])
def test_resolve_success_and_refusal(action, status):
    scripts = []
    def run(script):
        scripts.append(script)
        return {'status': status}
    assert action(run=run) == {'status': status}
    assert 'RunAs' not in scripts[0] and 'Code.exe' not in scripts[0]
    if action is not ca.resolve_service:
        assert 'CreationDate' in scripts[0] and 'ParentProcessId' in scripts[0]
    else:
        assert "Stop-Service -Name CoworkVMService" in scripts[0]
    def denied(_):
        raise SafetyError('Windows inspection failed')
    with pytest.raises(SafetyError):
        action(run=denied)
    assert 'secret-password' not in json.dumps({'status': status})
