import ctypes
import json
from types import SimpleNamespace

import pytest
from claude_reset import extension_protection as ext, l1_settings, strict_guard, wfp
from claude_reset.safeio import SafetyError
from claude_reset.strict_wfp import Identity, deny_rules, relay_permits


@pytest.fixture
def paths(tmp_path):
    return SimpleNamespace(home=tmp_path, roaming=tmp_path / 'roaming', state=tmp_path / 'state')


@pytest.mark.parametrize('own_wrapper', [True, False])
def test_remove_only_exact_owned_settings(paths, own_wrapper):
    path = paths.roaming / 'Code/User/settings.json'
    path.parent.mkdir(parents=True)
    foreign = [{'name': 'HTTP_PROXY', 'value': 'foreign'}, {'name': 'CUSTOM', 'value': 'keep'}, 'keep']
    wrapper = str(l1_settings.runner_path()) if own_wrapper else 'foreign-wrapper'
    data = {'claudeCode.environmentVariables': foreign + [dict(name=n, value=v) for n, v in l1_settings.OWNED_ENV],
            'claudeCode.claudeProcessWrapper': wrapper, 'editor.fontSize': 17}
    path.write_text(json.dumps(data))
    original = path.read_bytes()
    backups = []
    ext.remove_owned_settings(paths, crypto=SimpleNamespace(encrypt=lambda b: backups.append(b) or b'sealed'))
    saved = json.loads(path.read_text())
    assert saved['claudeCode.environmentVariables'] == foreign
    assert saved['claudeCode.claudeProcessWrapper'] == ('' if own_wrapper else wrapper)
    assert saved['editor.fontSize'] == 17 and backups == [original]


@pytest.mark.parametrize('mode', ['ok', 'changed', 'running', 'permit'])
def test_exact_filter_subset_preserves_others(paths, mode):
    binary = paths.home / '.vscode/extensions/anthropic.claude-code-1-win32-x64/resources/native-binary/claude.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'fixture')
    identity = Identity('app', str(binary))
    rules = deny_rules([identity])
    keys = {r.key.value() for r in rules} | {'foreign-key', 'desktop-key'}
    if mode == 'permit':
        keys.update(r.key.value() for r in relay_permits([identity], strict_guard.GATE_PORT))
    before = keys.copy()
    calls = []
    class Engine:
        handle = None
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def own_keys(self): return keys.copy()
        def exists_verified(self, rule):
            if mode == 'changed': raise SafetyError('changed')
            return rule.key.value() in keys
        def _call(self, name, signature, *args):
            calls.append(name)
            if name == 'FwpmFilterDeleteByKey0':
                keys.remove(ctypes.cast(args[1], ctypes.POINTER(wfp.GUID)).contents.value())
    if mode == 'ok':
        assert ext.remove_exact_filters(paths, engine_factory=Engine, idle=lambda: True) == len(rules)
        assert keys == {'foreign-key', 'desktop-key'}
        assert calls[-1] == 'FwpmTransactionCommit0'
    else:
        with pytest.raises(SafetyError):
            ext.remove_exact_filters(paths, engine_factory=Engine, idle=lambda: mode != 'running')
        assert keys == before and not calls


@pytest.mark.parametrize('passed', [True, False])
def test_exclusion_uses_existing_receipt_before_settings(paths, monkeypatch, passed):
    from claude_reset import uac_request
    calls = []
    def execute(p, operation, dispatch):
        assert p is paths and operation == 'remove'
        dispatch('exact-request')
        return {'passed': passed, 'retry_blocked': not passed}
    monkeypatch.setattr(uac_request, 'execute', execute)
    monkeypatch.setattr(strict_guard, 'dispatch_request', lambda r, **kw: calls.append((r, kw)))
    monkeypatch.setattr(ext, 'remove_owned_settings', lambda p: calls.append('settings'))
    assert ext.exclude(paths)['passed'] == passed
    assert calls == [('exact-request', {'exclude_extension': True})] + (['settings'] if passed else [])


@pytest.mark.parametrize('success', [True, False])
def test_child_exact_receipt_and_fixed_error(paths, monkeypatch, success):
    from claude_reset import uac_request
    identity = dict(request_id='fixture-request', operation='remove', state_root=str(paths.state))
    monkeypatch.setattr(uac_request, 'admit_child', lambda p, op, rid: identity)
    events = []
    monkeypatch.setattr(uac_request, 'child_event', lambda p, row, event: events.append((row, event)))
    def remove(p):
        if not success:
            raise SafetyError('secret-user 9.9.9.9 password')
        return 4
    monkeypatch.setattr(ext, 'remove_exact_filters', remove)
    report = paths.state / 'receipt.json'
    result = ext.remove_filters(paths, report, request_id='fixture-request')
    assert result['removed'] is success and result['finished']
    assert events == [(identity, 'finish')]
    assert json.loads(report.read_text()) == result
    assert 'secret-user' not in report.read_text() and '9.9.9.9' not in report.read_text()
