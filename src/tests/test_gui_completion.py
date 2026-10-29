"""Wizard progress, VLESS engine install/remove from the window, first exit check after the engine install."""
from types import SimpleNamespace

import pytest

from claude_reset import connections, netguard, proxy_form, remote_backend, wizard


def report(protection='not_installed', **parts):
    return {'protection': protection, 'checks': [{'id': k, 'status': v} for k, v in parts.items()]}


def history(*statuses, collection='complete'):
    return lambda _paths: {'collection': collection, 'rows': [{'status': s} for s in statuses]}


def test_wizard_from_zero_points_to_server_first():
    result = wizard.progress(None, check=lambda _: report(), history=history())
    assert [s['state'] for s in result['steps']] == ['todo', 'todo', 'todo', 'todo', 'waiting']
    assert result['next'] == 'server'


def test_wizard_marks_finished_steps_and_opens_checks_last():
    ready = report('installed', backend_task='ok', backend_listening='ok', connection_profile='ok')
    partial = wizard.progress(None, server_done=True, check=lambda _: ready, history=history('failed_or_partial'))
    assert {s['key']: s['state'] for s in partial['steps']} == {
        'server': 'done', 'cleanup': 'todo', 'connection': 'done', 'protection': 'done', 'checks': 'waiting'}
    assert partial['next'] == 'cleanup'
    done = wizard.progress(None, server_done=True, check=lambda _: ready, history=history('fixed_locations_wiped'))
    assert done['steps'][-1]['state'] == 'todo' and done['next'] == 'checks'


def test_wizard_unreadable_state_is_unknown_not_done():
    def broken(_):
        raise OSError('C:/Users/someone/private')
    result = wizard.progress(None, check=broken, history=history(collection='unavailable'))
    states = {s['key']: s['state'] for s in result['steps']}
    assert states['connection'] == states['protection'] == states['cleanup'] == 'unknown'
    assert 'someone' not in repr(result)


@pytest.mark.parametrize('status,expected', [
    ('installed', 'engine_installed'), ('installed_needs_attention', 'engine_needs_attention'),
    ('not_started', 'engine_not_started'), ('failed', 'engine_install_failed')])
def test_engine_install_maps_installer_status(monkeypatch, status, expected):
    monkeypatch.setattr(remote_backend, 'load', lambda _: None)
    calls = []
    fake = lambda paths, profile, archive=None: calls.append((profile, archive)) or {
        'status': status, 'error': 'SafetyError: C:/Users/someone/engine'}
    result = proxy_form.install_engine('paths', 'profile.json', 'engine.zip', install=fake)
    assert result == {'status': expected} and calls == [('profile.json', 'engine.zip')]


def test_engine_install_refused_while_remote_proxy_saved(monkeypatch):
    monkeypatch.setattr(remote_backend, 'load', lambda _: {'adapter': 'socks5'})
    result = proxy_form.install_engine('paths', 'profile.json', install=lambda *a, **k: pytest.fail('installed'))
    assert result == {'status': 'engine_remote_profile_saved'}


def test_engine_install_exception_text_stays_private(monkeypatch):
    monkeypatch.setattr(remote_backend, 'load', lambda _: None)
    def boom(*_a, **_k):
        raise RuntimeError('secret-password at C:/Users/someone')
    assert proxy_form.install_engine('paths', 'profile.json', install=boom) == {'status': 'engine_install_failed'}


def test_remove_backend_removes_engine_then_remote_profile():
    calls = []
    result = proxy_form.remove_backend('paths', remove=lambda p: calls.append('engine') or {'status': 'removed'},
                                       remote_remove=lambda p: calls.append('remote') or True)
    assert result == {'status': 'backend_removed'} and calls == ['engine', 'remote']


def test_remove_backend_refused_while_relay_open_keeps_remote_profile():
    calls = []
    result = proxy_form.remove_backend('paths', remove=lambda p: {'status': 'failed', 'error': 'relay listening'},
                                       remote_remove=lambda p: calls.append('remote') or True)
    assert result == {'status': 'backend_remove_refused'} and calls == []


def test_first_engine_check_proposes_exit_without_saved_profile(monkeypatch):
    monkeypatch.setattr(connections, 'load', lambda _: None)
    monkeypatch.setattr(netguard, 'status', lambda _: {'passed': True})
    monkeypatch.setattr(connections, 'measure', lambda url: {'status': 'measured', 'exit_ip': '9.9.9.9'})
    saved = []
    monkeypatch.setattr(connections, 'save', lambda paths, profile: saved.append(profile))
    assert proxy_form.LocalBackendDraft('paths').check() == {'status': 'proxy_confirmation_required'}
    draft = proxy_form.LocalBackendDraft('paths', first=True)
    assert draft.check() == {'status': 'proxy_checked'}
    assert draft.expected['local_proxy'] == netguard.PROXY_URL
    assert draft.expected['expected_exit_ips'] == ['9.9.9.9']
    assert draft.save('paths') == {'status': 'proxy_confirmation_required'} and not saved
    assert draft.save('paths', confirmed=True)['status'] == 'proxy_saved' and len(saved) == 1
