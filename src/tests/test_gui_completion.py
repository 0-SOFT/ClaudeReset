"""Wizard progress, VLESS engine install/remove from the window, first exit check after the engine install."""
from types import SimpleNamespace

import pytest
from proxy_fakes import Probe, measured

from claude_reset import config
from claude_reset.model.notes import Note
from claude_reset.network import connections, remote_backend
from claude_reset.services import progress as wizard
from claude_reset.services import proxy as proxy_form
from claude_reset.services.diagnostics import History, HistoryRow


def report(protection='not_installed', **parts):
    return {'protection': protection, 'checks': [{'id': k, 'status': v} for k, v in parts.items()]}


def history(*statuses, collection='complete'):
    rows = tuple(HistoryRow(n, status, Note('history.note')) for n, status in enumerate(statuses, 1))
    return lambda _paths: History(collection, rows=rows)


def folders(tmp_path):
    """Empty program folders: nothing saved yet."""
    return SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')


def test_wizard_from_zero_points_to_server_first():
    result = wizard.progress(None, check=lambda _: report(), history=history())
    assert [s.state for s in result.steps] == ['todo', 'todo', 'todo', 'todo', 'waiting']
    assert result.next == 'server'


def test_wizard_marks_finished_steps_and_opens_checks_last():
    ready = report('installed', backend_task='ok', backend_listening='ok', connection_profile='ok')
    partial = wizard.progress(None, server_done=True, check=lambda _: ready, history=history('failed_or_partial'))
    assert {s.key: s.state for s in partial.steps} == {
        'server': 'done', 'cleanup': 'todo', 'connection': 'done', 'protection': 'done', 'checks': 'waiting'}
    assert partial.next == 'cleanup'
    done = wizard.progress(None, server_done=True, check=lambda _: ready, history=history('fixed_locations_wiped'))
    assert done.steps[-1].state == 'todo' and done.next == 'checks'
    assert done.to_json() == {'steps': [{'key': key, 'state': 'done'} for key in wizard.STEPS[:-1]]
                              + [{'key': 'checks', 'state': 'todo'}], 'next': 'checks'}


def test_wizard_unreadable_state_is_unknown_not_done():
    def broken(_):
        raise OSError('C:/Users/someone/private')
    result = wizard.progress(None, check=broken, history=history(collection='unavailable'))
    states = {s.key: s.state for s in result.steps}
    assert states['connection'] == states['protection'] == states['cleanup'] == 'unknown'
    assert 'someone' not in repr(result)


@pytest.mark.parametrize('status,expected', [
    ('installed', 'engine_installed'), ('installed_needs_attention', 'engine_needs_attention'),
    ('not_started', 'engine_not_started'), ('failed', 'engine_install_failed')])
def test_engine_install_maps_installer_status(tmp_path, status, expected):
    calls = []
    fake = lambda paths, profile, archive=None: calls.append((profile, archive)) or {
        'status': status, 'error': 'SafetyError: C:/Users/someone/engine'}
    result = proxy_form.install_engine(folders(tmp_path), 'profile.json', 'engine.zip', install=fake)
    assert result.to_json() == {'status': expected} and calls == [('profile.json', 'engine.zip')]


def test_engine_install_refused_while_remote_proxy_saved(tmp_path):
    paths = folders(tmp_path)
    remote_backend.save(paths, proxy_form.ProxyDraft('8.8.8.8', 1080).profile)
    result = proxy_form.install_engine(paths, 'profile.json', install=lambda *a, **k: pytest.fail('installed'))
    assert result.to_json() == {'status': 'engine_remote_profile_saved'}


def test_engine_install_exception_text_stays_private(tmp_path):
    def boom(*_a, **_k):
        raise RuntimeError('secret-password at C:/Users/someone')
    assert proxy_form.install_engine(folders(tmp_path), 'profile.json', install=boom).to_json() == {
        'status': 'engine_install_failed', 'error_type': 'RuntimeError'}


def test_remove_backend_removes_engine_then_remote_profile():
    calls = []
    result = proxy_form.remove_backend('paths', remove=lambda p: calls.append('engine') or {'status': 'removed'},
                                       remote_remove=lambda p: calls.append('remote') or True)
    assert result.to_json() == {'status': 'backend_removed'} and calls == ['engine', 'remote']


def test_remove_backend_refused_while_relay_open_keeps_remote_profile():
    calls = []
    result = proxy_form.remove_backend('paths', remove=lambda p: {'status': 'failed', 'error': 'relay listening'},
                                       remote_remove=lambda p: calls.append('remote') or True)
    assert result.to_json() == {'status': 'backend_remove_refused'} and calls == []


def test_first_engine_check_proposes_exit_without_saved_profile(tmp_path):
    paths = folders(tmp_path)
    probe = Probe(backend_status={'passed': True}, measure_local=measured('9.9.9.9'))
    assert proxy_form.LocalBackendDraft(paths, probe=probe).check().to_json() == {
        'status': 'proxy_confirmation_required'}
    draft = proxy_form.LocalBackendDraft(paths, first=True, probe=probe)
    assert draft.check().to_json() == {'status': 'proxy_checked'}
    assert draft.expected['local_proxy'] == config.BACKEND_URL
    assert draft.expected['expected_exit_ips'] == ['9.9.9.9']
    assert draft.save(paths).to_json() == {'status': 'proxy_confirmation_required'} and connections.load(paths) is None
    saved = draft.save(paths, confirmed=True)
    assert saved.to_json() == {'status': 'proxy_saved', 'clients_changed': False}
    assert connections.load(paths) == draft.expected
