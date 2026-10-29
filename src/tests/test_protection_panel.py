from types import SimpleNamespace
from loopback_only import loopback_only
import pytest
from claude_reset import protection_panel as panel, app
from test_gui_shell import ui, button


@pytest.mark.parametrize('proxy_type', ['http', 'socks5'])
@pytest.mark.parametrize('reachable', [True, False])
def test_saved_type_retry_and_controller_labels(tmp_path, monkeypatch, proxy_type, reachable):
    from claude_reset import remote_backend as rb, connections
    from claude_reset.proxy_form import ProxyDraft
    guard = panel.strict_guard
    paths = SimpleNamespace(state=tmp_path, home=tmp_path, local=tmp_path / 'local')
    profile = ProxyDraft('8.8.8.8', 8080, 'private-user', 'private-password', proxy_type=proxy_type).profile
    rb.save(paths, profile)
    calls = []
    monkeypatch.setattr(rb, 'reachable', lambda p: {'status': 'reachable' if reachable else 'unreachable'})
    monkeypatch.setattr(rb, 'handshake_test', lambda p: calls.append(rb.proxy_url(p).split(':')[0]) or {'ok': True})
    monkeypatch.setattr(rb, 'measure_exit', lambda p: {'status': 'measured', 'exit_ip': '9.9.9.9'})
    draft, outcome = panel.check_saved_proxy(paths)
    assert draft.proxy_type == proxy_type
    assert outcome['status'] == ('proxy_checked' if reachable else 'proxy_unreachable')
    assert calls == ([proxy_type] if reachable else [])
    assert bool(draft.expected) == reachable
    assert rb.load(paths) == profile
    assert connections.load(paths) is None
    monkeypatch.setattr(guard, 'identities', lambda _: [])
    kind = 'remote_http' if proxy_type == 'http' else 'remote_socks5'
    assert guard.plan(paths)['tunnel_identity'] == kind
    # Exercise controller publication only up to unreachable peer; no WFP or relay.
    monkeypatch.setattr(rb, 'reachable', lambda p: {'status': 'unreachable'})
    monkeypatch.setattr(guard, 'Engine', lambda *a, **k: pytest.fail('real L1 forbidden'))
    monkeypatch.setattr(guard.l1_monitor, 'record_exit', lambda *a: None)
    state = guard._serve_admitted(paths, tmp_path / 'report.json', tmp_path,
                                  {'request_id': 'fixture', 'state': 'starting'})
    assert state['backend'] == kind and state['state'] == 'blocked_exit_unreachable'
    monkeypatch.setattr(panel.l1_check, 'check', lambda _: {})
    monkeypatch.setattr(guard, 'status', lambda _: {'last_report': state})
    text = panel.status(paths)['text']
    assert ('HTTP CONNECT' if proxy_type == 'http' else 'SOCKS5') in text
    assert all(secret not in text + str(outcome) for secret in ('private-user', 'private-password', '8.8.8.8', '9.9.9.9'))
    assert draft.check()['status'] == 'proxy_unreachable' and draft.expected is None


@pytest.mark.parametrize('initial,changed', [('socks5', 'http'), ('http', 'socks5')])
def test_change_type_requires_recheck_before_apply(ui, monkeypatch, initial, changed):
    from claude_reset import remote_backend as rb
    calls = []
    ui.run = lambda fn, cb, **kw: cb(fn())
    for key, value in dict(host='8.8.8.8', port='8080', username='', password='').items():
        ui.proxy_fields[key].set(value)
    monkeypatch.setattr(rb, 'reachable', lambda p: {'status': 'reachable'})
    monkeypatch.setattr(rb, 'handshake_test', lambda p: {'ok': True})
    monkeypatch.setattr(rb, 'measure_exit', lambda p: {'status': 'measured', 'exit_ip': '9.9.9.9'})
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *a: True)
    monkeypatch.setattr(panel.l1_install, 'restart', lambda p, **kw: calls.append(kw['proxy_draft'].proxy_type) or {'status': 'restarted'})
    ui.proxy_type.set(initial)
    button('Проверить прокси').options['command']()
    ui.proxy_type.set(changed)
    button('Применить проверенный прокси').options['command']()
    assert not calls
    button('Проверить прокси').options['command']()
    button('Применить проверенный прокси').options['command']()
    assert calls == [changed]


@pytest.mark.parametrize('action,module,name,status', [
    ('install', panel.l1_install, 'run', 'installed'),
    ('reinstall', panel.l1_install, 'run', 'installed'),
    ('restart', panel.l1_install, 'restart', 'restarted'),
    ('remove', panel.l1_remove, 'run', 'removed'),
])
@pytest.mark.parametrize('confirmed', [False, True])
def test_dispatch(tmp_path, monkeypatch, action, module, name, status, confirmed):
    paths = SimpleNamespace(state=tmp_path, home=tmp_path)
    calls = []
    monkeypatch.setattr(panel, 'limits', lambda _: {'known': True, 'lines': []})
    monkeypatch.setattr(module, name, lambda p, **kw: calls.append((p, kw)) or {'status': status})
    result = panel.perform(paths, action, confirmed=confirmed, protect_extension=True)
    assert bool(calls) == confirmed
    if confirmed:
        assert result['text'] == panel.RESULTS[status]
        assert calls[0][0] is paths
        if action in ('install', 'reinstall'):
            assert calls[0][1] == {'confirmed': True, 'protect_extension': True,
                                   'reinstall_controller': action == 'reinstall'}


def test_limits_read_only_and_unknown_refused(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(panel.strict_guard, 'l1_accept', lambda p, c: calls.append(c) or {'open_boundaries': list(panel.LIMITS)})
    assert len(panel.limits(tmp_path)['lines']) == 10
    assert calls == [False]
    monkeypatch.setattr(panel.strict_guard, 'l1_accept', lambda *a: {'open_boundaries': ['new']})
    monkeypatch.setattr(panel.l1_install, 'run', lambda *a, **k: pytest.fail('unexpected install'))
    assert 'недоступна' in panel.perform(tmp_path, 'install', confirmed=True)['text']


@pytest.mark.parametrize('status', ['installed_needs_attention', 'removed_with_leftovers', 'relay_not_open', 'reconcile_required', 'failed'])
def test_partial_and_secret_results(status):
    secret = 'secret-user-password 198.51.100.99 2001:db8::8'
    output = panel.result({'status': status, 'error': secret, 'reason': secret,
                           'steps': [{'detail': secret}], 'retry_blocked': True})['text']
    assert secret not in output and 'Повтор запрещён' in output
    assert output.startswith(panel.RESULTS.get(status, 'Операция не завершена'))


@pytest.mark.parametrize('can_install', [True, False, None])
def test_status_no_secrets_or_live_claim(tmp_path, monkeypatch, can_install):
    secret = 'secret-user-password 198.51.100.99'
    monkeypatch.setattr(panel.l1_check, 'check', lambda _: {
        'can_install': can_install, 'checks': [{'id': 'relay_listening', 'status': 'ok', 'detail': secret}]})
    monkeypatch.setattr(panel.strict_guard, 'status', lambda _: {
        'last_report': {'state': 'relay_open', 'stop_reason': secret}})
    text = panel.status(tmp_path)['text']
    assert secret not in text
    assert 'исторический' in text and 'не подтверждают' in text
    assert ('предусловия не подтверждены' in text) == (can_install is not True)


@pytest.mark.parametrize('action,label', [('install', 'Включить защиту L1'), ('restart', 'Перезапустить L1'), ('remove', 'Снять защиту L1')])
@pytest.mark.parametrize('accept', [False, True])
def test_window_buttons_confirmation(ui, monkeypatch, action, label, accept):
    calls, prompts = [], []
    ui.run = lambda fn, callback, **kw: callback(fn())
    monkeypatch.setattr(panel, 'limits', lambda _: {'known': True, 'lines': list(panel.LIMITS.values())})
    monkeypatch.setattr(panel, 'perform', lambda p, a, **kw: calls.append((a, kw)) or {'text': 'fixture-result'})
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda title, text: prompts.append(text) or accept)
    button(label).options['command']()
    assert len(calls) == int(accept) and prompts
    if accept:
        assert calls[0] == (action, {'confirmed': True, 'protect_extension': None})
        assert ui.protection_text.get() == 'fixture-result'
    if action == 'install':
        assert all(line in prompts[0] for line in panel.LIMITS.values())


def test_window_status_and_extension_choice(ui, monkeypatch):
    ui.run = lambda fn, callback, **kw: callback(fn())
    monkeypatch.setattr(panel, 'status', lambda _: {'text': 'fixture-status'})
    button('Обновить состояние L1').options['command']()

    assert ui.protection_text.get() == 'fixture-status'
    ui.protect_extension.set(True)
    ui.protection_extension_changed()
    assert ui.protection_extension_choice is True
    ui.worker = SimpleNamespace(busy=True)
    monkeypatch.setattr(panel, 'status', lambda _: pytest.fail('busy'))
    button('Обновить состояние L1').options['command']()


@pytest.mark.parametrize('reason', ['exit_mismatch', 'exit_probe_failed', 'monitor_error', 'close_requested',
                                   'profile_changed', 'backend_changed', 'backend_config_failed', 'exception'])
def test_stop_reasons_are_russian(tmp_path, monkeypatch, reason):
    monkeypatch.setattr(panel.l1_check, 'check', lambda _: {})
    monkeypatch.setattr(panel.strict_guard, 'status', lambda _: {'last_report': {'stop_reason': reason}})
    text = panel.status(tmp_path)['text'].split('Причина последней остановки: ')[1]
    assert not text.startswith('не установлена') and reason not in text

@pytest.mark.parametrize('action,kwargs', [('change_proxy', {'proxy_draft': SimpleNamespace(expected={})}), ('extension', {'protect_extension': True}), ('extension', {'protect_extension': False})])
@pytest.mark.parametrize('confirmed', [True, False])
def test_new_dispatch(tmp_path, monkeypatch, action, kwargs, confirmed):
    calls = []
    monkeypatch.setattr(panel.l1_install, 'restart', lambda p, **kw: calls.append(kw) or {'status': 'restarted'})
    panel.perform(tmp_path, action, confirmed=confirmed, **kwargs)
    assert calls == ([kwargs] if confirmed else [])
    panel.perform(tmp_path, action, confirmed=True)
    assert len(calls) == int(confirmed)


@pytest.mark.parametrize('outcome', ['proxy_checked', 'proxy_unreachable', 'proxy_login_or_connect_refused'])
def test_saved_proxy_blockers(tmp_path, monkeypatch, outcome):
    from claude_reset import remote_backend, proxy_form
    monkeypatch.setattr(remote_backend, 'load', lambda _: dict(host='8.8.8.8', port=1080, username='secret-user', password='secret-pass'))
    monkeypatch.setattr(proxy_form.ProxyDraft, 'check', lambda _: {'status': outcome})
    draft, public = panel.check_saved_proxy(tmp_path)
    assert draft.profile['password'] == 'secret-pass' and public == {'status': outcome}
    assert 'secret' not in str(public) and '8.8.8.8' not in str(public)
    monkeypatch.setattr(remote_backend, 'load', lambda _: None)
    from claude_reset import connections
    monkeypatch.setattr(connections, 'load', lambda _: None)
    assert panel.check_saved_proxy(tmp_path)[1]['status'] == 'proxy_confirmation_required'


@pytest.mark.parametrize('accept', [True, False])
def test_window_change_checked_proxy(ui, monkeypatch, accept):
    from claude_reset.proxy_form import ProxyDraft
    draft = ProxyDraft('8.8.8.8', 1080, 'secret-user', 'secret-pass')
    draft.expected = {'expected_exit_ips': ['9.9.9.9']}
    ui.proxy_draft = draft
    for k, var in ui.proxy_fields.items():
        var.set(str(draft.profile[k]))
    calls = []
    ui.run = lambda fn, cb, **kw: cb(fn())
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *a: accept)
    monkeypatch.setattr(panel, 'perform', lambda p, a, **kw: calls.append((a, kw)) or {'text': 'fixture'})
    button('Применить проверенный прокси').options['command']()
    assert len(calls) == int(accept)
    ui.proxy_fields['password'].set('edited')
    button('Применить проверенный прокси').options['command']()
    assert len(calls) == int(accept)
    assert 'secret' not in ui.protection_text.get() and '9.9.9.9' not in ui.protection_text.get()


def test_window_retry_then_confirm(ui, monkeypatch):
    draft = SimpleNamespace(expected={'expected_exit_ips': ['9.9.9.9']})
    ui.run = lambda fn, cb, **kw: cb(fn())
    monkeypatch.setattr(panel, 'check_saved_proxy', lambda _: (draft, {'status': 'proxy_checked'}))
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda *a: True)
    calls = []
    monkeypatch.setattr(panel, 'perform', lambda p, a, **kw: calls.append(kw) or {'text': 'fixture'})
    button('Повторить проверку / проверить новый выход').options['command']()
    button('Подтвердить новый выход и перезапустить').options['command']()
    assert calls == [{'confirmed': True, 'proxy_draft': draft}]
    button('Ввести реквизиты / выбрать другой прокси').options['command']()
    assert ui.tabs.selected == next(page for page, label in ui.tabs.pages if label == 'Соединение')
    ui.protect_extension.set(True)
    ui.protection_extension_changed()
    button('Применить выбор расширения').options['command']()
    assert calls[-1] == {'confirmed': True, 'protect_extension': True}

@pytest.mark.parametrize('mode', ['mismatch', 'unreachable', 'measurement_failed', 'router'])
def test_vless_retry_exit_confirmation(tmp_path, monkeypatch, mode):
    from claude_reset import connections, remote_backend, netguard
    saved = dict(schema=1, local_proxy=netguard.PROXY_URL, router_proxy=None,
                 expected_exit_ips=['8.8.8.8'])
    if mode == 'router':
        saved['router_proxy'] = 'http://9.9.9.9:8080'
    writes, probes = [], []
    monkeypatch.setattr(remote_backend, 'load', lambda _: None)
    monkeypatch.setattr(connections, 'load', lambda _: saved)
    monkeypatch.setattr(netguard, 'status', lambda _: {'passed': mode != 'unreachable'})
    monkeypatch.setattr(connections, 'measure', lambda proxy: probes.append(proxy) or
                        {'status': 'measurement_failed' if mode == 'measurement_failed' else 'measured', 'exit_ip': '1.1.1.1'})
    monkeypatch.setattr(connections, 'save', lambda p, profile: writes.append(profile))
    monkeypatch.setattr(remote_backend, 'save', lambda *a: pytest.fail('must preserve VLESS backend'))
    draft, result = panel.check_saved_proxy(tmp_path)
    assert '1.1.1.1' not in str(result) and '8.8.8.8' not in str(result)
    assert not writes
    draft.save(tmp_path)
    assert not writes
    if mode == 'mismatch':
        assert result['status'] == 'proxy_checked'
        draft.save(tmp_path, confirmed=True)
        assert writes[0]['expected_exit_ips'] == ['1.1.1.1']
        monkeypatch.setattr(netguard, 'status', lambda _: {'passed': False})
        assert draft.check()['status'] == 'proxy_unreachable' and draft.expected is None
    else:
        assert draft.expected is None
        draft.save(tmp_path, confirmed=True)
        assert not writes
    assert probes == ([netguard.PROXY_URL] if mode in ('mismatch', 'measurement_failed') else [])

@pytest.mark.parametrize('accept', [True, False])
def test_window_exclude_extension(ui, monkeypatch, accept):
    calls, prompts, waits = [], [], []
    ui.run = lambda fn, cb, **kw: waits.append(kw) or cb(fn())
    ui.protect_extension.set(False)
    ui.protection_extension_changed()
    monkeypatch.setattr(app.messagebox, 'askyesno', lambda title, text: prompts.append(text) or accept)
    monkeypatch.setattr(panel, 'perform', lambda p, a, **kw: calls.append((a, kw)) or {'text': 'fixture'})
    button('Применить выбор расширения').options['command']()
    assert calls == ([('extension', {'confirmed': True, 'protect_extension': False})] if accept else [])
    assert 'UAC' in prompts[0] and 'без защиты L1' in prompts[0]
    if accept:
        assert waits == [{'waiting_uac': True}]
