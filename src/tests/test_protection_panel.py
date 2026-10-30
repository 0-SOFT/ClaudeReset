from types import SimpleNamespace
from loopback_only import loopback_only
import pytest
from claude_reset.ui import protection_panel as panel, expert_window as app
from claude_reset.services import proxy as proxy_service
from test_gui_shell import ui, button
from claude_reset import config
from claude_reset.network import controller, gate_rules
from claude_reset.model.status import Protection
from dialog_fakes import script
from proxy_fakes import REACHABLE, Probe, working
from scripted import Scripted, Strict


@pytest.mark.parametrize('proxy_type', ['http', 'socks5'])
@pytest.mark.parametrize('reachable', [True, False])
def test_saved_type_retry_and_controller_labels(tmp_path, proxy_type, reachable):
    from claude_reset.network import remote_backend as rb, connections
    from claude_reset.services.proxy import ProxyDraft
    paths = SimpleNamespace(state=tmp_path, home=tmp_path, local=tmp_path / 'local')
    profile = ProxyDraft('8.8.8.8', 8080, 'private-user', 'private-password', proxy_type=proxy_type).profile
    rb.save(paths, profile)
    calls = []
    probe = working('9.9.9.9', reachable={'status': 'reachable' if reachable else 'unreachable'},
                    handshake=lambda p: calls.append(rb.proxy_url(p).split(':')[0]) or {'ok': True})
    draft, outcome = proxy_service.check_saved(paths, probe=probe)
    assert draft.proxy_type == proxy_type
    assert outcome['status'] == ('proxy_checked' if reachable else 'proxy_unreachable')
    assert calls == ([proxy_type] if reachable else [])
    assert bool(draft.expected) == reachable
    assert rb.load(paths) == profile
    assert connections.load(paths) is None
    # The client identities are read from the test's own folders, where only the packages are known.
    kind = 'remote_http' if proxy_type == 'http' else 'remote_socks5'
    assert gate_rules.plan(paths)['tunnel_identity'] == kind
    # Exercise controller publication only up to unreachable peer; no WFP or relay.
    probe.answers['reachable'] = {'status': 'unreachable'}
    state = controller.run_admitted(paths, tmp_path / 'report.json', tmp_path,
                                    {'request_id': 'fixture', 'state': 'starting'},
                                    engine=lambda *a, **k: pytest.fail('real L1 forbidden'), probe=probe)
    assert state['backend'] == kind and state['state'] == 'blocked_exit_unreachable'
    text = panel.status(paths, l1=Scripted(check={}, report={'last_report': state}))['text']
    assert ('HTTP CONNECT' if proxy_type == 'http' else 'SOCKS5') in text
    assert all(secret not in text + str(outcome) for secret in ('private-user', 'private-password', '8.8.8.8', '9.9.9.9'))
    assert draft.check()['status'] == 'proxy_unreachable' and draft.expected is None


@pytest.mark.parametrize('initial,changed', [('socks5', 'http'), ('http', 'socks5')])
def test_change_type_requires_recheck_before_apply(ui, initial, changed):
    from claude_reset.network import remote_backend as rb
    calls = []
    ui.run = lambda fn, cb, **kw: cb(fn())
    for key, value in dict(host='8.8.8.8', port='8080', username='', password='').items():
        ui.proxy_fields[key].set(value)
    ui.probe = working('9.9.9.9')
    script(ui, askyesno=True)
    ui.l1 = Strict(restart=lambda p, **kw: calls.append(kw['proxy_draft'].proxy_type) or {'status': 'restarted'})
    ui.proxy_type.set(initial)
    button('Проверить прокси').options['command']()
    ui.proxy_type.set(changed)
    button('Применить проверенный прокси').options['command']()
    assert not calls
    button('Проверить прокси').options['command']()
    button('Применить проверенный прокси').options['command']()
    assert calls == [changed]


@pytest.mark.parametrize('action,name,status', [
    ('install', 'install', 'installed'),
    ('reinstall', 'install', 'installed'),
    ('restart', 'restart', 'restarted'),
    ('remove', 'remove', 'removed'),
])
@pytest.mark.parametrize('confirmed', [False, True])
def test_dispatch(tmp_path, action, name, status, confirmed):
    paths = SimpleNamespace(state=tmp_path, home=tmp_path)
    calls = []
    l1 = Strict(boundaries=list(panel.LIMITS), **{name: lambda p, **kw: calls.append((p, kw)) or {'status': status}})
    result = panel.perform(paths, action, confirmed=confirmed, protect_extension=True, l1=l1)
    assert bool(calls) == confirmed
    if confirmed:
        assert result['text'] == panel.RESULTS[status]
        assert calls[0][0] is paths
        if action in ('install', 'reinstall'):
            assert calls[0][1] == {'confirmed': True, 'protect_extension': True,
                                   'reinstall_controller': action == 'reinstall'}


def test_limits_read_only_and_unknown_refused(tmp_path):
    l1 = Strict(boundaries=list(panel.LIMITS))
    assert len(panel.limits(tmp_path, l1=l1)['lines']) == 10
    assert [name for name, _, _ in l1.calls] == ['boundaries']
    # A boundary the window does not know stops the install before it starts: Strict refuses an install call.
    assert 'недоступна' in panel.perform(tmp_path, 'install', confirmed=True, l1=Strict(boundaries=['new']))['text']


@pytest.mark.parametrize('status', ['installed_needs_attention', 'removed_with_leftovers', 'relay_not_open', 'reconcile_required', 'failed'])
def test_partial_and_secret_results(status):
    secret = 'secret-user-password 198.51.100.99 2001:db8::8'
    output = panel.result({'status': status, 'error': secret, 'reason': secret,
                           'steps': [{'detail': secret}], 'retry_blocked': True})['text']
    assert secret not in output and 'Повтор запрещён' in output
    assert output.startswith(panel.RESULTS.get(status, 'Операция не завершена'))


@pytest.mark.parametrize('can_install', [True, False, None])
def test_status_no_secrets_or_live_claim(tmp_path, can_install):
    secret = 'secret-user-password 198.51.100.99'
    l1 = Strict(check={'can_install': can_install,
                       'checks': [{'id': 'relay_listening', 'status': 'ok', 'detail': secret}]},
                report={'last_report': {'state': 'relay_open', 'stop_reason': secret}})
    text = panel.status(tmp_path, l1=l1)['text']
    assert secret not in text
    assert 'исторический' in text and 'не подтверждают' in text
    assert ('предусловия не подтверждены' in text) == (can_install is not True)


@pytest.mark.parametrize('action,label', [('install', 'Включить защиту L1'), ('restart', 'Перезапустить L1'), ('remove', 'Снять защиту L1')])
@pytest.mark.parametrize('accept', [False, True])
def test_window_buttons_confirmation(ui, action, label, accept):
    prompts = []
    ui.run = lambda fn, callback, **kw: callback(fn())
    status = {'install': 'installed', 'restart': 'restarted', 'remove': 'removed'}[action]
    ui.l1 = Strict(boundaries=list(panel.LIMITS), **{action: {'status': status}})
    script(ui, askyesno=lambda title, text: prompts.append(text) or accept)
    button(label).options['command']()
    calls = [(name, kw) for name, _, kw in ui.l1.calls if name != 'boundaries']
    assert len(calls) == int(accept) and prompts
    if accept:
        options = {'confirmed': True, 'protect_extension': None, 'reinstall_controller': False}
        assert calls[0] == (action, options if action == 'install' else {})
        assert ui.protection_text.get() == panel.RESULTS[status]
    if action == 'install':
        assert all(line in prompts[0] for line in panel.LIMITS.values())


def test_window_status_and_extension_choice(ui):
    ui.run = lambda fn, callback, **kw: callback(fn())
    ui.l1 = Strict(check={}, report={})
    button('Обновить состояние L1').options['command']()

    assert ui.protection_text.get() == panel.status(ui.paths, l1=ui.l1)['text']
    ui.protect_extension.set(True)
    ui.protection_extension_changed()
    assert ui.protection_extension_choice is True
    ui.worker = SimpleNamespace(busy=True)
    ui.l1 = Strict()   # a busy window asks nothing
    button('Обновить состояние L1').options['command']()


@pytest.mark.parametrize('reason', ['exit_mismatch', 'exit_probe_failed', 'monitor_error', 'close_requested',
                                   'profile_changed', 'backend_changed', 'backend_config_failed', 'exception'])
def test_stop_reasons_are_russian(tmp_path, reason):
    l1 = Strict(check={}, report={'last_report': {'stop_reason': reason}})
    text = panel.status(tmp_path, l1=l1)['text'].split('Причина последней остановки: ')[1]
    assert not text.startswith('не установлена') and reason not in text

@pytest.mark.parametrize('action,kwargs', [('change_proxy', {'proxy_draft': SimpleNamespace(expected={})}), ('extension', {'protect_extension': True}), ('extension', {'protect_extension': False})])
@pytest.mark.parametrize('confirmed', [True, False])
def test_new_dispatch(tmp_path, action, kwargs, confirmed):
    calls = []
    l1 = Strict(restart=lambda p, **kw: calls.append(kw) or {'status': 'restarted'})
    panel.perform(tmp_path, action, confirmed=confirmed, l1=l1, **kwargs)
    assert calls == ([kwargs] if confirmed else [])
    panel.perform(tmp_path, action, confirmed=True, l1=l1)
    assert len(calls) == int(confirmed)


@pytest.mark.parametrize('outcome', ['proxy_checked', 'proxy_unreachable', 'proxy_login_or_connect_refused'])
def test_saved_proxy_blockers(tmp_path, outcome):
    from claude_reset.network import remote_backend
    paths = SimpleNamespace(state=tmp_path / 'saved', local=tmp_path / 'local')
    remote_backend.save(paths, proxy_service.ProxyDraft('8.8.8.8', 1080, 'secret-user', 'secret-pass').profile)
    probe = {'proxy_checked': working('9.9.9.9'),
             'proxy_unreachable': Probe(reachable={'status': 'unreachable'}),
             'proxy_login_or_connect_refused': Probe(reachable=REACHABLE, handshake={'ok': False})}[outcome]
    draft, public = proxy_service.check_saved(paths, probe=probe)
    assert draft.profile['password'] == 'secret-pass' and public['status'] == outcome
    assert 'secret' not in str(public) and '8.8.8.8' not in str(public)
    nothing_saved = SimpleNamespace(state=tmp_path / 'empty', local=tmp_path / 'local')
    assert proxy_service.check_saved(nothing_saved, probe=Probe())[1]['status'] == 'proxy_confirmation_required'


@pytest.mark.parametrize('accept', [True, False])
def test_window_change_checked_proxy(ui, accept):
    from claude_reset.services.proxy import ProxyDraft
    draft = ProxyDraft('8.8.8.8', 1080, 'secret-user', 'secret-pass')
    draft.expected = {'expected_exit_ips': ['9.9.9.9']}
    ui.proxy_draft = draft
    for k, var in ui.proxy_fields.items():
        var.set(str(draft.profile[k]))
    ui.run = lambda fn, cb, **kw: cb(fn())
    script(ui, askyesno=accept)
    ui.l1 = Strict(restart={'status': 'restarted'})
    button('Применить проверенный прокси').options['command']()
    assert ui.l1.calls == ([('restart', (ui.paths,), {'proxy_draft': draft})] if accept else [])
    ui.proxy_fields['password'].set('edited')
    button('Применить проверенный прокси').options['command']()
    assert len(ui.l1.calls) == int(accept)
    assert 'secret' not in ui.protection_text.get() and '9.9.9.9' not in ui.protection_text.get()


def test_window_retry_then_confirm(ui):
    from claude_reset.network import remote_backend as rb
    rb.save(ui.paths, proxy_service.ProxyDraft('8.8.8.8', 1080).profile)
    ui.probe = working('9.9.9.9')
    ui.run = lambda fn, cb, **kw: cb(fn())
    script(ui, askyesno=True)
    ui.l1 = Strict(restart={'status': 'restarted'})
    button('Повторить проверку / проверить новый выход').options['command']()
    button('Подтвердить новый выход и перезапустить').options['command']()
    assert [kw['proxy_draft'].expected['expected_exit_ips'] for _, _, kw in ui.l1.calls] == [['9.9.9.9']]
    button('Ввести реквизиты / выбрать другой прокси').options['command']()
    assert ui.tabs.selected == next(page for page, label in ui.tabs.pages if label == 'Соединение')
    ui.protect_extension.set(True)
    ui.protection_extension_changed()
    button('Применить выбор расширения').options['command']()
    assert ui.l1.calls[-1] == ('restart', (ui.paths,), {'protect_extension': True})

@pytest.mark.parametrize('mode', ['mismatch', 'unreachable', 'measurement_failed', 'router'])
def test_vless_retry_exit_confirmation(tmp_path, mode):
    from claude_reset.network import connections, remote_backend
    paths = SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    saved = dict(schema=1, local_proxy=config.BACKEND_URL, router_proxy=None,
                 expected_exit_ips=['8.8.8.8'])
    if mode == 'router':
        saved['router_proxy'] = 'http://9.9.9.9:8080'
    connections.save(paths, saved)
    probes = []
    probe = Probe(backend_status={'passed': mode != 'unreachable'},
                  measure_local=lambda proxy: probes.append(proxy) or
                  {'status': 'measurement_failed' if mode == 'measurement_failed' else 'measured', 'exit_ip': '1.1.1.1'})
    draft, result = proxy_service.check_saved(paths, probe=probe)
    assert '1.1.1.1' not in str(result) and '8.8.8.8' not in str(result)
    draft.save(paths)
    assert connections.load(paths) == saved
    if mode == 'mismatch':
        assert result['status'] == 'proxy_checked'
        draft.save(paths, confirmed=True)
        assert connections.load(paths)['expected_exit_ips'] == ['1.1.1.1']
        probe.answers['backend_status'] = {'passed': False}
        assert draft.check()['status'] == 'proxy_unreachable' and draft.expected is None
    else:
        assert draft.expected is None
        draft.save(paths, confirmed=True)
        assert connections.load(paths) == saved
    assert remote_backend.load(paths) is None   # the VLESS backend is kept, no remote proxy appears
    assert probes == ([config.BACKEND_URL] if mode in ('mismatch', 'measurement_failed') else [])

@pytest.mark.parametrize('accept', [True, False])
def test_window_exclude_extension(ui, accept):
    prompts, waits = [], []
    ui.run = lambda fn, cb, **kw: waits.append(kw) or cb(fn())
    ui.protect_extension.set(False)
    ui.protection_extension_changed()
    script(ui, askyesno=lambda title, text: prompts.append(text) or accept)
    ui.l1 = Strict(restart={'status': 'restarted'})
    button('Применить выбор расширения').options['command']()
    assert ui.l1.calls == ([('restart', (ui.paths,), {'protect_extension': False})] if accept else [])
    assert 'UAC' in prompts[0] and 'без защиты L1' in prompts[0]
    if accept:
        assert waits == [{'waiting_uac': True}]


def test_every_final_status_of_a_protection_operation_has_its_own_text():
    # 'failed' keeps the generic text on purpose: the cause is unknown and the error text is never shown.
    assert set(Protection) - set(panel.RESULTS) == {Protection.FAILED}
    assert set(panel.RESULTS) <= set(Protection)


def test_every_next_step_has_command_line_words():
    from claude_reset.ui import expert_window as app
    from claude_reset import cli
    from claude_reset.model.status import NextAction
    assert set(cli.NEXT_STEPS) == set(NextAction)
    report = {'steps': [{'next': NextAction.CONFIRM_LIMITS}], 'next': 'free text stays'}
    assert cli.explain_next(report) == {'steps': [{'next': 'Прочитайте список и повторите с --confirm-l1-limits'}],
                                        'next': 'free text stays'}


def test_every_proxy_step_has_its_own_text():
    from claude_reset.ui import expert_window as app, proxy_flow
    from claude_reset.model.status import Proxy
    # A failed check keeps the generic text on purpose; the main window never imports engine profiles.
    assert set(Proxy) - set(app.PROXY_MESSAGES) == {Proxy.PROXY_CHECK_FAILED}
    assert set(Proxy) - set(proxy_flow.MESSAGES) == {Proxy.VLESS_IMPORTED, Proxy.VLESS_IMPORT_REFUSED}
