from loopback_only import loopback_only
import json
from types import SimpleNamespace

import pytest

from claude_reset import connections, proxy_form, remote_backend as rb
from claude_reset.safeio import SafetyError
from test_remote_backend import FakeSocks, loopback_open, HOST, USER, PASSWORD
from test_gui_shell import ui, Widget, button


def draft():
    return proxy_form.ProxyDraft(HOST, '1080', USER, PASSWORD)


@pytest.mark.parametrize('accepted', [True, False])
def test_check_real_socks_login_connect_and_refusal(monkeypatch, accepted):
    server = FakeSocks(password=PASSWORD if accepted else 'different')
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'reachable'})
    def handshake(profile):
        try:
            loopback_open(server, auth=rb.auth_of(profile)).close()
            return {'ok': True}
        except SafetyError:
            return {'ok': False}
    monkeypatch.setattr(rb, 'handshake_test', handshake)
    monkeypatch.setattr(rb, 'measure_exit', lambda _: {'status': 'measured', 'exit_ip': HOST})
    value = draft()
    try:
        result = value.check()
        assert result['status'] == ('proxy_checked' if accepted else 'proxy_login_or_connect_refused')
        assert bool(value.expected) == accepted
        assert server.requests == (['claude.ai'] if accepted else [])
    finally:
        server.listener.close()


@pytest.mark.parametrize('mode', ['unreachable', 'measurement', 'exception'])
def test_check_failures_have_no_private_data(monkeypatch, mode, capsys):
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'unreachable' if mode == 'unreachable' else 'reachable'})
    monkeypatch.setattr(rb, 'handshake_test', lambda _: {'ok': True})
    def measure(_):
        if mode == 'exception':
            raise ValueError(f'{USER} {PASSWORD} {HOST}')
        return {'status': 'failed', 'error': PASSWORD}
    monkeypatch.setattr(rb, 'measure_exit', measure)
    value = draft()
    result = value.check()
    assert value.expected is None
    assert result['status'] != 'proxy_checked'
    public = json.dumps(result) + repr(value) + str(capsys.readouterr())
    assert all(secret not in public for secret in (USER, PASSWORD, HOST))


@pytest.mark.parametrize('exit_ip', [HOST, '2606:4700:4700::1111'])
def test_save_confirmation_and_dpapi_leak_check(monkeypatch, tmp_path, capsys, exit_ip):
    paths = SimpleNamespace(state=tmp_path / 'state', local=tmp_path / 'local')
    value = draft()
    assert value.save(paths, confirmed=True)['status'] == 'proxy_confirmation_required'
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'reachable'})
    monkeypatch.setattr(rb, 'handshake_test', lambda _: {'ok': True})
    monkeypatch.setattr(rb, 'measure_exit', lambda _: {'status': 'measured', 'exit_ip': exit_ip})
    assert value.check()['status'] == 'proxy_checked'
    assert value.save(paths)['status'] == 'proxy_confirmation_required'
    assert not paths.state.exists()
    result = value.save(paths, confirmed=True)
    assert result['status'] == 'proxy_saved'
    assert rb.load(paths) == value.profile
    assert connections.load(paths)['expected_exit_ips'] == [exit_ip]
    public = json.dumps(result).encode() + str(capsys.readouterr()).encode()
    for path in tmp_path.rglob('*'):
        if path.is_file():
            public += path.read_bytes()
    assert all(secret.encode() not in public for secret in (USER, PASSWORD, HOST, exit_ip))


def test_ipv6_peer_refused_without_disclosing_address():
    address = '2606:4700:4700::1111'
    with pytest.raises(SafetyError) as error:
        proxy_form.ProxyDraft(address, '1080')
    assert address not in str(error.value)


@pytest.mark.parametrize('valid', [True, False])
def test_vless_window_import_dpapi_and_refusal(ui, monkeypatch, tmp_path, capsys, valid):
    from test_backend_profiles import profile
    from claude_reset import backend_profiles
    value = profile()
    outbound = value['config']['outbounds'][0]
    secrets = [outbound['uuid'], outbound['server'], outbound['tls']['server_name'],
               outbound['tls']['reality']['public_key']]
    if not valid:
        value['adapter'] = PASSWORD
    source = tmp_path / 'input' / 'profile.json'
    source.parent.mkdir()
    source.write_text(json.dumps(value))
    ui.paths.state = tmp_path / 'saved'
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **_: str(source))
    outcomes = []
    def run(action, callback):
        result = action()
        outcomes.append(result)
        callback(result)
    ui.run = run
    button('Импортировать VLESS+Reality (JSON)').options['command']()
    assert outcomes[0]['status'] == ('vless_imported' if valid else 'vless_import_refused')
    if valid:
        assert backend_profiles.load(ui.paths, outcomes[0]['profile_id']) == value
        assert not outcomes[0]['selected'] and not outcomes[0]['clients_changed']
    else:
        assert not ui.paths.state.exists()
    public = (json.dumps(outcomes) + ui.status.get() + str(capsys.readouterr())).encode()
    for file in ui.paths.state.rglob('*'):
        if file.is_file():
            public += file.read_bytes()
    assert all(secret.encode() not in public for secret in secrets + [PASSWORD, USER])
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **_: '')
    button('Импортировать VLESS+Reality (JSON)').options['command']()
    assert len(outcomes) == 1


def test_invalid_form_has_safe_exception():
    with pytest.raises(SafetyError) as error:
        proxy_form.ProxyDraft(PASSWORD, USER)
    assert PASSWORD not in str(error.value) and USER not in str(error.value)


@pytest.mark.parametrize('mode', ['refused', 'dropped'])
def test_connect_refusal_and_disconnect_never_measure_or_save(monkeypatch, tmp_path, mode):
    from claude_reset import tunnel_transport
    server = FakeSocks(connect_reply=5 if mode == 'refused' else 0, drop_connect=mode == 'dropped')
    original = tunnel_transport.open_stream
    monkeypatch.setattr(tunnel_transport, 'open_stream', lambda url, host, port, verify, **kw:
                        original(f'socks5://127.0.0.1:{server.port}', host, port, verify, auth=kw['auth']))
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'reachable'})
    monkeypatch.setattr(rb, 'measure_exit', lambda _: pytest.fail('must not measure after refusal'))
    value = draft()
    try:
        assert value.check() == {'status': 'proxy_login_or_connect_refused'}
        assert value.expected is None
        paths = SimpleNamespace(state=tmp_path / 'state')
        assert value.save(paths, confirmed=True)['status'] == 'proxy_confirmation_required'
        assert not paths.state.exists()
    finally:
        server.listener.close()


def test_window_buttons_and_stale_draft(ui, monkeypatch):
    for key, value in zip(('host', 'port', 'username', 'password'), (HOST, '1080', USER, PASSWORD)):
        ui.proxy_fields[key].set(value)
    assert any(w.options.get('textvariable') is ui.proxy_fields['password'] and
               w.options.get('show') == '*' for w in Widget.all)
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'reachable'})
    monkeypatch.setattr(rb, 'handshake_test', lambda _: {'ok': True})
    monkeypatch.setattr(rb, 'measure_exit', lambda _: {'status': 'measured', 'exit_ip': HOST})
    ui.run = lambda action, callback: callback(action())
    button('Проверить прокси').options['command']()
    assert ui.proxy_draft.expected
    confirms = []
    monkeypatch.setattr('claude_reset.app.messagebox.askyesno', lambda *args: confirms.append(args) or True)
    button('Сохранить прокси и выход').options['command']()
    assert confirms and rb.load(ui.paths)['password'] == PASSWORD
    ui.proxy_fields['password'].set('changed')
    button('Сохранить прокси и выход').options['command']()
    assert len(confirms) == 1
    assert 'Сначала' in ui.status.get()


@pytest.mark.parametrize('accepted', [True, False])
@pytest.mark.parametrize('authenticated', [True, False])
def test_http_form_check_save_and_leak(ui, monkeypatch, tmp_path, capsys, accepted, authenticated):
    import base64
    import socket
    from test_tunnel_transport import Backend
    server = Backend('http', refuse=not accepted)
    original = socket.create_connection
    attempts = []
    def route(address, *args, **kwargs):
        attempts.append(address)
        assert address == (HOST, 8080)
        return original(('127.0.0.1', int(server.url.rsplit(':', 1)[1])), *args, **kwargs)
    monkeypatch.setattr(socket, 'create_connection', route)
    monkeypatch.setattr(rb, 'reachable', lambda _: {'status': 'reachable'})
    measured = []
    def measure(profile):
        measured.append(profile)
        return {'status': 'measured', 'exit_ip': HOST}
    monkeypatch.setattr(rb, 'measure_exit', measure)
    ui.proxy_type.set('http')
    for key, value in zip(('host', 'port', 'username', 'password'),
                          (HOST, '8080', USER if authenticated else '', PASSWORD if authenticated else '')):
        ui.proxy_fields[key].set(value)
    ui.run = lambda action, callback: callback(action())
    confirms = []
    monkeypatch.setattr('claude_reset.app.messagebox.askyesno', lambda *args: confirms.append(True) or True)
    try:
        button('Проверить прокси').options['command']()
        button('Сохранить прокси и выход').options['command']()
        assert bool(confirms) == accepted
        assert bool(measured) == accepted
        assert attempts == [(HOST, 8080)]
        if accepted:
            saved = rb.load(ui.paths)
            assert saved['adapter'] == rb.HTTP_ADAPTER
            assert rb.proxy_url(saved) == f'http://{HOST}:8080'
            assert connections.load(ui.paths)['expected_exit_ips'] == [HOST]
            ui.proxy_type.set('socks5')
            button('Сохранить прокси и выход').options['command']()
            assert len(confirms) == 1
            assert rb.load(ui.paths) == saved
        else:
            assert rb.load(ui.paths) is None
        token = base64.b64encode(f'{USER}:{PASSWORD}'.encode())
        assert (b'Proxy-Authorization: Basic ' + token in server.headers[0]) == authenticated
        public = (ui.status.get() + str(ui.messages) + str(capsys.readouterr())).encode()
        for file in tmp_path.rglob('*'):
            if file.is_file():
                public += file.read_bytes()
        assert all(value.encode() not in public for value in (HOST, USER, PASSWORD))
        assert token not in public
    finally:
        server.close()


@pytest.mark.parametrize('changes', [{'proxy_type': 'https'}, {'proxy_type': 'http', 'username': 'bad:user'}])
def test_http_form_refuses_unsupported_type_or_login(changes):
    with pytest.raises(SafetyError):
        proxy_form.ProxyDraft(HOST, '8080', password=PASSWORD, **dict({'username': USER}, **changes))


@pytest.mark.parametrize('existing', [None, b'previous encrypted profile'])
def test_saving_the_pair_rolls_back_the_proxy_when_the_exit_fails(tmp_path, monkeypatch, existing):
    from types import SimpleNamespace
    from claude_reset import connections, proxy_form, remote_backend
    paths = SimpleNamespace(state=tmp_path)
    target = remote_backend.path_of(paths)
    if existing is not None:
        target.write_bytes(existing)
    monkeypatch.setattr(remote_backend, 'save', lambda p, profile: target.write_bytes(b'new profile'))

    def refuse(p, profile):
        raise OSError('disk full')
    monkeypatch.setattr(connections, 'save', refuse)
    draft = proxy_form.ProxyDraft.__new__(proxy_form.ProxyDraft)
    draft.profile, draft.expected = {'host': '9.9.9.9'}, {'expected_exit_ips': ['9.9.9.9']}
    with pytest.raises(OSError):
        draft.save(paths, confirmed=True)
    assert (target.read_bytes() if target.exists() else None) == existing
