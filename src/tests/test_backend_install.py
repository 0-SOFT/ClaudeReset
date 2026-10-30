import base64
import hashlib
import io
import json
import subprocess
import types
import zipfile

import pytest

from claude_reset.backend import install as bi
from claude_reset.backend import location as backend_location
from claude_reset.elevation import claims
from claude_reset.safeio import SafetyError

KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
EXIT_SERVER = '93.184.216.34'                   # a literal public address; never contacted by these tests
UUID = '11111111-2222-3333-4444-555555555555'


def tunnel_config(**changes):
    outbound = {'type': 'vless', 'tag': 'selected-tunnel', 'server': EXIT_SERVER, 'server_port': 443, 'uuid': UUID,
                'tls': {'enabled': True, 'server_name': 'example.org', 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                        'reality': {'enabled': True, 'public_key': KEY, 'short_id': 'ab12'}}}
    outbound.update(changes)
    return {'log': {'disabled': True},
            'inbounds': [{'type': 'http', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': 1080}],
            'outbounds': [outbound], 'route': {'final': 'selected-tunnel'}}


def synthetic_engine():
    """A small archive laid out like the official one, plus a lock that matches it."""
    buffer = io.BytesIO()
    exe = b'MZ-synthetic-engine'
    with zipfile.ZipFile(buffer, 'w') as bundle:
        bundle.writestr('sing-box-0.0.1-windows-amd64/sing-box.exe', exe)
        bundle.writestr('sing-box-0.0.1-windows-amd64/libcronet.dll', b'dll')
    data = buffer.getvalue()
    return data, {'asset': 'sing-box-0.0.1-windows-amd64.zip', 'url': 'https://example.invalid/engine.zip', 'bytes': len(data),
                  'sha256': hashlib.sha256(data).hexdigest(), 'executable_sha256': hashlib.sha256(exe).hexdigest(), 'version': '0.0.1'}


def opener_for(data):
    def opener(url, timeout=0):
        assert url == 'https://example.invalid/engine.zip'
        return io.BytesIO(data)
    return opener


@pytest.fixture
def setup(tmp_path, monkeypatch):
    data, lock = synthetic_engine()
    monkeypatch.setattr(bi, 'load_lock', lambda: lock)
    profile = {'schema': 1, 'adapter': 'sing_box_vless_reality_v1', 'engine_path': 'C:\\unused\\engine.exe',
               'engine_sha256': lock['executable_sha256'], 'engine_version': '0.0.1', 'config': tunnel_config()}
    file = tmp_path / 'profile.json'
    file.write_text(json.dumps(profile))
    paths = types.SimpleNamespace(home=tmp_path / 'home', state=tmp_path / 'state', local=tmp_path / 'local')
    paths.home.mkdir()
    return types.SimpleNamespace(paths=paths, file=file, data=data, lock=lock, profile=profile, tmp=tmp_path)


def guard_of(base):
    return backend_location.Guard(base, base / 'pythonw.exe', {'state': 'Ready', 'enabled': True, 'run_level': 'Limited'})


def test_runtime_config_has_exactly_the_shape_the_controller_checks():
    runtime = bi.build_runtime_config(tunnel_config(), secret='s' * 32)
    result = backend_location.check_proxy_config(runtime)
    assert result['passed'] and [o['tag'] for o in runtime['outbounds']] == ['snow-only']
    assert runtime['outbounds'][0]['server'] == EXIT_SERVER and runtime['route'] == {'final': 'snow-only'}


@pytest.mark.parametrize('changes', [{'server': '10.0.0.1'}, {'server': 'tunnel.example.org'}, {'type': 'trojan'},
                                     {'uuid': 'not-a-uuid'}])
def test_unsupported_tunnels_are_refused_before_anything_is_written(changes):
    with pytest.raises(SafetyError):
        bi.build_runtime_config(tunnel_config(**changes))


def test_engine_is_verified_and_extracted_with_its_neighbours(tmp_path):
    data, lock = synthetic_engine()
    exe = bi.acquire_engine(tmp_path / 'engine', lock, opener=opener_for(data))
    assert exe.name == 'sing-box.exe' and (exe.parent / 'libcronet.dll').is_file()
    assert not (tmp_path / ('download-' + lock['asset'])).exists()


def test_engine_with_a_wrong_hash_or_size_is_refused(tmp_path):
    data, lock = synthetic_engine()
    with pytest.raises(SafetyError):
        bi.acquire_engine(tmp_path / 'a', dict(lock, sha256='0' * 64), opener=opener_for(data))
    with pytest.raises(SafetyError):
        bi.acquire_engine(tmp_path / 'b', dict(lock, executable_sha256='0' * 64), opener=opener_for(data))
    with pytest.raises(SafetyError):
        bi.acquire_engine(tmp_path / 'c', dict(lock, bytes=len(data) - 1), opener=opener_for(data))


def test_archive_paths_that_escape_are_refused(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as bundle:
        bundle.writestr('../evil/sing-box.exe', b'x')
    data = buffer.getvalue()
    lock = {'asset': 'x.zip', 'url': 'https://example.invalid/engine.zip', 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'executable_sha256': '0' * 64}
    with pytest.raises(SafetyError):
        bi.acquire_engine(tmp_path / 'e', lock, opener=opener_for(data))


def test_a_local_archive_is_used_without_any_download(tmp_path):
    data, lock = synthetic_engine()
    local = tmp_path / 'engine.zip'
    local.write_bytes(data)
    never = lambda *a, **k: pytest.fail('no download expected')
    assert bi.acquire_engine(tmp_path / 'engine', lock, archive=local, opener=never).is_file() and local.exists()


def test_prepared_files_pass_the_controllers_own_static_check(setup):
    base, worker = bi.prepare(setup.paths, setup.file, opener=opener_for(setup.data))
    meta = json.loads((base / 'profile.json').read_text())
    assert meta['plaintext_config_written'] is False and meta['proxy_url'] == 'http://127.0.0.1:25080'
    assert backend_location.check_engine_and_config(guard_of(base))['passed'] is True
    text = worker.read_text('utf-8')
    assert bi.PLACEHOLDER not in text and str(bi.ROOT / 'src') in text
    compile(text, 'proxy_worker.py', 'exec')
    assert EXIT_SERVER not in (base / 'profile.json').read_text() and UUID.encode() not in (base / 'snow-config.dpapi').read_bytes()


def test_a_profile_naming_another_engine_is_refused(setup):
    profile = dict(setup.profile, engine_sha256='f' * 64)
    setup.file.write_text(json.dumps(profile))
    with pytest.raises(SafetyError):
        bi.prepare(setup.paths, setup.file, opener=opener_for(setup.data))
    assert not (bi.base_directory(setup.paths) / 'snow-config.dpapi').exists()


class Windows:
    def __init__(self, task=False, fail=()):
        self.task, self.fail, self.scripts = task, fail, []

    def __call__(self, command, **kwargs):
        script = command[-1]
        self.scripts.append(script)
        for word in self.fail:
            if word in script:
                return subprocess.CompletedProcess(command, 1, '', 'refused by test')
        if 'Get-ScheduledTask' in script and 'Register-ScheduledTask' not in script:
            return subprocess.CompletedProcess(command, 0, 'yes' if self.task else '', '')
        if 'Register-ScheduledTask' in script:
            self.task = True
        if 'Unregister-ScheduledTask' in script:
            self.task = False
        return subprocess.CompletedProcess(command, 0, '', '')


def run_install(setup, windows, monkeypatch, *, worker_state='running', measured=None, busy=()):
    pythonw = setup.tmp / 'pythonw.exe'
    pythonw.write_bytes(b'x')
    monkeypatch.setattr(backend_location, 'locate_guard', lambda: guard_of(bi.base_directory(setup.paths)))
    return bi.install(setup.paths, setup.file, runner=windows, opener=opener_for(setup.data), pythonw=pythonw,
                      port_busy=lambda port: port in busy,
                      measure=lambda proxy: measured or {'status': 'measured', 'exit_ip': '203.0.113.9', 'address_family': 4},
                      wait=lambda base: {'state': worker_state, 'error_type': 'RuntimeError'})


def test_install_registers_a_limited_task_and_never_reports_the_exit_address(setup, monkeypatch):
    windows = Windows()
    result = run_install(setup, windows, monkeypatch)
    assert result['status'] == 'installed' and result['static_check'] and result['exit_measured']
    assert result['elevation_used'] is False and result['firewall_changed'] is False and result['clients_changed'] is False
    assert '203.0.113.9' not in json.dumps(result) and EXIT_SERVER not in json.dumps(result)
    register = next(s for s in windows.scripts if 'Register-ScheduledTask' in s)
    assert '-RunLevel Limited' in register and 'AtLogOn' in register and 'no overwrite' in register
    assert not any(w in ' '.join(windows.scripts) for w in ('New-NetFirewall', 'netsh', 'Set-DnsClient', 'HKLM'))


@pytest.mark.parametrize('windows, busy, reason', [
    (Windows(task=True), (), 'task_exists'),
    (Windows(), (25080,), 'port_25080_in_use'),
    (Windows(), (25081,), 'port_25081_in_use'),
])
def test_install_refuses_to_disturb_an_existing_backend_and_writes_nothing(setup, monkeypatch, windows, busy, reason):
    result = run_install(setup, windows, monkeypatch, busy=busy)
    assert result['status'] == 'not_started' and any(r.startswith(reason) for r in result['reasons'])
    assert not bi.base_directory(setup.paths).exists()
    assert not any('Register-ScheduledTask' in s for s in windows.scripts)


def test_install_refuses_a_non_empty_target_directory(setup, monkeypatch):
    base = bi.base_directory(setup.paths)
    base.mkdir(parents=True)
    (base / 'keep.txt').write_text('mine')
    result = run_install(setup, Windows(), monkeypatch)
    assert result['status'] == 'not_started' and any(r.startswith('directory_not_empty') for r in result['reasons'])
    assert (base / 'keep.txt').read_text() == 'mine'


def test_a_worker_that_fails_is_reported_with_its_error_type_only(setup, monkeypatch):
    result = run_install(setup, Windows(), monkeypatch, worker_state='failed')
    assert result['status'] == 'failed' and 'RuntimeError' in result['error'] and UUID not in json.dumps(result)


def test_unmeasured_exit_leaves_the_install_flagged(setup, monkeypatch):
    result = run_install(setup, Windows(), monkeypatch, measured={'status': 'measurement_failed'})
    assert result['status'] == 'installed_needs_attention' and result['exit_measured'] is False


def test_remove_deletes_what_was_installed_and_stops_the_task(setup, monkeypatch):
    windows = Windows()
    run_install(setup, windows, monkeypatch)
    base = bi.base_directory(setup.paths)
    (base / 'worker-status.json').write_text(json.dumps({'state': 'stopped', 'instance': 'a' * 32}))
    result = bi.remove(setup.paths, runner=windows, port_busy=lambda port: False, sleep=lambda s: None)
    assert result['status'] == 'removed' and not base.exists() and windows.task is False


def test_remove_refuses_while_the_relay_is_listening(setup, monkeypatch):
    windows = Windows()
    run_install(setup, windows, monkeypatch)
    result = bi.remove(setup.paths, runner=windows, port_busy=lambda port: port == 25082, sleep=lambda s: None)
    assert result['status'] == 'failed' and 'controller' in result['error'] and bi.base_directory(setup.paths).exists()


def test_remove_leaves_foreign_files_alone(setup, monkeypatch):
    windows = Windows()
    run_install(setup, windows, monkeypatch)
    base = bi.base_directory(setup.paths)
    (base / 'foreign.txt').write_text('keep')
    result = bi.remove(setup.paths, runner=windows, port_busy=lambda port: False, sleep=lambda s: None)
    assert result['status'] == 'removed_with_leftovers' and (base / 'foreign.txt').read_text() == 'keep'


def test_backend_nested_install_and_remove_hold_outer_claim(setup, monkeypatch):
    from claude_reset.elevation import request as uac
    windows = Windows()

    @claims.serialized('test-l1-chain', completed={'done'})
    def chain(paths):
        claim = claims.pending_path(paths).read_bytes()
        assert run_install(setup, windows, monkeypatch)['status'] == 'installed'
        assert claims.pending_path(paths).read_bytes() == claim
        assert bi.remove(paths, runner=windows, port_busy=lambda port: False)['status'] == 'removed'
        assert claims.pending_path(paths).read_bytes() == claim
        return {'status': 'done'}

    assert chain(setup.paths)['status'] == 'done'
    assert not claims.blocked(setup.paths)
