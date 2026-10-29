import json
import threading
import urllib.request
import urllib.error
from pathlib import Path
import pytest
from test_reset import paths, platform, FakeCrypto, apply, plan_for
from claude_reset.browser_probe import browser_measurement, validate_measurement
from claude_reset.services import launch_clean_chrome
from claude_reset.services import managed_chrome_profiles
from claude_reset.safeio import SafetyError
from claude_reset.core import build_plan
from claude_reset.windows import ps_json


def test_browser_measurement_loopback_only():
    expected = {'timezone':'Europe/Istanbul','offset_minutes':180,'languages':['en-US','ru'],'geolocation':'denied'}
    def launch(url):
        from urllib.parse import urlsplit
        origin = 'http://' + urlsplit(url).netloc
        with urllib.request.urlopen(url, timeout=2) as response:
            assert 'navigator.languages' in response.read().decode()
        request = urllib.request.Request(url, data=json.dumps(expected).encode(),
                  headers={'Content-Type':'application/json', 'Origin':origin, 'Accept-Language':'en-US,en;q=0.9,ru;q=0.8'})
        with urllib.request.urlopen(request, timeout=2) as response:
            assert json.load(response)['offset_minutes'] == 180
    result = browser_measurement(launch, timeout=2)
    assert result['timezone'] == 'Europe/Istanbul'
    assert result['accept_language'] == 'en-US,en;q=0.9,ru;q=0.8'
    assert result['network_verified'] is False


@pytest.mark.parametrize('body', [b'{}', b'x'*4096])
def test_browser_measurement_rejects_untrusted_origin(body):
    def launch(url):
        request = urllib.request.Request(url, data=body, headers={'Content-Type':'application/json', 'Origin':'https://untrusted.test'})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 400
    with pytest.raises(SafetyError, match='timed out'):
        browser_measurement(launch, timeout=0.05)


def test_browser_measurement_rejects_unexpected_content():
    obj = {'timezone':'Europe/Istanbul','offset_minutes':180,'languages':['en'],'geolocation':'prompt','token':'secret'}
    with pytest.raises(SafetyError):
        validate_measurement(obj, 'en')


@pytest.mark.parametrize('url', ['https://claude.ai.evil.test/', 'file:///C:/data', 'https://claude.ai@evil.test/', 'https://claude.ai:444/', 'javascript:alert(1)', 'http://claude.ai/', 'https://claude.ai\n--bad'])
def test_oauth_link_cannot_escape_allowlist(paths, url):
    p = plan_for(paths, ('chrome',))
    apply(paths, p)
    with pytest.raises(SafetyError):
        launch_clean_chrome(paths, p.id, url)


@pytest.mark.parametrize('url,loopback', [('https://claude.com/cai/oauth/authorize?state=TEST_ONLY', False),
                                        ('http://127.0.0.1:12345/fixture', True)])
def test_legacy_managed_profile_cannot_bypass_windows_gate(paths, monkeypatch, url, loopback):
    p = plan_for(paths, ('chrome',))
    apply(paths, p)
    monkeypatch.setattr('subprocess.Popen', lambda *a, **kw: pytest.fail('Browser must not start outside isolation'))
    with pytest.raises(SafetyError, match='без сетевой защиты отключён') as error:
        launch_clean_chrome(paths, p.id, url, loopback_probe=loopback)
    assert 'TEST_ONLY' not in str(error.value)


@pytest.mark.parametrize('kind', ['sessions', 'code_tokens', 'help'])
def test_server_links_do_not_start_shared_browser(monkeypatch, kind):
    from claude_reset.services import open_server_page
    monkeypatch.setattr('webbrowser.open', lambda *a, **kw: pytest.fail('Shared browser bypass'))
    with pytest.raises(SafetyError, match='общий браузер отключено'):
        open_server_page(kind)


def test_managed_profile_discovery_requires_valid_owned_marker(paths):
    assert managed_chrome_profiles(paths) == []
    p = plan_for(paths, ('chrome',))
    apply(paths, p)
    root = paths.state / 'ChromeProfiles'
    (root / 'unmanaged').mkdir()
    assert managed_chrome_profiles(paths) == [p.id]
    marker = root / p.id / 'claude-reset-profile.json'
    marker.write_text(json.dumps({'created_by':'ClaudeReset','run':'0' * 32}))
    with pytest.raises(SafetyError, match='marker'):
        managed_chrome_profiles(paths)
    marker.write_text('{broken')
    with pytest.raises(SafetyError, match='marker'):
        managed_chrome_profiles(paths)


def test_open_chrome_single_profile_and_ambiguous_selection(paths, monkeypatch):
    from claude_reset.app import App
    from types import SimpleNamespace
    first = plan_for(paths, ('chrome',))
    apply(paths, first)
    launched = []
    monkeypatch.setattr('claude_reset.app.launch_clean_chrome', lambda p, r: launched.append(r))
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **kw: pytest.fail('Single profile needs no picker'))
    app = SimpleNamespace(paths=paths, last_run=None, safe=lambda fn: fn())
    App.open_chrome(app)
    assert launched == [first.id]
    second = plan_for(paths, ('chrome',))
    apply(paths, second)
    app.last_run = None
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **kw: '')
    App.open_chrome(app)
    assert app.last_run is None and launched == [first.id]


def test_windows_inspection_timeout_is_sanitized(monkeypatch):
    import subprocess
    def fail(*args, **kw):
        raise subprocess.TimeoutExpired('SECRET_COMMAND', 55)
    monkeypatch.setattr('claude_reset.windows.subprocess.run', fail)
    with pytest.raises(SafetyError) as error:
        ps_json('fixture')
    assert 'SECRET_COMMAND' not in str(error.value)


def test_unknown_version_never_silently_allows_desktop_reset(paths):
    root = paths.local / 'Claude-Data/test'
    root.mkdir(parents=True)
    (root / 'config.json').write_text('{}')
    state = platform()
    state['desktop_versions'] = ['99.0.0']
    assert build_plan(paths, ('desktop',), platform_state=state, env={}).blockers
