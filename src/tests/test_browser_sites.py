import json
import sqlite3
from types import SimpleNamespace

import pytest
from dialog_fakes import script
from scripted import Strict
from test_reset import paths

from claude_reset.model.confirmation import Confirmation
from claude_reset.reset import browser_sites as sites
from claude_reset.safeio import SafetyError
from claude_reset.ui import expert_window as app
from claude_reset.ui.expert.cleanup import CleanupTab


@pytest.fixture
def browser(paths):
    profile = paths.local / sites.ROOTS['Chrome'] / 'Default'
    database = profile / 'Network/Cookies'
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE cookies(host_key TEXT, value TEXT)')
        db.executemany('INSERT INTO cookies VALUES (?, ?)', [(host, 'secret-password 192.0.2.9 private-user') for host in
                       ('claude.ai', '.claude.ai', 'www.claude.ai', 'notclaude.ai', 'claude.ai.other', 'example.com')])
    for name in (*sites.ORIGIN_DIRS, 'IndexedDB/https_example.com_0.indexeddb.leveldb'):
        folder = profile / name
        folder.mkdir(parents=True)
        (folder / 'data').write_bytes(b'private-user')
    (profile / 'Preferences').write_bytes(b'unchanged')
    return profile, database


def test_preview_and_clear_preserve_other_sites_and_profile(paths, browser):
    profile, database = browser
    before = sites.site_data(paths, inspect=lambda: False)
    assert before['profiles'][0]['cookies_found'] == 3
    assert before['profiles'][0]['cookies_removed'] == 0
    after = sites.site_data(paths, erase=True, confirmation=Confirmation.ERASE, inspect=lambda: False)
    assert after['profiles'][0]['cookies_removed'] == 3
    assert not after['all_site_data_verified_absent']
    with sqlite3.connect(database) as db:
        assert [row[0] for row in db.execute('SELECT host_key FROM cookies')] == ['notclaude.ai', 'claude.ai.other', 'example.com']
    assert (profile / 'Preferences').read_bytes() == b'unchanged'
    assert (profile / 'IndexedDB/https_example.com_0.indexeddb.leveldb/data').exists()
    assert not any((profile / name).exists() for name in sites.ORIGIN_DIRS)
    public = json.dumps([before, after, sites.external_scope_report()])
    assert all(secret not in public for secret in ('private-user', 'secret-password', '192.0.2.9', str(profile)))


@pytest.mark.parametrize('running,word', [(True, Confirmation.ERASE), (False, None), (False, 'СТЕРЕТЬ'), (False, 'erase')])
def test_refusal_before_mutation(paths, browser, running, word):
    profile, database = browser
    original = database.read_bytes()
    with pytest.raises(SafetyError):
        sites.site_data(paths, erase=True, confirmation=word, inspect=lambda: running)
    assert database.read_bytes() == original
    assert all((profile / name).exists() for name in sites.ORIGIN_DIRS)


def test_bad_schema_error_contains_no_path(paths, browser):
    profile, database = browser
    with sqlite3.connect(database) as db:
        db.execute('DROP TABLE cookies')
    with pytest.raises(SafetyError) as caught:
        sites.site_data(paths, erase=True, confirmation=Confirmation.ERASE, inspect=lambda: False)
    assert str(profile) not in str(caught.value)
    assert all((profile / name).exists() for name in sites.ORIGIN_DIRS)


def test_edge_and_external_scope(paths):
    (paths.local / sites.ROOTS['Edge'] / 'Profile 2').mkdir(parents=True)
    result = sites.site_data(paths, inspect=lambda: False)
    assert result['profiles'][0]['browser'] == 'Edge'
    external = sites.external_scope_report()
    assert not external['changed'] and len(external['areas']) == 5
    assert all(row['status'] == 'not_inspected' for row in external['areas'])


def test_gui_dispatch_and_cancel():
    ui = app.App.__new__(app.App)
    ui.paths, ui.operation = object(), None
    ui.worker = SimpleNamespace(busy=False)
    received, calls = [], []
    ui.show_json = received.append
    ui.run = lambda work, callback: callback(work())
    ui.browser_sites = Strict(site_data=lambda paths, **kw: calls.append(kw) or {'ok': True})
    tab = CleanupTab(ui)
    tab.preview_browser_sites()
    script(ui, askstring=None)
    tab.clear_browser_sites()
    assert calls == [{}]
    script(ui, askstring='СТЕРЕТЬ')
    tab.clear_browser_sites()
    assert calls[-1] == {'erase': True, 'confirmation': Confirmation.ERASE}
    tab.report_external_scope()
    assert received[-1]['mode'] == 'report_only'


@pytest.mark.parametrize('browser', ['Chrome', 'Edge'])
def test_manual_settings_target_and_preservation(paths, browser):
    profile = paths.local / sites.ROOTS[browser] / 'Profile 2'
    profile.mkdir(parents=True)
    for relative in ('Local Storage/leveldb/data', 'Session Storage/data',
                     'Service Worker/Database/data', 'Cache/data', 'Preferences'):
        target = profile / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'secret-password private-user 192.0.2.9')
    before = {p.relative_to(profile): p.read_bytes() for p in profile.rglob('*') if p.is_file()}
    relative = ('Google/Chrome/Application/chrome.exe' if browser == 'Chrome'
                else 'Microsoft/Edge/Application/msedge.exe')
    executable = paths.local / relative
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b'fixture never executed')
    calls = []
    rows = sites.manual_cleanup_profiles(paths)
    assert rows == [{'browser': browser, 'profile_number': 1}]
    result = sites.open_site_settings(paths, 1, environ={}, launch=lambda *a, **kw: calls.append((a, kw)))
    argv = calls[0][0][0]
    assert argv[:2] == [str(executable), '--profile-directory=Profile 2']
    assert argv[2] == ('chrome' if browser == 'Chrome' else 'edge') + '://settings/'
    assert calls[0][1] == {}  # only the argument list: windows.process.start_quietly runs it without a shell
    assert not result['all_site_data_verified_absent'] and result['status'] == 'manual_action_required'
    assert before == {p.relative_to(profile): p.read_bytes() for p in profile.rglob('*') if p.is_file()}
    public = json.dumps([rows, result])
    assert all(secret not in public for secret in ('secret-password', 'private-user', '192.0.2.9', str(profile)))
    def fail(*a, **kw):
        raise OSError('secret-password private-user 192.0.2.9')
    with pytest.raises(SafetyError) as error:
        sites.open_site_settings(paths, 1, environ={}, launch=fail)
    assert 'private-user' not in str(error.value)


def test_manual_settings_refusals(paths, browser):
    calls = []
    for number in (0, 2, True, '1'):
        with pytest.raises(SafetyError):
            sites.open_site_settings(paths, number, environ={}, launch=lambda *a, **kw: calls.append(a))
    with pytest.raises(SafetyError, match='not found'):
        sites.open_site_settings(paths, 1, environ={}, launch=lambda *a, **kw: calls.append(a))
    assert calls == []


def test_manual_settings_gui_selection_cancel_and_empty():
    ui = app.App.__new__(app.App)
    ui.paths, ui.operation = object(), None
    ui.worker = SimpleNamespace(busy=False)
    calls, reports = [], []
    ui.run = lambda work, callback: callback(work())
    ui.show_json = reports.append
    ui.browser_sites = Strict(manual_cleanup_profiles=[{'browser': 'Edge', 'profile_number': 1}],
                              open_site_settings=lambda paths, number: calls.append(number) or {'status': 'manual_action_required'})
    tab = CleanupTab(ui)
    script(ui, askinteger=None)
    tab.browser_site_settings()
    assert calls == []
    script(ui, askinteger=1)
    tab.browser_site_settings()
    assert calls == [1] and reports[-1]['status'] == 'manual_action_required'
    ui.browser_sites.answers['manual_cleanup_profiles'] = []
    tab.browser_site_settings()
    assert calls == [1]
