import base64
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import pytest
from claude_reset.layout import Paths
from claude_reset.reset.planner import build_plan
from claude_reset.reset.execution import Executor, recover_memory
from claude_reset.reset.core import snapshot_memory, restore_memory, validate_memory_bundle
from claude_reset.safeio import SafetyError, guarded, remove_owned, fingerprint
from claude_reset.reset.new_account import network_probe, launch_clean_chrome
from claude_reset.windows.system import DPAPI, set_istanbul_same_offset
from claude_reset.windows.system import DPAPI


# The tests encrypt with the program's own current-user DPAPI, so code that builds its own crypto reads what
# the tests wrote; doubles that fail on purpose subclass it.
FakeCrypto = DPAPI


def platform():
    return {'processes': [], 'environment_presence': {}, 'packages': [],
            'cli_version': '2.1.274.0', 'extension_versions': ['2.1.308'],
            'timezone': {'id': 'Russian Standard Time', 'offset_minutes': 180,
                         'candidate': 'Turkey Standard Time', 'candidate_offset_minutes': 180}}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding='utf-8')


def database(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('create table ItemTable(key text primary key,value blob)')
        db.execute('insert into ItemTable values (?,?)', ('Anthropic.claude-code', 'OLD_ACCOUNT_TOKEN'))
        db.execute('insert into ItemTable values (?,?)', ('other.extension', 'KEEP_ME'))
        db.execute('insert into ItemTable values (?,?)', ('history.recentlyOpenedPathsList', 'KEEP_PATH_HISTORY'))


@pytest.fixture
def paths(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith(('CLAUDE', 'ANTHROPIC')):
            monkeypatch.delenv(key, raising=False)
    home = tmp_path / "Пользователь O'Brien with spaces"
    roaming, local = home / 'AppData/Roaming', home / 'AppData/Local'
    roaming.mkdir(parents=True)
    local.mkdir(parents=True)
    return Paths(home, roaming, local, local / 'ClaudeReset')


@pytest.fixture
def populated(paths):
    write(paths.home / '.claude/.credentials.json', '{"token":"NEVER_LOG_THIS"}')
    write(paths.home / '.claude/settings.json', '{"hooks":{"test":"old hook"}}')
    write(paths.home / '.claude/history.jsonl', 'OLD_HISTORY')
    write(paths.home / '.claude/projects/project-one/memory/MEMORY.md', 'Preserved memory. Europe/Moscow')
    write(paths.home / '.claude/agent-memory/reviewer/MEMORY.md', 'Reviewer notes')
    write(paths.home / '.claude/CLAUDE.md', 'User instructions')
    write(paths.home / '.claude.json', '{"oauthAccount":"old account"}')
    write(paths.home / '.claude.json.backup', '{"oauthAccount":"old account"}')
    write(paths.home / 'Documents/user-project/main.py', 'DO NOT DELETE')
    write(paths.roaming / 'Code/User/settings.json', '{"editor.fontSize":16}')
    database(paths.roaming / 'Code/User/globalStorage/state.vscdb')
    database(paths.roaming / 'Code/User/workspaceStorage/example/state.vscdb')
    write(paths.roaming / 'Code/User/globalStorage/anthropic.claude-code/state.json', '{}')
    write(paths.local / 'Google/Chrome/User Data/Default/Preferences', '{"keep":"existing profile"}')
    return paths


def plan_for(paths, components=('code', 'vscode', 'chrome')):
    return build_plan(paths, components, platform_state=platform(), env={})


def apply(paths, plan):
    return Executor(paths, FakeCrypto(), platform).apply(plan, consent_id=plan.id, server_step_complete=True)


def test_audit_is_read_only(populated):
    before = fingerprint(populated.home, populated.home)
    plan = plan_for(populated)
    assert not plan.blockers
    assert plan.memory_count == 3
    assert fingerprint(populated.home, populated.home) == before
    assert not populated.state.exists()


def test_report_never_leaks_tokens_paths_or_memory(populated):
    data = json.dumps(plan_for(populated).redacted())
    for secret in ('NEVER_LOG_THIS', 'OLD_ACCOUNT_TOKEN', "O'Brien", 'Reviewer notes', 'Europe/Moscow'):
        assert secret not in data


def test_end_to_end_local_reset_preserves_memory_and_unrelated_data(populated):
    plan = plan_for(populated)
    result = apply(populated, plan)
    config = populated.home / '.claude'
    assert not (config / '.credentials.json').exists()
    assert not (config / 'history.jsonl').exists()
    assert not (populated.home / '.claude.json').exists()
    assert not (populated.home / '.claude.json.backup').exists()
    assert (config / 'projects/project-one/memory/MEMORY.md').read_text() == 'Preserved memory. Europe/Moscow'
    assert (config / 'CLAUDE.md').read_text() == 'User instructions'
    assert (populated.home / 'Documents/user-project/main.py').read_text() == 'DO NOT DELETE'
    assert (populated.local / 'Google/Chrome/User Data/Default/Preferences').exists()
    assert (populated.state / 'ChromeProfiles' / plan.id).is_dir()
    settings = json.loads((populated.roaming / 'Code/User/settings.json').read_text())
    assert settings == {'editor.fontSize': 16, 'telemetry.telemetryLevel': 'off'}
    assert 'DISABLE_TELEMETRY' not in json.loads((config / 'settings.json').read_text())['env']
    for p in (populated.roaming / 'Code/User').rglob('state.vscdb'):
        with sqlite3.connect(p) as db:
            rows = dict(db.execute('select key,value from ItemTable'))
            assert 'Anthropic.claude-code' not in rows
            assert rows['other.extension'] == 'KEEP_ME'
            assert rows['history.recentlyOpenedPathsList'] == 'KEEP_PATH_HISTORY'
            assert db.execute('pragma integrity_check').fetchone()[0] == 'ok'
    assert result['full_reset'] is False
    assert result['ready_for_new_account'] is False
    assert result['server'] == 'user_reported_complete_not_independently_verified'


def test_exact_consent_required(populated):
    p = plan_for(populated)
    with pytest.raises(SafetyError):
        Executor(populated, FakeCrypto(), platform).apply(p, consent_id='not-the-plan', server_step_complete=True)
    assert (populated.home / '.claude/.credentials.json').exists()


def test_server_step_precedes_local_deletion(populated):
    p = plan_for(populated)
    with pytest.raises(SafetyError, match='server'):
        Executor(populated, FakeCrypto(), platform).apply(p, consent_id=p.id)
    assert not populated.state.exists()


def test_changed_files_invalidate_plan(populated):
    p = plan_for(populated)
    write(populated.home / '.claude/new-session.json', 'new work')
    with pytest.raises(SafetyError):
        apply(populated, p)
    assert (populated.home / '.claude/.credentials.json').exists()


def test_new_auth_source_in_environment_blocks_apply(populated, monkeypatch):
    p = plan_for(populated)
    monkeypatch.setenv('CLAUDE_CODE_OAUTH_TOKEN', 'SECRET')
    with pytest.raises(SafetyError):
        apply(populated, p)
    assert (populated.home / '.claude/.credentials.json').exists()


def test_running_process_blocks_apply(populated):
    p = plan_for(populated)
    def active():
        s = platform()
        s['processes'] = [{'kind': 'Code.exe', 'pid': 42}]
        return s
    with pytest.raises(SafetyError):
        Executor(populated, FakeCrypto(), active).apply(p, consent_id=p.id, server_step_complete=True)
    assert not populated.state.exists()


def test_crypto_failure_before_data_deletion(populated):
    class Broken(FakeCrypto):
        def encrypt(self, data):
            raise RuntimeError('do not log user values')
    p = plan_for(populated)
    with pytest.raises(SafetyError):
        Executor(populated, Broken(), platform).apply(p, consent_id=p.id, server_step_complete=True)
    assert (populated.home / '.claude/.credentials.json').exists()
    report = json.loads((populated.state / 'runs' / p.id / 'result.json').read_text())
    assert report['status'] == 'failed_or_partial'
    assert 'do not log' not in json.dumps(report)


def test_corrupt_memory_archive_blocks_before_deletion(populated):
    class Broken(FakeCrypto):
        def decrypt(self, data):
            return b'{"schema":1,"files":[]}'
    p = plan_for(populated)
    with pytest.raises(SafetyError):
        Executor(populated, Broken(), platform).apply(p, consent_id=p.id, server_step_complete=True)
    assert (populated.home / '.claude/.credentials.json').exists()


def test_memory_recovery_exports_without_overwriting_active_profile(populated):
    p = plan_for(populated)
    apply(populated, p)
    active = populated.home / '.claude/CLAUDE.md'
    active.write_text('NEW MEMORY')
    export = recover_memory(populated, p.id, FakeCrypto())
    assert (export / 'CLAUDE.md').read_text() == 'User instructions'
    assert active.read_text() == 'NEW MEMORY'


@pytest.mark.parametrize('name', ['../escape.md', '/absolute.md', 'C:/escape.md', 'projects/x/../../escape.md', 'folder\\file.md', 'settings.json'])
def test_memory_archive_rejects_path_injection(paths, name):
    import hashlib
    bundle = {'schema': 1, 'files': [{'path': name, 'data': base64.b64encode(b'a').decode(), 'sha256': hashlib.sha256(b'a').hexdigest()}]}
    with pytest.raises(SafetyError):
        restore_memory(bundle, paths.home / '.claude')


def test_memory_archive_rejects_duplicates(populated):
    bundle, _ = snapshot_memory(populated.home / '.claude')
    bundle['files'].append(bundle['files'][0])
    with pytest.raises(SafetyError):
        validate_memory_bundle(bundle)


def test_never_delete_root(paths):
    with pytest.raises(SafetyError):
        remove_owned(paths.home, paths.home)


def test_never_delete_outside_root(paths):
    outside = paths.home.parent / 'outside.txt'
    outside.write_text('KEEP')
    with pytest.raises(SafetyError):
        remove_owned(outside, paths.home)
    assert outside.read_text() == 'KEEP'


def test_symlink_cannot_escape(paths):
    outside = paths.home.parent / 'outside'
    outside.mkdir()
    write(outside / 'keep.md', 'KEEP')
    link = paths.home / '.claude'
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Symbolic link privilege not available')
    with pytest.raises(SafetyError):
        remove_owned(link, paths.home)
    assert (outside / 'keep.md').read_text() == 'KEEP'


@pytest.mark.skipif(os.name != 'nt', reason='Windows junction')
def test_windows_junction_is_rejected(paths):
    from claude_reset.windows.system import ps_json
    outside = paths.home.parent / 'junction-target'
    outside.mkdir()
    write(outside / 'keep.txt', 'KEEP')
    link = paths.home / 'junction'
    def ps_path(p):
        encoded = base64.b64encode(str(p).encode('utf-8')).decode()
        return "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "')))"
    script = '$null=New-Item -ItemType Junction -Path ' + ps_path(link) + ' -Target ' + ps_path(outside) + '; @{ok=$true}|ConvertTo-Json'
    assert ps_json(script)['ok']
    with pytest.raises(SafetyError):
        remove_owned(link, paths.home)
    assert (outside / 'keep.txt').read_text() == 'KEEP'
    # rmdir removes the junction entry only; target was asserted intact.
    os.rmdir(link)


def test_gui_can_render_fixture_plan_without_scanning_live_data(paths, tk_root):
    import tkinter as tk
    from claude_reset.ui.expert_window import App
    root = tk.Toplevel(tk_root)  # the run's one Tk interpreter (see conftest.py)
    root.withdraw()
    try:
        app = App(root=root, paths=paths)
        p = plan_for(paths, ('chrome',))
        app.show_plan(p)
        root.update_idletasks()
        assert root.state() == 'withdrawn'
        assert 'ПЛАН ЛОКАЛЬНЫХ ОПЕРАЦИЙ' in app.text.get('1.0', 'end')
        from tkinter.scrolledtext import ScrolledText
        result = {'observations': ['not_verified'] * 1000}
        window = app.show_json(result)
        root.update_idletasks()
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        text = next(w for w in descendants(window) if isinstance(w, ScrolledText))
        assert str(text.cget('state')) == 'disabled'
        assert json.loads(text.get('1.0', 'end')) == result
        assert window.winfo_reqheight() < root.winfo_screenheight()
        assert not paths.state.exists()
    finally:
        root.destroy()


def test_unknown_component_is_not_silently_accepted(paths):
    p = plan_for(paths, ('desktop',))
    assert p.blockers
    assert not p.actions


def test_unknown_versions_block_mutations(populated):
    state = platform()
    state['cli_version'] = '9.9.9'
    state['extension_versions'] = ['9.9.9']
    p = build_plan(populated, platform_state=state, env={})
    assert len([x for x in p.blockers if 'version' in x]) == 2


def test_alternative_auth_and_custom_roots_block(paths):
    p = build_plan(paths, platform_state=platform(), env={'ANTHROPIC_API_KEY': 'SENSITIVE_AUTH_VALUE_9714', 'CLAUDE_CONFIG_DIR': '/elsewhere'})
    assert len(p.blockers) >= 2
    assert 'SENSITIVE_AUTH_VALUE_9714' not in json.dumps(p.redacted())


def test_account_manager_archives_are_not_treated_as_active_restorers(paths):
    (paths.local / '0-code/accounts').mkdir(parents=True)
    assert not any('plan.account_manager' in x for x in plan_for(paths).blockers)
    state = platform()
    state['account_manager_active'] = True
    assert any('plan.account_manager' in x for x in build_plan(paths, platform_state=state, env={}).blockers)


def test_unparseable_vscode_settings_are_not_overwritten(paths):
    write(paths.roaming / 'Code/User/settings.json', '// JSONC\n{"font": 12,,}')
    p = plan_for(paths, ('vscode',))
    assert p.blockers


def test_unknown_database_schema_blocks(paths):
    p = paths.roaming / 'Code/User/globalStorage/state.vscdb'
    p.parent.mkdir(parents=True)
    with sqlite3.connect(p) as db:
        db.execute('create table Unexpected(x text)')
    assert plan_for(paths, ('vscode',)).blockers


def test_secretstorage_requires_explicit_adapter(paths):
    p = paths.roaming / 'Code/User/globalStorage/state.vscdb'
    database(p)
    with sqlite3.connect(p) as db:
        db.execute('insert into ItemTable values (?,?)', ('secret://Anthropic.claude-code', 'secret'))
    assert any('plan.secret_storage_entry' in x for x in plan_for(paths, ('vscode',)).blockers)


def test_tampered_action_target_is_rejected(populated):
    p = plan_for(populated)
    p.actions[0].target = str(populated.home / 'Documents')
    with pytest.raises(SafetyError):
        apply(populated, p)
    assert (populated.home / 'Documents/user-project/main.py').exists()


def test_tampered_chrome_target_is_rejected(paths):
    p = plan_for(paths, ('chrome',))
    p.actions[0].target = str(paths.home / 'Documents')
    with pytest.raises(SafetyError):
        apply(paths, p)


def test_second_plan_keeps_memory_and_other_extensions(populated):
    apply(populated, plan_for(populated))
    p = plan_for(populated)
    assert not p.blockers
    assert p.memory_count == 3
    apply(populated, p)
    assert (populated.home / '.claude/CLAUDE.md').read_text() == 'User instructions'


@pytest.mark.skipif(os.name != 'nt', reason='Windows DPAPI')
def test_real_dpapi_round_trip():
    crypto = DPAPI()
    data = b'fixture-only memory; not user data'
    encrypted = crypto.encrypt(data)
    assert data not in encrypted
    assert crypto.decrypt(encrypted) == data
    with pytest.raises(SafetyError):
        crypto.decrypt(b'not a memory archive')


def test_timezone_rejects_offset_change():
    state = platform()
    state['timezone']['offset_minutes'] = 120
    with pytest.raises(SafetyError):
        set_istanbul_same_offset(inspect=lambda: state, run=lambda *a, **k: pytest.fail('Must not change timezone'))


def test_timezone_uses_only_tzutil_not_clock_change():
    states = [platform(), platform()]
    states[1]['timezone']['id'] = 'Turkey Standard Time'
    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)
    result = set_istanbul_same_offset(inspect=lambda: states.pop(0), run=fake_run)
    assert calls[0][1:] == ['/s', 'Turkey Standard Time']
    assert result['clock_adjusted'] is False


def test_network_probe_never_claims_full_tunnel():
    class Response(io.BytesIO):
        def __init__(self, url, ip):
            super().__init__(json.dumps({'ip': ip}).encode())
            self.url = url
        def geturl(self):
            return self.url
    class Opener:
        def open(self, request, **kwargs):
            return Response(request.full_url, '2001:db8::1' if 'api6.' in request.full_url else '203.0.113.4')
    result = network_probe(Opener())
    assert [x['status'] for x in result['observations']] == ['observed', 'observed']
    assert result['full_tunnel_verified'] is False
    assert result['router_modified'] is False


def test_network_failure_does_not_mean_safe():
    class Broken:
        def open(self, *args, **kwargs):
            raise OSError('offline')
    result = network_probe(Broken())
    assert result['full_tunnel_verified'] is False
    assert all(x['status'] == 'unavailable_or_error' for x in result['observations'])


def test_chrome_refuses_unmanaged_directory(paths):
    with pytest.raises(SafetyError):
        launch_clean_chrome(paths, '0' * 32)
