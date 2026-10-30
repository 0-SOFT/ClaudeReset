import dataclasses
import json
import sqlite3
from pathlib import Path

import pytest
from test_reset import FakeCrypto, apply, database, paths, platform, populated, write

from claude_reset.model import jsonc
from claude_reset.model.reset import Selection
from claude_reset.reset.execution import Executor, operation_lock, recover_memory
from claude_reset.reset.planner import build_plan
from claude_reset.reset.policy import policy_plan, save_policy
from claude_reset.reset.verification import save_evidence, summarize, template
from claude_reset.safeio import SafetyError, fingerprint, guarded


def plan(paths, components=('code', 'vscode', 'chrome'), selection=None, state=None, env=None):
    return build_plan(paths, components, selection=selection, platform_state=state or platform(), env=env or {})


@pytest.mark.parametrize('source', [
    '{/*comment*/"editor.fontSize":16,}',
    '{"url":"https://example.test/a/*b*/", "nested":[1,2,], // end\n}',
    '{"telemetry.telemetryLevel": /* preserve */ "all", "x":{"a":"\\\"//"},}',
    '{\n// leading comment\n}',
])
def test_jsonc_preserves_comments_and_semantics(paths, source):
    p = paths.home / 'settings.json'
    write(p, source)
    before = jsonc.loads(source)
    jsonc.set_property(p, paths.home, 'telemetry.telemetryLevel', 'off')
    result = p.read_text('utf-8')
    assert jsonc.loads(result) == {**before, 'telemetry.telemetryLevel': 'off'}
    for comment in ('/*comment*/', '// end', '/* preserve */', '// leading comment'):
        if comment in source:
            assert comment in result
    saved = result
    jsonc.set_property(p, paths.home, 'telemetry.telemetryLevel', 'off')
    assert p.read_text('utf-8') == saved


@pytest.mark.parametrize('source', ['{"a":1,"a":2}', '{"a":NaN}', '{/*unfinished', '{"a":1,,}', '[]', '{"nested":{"a":1,"a":2}}'])
def test_ambiguous_jsonc_is_rejected(source):
    with pytest.raises(SafetyError):
        jsonc.loads(source)


def test_named_vscode_profile_jsonc_and_backups(paths):
    root = paths.roaming / 'Code/User/profiles/synthetic'
    write(root / 'settings.json', '// comment\n{"editor.fontSize":13,}')
    database(root / 'globalStorage/state.vscdb')
    database(root / 'globalStorage/state.vscdb.backup')
    write(root / 'globalStorage/other.extension/data', 'KEEP')
    result = apply(paths, plan(paths, ('vscode',)))
    assert result['local_reset'] == 'completed_for_selected_operations'
    assert '// comment' in (root / 'settings.json').read_text()
    assert jsonc.read(root / 'settings.json', root)['editor.fontSize'] == 13
    assert (root / 'globalStorage/other.extension/data').read_text() == 'KEEP'
    for file in root.rglob('state.vscdb*'):
        with sqlite3.connect(file) as db:
            assert dict(db.execute('select key,value from ItemTable')) == {'other.extension':'KEEP_ME', 'history.recentlyOpenedPathsList':'KEEP_PATH_HISTORY'}


def test_unknown_custom_root_requires_selection(paths):
    custom = paths.home / 'CustomCode'
    write(custom / '.credentials.json', '{"token":"PRIVATE"}')
    p = plan(paths, ('code',), env={'CLAUDE_CONFIG_DIR': str(custom)})
    assert any('plan.custom_directory_unselected' in b for b in p.blockers)
    assert 'PRIVATE' not in json.dumps(p.redacted())


def test_custom_code_profile_roundtrip(paths, monkeypatch):
    custom = paths.home / 'CustomCode'
    write(custom / '.credentials.json', '{"token":"PRIVATE"}')
    write(custom / 'memory/MEMORY.md', 'exact\r\ntext')
    original = (custom / 'memory/MEMORY.md').read_bytes()
    monkeypatch.setenv('CLAUDE_CONFIG_DIR', str(custom))
    selection = Selection([str(custom)])
    p = build_plan(paths, ('code',), selection=selection, platform_state=platform())
    assert not p.blockers
    apply(paths, p)
    assert not (custom / '.credentials.json').exists()
    assert (custom / 'memory/MEMORY.md').read_bytes() == original
    assert not (paths.home / '.claude').exists()


def test_multiple_memories_recover_into_separate_roots(paths):
    custom = paths.home / 'other-code'
    write(custom / 'CLAUDE.md', 'second')
    write(paths.home / '.claude/CLAUDE.md', 'first')
    state = platform()
    state['custom_roots'] = [{'component':'code', 'path':str(custom)}]
    p = plan(paths, ('code',), Selection([str(custom), str(paths.home / '.claude')]), state)
    Executor(paths, FakeCrypto(), lambda: state).apply(p, consent_id=p.id, server_step_complete=True)
    exported = recover_memory(paths, p.id, FakeCrypto())
    assert (exported / 'profile-1/CLAUDE.md').read_text() == 'first'
    assert (exported / 'profile-2/CLAUDE.md').read_text() == 'second'


def test_custom_config_cannot_be_user_home(paths):
    p = plan(paths, ('code',), Selection([str(paths.home)]), env={'CLAUDE_CONFIG_DIR':str(paths.home)})
    assert p.blockers
    assert not any(a.target == str(paths.home) for a in p.actions)


def test_unknown_user_work_inside_config_blocks(paths):
    write(paths.home / '.claude/my-important-document.txt', 'KEEP')
    p = plan(paths, ('code',))
    assert any('plan.code_unknown_entries' in b for b in p.blockers)
    with pytest.raises(SafetyError):
        apply(paths, p)
    assert (paths.home / '.claude/my-important-document.txt').read_text() == 'KEEP'


def test_code_housekeeping_marker_can_be_reset_after_client_recreates_it(paths):
    root = paths.home / '.claude'
    write(root / 'memory/MEMORY.md', 'preserve exactly\n')
    memory_before = (root / 'memory/MEMORY.md').read_bytes()
    for timestamp in ('2026-10-23T00:00:00.000Z', '2026-10-24T00:00:00.000Z'):
        write(root / '.last-cleanup', timestamp)
        p = plan(paths, ('code',))
        assert not p.blockers
        apply(paths, p)
        assert not (root / '.last-cleanup').exists()
        assert (root / 'memory/MEMORY.md').read_bytes() == memory_before


def test_cleanup_marker_does_not_allow_similarly_named_user_work(paths):
    root = paths.home / '.claude'
    write(root / '.last-cleanup', '2026-10-23T00:00:00.000Z')
    write(root / '.last-cleanup-notes.md', 'KEEP')
    p = plan(paths, ('code',))
    assert any('plan.code_unknown_entries' in b for b in p.blockers)
    with pytest.raises(SafetyError):
        apply(paths, p)
    assert (root / '.last-cleanup-notes.md').read_text() == 'KEEP'


def test_project_hook_and_auth_block_without_leaking(paths):
    project = paths.home / 'Project'
    write(project / '.claude/settings.local.json', '{"env":{"ANTHROPIC_API_KEY":"SECRET123"},"hooks":{"x":"TOKEN_COPY_COMMAND"}}')
    before = fingerprint(project, project)
    p = plan(paths, ('code',), Selection(projects=[str(project)]))
    assert any('plan.project_auth' in b for b in p.blockers)
    assert 'SECRET123' not in json.dumps(p.redacted())
    assert 'TOKEN_COPY_COMMAND' not in json.dumps(p.redacted())
    assert fingerprint(project, project) == before


def test_remote_environments_are_explicitly_not_covered(paths):
    state = platform()
    state['remote_environments'] = ['wsl', 'ssh', 'docker']
    p = plan(paths, ('chrome',), state=state)
    assert {x['kind'] for x in p.redacted()['inventory']['environments']} == {'wsl','ssh','docker'}
    assert all(x['status'] == 'not_covered' for x in p.inventory.environments)


def test_unrelated_node_and_old_chrome_do_not_block_new_profile(paths):
    state = platform()
    state['processes'] = [{'kind':'unclassified-node'}, {'kind':'chrome.exe'}]
    p = plan(paths, ('chrome',), state=state)
    assert not p.blockers
    Executor(paths, FakeCrypto(), lambda: state).apply(p, consent_id=p.id, server_step_complete=True)


def test_active_restorer_blocks(paths):
    state = platform()
    state['restore_sources'] = ['scheduled_task']
    assert plan(paths, ('code',), state=state).blockers


def test_desktop_known_state_preserves_binaries_and_registration(paths):
    root = paths.local / 'Claude-Data/synthetic-package'
    for name in ('config.json', 'Network/Cookies', 'Partitions/fixture/Network/Cookies', '.hybrid-token-handoff', 'sentry/queue', 'bridge-state.json'):
        write(root / name, 'OLD_SECRET')
    for name in ('ant-device-registry.json', 'ant-device-key-generation.json', 'claude-code/2.1.308/claude.exe', 'vm_bundles/claudevm.bundle/rootfs.vhdx'):
        write(root / name, 'KEEP')
    state = platform()
    state['desktop_versions'] = ['3.1623.4']
    p = plan(paths, ('desktop',), state=state)
    assert not p.blockers
    assert 'OLD_SECRET' not in json.dumps(p.redacted())
    result = Executor(paths, FakeCrypto(), lambda: state).apply(p, consent_id=p.id, server_step_complete=True)
    assert not (root / 'Network').exists()
    assert not (root / 'Partitions').exists()
    assert (root / 'ant-device-key-generation.json').read_text() == 'KEEP'
    assert (root / 'vm_bundles/claudevm.bundle/rootfs.vhdx').read_text() == 'KEEP'
    assert result['desktop_keys'] == 'preserved_not_verified'


def test_desktop_work_and_unknown_schemas_block(paths):
    root = paths.local / 'Claude-Data/synthetic'
    write(root / 'local-agent-mode-sessions/work.txt', 'UNEXPORTED_WORK')
    write(root / 'new-unknown-store', 'UNKNOWN')
    state = platform()
    state['desktop_versions'] = ['3.1623.4']
    p = plan(paths, ('desktop',), state=state)
    assert any('export' in b for b in p.blockers)
    assert any('plan.desktop_schema_unknown' in b for b in p.blockers)
    with pytest.raises(SafetyError):
        Executor(paths, FakeCrypto(), lambda: state).apply(p, consent_id=p.id, server_step_complete=True)
    assert (root / 'local-agent-mode-sessions/work.txt').exists()


def test_strict_telemetry_is_explicit_opt_in(paths):
    p = plan(paths, ('code',), Selection(privacy='strict'))
    apply(paths, p)
    settings = jsonc.read(paths.home / '.claude/settings.json', paths.home)
    assert settings['env']['DISABLE_TELEMETRY'] == '1'
    assert any('plan.telemetry_strict' in x for x in p.observations)


@pytest.mark.parametrize('version,name', [
    ('3.6556.1.0', 'config.json.journal'),
    ('3.1623.4.0', 'developer_settings.json'),
    ('3.6556.2.0', 'config.json.journal.backup'),
    ('3.6556.2.0', 'developer_settings.json.journal'),
])
def test_desktop_journal_review_does_not_expand_unknown_scope(paths, version, name):
    root = paths.local / 'Claude-Data/synthetic-package'
    write(root / name, 'UNKNOWN_USER_DATA')
    state = platform()
    state['desktop_versions'] = [version]
    p = plan(paths, ('desktop',), state=state)
    assert any('plan.desktop_schema_unknown' in b for b in p.blockers)
    with pytest.raises(SafetyError):
        Executor(paths, FakeCrypto(), lambda: state).apply(p, consent_id=p.id, server_step_complete=True)
    assert (root / name).read_text() == 'UNKNOWN_USER_DATA'


def test_policy_is_encrypted_and_stable_after_own_output(paths):
    p = plan(paths, ('chrome',))
    policy = paths.home / 'policy.dpapi'
    save_policy(policy, p, consent_id=p.id, crypto=FakeCrypto())
    assert str(paths.home).encode() not in policy.read_bytes()
    apply(paths, p)
    p2 = policy_plan(paths, policy, crypto=FakeCrypto(), platform_state=platform(), env={})
    assert not p2.blockers
    apply(paths, p2)


def test_policy_blocks_new_named_profile_and_new_versions(paths):
    p = plan(paths, ('vscode',))
    policy = paths.home / 'policy.dpapi'
    save_policy(policy, p, consent_id=p.id, crypto=FakeCrypto())
    write(paths.roaming / 'Code/User/profiles/new/settings.json', '{}')
    changed = policy_plan(paths, policy, crypto=FakeCrypto(), platform_state=platform(), env={})
    assert any('plan.policy_profiles_changed' in b for b in changed.blockers)
    state = platform()
    state['cli_version'] = '9.0.0'
    assert any('plan.policy_versions_changed' in b for b in policy_plan(paths, policy, crypto=FakeCrypto(), platform_state=state, env={}).blockers)


def test_duplicate_or_reordered_actions_rejected(populated):
    p = plan(populated)
    p = dataclasses.replace(p, actions=(p.actions[0],) + p.actions)
    with pytest.raises(SafetyError):
        apply(populated, p)


def test_concurrent_executor_is_blocked(paths):
    with operation_lock(paths):
        with pytest.raises(SafetyError):
            with operation_lock(paths):
                pytest.fail('must not acquire twice')


def test_checkpoint_resume_after_failure_between_actions(populated, monkeypatch):
    p = plan(populated)
    executor = Executor(populated, FakeCrypto(), platform)
    check = executor.check_processes
    count = 0
    def fail_second(plan):
        nonlocal count
        count += 1
        if count == 2:
            raise SafetyError('fixture failure')
        check(plan)
    executor.check_processes = fail_second
    with pytest.raises(SafetyError):
        executor.apply(p, consent_id=p.id, server_step_complete=True)
    result = Executor(populated, FakeCrypto(), platform).resume(p.id)
    assert result['status'] == 'local_operations_completed_partial_coverage'
    assert not (populated.home / '.claude.json').exists()
    assert (populated.home / '.claude/CLAUDE.md').read_text() == 'User instructions'


def test_interrupted_action_requires_review_but_memory_survives(populated, monkeypatch):
    p = plan(populated)
    def fail(*args):
        raise OSError('SECRET_PATH_NOT_TO_LOG')
    monkeypatch.setattr('claude_reset.reset.execution.remove_owned', fail)
    with pytest.raises(SafetyError):
        apply(populated, p)
    with pytest.raises(SafetyError, match='uncertain outcome'):
        Executor(populated, FakeCrypto(), platform).resume(p.id)
    export = recover_memory(populated, p.id, FakeCrypto())
    assert (export / 'CLAUDE.md').read_text() == 'User instructions'
    result = (populated.state / 'runs' / p.id / 'result.json').read_text()
    assert 'SECRET_PATH_NOT_TO_LOG' not in result


def test_resume_never_overwrites_new_work(populated, monkeypatch):
    p = plan(populated)
    executor = Executor(populated, FakeCrypto(), platform)
    calls = 0
    def stop(plan):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise SafetyError('stop')
    executor.check_processes = stop
    with pytest.raises(SafetyError):
        executor.apply(p, consent_id=p.id, server_step_complete=True)
    write(populated.home / '.claude/CLAUDE.md', 'NEW_WORK')
    with pytest.raises(SafetyError, match='changed since interruption'):
        Executor(populated, FakeCrypto(), platform).resume(p.id)
    assert (populated.home / '.claude/CLAUDE.md').read_text() == 'NEW_WORK'


def test_manual_evidence_never_becomes_independent_verification(paths):
    p = plan(paths, ('chrome',))
    apply(paths, p)
    evidence = template(p.id, ['chrome'])
    evidence['checks'] = {k:'user_reported_pass' for k in evidence['checks']}
    summary = save_evidence(paths, evidence, crypto=FakeCrypto())
    assert summary['ready_for_new_account'] is False
    assert summary['full_tunnel_verified'] is False
    evidence['token'] = 'DO_NOT_STORE'
    with pytest.raises(SafetyError):
        summarize(evidence)


def test_geolocation_block_in_fresh_profile(paths):
    p = plan(paths, ('chrome',))
    apply(paths, p)
    preferences = jsonc.read(paths.state / 'ChromeProfiles' / p.id / 'Default/Preferences', paths.state)
    assert preferences['profile']['default_content_setting_values']['geolocation'] == 2


@pytest.mark.parametrize('part', ['file.txt:ads', 'CON', 'NUL.md', 'trailing.', 'trailing '])
def test_windows_path_aliases_rejected(paths, part):
    with pytest.raises(SafetyError):
        guarded(paths.home / part, paths.home)


def test_missing_config_directory_does_not_bypass_version_gate(paths):
    write(paths.home / '.claude.json', '{"userID":"OLD"}')
    state = platform()
    state['cli_version'] = 'unknown'
    assert any('version' in b for b in plan(paths, ('code',), state=state).blockers)


def test_cross_component_overlap_is_blocked(paths):
    custom = paths.roaming / 'Code/User/globalStorage/anthropic.claude-code'
    write(custom / 'CLAUDE.md', 'DO_NOT_LOSE_MEMORY')
    state = platform()
    state['custom_roots'] = [{'component':'code','path':str(custom)}]
    selection = Selection([str(custom), str(paths.roaming / 'Code/User')])
    assert any('overlap' in b for b in plan(paths, ('code','vscode'), selection, state).blockers)


def test_pending_wal_is_not_ignored_or_modified_during_audit(paths):
    p = paths.roaming / 'Code/User/globalStorage/state.vscdb'
    database(p)
    journal = Path(str(p) + '-wal')
    journal.write_bytes(b'UNPROCESSED_WAL')
    before = journal.read_bytes()
    proposed = plan(paths, ('vscode',))
    assert any('pending journal' in b for b in proposed.blockers)
    assert journal.read_bytes() == before


def test_identifier_comparisons_use_random_run_key_and_no_values(populated):
    from claude_reset.reset.execution import verify_run
    from claude_reset.reset.identifiers import baseline, compare
    write(populated.home / '.claude.json', '{"userID":"OLD_ACCOUNT_VALUE"}')
    p = plan(populated, ('code',))
    first, second = baseline(p, populated), baseline(p, populated)
    assert first['key'] != second['key']
    assert first['values'] != second['values']
    assert 'OLD_ACCOUNT_VALUE' not in json.dumps(first)
    assert any(x['status'] == 'unchanged' for x in compare(p, populated, first)['comparisons'])
    apply(populated, p)
    result = verify_run(populated, p.id, FakeCrypto())
    assert any(x['status'] == 'old_value_removed_new_value_not_observed' for x in result['comparisons'])
    write(populated.home / '.claude.json', '{"userID":"NEW_ACCOUNT_VALUE"}')
    result = verify_run(populated, p.id, FakeCrypto())
    assert any(x['status'] == 'changed' for x in result['comparisons'])
    assert 'NEW_ACCOUNT_VALUE' not in json.dumps(result)
    assert result['ready_for_new_account'] is False


def test_adjacent_backup_prefix_does_not_delete_user_documents(paths):
    write(paths.home / '.claude.json.backup-my-notes.md', 'KEEP_USER_WORK')
    write(paths.home / '.claude.json.backup.1770000000', '{"userID":"old"}')
    p = plan(paths, ('code',))
    apply(paths, p)
    assert (paths.home / '.claude.json.backup-my-notes.md').read_text() == 'KEEP_USER_WORK'
    assert not (paths.home / '.claude.json.backup.1770000000').exists()


def test_windows_locked_file_stops_apply_and_keeps_archive(populated):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    proposed = plan(populated, ('code',))
    handle = kernel.CreateFileW(str(populated.home / '.claude/.credentials.json'), 0x80000000, 0, None, 3, 0x80, None)
    assert handle != ctypes.c_void_p(-1).value
    try:
        with pytest.raises(SafetyError):
            apply(populated, proposed)
    finally:
        kernel.CloseHandle(handle)
    result = json.loads((populated.state / 'runs' / proposed.id / 'result.json').read_text())
    assert result['status'] == 'failed_or_partial'
    assert result['ready_for_new_account'] is False
    exported = recover_memory(populated, proposed.id, FakeCrypto())
    assert (exported / 'CLAUDE.md').read_text() == 'User instructions'


def test_abrupt_process_exit_after_deletion_preserves_dpapi_memory(populated):
    import subprocess
    import sys

    from claude_reset.model.ids import new_id
    run_id = new_id()
    child = '''
import dataclasses, json, os, sys
from pathlib import Path
from claude_reset.layout import Paths
from claude_reset.reset.planner import build_plan
from claude_reset.reset.execution import Executor
import claude_reset.reset.execution as engine
paths = Paths(*[Path(p) for p in json.loads(sys.argv[1])])
state = json.loads(sys.argv[2])
plan = build_plan(paths, ('code',), platform_state=state, env={})
plan = dataclasses.replace(plan, id=sys.argv[3])
original = engine.remove_owned
def abrupt(target, root):
    original(target, root)
    os._exit(91)
engine.remove_owned = abrupt
Executor(paths, inspect=lambda: state).apply(plan, consent_id=plan.id, server_step_complete=True)
'''
    args = json.dumps([str(p) for p in (populated.home, populated.roaming, populated.local, populated.state)])
    process = subprocess.run([sys.executable, '-c', child, args, json.dumps(platform()), run_id],
                             cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=40)
    assert process.returncode == 91
    assert not (populated.home / '.claude').exists()
    with pytest.raises(SafetyError, match='uncertain outcome'):
        Executor(populated, inspect=platform).resume(run_id)
    result = json.loads((populated.state / 'runs' / run_id / 'result.json').read_text())
    assert result['status'] == 'started'
    assert result['ready_for_new_account'] is False
    exported = recover_memory(populated, run_id)
    assert (exported / 'CLAUDE.md').read_text() == 'User instructions'


@pytest.mark.parametrize('checkpoint', ['before_first_action', 'committed_before_public_report'])
def test_abrupt_checkpoint_exit_can_resume_without_false_completion(populated, checkpoint):
    """Actual process death at durable journal boundaries, on disposable profiles only."""
    import subprocess
    import sys

    from claude_reset.model.ids import new_id
    run_id = new_id()
    child = '''
import dataclasses, json, os, sys
from pathlib import Path
from claude_reset.layout import Paths
from claude_reset.reset.planner import build_plan
from claude_reset.reset.execution import Executor
paths = Paths(*[Path(p) for p in json.loads(sys.argv[1])])
state = json.loads(sys.argv[2])
plan = build_plan(paths, ('code',), platform_state=state, env={})
plan = dataclasses.replace(plan, id=sys.argv[3])
executor = Executor(paths, inspect=lambda: state)
original = executor.write_private
def crash_after_checkpoint(path, value):
    original(path, value)
    if path.name == 'journal.dpapi' and value['in_progress'] is None:
        desired = 0 if sys.argv[4] == 'before_first_action' else 1
        if value['next'] == desired:
            os._exit(92)
executor.write_private = crash_after_checkpoint
executor.apply(plan, consent_id=plan.id, server_step_complete=True)
'''
    memory = (populated.home / '.claude/CLAUDE.md').read_bytes()
    args = json.dumps([str(p) for p in (populated.home, populated.roaming, populated.local, populated.state)])
    process = subprocess.run([sys.executable, '-c', child, args, json.dumps(platform()), run_id, checkpoint],
                             cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=40)
    assert process.returncode == 92
    run = populated.state / 'runs' / run_id
    interrupted = json.loads((run / 'result.json').read_text())
    assert interrupted['status'] == 'started'
    assert interrupted['completed'] == []
    assert interrupted['ready_for_new_account'] is False
    executor = Executor(populated, inspect=platform)
    journal = executor.read_private(run / 'journal.dpapi')
    assert journal['in_progress'] is None
    assert journal['next'] == (0 if checkpoint == 'before_first_action' else 1)
    resumed = executor.resume(run_id)
    assert resumed['local_reset'] == 'completed_for_selected_operations'
    assert resumed['ready_for_new_account'] is False
    assert resumed['full_reset'] is False
    assert len(resumed['completed']) == len(journal['plan']['actions'])
    assert (populated.home / '.claude/CLAUDE.md').read_bytes() == memory
    assert not (populated.home / '.claude/.credentials.json').exists()
    exported = recover_memory(populated, run_id)
    assert (exported / 'CLAUDE.md').read_bytes() == memory
