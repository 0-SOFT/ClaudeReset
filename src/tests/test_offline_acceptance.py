"""Synthetic T-02/T-08 coverage, never a claim about historical client traffic."""
import json
import socket
import sqlite3
import subprocess
import webbrowser

import pytest

from test_reset import paths, populated, platform, write
from claude_reset.core import build_plan, recover_memory, validate_memory_bundle
from claude_reset.discovery import Selection
from claude_reset.execution import Executor, archive_profiles
from claude_reset.safeio import SafetyError


def fixtures(paths):
    desktop = paths.local / 'Claude-Data/synthetic-package'
    queues = [
        paths.home / '.claude/telemetry/old.json',
        paths.home / '.claude/statsig/events.json',
        paths.home / '.claude/statsig-cache/pending.json',
        paths.home / '.claude/feedback/pending.json',
        desktop / 'sentry/queue/pending.json',
        desktop / 'Crashpad/reports/pending.dmp',
        paths.roaming / 'Code/User/globalStorage/anthropic.claude-code/pending.json',
    ]
    for path in queues:
        write(path, 'OLD_QUEUE_CANARY_DO_NOT_RESTORE')
    write(desktop / 'config.json', '{"oauth:tokenCache":"OLD_AUTH_CANARY"}')
    write(desktop / 'config.json.journal', 'OLD_JOURNALED_AUTH_CANARY_DO_NOT_RESTORE')
    write(desktop / 'developer_settings.json', '{"allowDevTools":true}')
    write(desktop / 'ant-device-registry.json', 'PRESERVE_REGISTRATION')
    write(desktop / 'vm_bundles/claudevm.bundle/rootfs.vhdx', 'PRESERVE_BINARY')
    state = platform()
    state['desktop_versions'] = ['3.6556.2.0']
    return desktop, queues, state


def prohibit_io(monkeypatch):
    attempts = []
    def fail(*args, **kwargs):
        attempts.append(True)
        raise AssertionError('Reset attempted network access or external process launch')
    monkeypatch.setattr(socket, 'socket', fail)
    monkeypatch.setattr(socket, 'getaddrinfo', fail)
    monkeypatch.setattr(subprocess, 'Popen', fail)
    monkeypatch.setattr(webbrowser, 'open', fail)
    return attempts


@pytest.mark.parametrize('privacy', ['compatible', 'strict'])
def test_reset_with_network_and_process_launch_unavailable(populated, monkeypatch, privacy):
    desktop, queues, state = fixtures(populated)
    memory = populated.home / '.claude/projects/project-one/memory/MEMORY.md'
    original = memory.read_bytes()
    attempts = prohibit_io(monkeypatch)
    plan = build_plan(populated, ('code', 'vscode', 'desktop', 'chrome'),
                      platform_state=state, env={}, selection=Selection(privacy=privacy))
    assert not plan.blockers
    executor = Executor(populated, inspect=lambda: state)  # Real Windows DPAPI.
    result = executor.apply(plan, consent_id=plan.id, server_step_complete=True)
    assert not attempts
    assert all(not path.exists() for path in queues)
    assert not (populated.home / '.claude/.credentials.json').exists()
    assert not (desktop / 'config.json').exists()
    assert not (desktop / 'config.json.journal').exists()
    assert (desktop / 'developer_settings.json').read_text() == '{"allowDevTools":true}'
    assert memory.read_bytes() == original
    assert (desktop / 'ant-device-registry.json').read_text() == 'PRESERVE_REGISTRATION'
    assert (desktop / 'vm_bundles/claudevm.bundle/rootfs.vhdx').read_text() == 'PRESERVE_BINARY'
    assert (populated.home / 'Documents/user-project/main.py').read_text() == 'DO NOT DELETE'
    old_chrome = populated.local / 'Google/Chrome/User Data/Default/Preferences'
    assert json.loads(old_chrome.read_text()) == {'keep': 'existing profile'}
    for database in (populated.roaming / 'Code/User').rglob('state.vscdb'):
        with sqlite3.connect(database) as connection:
            assert connection.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            assert dict(connection.execute('SELECT key,value FROM ItemTable')) == {
                'other.extension': 'KEEP_ME', 'history.recentlyOpenedPathsList': 'KEEP_PATH_HISTORY'}
    run = populated.state / 'runs' / plan.id
    archive = executor._read_private(run / 'memory.dpapi')
    assert len(archive_profiles(archive)) == 1
    for profile in archive_profiles(archive):
        for name, data in validate_memory_bundle(profile):
            assert b'OLD_QUEUE_CANARY' not in data and b'OLD_AUTH_CANARY' not in data
    recovered = recover_memory(populated, plan.id)
    assert (recovered / 'projects/project-one/memory/MEMORY.md').read_bytes() == original
    assert 'OLD_QUEUE_CANARY' not in json.dumps(archive)
    assert 'OLD_AUTH_CANARY' not in json.dumps(archive)
    report = json.dumps(result)
    assert all(value not in report for value in ('OLD_QUEUE_CANARY', 'OLD_AUTH_CANARY', 'NEVER_LOG_THIS'))
    assert result['local_reset'] == 'completed_for_selected_operations'
    assert not result['ready_for_new_account'] and not result['full_reset']
    assert not attempts


def test_old_queue_reappearing_at_final_check_invalidates_completion(populated, monkeypatch):
    desktop, queues, state = fixtures(populated)
    attempts = prohibit_io(monkeypatch)
    plan = build_plan(populated, ('code', 'vscode', 'desktop'), platform_state=state, env={})
    assert not plan.blockers
    executor = Executor(populated, inspect=lambda: state)
    original_check = executor._check_processes
    checks = 0
    def restore_at_final_check(current):
        nonlocal checks
        original_check(current)
        checks += 1
        if checks == len(plan.actions) + 1:
            write(queues[0], 'OLD_QUEUE_CANARY_DO_NOT_RESTORE')
    monkeypatch.setattr(executor, '_check_processes', restore_at_final_check)
    with pytest.raises(SafetyError, match='Apply stopped'):
        executor.apply(plan, consent_id=plan.id, server_step_complete=True)
    result = json.loads((populated.state / 'runs' / plan.id / 'result.json').read_text())
    assert queues[0].exists()
    assert result['status'] == 'failed_or_partial'
    assert not result['ready_for_new_account']
    assert (recover_memory(populated, plan.id) / 'CLAUDE.md').read_text() == 'User instructions'
    assert not attempts
