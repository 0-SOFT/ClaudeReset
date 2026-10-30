"""Synthetic metadata only; no Credential Manager API is called."""
import json

import pytest
from test_reset import FakeCrypto, paths, platform, write

from claude_reset.model.reset import Selection
from claude_reset.reset.execution import Executor
from claude_reset.reset.planner import build_plan
from claude_reset.reset.secure_storage import BLOCKER, VARIABLES
from claude_reset.safeio import SafetyError, fingerprint


@pytest.mark.parametrize('component', ['code', 'vscode'])
@pytest.mark.parametrize('source', ['process', 'user', 'machine'])
@pytest.mark.parametrize('value', ['', '1', 'PRIVATE_FIXTURE_VALUE'])
def test_secure_storage_environment_blocks_without_exporting_values(paths, component, source, value):
    for name in VARIABLES:
        env = {}; state = platform()
        if source == 'process': env[name.lower()] = value
        else: state['environment_presence'] = {source + ':' + name.lower(): bool(value)}
        plan = build_plan(paths, (component,), platform_state=state, env=env)
        assert BLOCKER in plan.blockers
        assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(plan.redacted())


@pytest.mark.parametrize('component', ['code', 'vscode'])
@pytest.mark.parametrize('relative', ['.claude.json', '.claude/.config.json', '.claude/.claude.json'])
def test_cached_feature_blocks_file_only_reset_and_preserves_state(paths, component, relative):
    path = paths.home / relative
    write(path, json.dumps({'cachedGrowthBookFeatures': {'tengu_windows_credman': True},
                            'unrelatedPrivateField': 'PRIVATE_FIXTURE_VALUE'}))
    before = fingerprint(paths.home, paths.home)
    plan = build_plan(paths, (component,), platform_state=platform(), env={})
    assert BLOCKER in plan.blockers
    assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(plan.redacted())
    assert fingerprint(paths.home, paths.home) == before


@pytest.mark.parametrize('value', [True, None, 1, 'false'])
def test_unknown_or_enabled_feature_is_not_treated_as_false(paths, value):
    write(paths.home / '.claude.json', json.dumps({'cachedGrowthBookFeatures': {'tengu_windows_credman': value}}))
    assert BLOCKER in build_plan(paths, ('code',), platform_state=platform(), env={}).blockers


def test_explicit_false_does_not_claim_current_credential_storage_is_empty(paths):
    write(paths.home / '.claude.json', json.dumps({'cachedGrowthBookFeatures': {'tengu_windows_credman': False}}))
    result = build_plan(paths, ('code',), platform_state=platform(), env={})
    assert BLOCKER not in result.blockers
    assert not any(row.get('kind') == 'secure_storage' for row in result.inventory.sources)


@pytest.mark.parametrize('relative', ['.claude/settings.json', '.claude/settings.local.json',
    'AppData/Roaming/Code/User/settings.json', 'AppData/Roaming/Code/User/profiles/named/settings.json'])
def test_settings_aliases_block_without_secret_values(paths, relative):
    path = paths.home / relative
    name = 'claude_securestorage_config_dir'
    obj = {'env': {name: 'PRIVATE_FIXTURE_VALUE'}} if relative.startswith('.claude') else {
        'claudeCode.environmentVariables': [{'name': name, 'value': 'PRIVATE_FIXTURE_VALUE'}]}
    write(path, json.dumps(obj))
    plan = build_plan(paths, ('code', 'vscode'), platform_state=platform(), env={})
    assert BLOCKER in plan.blockers
    assert 'PRIVATE_FIXTURE_VALUE' not in json.dumps(plan.redacted())


def test_selected_custom_profile_feature_blocks(paths):
    root = paths.home / 'custom'
    write(root / '.claude.json', json.dumps({'cachedGrowthBookFeatures': {'tengu_windows_credman': True}}))
    result = build_plan(paths, ('code',), selection=Selection(profiles=[str(root)]),
                        platform_state=platform(), env={'CLAUDE_CONFIG_DIR': str(root)})
    assert BLOCKER in result.blockers


def test_unrelated_browser_operation_does_not_read_code_authentication_metadata(paths):
    write(paths.home / '.claude.json', 'malformed private metadata')
    plan = build_plan(paths, ('chrome',), platform_state=platform(),
                      env={'CLAUDE_SECURESTORAGE_CONFIG_DIR': 'PRIVATE_FIXTURE_VALUE'})
    assert BLOCKER not in plan.blockers
    assert 'plan.discovery_failed' not in plan.blockers


def test_unknown_extension_version_remains_unapproved(paths):
    state = platform(); state['extension_versions'] = ['2.1.999']
    write(paths.roaming / 'Code/User/settings.json', '{}')
    plan = build_plan(paths, ('vscode',), platform_state=state, env={})
    assert any('version' in reason.lower() for reason in plan.blockers)


@pytest.mark.parametrize('source', ['feature', 'persistent_environment'])
def test_secure_storage_appearing_after_preview_prevents_reset(paths, source):
    credential = paths.home / '.claude/.credentials.json'
    write(credential, '{"token":"PRIVATE_FIXTURE_VALUE"}')
    plan = build_plan(paths, ('code',), platform_state=platform(), env={})
    assert not plan.blockers
    state = platform()
    if source == 'feature':
        write(paths.home / '.claude.json', json.dumps({'cachedGrowthBookFeatures': {'tengu_windows_credman': True}}))
    else:
        state['environment_presence'] = {'User:CLAUDE_CODE_FORCE_WINDOWS_CREDMAN': True}
    before = fingerprint(paths.home / '.claude', paths.home)
    with pytest.raises(SafetyError):
        Executor(paths, FakeCrypto(), inspect=lambda: state).apply(
            plan, consent_id=plan.id, server_step_complete=True)
    assert fingerprint(paths.home / '.claude', paths.home) == before
    assert credential.read_text() == '{"token":"PRIVATE_FIXTURE_VALUE"}'
