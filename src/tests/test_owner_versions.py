"""The versions the owner added on 28 Oct 2026 pass the version gate; every other gate stays in force."""
import pytest

from test_reset import paths, write, platform
from claude_reset.reset.planner import build_plan

VERSION_BLOCKERS = ('version_unverified',)


def version_blockers(plan):
    return [b for b in plan.blockers if any(text in b for text in VERSION_BLOCKERS)]


@pytest.mark.parametrize('version', ['2.1.301', '2.1.310', '2.1.311'])
def test_owner_extension_versions_pass_the_version_gate(paths, version):
    state = platform()
    state['extension_versions'] = [version]
    write(paths.roaming / 'Code/User/settings.json', '{}')
    assert version_blockers(build_plan(paths, ('vscode',), platform_state=state, env={})) == []


def test_an_unlisted_extension_version_is_still_refused(paths):
    state = platform()
    state['extension_versions'] = ['2.1.311', '2.1.999']
    write(paths.roaming / 'Code/User/settings.json', '{}')
    assert version_blockers(build_plan(paths, ('vscode',), platform_state=state, env={}))


@pytest.mark.parametrize('version', ['4.29.0.0', '2.31226.1.0'])
def test_owner_desktop_versions_pass_the_version_gate(paths, version):
    from claude_reset.reset import catalog
    assert version in catalog.DESKTOP_VERSIONS and version in catalog.DESKTOP_JOURNAL_VERSIONS


def test_the_account_key_reset_still_refuses_the_new_desktop_versions():
    from claude_reset.model.compatibility import CLIENTS
    pinned = CLIENTS['desktop']['native_reset_hashes']
    assert '4.29.0.0' not in pinned and '2.31226.1.0' not in pinned


def test_without_a_standalone_cli_the_extension_version_decides(paths):
    write(paths.home / '.claude/settings.json', '{}')
    state = platform()
    state['cli_version'] = None
    state['extension_versions'] = ['2.1.311']
    assert not [b for b in build_plan(paths, ('code',), platform_state=state, env={}).blockers if 'plan.code_version_unverified' in b]


@pytest.mark.parametrize('extension_versions', [[], ['2.1.999'], ['2.1.311', '2.1.999']])
def test_without_a_cli_and_without_a_known_extension_the_code_reset_is_still_refused(paths, extension_versions):
    write(paths.home / '.claude/settings.json', '{}')
    state = platform()
    state['cli_version'] = None
    state['extension_versions'] = extension_versions
    assert [b for b in build_plan(paths, ('code',), platform_state=state, env={}).blockers if 'plan.code_version_unverified' in b]


def test_an_unknown_cli_version_is_still_refused_even_with_a_known_extension(paths):
    write(paths.home / '.claude/settings.json', '{}')
    state = platform()
    state['cli_version'] = '9.9.9'
    state['extension_versions'] = ['2.1.311']
    assert [b for b in build_plan(paths, ('code',), platform_state=state, env={}).blockers if 'plan.code_version_unverified' in b]


def test_unknown_entries_in_the_claude_profile_still_block_on_an_owner_version(paths):
    write(paths.home / '.claude/settings.json', '{}')
    write(paths.home / '.claude/some-new-thing/x.json', '{}')
    state = platform()
    state['cli_version'] = None
    state['extension_versions'] = ['2.1.311']
    blockers = build_plan(paths, ('code',), platform_state=state, env={}).blockers
    assert any('plan.code_unknown_entries' in b or 'unknown' in b.lower() for b in blockers)
