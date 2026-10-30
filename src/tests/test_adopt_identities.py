import types

import pytest

from claude_reset import layout
from claude_reset.network import gate_rules as guard
from claude_reset.network.strict_wfp import LAYERS, Identity


class FakeEngine:
    installed = []
    fail = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def install(self, rules):
        if FakeEngine.fail:
            raise RuntimeError('boom')
        FakeEngine.installed.append([r.identity.value for r in rules])


class FakeLease:
    def __init__(self):
        self.rules = []

    def install(self, rules):
        self.rules.append([(r.identity.value, r.port) for r in rules])


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch):
    FakeEngine.installed, FakeEngine.fail = [], False
    monkeypatch.setattr(guard, 'Engine', FakeEngine)


def home_with(tmp_path, *, cli=False, versions=()):
    if cli:
        (tmp_path / '.local/bin').mkdir(parents=True)
        (tmp_path / '.local/bin/claude.exe').write_bytes(b'x')
    for version in versions:
        folder = tmp_path / f'.vscode/extensions/anthropic.claude-code-{version}-win32-x64/resources/native-binary'
        folder.mkdir(parents=True)
        (folder / 'claude.exe').write_bytes(b'x')
    return types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state')


def images(targets):
    return [t.value for t in targets if t.kind == 'app']


def test_absent_cli_is_skipped_instead_of_refusing(tmp_path):
    targets = guard.identities(home_with(tmp_path))
    assert images(targets) == [] and [t.kind for t in targets] == ['package', 'package']
    assert guard.cli_state(home_with(tmp_path)) == {'present': False, 'reviewed_hash': None}


def test_cli_with_an_unreviewed_hash_is_still_denied_by_path(tmp_path):
    paths = home_with(tmp_path, cli=True)
    assert images(guard.identities(paths)) == [str(tmp_path / '.local/bin/claude.exe')]
    assert guard.cli_state(paths) == {'present': True, 'reviewed_hash': False}


def test_every_installed_extension_version_is_covered(tmp_path):
    names = images(guard.identities(home_with(tmp_path, versions=('2.1.301', '2.1.311'))))
    assert len(names) == 2 and any('2.1.301' in n for n in names) and any('2.1.311' in n for n in names)


def test_exclusion_flag_still_removes_the_extension_binaries(tmp_path):
    paths = home_with(tmp_path, versions=('2.1.311',))
    (paths.state / 'strict-guard').mkdir(parents=True)
    (paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG).write_text('')
    assert images(guard.identities(paths)) == []


def test_nothing_new_changes_nothing(tmp_path):
    paths = home_with(tmp_path, versions=('2.1.311',))
    targets, lease, state = guard.identities(paths), FakeLease(), {}
    assert guard.adopt_new_identities(paths, targets, lease, state) is targets
    assert FakeEngine.installed == [] and lease.rules == [] and state == {}


def test_new_extension_version_gets_deny_then_permit(tmp_path):
    paths = home_with(tmp_path, versions=('2.1.311',))
    targets, lease, state = guard.identities(paths), FakeLease(), {}
    home_with(tmp_path, versions=('2.1.312',))
    result = guard.adopt_new_identities(paths, targets, lease, state)
    new = [t.value for t in result if '2.1.312' in t.value]
    assert len(result) == len(targets) + 1 and len(new) == 1
    assert FakeEngine.installed == [new * len(LAYERS)]              # one transaction: a deny per layer
    assert lease.rules == [[(new[0], 25082)]] and state['adopted'] == new and 'adopt_error' not in state
    assert guard.adopt_new_identities(paths, result, lease, state) is result   # adopted once, not again


def test_deny_failure_is_recorded_gives_no_permit_and_never_raises(tmp_path):
    paths = home_with(tmp_path, versions=('2.1.311',))
    targets, lease, state = guard.identities(paths), FakeLease(), {}
    home_with(tmp_path, versions=('2.1.312',))
    FakeEngine.fail = True
    assert guard.adopt_new_identities(paths, targets, lease, state) is targets
    assert lease.rules == [] and state['adopt_error'] == 'RuntimeError'
    FakeEngine.fail = False
    assert len(guard.adopt_new_identities(paths, targets, lease, state)) == len(targets) + 1
    assert 'adopt_error' not in state


def test_identity_type_is_unchanged():
    assert Identity('app', r'C:\x\claude.exe').kind == 'app'
