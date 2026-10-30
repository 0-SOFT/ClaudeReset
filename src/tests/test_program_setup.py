"""Installed-program detection and self-removal: protection first, then shortcuts, entry and folder."""
from types import SimpleNamespace

import pytest

from claude_reset.services import program_setup


@pytest.fixture
def installed(tmp_path):
    home = tmp_path / 'ClaudeReset'
    app = home / 'app-1.0.0'
    (app / 'src').mkdir(parents=True)
    (home / 'current.txt').write_text('app-1.0.0', encoding='utf-8')
    return home, app


def paths_with_state(tmp_path, archives=False):
    state = tmp_path / 'state'
    state.mkdir()
    if archives:
        (state / 'runs').mkdir()
    return SimpleNamespace(state=state)


class FakeRegistry:
    def __init__(self, values):
        self.data, self.deleted = values, False

    def values(self):
        return dict(self.data)

    def delete(self):
        self.deleted = True


def test_only_the_current_version_folder_is_an_installation(installed, tmp_path):
    home, app = installed
    assert program_setup.installation(app) == home
    (home / 'current.txt').write_text('app-2.0.0')
    assert program_setup.installation(app) is None
    assert program_setup.installation(tmp_path / 'checkout') is None
    plain = tmp_path / 'portable' / 'ClaudeReset-1.0.0'
    plain.mkdir(parents=True)
    assert program_setup.installation(plain) is None


def test_uninstall_switches_protection_off_first_then_removes_everything(installed, tmp_path):
    home, app = installed
    start = tmp_path / 'ClaudeReset.lnk'
    start.write_text('link')
    other = tmp_path / 'Other.lnk'
    other.write_text('link')
    registry = FakeRegistry({'ShortcutStartMenu': str(start), 'ShortcutDesktop': str(other)})
    calls, spawned = [], []
    result = program_setup.uninstall(
        paths_with_state(tmp_path, archives=True), root=app,
        step=lambda label, fn, uac=False: calls.append((label, uac)) or fn(),
        summary=lambda p: {'state': 'paused', 'proxy_saved': True},
        remove_protection=lambda p: {'status': 'removed'}, registry=registry,
        spawn=lambda args, **kw: spawned.append((args, kw)))
    assert calls == [('remove', True)]
    assert result['status'] == 'removed' and result['shortcuts_removed'] == 1
    assert not start.exists() and other.exists()            # only ClaudeReset.lnk is ever removed
    assert registry.deleted and str(home) in spawned[0][0][-1] and 'rmdir /s /q' in spawned[0][0][-1]
    assert spawned[0][1]['cwd'] != str(home)


def test_failed_protection_removal_keeps_the_program(installed, tmp_path):
    home, app = installed
    registry = FakeRegistry({})
    result = program_setup.uninstall(
        paths_with_state(tmp_path), root=app, summary=lambda p: {'state': 'on'},
        remove_protection=lambda p: {'status': 'removed_with_leftovers'}, registry=registry,
        spawn=lambda *a, **k: pytest.fail('folder removal scheduled'))
    assert result == {'status': 'protection_not_removed'} and not registry.deleted


def test_no_protection_means_no_uac(installed, tmp_path):
    home, app = installed
    result = program_setup.uninstall(
        paths_with_state(tmp_path), root=app, summary=lambda p: {'state': 'off', 'proxy_saved': False},
        remove_protection=lambda p: pytest.fail('protection touched'), registry=FakeRegistry({}),
        spawn=lambda *a, **k: None)
    assert result['status'] == 'removed'


def test_a_copy_that_was_not_installed_is_not_removed(tmp_path):
    result = program_setup.uninstall(paths_with_state(tmp_path), root=tmp_path / 'src-checkout',
                                      summary=lambda p: pytest.fail('checked'))
    assert result == {'status': 'not_installed'}


def test_folder_removal_refuses_other_folders(tmp_path):
    with pytest.raises(ValueError):
        program_setup.schedule_folder_removal(tmp_path, spawn=lambda *a, **k: pytest.fail('spawned'))


def test_plan_reports_archives_and_protection(installed, tmp_path):
    home, app = installed
    plan = program_setup.plan(paths_with_state(tmp_path, archives=True), root=app,
                              summary=lambda p: {'state': 'off', 'proxy_saved': True})
    assert plan['installed'] and plan['protection'] and plan['archives']
