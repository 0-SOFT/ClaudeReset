"""One-button reset: blocker mapping, automatic resolution, wipe and plain results."""
from types import SimpleNamespace

import pytest

from claude_reset import cleanup, reset_flow
from claude_reset.safeio import SafetyError


class FakeActions:
    def __init__(self, **outcomes):
        self.calls, self.outcomes = [], outcomes

    def __getattr__(self, name):
        def action(*args):
            self.calls.append(name)
            value = self.outcomes.get(name, 'ok')
            if isinstance(value, Exception):
                raise value
            return value(*args) if callable(value) else value
        return action


@pytest.fixture
def world(monkeypatch, tmp_path):
    """prepare_wipe/preview driven by a mutable list of blockers and processes."""
    state = SimpleNamespace(blockers=[], processes=[], rows=[], credentials=(), checks=0, plans=[])

    def prepare(paths, mode, *, accept_unlisted=False, inspect=None, cowork_export=None):
        inspect()
        plan = cleanup.WipePlan(f'plan{len(state.plans)}', mode, (), (), accept_unlisted,
                                tuple(b for b in state.blockers if not (b == 'unlisted_version' and accept_unlisted)),
                                state.credentials, cowork_export)
        state.plans.append(plan)
        return plan

    def preview(paths, mode):
        return {'rows': state.rows, 'bytes': sum(r['bytes'] for r in state.rows)}

    def inspect():
        state.checks += 1
        return {'processes': [{'kind': k} for k in state.processes]}
    monkeypatch.setattr(cleanup, 'prepare_wipe', prepare)
    monkeypatch.setattr(cleanup, 'preview', preview)
    state.inspect = inspect
    state.paths = SimpleNamespace(home=tmp_path, local=tmp_path, state=tmp_path / 'state')
    return state


def session(world, actions, keep=True):
    return reset_flow.ResetSession(world.paths, keep_memory=keep, inspect=world.inspect, actions=actions)


def test_check_reports_found_data_in_plain_words(world):
    world.rows = [{'label': 'Desktop', 'status': 'present', 'bytes': 3 * 1024 ** 3, 'files': 1},
                  {'label': 'Claude Code', 'status': 'absent', 'bytes': 0, 'files': 0}]
    world.credentials = ('LegacyGeneric:target=Claude',)
    result = session(world, FakeActions()).check()
    assert result['rows'] == [{'label': 'Claude Desktop: вход, история, настройки', 'size': '3,0 ГБ', 'status': 'present'}]
    assert result['credentials'] == 1 and result['ready'] and not result['nothing_found']


def test_empty_computer_is_nothing_found(world):
    assert session(world, FakeActions()).check()['nothing_found'] is True


def test_open_vscode_is_a_task_for_the_person_not_the_program(world):
    world.blockers, world.processes = ['processes'], ['Code.exe']
    blockers = session(world, FakeActions()).check()['blockers']
    assert [(b['key'], b['kind']) for b in blockers] == [('vscode', 'user')]
    world.processes = ['Code.exe', 'Claude.exe']
    blockers = session(world, FakeActions()).check()['blockers']
    assert [(b['key'], b['kind']) for b in blockers] == [('vscode', 'user'), ('processes', 'auto')]


def test_resolve_runs_safe_actions_in_order_then_checks_again(world):
    world.blockers = ['processes', 'cowork_service', 'cowork_export', 'extra_entries']
    world.processes = ['Claude.exe', 'cowork-svc.exe']

    def cleared(*_):
        world.blockers, world.processes = [], []
        return 'ok'
    actions = FakeActions(export_cowork=('run1', 'run2'), archive_extras=cleared)
    run = session(world, actions)
    run.check()
    labels = []
    result = run.resolve(step=lambda label, fn, uac=False: labels.append(label) or fn())
    assert actions.calls == ['close_claude', 'stop_cowork', 'export_cowork', 'archive_extras']
    assert labels == ['close_claude', 'stop_cowork', 'export_cowork', 'archive_extras', 'check']
    assert result['resolved'] == ['processes', 'cowork_service', 'cowork_export', 'extra_entries']
    assert result['ready'] and run.cowork_export == ('run1', 'run2') and run.plan.cowork_export == ('run1', 'run2')


def test_service_process_alone_is_stopped_through_the_service(world):
    world.blockers, world.processes = ['processes'], ['cowork-svc.exe']
    actions = FakeActions()
    run = session(world, actions)
    run.check()
    run.resolve()
    assert actions.calls == ['close_claude', 'stop_cowork']


def test_claude_that_did_not_close_becomes_a_task_for_the_person(world):
    world.blockers, world.processes = ['processes'], ['Claude.exe']
    run = session(world, FakeActions())
    run.check()
    result = run.resolve()
    assert [b['key'] for b in result['blockers']] == ['claude_running']
    assert result['blockers'][0]['kind'] == 'user'


def test_failed_export_is_reported_and_blocks(world):
    world.blockers = ['cowork_export']
    run = session(world, FakeActions(export_cowork=None))
    run.check()
    result = run.resolve()
    assert result['failed'] == ['cowork_export'] and not result['ready']


def test_wipe_needs_the_word_and_a_clean_plan(world):
    run = session(world, FakeActions())
    with pytest.raises(SafetyError):
        run.wipe('стереть')
    with pytest.raises(SafetyError):
        run.wipe('СТЕРЕТЬ')                           # never checked
    world.blockers = ['vscode']
    run.check()
    with pytest.raises(SafetyError):
        run.wipe('СТЕРЕТЬ')


def test_wipe_resets_keys_first_rechecks_and_reports(world):
    reports = {'status': 'fixed_locations_wiped', 'memory': 'restored_verbatim', 'credentials_removed': 2,
               'audit_before_memory_restore': {'zero_file_remainder': True}, 'audit': {'zero_file_remainder': False}}
    actions = FakeActions(reset_desktop_keys='reset', wipe=lambda plan, word: reports, clear_browsers='browsers_open')
    run = session(world, actions)
    run.check()
    labels = []
    result = run.wipe('СТЕРЕТЬ', browsers=True, step=lambda label, fn, uac=False: labels.append(label) or fn())
    assert labels == ['desktop_keys', 'check', 'wipe', 'browsers']
    assert result == {'status': 'done', 'memory': 'restored_verbatim', 'desktop_keys': 'reset',
                      'browsers': 'browsers_open', 'passwords_removed': 2, 'no_files_left': True}
    assert run.plan is None


def test_wipe_without_memory_uses_the_final_audit(world):
    actions = FakeActions(reset_desktop_keys='not_present',
                          wipe=lambda plan, word: {'status': 'fixed_locations_wiped', 'audit': {'zero_file_remainder': True}})
    run = session(world, actions, keep=False)
    run.check()
    assert run.mode == 'wipe' and world.plans[-1].mode == 'wipe'
    result = run.wipe('СТЕРЕТЬ')
    assert result['no_files_left'] is True and result['browsers'] == 'not_requested'


def test_failed_wipe_is_a_plain_result_not_an_exception(world):
    actions = FakeActions(reset_desktop_keys='not_supported', wipe=SafetyError('C:/Users/someone/.claude'))
    run = session(world, actions)
    run.check()
    result = run.wipe('СТЕРЕТЬ')
    assert result == {'status': 'failed', 'desktop_keys': 'not_supported'} and 'someone' not in repr(result)


def test_archive_extras_falls_back_to_no_copy_when_a_file_looks_like_a_secret(monkeypatch, tmp_path):
    from claude_reset import customizations
    paths = SimpleNamespace(home=tmp_path)
    plans, applied = [], []
    monkeypatch.setattr(customizations, 'extra_entries', lambda profile: ['agents', 'secrets.env'])

    def create(paths, entries):
        plans.append(list(entries))
        if entries:
            raise SafetyError('possible credential')
        return {'run': 'a' * 32}
    monkeypatch.setattr(customizations, 'create_plan', create)
    monkeypatch.setattr(customizations, 'apply_plan', lambda p, run, server_step_complete: applied.append((run, server_step_complete)) or {})
    reset_flow.Actions(paths).archive_extras()
    assert plans == [['agents', 'secrets.env'], []] and applied == [('a' * 32, True)]


def test_browser_cleanup_reports_open_browsers(monkeypatch, tmp_path):
    from claude_reset import browser_sites
    def refuse(paths, **_):
        raise SafetyError('Закройте Chrome и Edge самостоятельно и повторите проверку.')
    monkeypatch.setattr(browser_sites, 'site_data', refuse)
    assert reset_flow.Actions(tmp_path).clear_browsers() == 'browsers_open'
    monkeypatch.setattr(browser_sites, 'site_data', lambda paths, **kw: kw)
    assert reset_flow.Actions(tmp_path).clear_browsers() == 'cleared'


def test_desktop_keys_states(monkeypatch, tmp_path):
    from claude_reset import desktop_keys
    from claude_reset.native_worker import FAMILY
    paths = SimpleNamespace(local=tmp_path, state=tmp_path)
    assert reset_flow.Actions(paths).reset_desktop_keys() == 'not_present'
    (tmp_path / 'Claude-Data' / FAMILY.lower()).mkdir(parents=True)
    def unsupported(*_):
        raise SafetyError('validated MSIX installation')
    monkeypatch.setattr(desktop_keys, 'create_plan', unsupported)
    assert reset_flow.Actions(paths).reset_desktop_keys() == 'not_supported'
    monkeypatch.setattr(desktop_keys, 'create_plan', lambda p, profile: {'run': 'r', 'keys': 0})
    assert reset_flow.Actions(paths).reset_desktop_keys() == 'no_keys'
    applied = []
    monkeypatch.setattr(desktop_keys, 'create_plan', lambda p, profile: {'run': 'r', 'keys': 2})
    monkeypatch.setattr(desktop_keys, 'apply_plan', lambda p, run, server_step_complete: applied.append(run))
    assert reset_flow.Actions(paths).reset_desktop_keys() == 'reset' and applied == ['r']


def test_sizes_are_human():
    assert [reset_flow.size_text(n) for n in (5, 2048, 5 * 1024 ** 2 + 1)] == ['5 Б', '2,0 КБ', '5,0 МБ']
