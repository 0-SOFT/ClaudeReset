import pytest

from claude_reset.network.l1_recovery import backoff, decide

INSTANCE = 'a' * 32


def check(state='blocked_controller_stopped', close=None, **kw):
    return decide(dict(instance=INSTANCE, state=state, live_permit_session=state == 'relay_open'),
                  close or {}, **dict(armed=True, task_running=False, relay_listening=False,
                                     consent_present=True, **kw))


@pytest.mark.parametrize('state', ['blocked_controller_stopped', 'blocked_exit_mismatch', 'blocked_error'])
def test_outage_can_only_retry_the_full_controller(state):
    assert check(state)['restart'] is True


@pytest.mark.parametrize('state', ['blocked_controller_stopped', 'blocked_exit_mismatch', 'relay_open'])
def test_matching_explicit_close_disarms_recovery(state):
    r = check(state, dict(instance=INSTANCE))
    assert r == dict(reason='explicit_close_request', armed=False, restart=False)


def test_old_close_request_does_not_disable_a_later_manually_started_controller():
    assert check(close=dict(instance='b' * 32))['restart'] is True


@pytest.mark.parametrize('state', ['blocked_profile_required', 'direct_sockets_blocked_coverage_incomplete',
                                 'preparing', 'unknown', None])
def test_unaccepted_startup_states_do_not_trigger_recovery(state):
    assert check(state)['restart'] is False


@pytest.mark.parametrize('instance', [None, '', 'a' * 31, '../other', True, {}])
def test_invalid_identity_is_not_a_restart_capability(instance):
    r = decide(dict(instance=instance, state='blocked_controller_stopped'), {}, armed=True,
               task_running=False, relay_listening=False, consent_present=True)
    assert not r['restart'] and not r['armed']


def test_running_task_and_unverified_listener_prevent_duplicate_start():
    args = dict(armed=True, task_running=True, relay_listening=False, consent_present=True)
    state = dict(instance=INSTANCE, state='blocked_controller_stopped')
    assert decide(state, {}, **args)['reason'] == 'controller_task_running'
    args.update(task_running=False, relay_listening=True)
    assert decide(state, {}, **args)['reason'] == 'unverified_listener_present'


def test_recovery_requires_observing_an_enabled_relay_and_consent():
    args = dict(armed=False, task_running=False, relay_listening=False, consent_present=True)
    state = dict(instance=INSTANCE, state='blocked_controller_stopped')
    assert not decide(state, {}, **args)['restart']
    args.update(relay_listening=True, task_running=True)
    state.update(state='relay_open', live_permit_session=True)
    assert decide(state, {}, **args)['armed'] is True
    args['consent_present'] = False
    assert decide(state, {}, **args) == dict(reason='consent_absent', armed=False, restart=False)


def test_backoff_is_bounded():
    assert [backoff(i) for i in range(1, 8)] == [15, 30, 60, 120, 240, 300, 300]
