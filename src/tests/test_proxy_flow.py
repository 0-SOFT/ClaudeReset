"""Proxy and protection summary, one fix per problem, connect and recheck."""
from types import SimpleNamespace

import pytest

from claude_reset.network import l1_check, remote_backend
from claude_reset.ui import proxy_flow
from claude_reset.ui.text import ENGLISH, RUSSIAN
from claude_reset import config

PARTS = ('isolation_package', 'backend_task', 'backend_listening', 'controller_files', 'controller_task',
         'connection_profile', 'consent', 'relay_listening')


def facts(task='Ready', **parts):
    ok = {k: parts.get(k, 'missing') for k in PARTS}
    checks = [{'id': k, 'status': v} for k, v in ok.items()] + [{'id': 'client_desktop', 'status': 'ok'}]
    protection = 'installed' if all(v == 'ok' for v in ok.values()) else (
        'partial' if any(v == 'ok' for v in ok.values()) else 'not_installed')
    return {'tasks': {config.CONTROLLER_TASK: task}, 'report': {'protection': protection, 'checks': checks}}


def summarize(data, stop_reason=None, profile=None):
    return proxy_flow.summary(None, collect=lambda _: data, evaluate=lambda f: f['report'],
                              status=lambda _: {'last_report': {'stop_reason': stop_reason}}, remote=lambda _: profile)


ALL = {k: 'ok' for k in PARTS}


def test_working_protection_is_on():
    result = summarize(facts(**ALL), profile={'adapter': 'socks5'})
    assert (result['state'], result['fix'], result['proxy']) == ('on', None, 'SOCKS5')
    assert result['clients'][0] == {'name': 'Claude Desktop', 'present': True}


def test_paused_protection_says_claude_goes_out_directly():
    data = facts(task='Disabled', **dict(ALL, relay_listening='missing'))
    result = summarize(data)
    assert result['state'] == 'paused' and result['fix'] == 'resume' and 'напрямую' in result['text']
    assert result['proxy'] == 'VLESS'


@pytest.mark.parametrize('reason,fix', [('exit_mismatch', 'accept_exit'), ('proxy_unreachable', 'retry'),
                                        ('backend_config_failed', 'reenter'), (None, 'restart')])
def test_stopped_protection_is_a_problem_with_one_fix(reason, fix):
    result = summarize(facts(**dict(ALL, relay_listening='missing')), stop_reason=reason,
                       profile={'adapter': remote_backend.HTTP_ADAPTER})
    assert (result['state'], result['fix'], result['proxy']) == ('problem', fix, 'HTTP')
    assert 'без сети' in result['title']


def test_half_installed_and_absent_protection():
    assert summarize(facts(consent='ok'))['state'] == 'partial'
    assert summarize(facts(backend_task='ok', connection_profile='ok'))['state'] == 'off'
    assert summarize(facts())['proxy_saved'] is False


def test_unreadable_state_is_unknown():
    def broken(_):
        raise OSError('C:/Users/someone')
    result = proxy_flow.summary(None, collect=broken)
    assert result['state'] == 'unknown' and 'someone' not in repr(result)


def test_draft_returns_the_fixed_hint_for_wrong_fields():
    draft, error = proxy_flow.draft('socks5', 'not-an-ip', '1080', '', '', language=RUSSIAN)
    assert draft is None and 'IPv4' in error
    draft, error = proxy_flow.draft('socks5', '9.9.9.9', '1080', 'user', 'secret-pass', language=RUSSIAN)
    assert error is None and draft.profile['host'] == '9.9.9.9'


def test_draft_hint_is_in_the_window_language():
    _, russian = proxy_flow.draft('socks5', 'not-an-ip', '1080', '', '', language=RUSSIAN)
    _, english = proxy_flow.draft('socks5', 'not-an-ip', '1080', '', '', language=ENGLISH)
    assert russian != english and 'IPv4' in english and not any('а' <= c <= 'я' for c in english.lower())


class Draft:
    def __init__(self, expected=True, saved='proxy_saved'):
        self.expected = {'expected_exit_ips': ['9.9.9.9']} if expected else None
        self.saved, self.saves = saved, []

    def save(self, paths, *, confirmed=False):
        self.saves.append(confirmed)
        return {'status': self.saved}


def test_connect_saves_then_installs_or_changes_the_running_protection():
    calls = []
    perform = lambda paths, action, **kw: calls.append((action, kw)) or {'text': 'ok-' + action}
    draft = Draft()
    assert proxy_flow.connect('p', draft, installed=False, protect_extension=True, perform=perform) == {'text': 'ok-install', 'ok': True}
    assert draft.saves == [True] and calls[-1] == ('install', {'confirmed': True, 'protect_extension': True})
    assert proxy_flow.connect('p', draft, installed=True, perform=perform)['text'] == 'ok-change_proxy'
    assert calls[-1][1]['proxy_draft'] is draft and draft.saves == [True]


def test_connect_refuses_unchecked_or_unsaved_drafts():
    perform = lambda *a, **k: pytest.fail('performed')
    assert proxy_flow.connect('p', None, installed=False, perform=perform)['ok'] is False
    assert proxy_flow.connect('p', Draft(expected=False), installed=False, perform=perform)['ok'] is False
    assert proxy_flow.connect('p', Draft(saved='proxy_confirmation_required'), installed=False, perform=perform)['ok'] is False


def test_recheck_tells_whether_the_exit_is_unchanged():
    draft = Draft()
    same = proxy_flow.recheck('p', check_saved=lambda p: (draft, {'status': 'proxy_checked'}),
                              load=lambda p: {'expected_exit_ips': ['9.9.9.9']})
    assert same[0] is draft and same[1]['same_exit'] is True
    moved = proxy_flow.recheck('p', check_saved=lambda p: (draft, {'status': 'proxy_checked'}),
                               load=lambda p: {'expected_exit_ips': ['8.8.8.8']})
    assert moved[1]['same_exit'] is False
    failed = proxy_flow.recheck('p', check_saved=lambda p: (None, {'status': 'proxy_unreachable'}))
    assert failed[0] is None and failed[1]['text'] == proxy_flow.MESSAGES['proxy_unreachable']
