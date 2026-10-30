"""A programming error inside a scenario is never hidden: the result names its kind, or it reaches the caller.

Scenarios that must always answer the window (a proxy check, the protection state, a reset step) keep a broad
handler and report error_type; reads whose failures are known (OSError, ValueError, SafetyError) catch only those.
"""
from types import SimpleNamespace

import pytest

from claude_reset import layout
from claude_reset.model.confirmation import Confirmation
from claude_reset.model.status import BlockerKind
from claude_reset.services import diagnostics, progress, protection, proxy
from claude_reset.services.reset import Actions, Blocker, CheckResult, ResetSession


def broken(*_args, **_kwargs):
    raise AttributeError('a bug, not a refusal')


class BrokenProbe:
    reachable = handshake = measure_exit = measure_local = backend_status = check = coverage = staticmethod(broken)


def test_proxy_check_names_the_error():
    draft = proxy.ProxyDraft('93.184.216.34', 1080, probe=BrokenProbe())
    assert draft.check().to_json() == {'status': 'proxy_check_failed', 'error_type': 'AttributeError'}


def test_engine_install_and_backend_removal_name_the_error(tmp_path):
    assert proxy.install_engine(tmp_path, tmp_path / 'profile.json', install=broken).error_type == 'AttributeError'
    assert proxy.remove_backend(tmp_path, remove=broken).error_type == 'AttributeError'


def test_protection_state_names_the_error(tmp_path):
    result = protection.state(tmp_path, collect=broken)
    assert result.state == 'unknown' and result.error_type == 'AttributeError'


def test_protection_state_reads_only_hide_known_failures(tmp_path):
    with pytest.raises(AttributeError):
        protection.state(tmp_path, collect=lambda paths: {}, evaluate=lambda facts: {}, status=broken)


def test_progress_lets_a_bug_reach_the_caller(tmp_path):
    with pytest.raises(AttributeError):
        progress.progress(tmp_path, check=broken)


def test_advice_names_the_error():
    assert diagnostics.advise('DE', inspect=broken).error_type == 'AttributeError'


def test_reset_resolution_names_the_failed_step():
    actions = SimpleNamespace(close_claude=broken, stop_cowork=broken, export_cowork=broken, archive_extras=broken)
    session = ResetSession(SimpleNamespace(), actions=actions)
    session.blockers = lambda: [Blocker('processes', BlockerKind.AUTO)]
    session.check = lambda step: CheckResult(rows=(), total_bytes=0, credentials=0, blockers=(), ready=True,
                                             nothing_found=True)
    result = session.resolve()
    assert result.failed == ('processes',) and result.errors == {'processes': 'AttributeError'}


def test_desktop_key_bug_stops_the_reset_before_anything_is_erased(tmp_path):
    paths = SimpleNamespace(local=tmp_path, roaming=tmp_path, home=tmp_path, state=tmp_path)
    layout.desktop_data(paths).mkdir(parents=True)
    actions = Actions(paths, desktop_keys=SimpleNamespace(create_plan=broken))
    session = ResetSession(paths, actions=actions)
    session.plan = SimpleNamespace(blockers=())

    def step(label, fn, uac=False):
        assert label == 'desktop_keys', 'a step after the failed key reset ran'
        return fn()
    with pytest.raises(AttributeError, match='a bug'):
        session.wipe(Confirmation.ERASE, step=step)
