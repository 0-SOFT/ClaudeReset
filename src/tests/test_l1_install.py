import json
import types
from pathlib import Path

import pytest

from claude_reset import layout
from claude_reset.elevation import claims
from claude_reset.model.status import NextAction
from claude_reset.network import l1_install as inst


def state(**statuses):
    ids = {'backend_task': 'ok', 'backend_listening': 'ok', 'connection_profile': 'ok', 'isolation_package': 'missing', 'consent': 'missing',
           'controller_task': 'missing', 'controller_files': 'missing', 'relay_listening': 'missing'}
    ids.update(statuses)
    return {'can_install': True, 'protection': 'partial', 'blockers': [], 'checks': [{'id': k, 'status': v} for k, v in ids.items()]}


class Fake:
    """Records the order of side effects; every dependency can be told to fail."""
    def __init__(self, initial=None, **fail):
        self.calls, self.fail, self.initial, self.checks = [], fail, initial or state(), 0

    def check(self, paths):
        self.calls.append('check')
        self.checks += 1
        if self.checks == 1:
            return self.initial
        return {'can_install': True, 'protection': 'installed', 'checks': []}

    def register_package(self, paths):
        self.calls.append('package')
        return {'passed': not self.fail.get('package'), 'status': 'failed' if self.fail.get('package') else 'registered', 'error': 'refused'}

    def consent(self, paths, confirmed):
        self.calls.append(f'consent:{confirmed}')
        return {'passed': bool(confirmed), 'open_boundaries': ['dns_service_delegation', 'cowork_guest_boundary']}

    def build(self, out):
        self.calls.append('build')
        if self.fail.get('build'):
            raise RuntimeError('no PyInstaller')
        return Path('dist')

    def autostart(self, exe, paths):
        self.calls.append('autostart')
        return {'status': 'unknown', 'retry_blocked': True} if self.fail.get('autostart') else {'passed': True}

    def current_instance(self, folder):
        return 'old-instance'

    def start(self, folder=None, stale=None):
        self.calls.append('start')
        self.stale_at_start = stale
        return not self.fail.get('start')

    def wait_relay(self, folder, stale=None):
        self.calls.append('wait_relay')
        self.stale_at_wait = stale
        return (not self.fail.get('relay')), {'state': 'blocked_error' if self.fail.get('relay') else 'relay_open',
                                              'level': 'L1_owner_accepted_limits', 'stop_reason': 'exception'}

    def stop_controller(self, paths):
        self.calls.append('stop_controller')
        return not self.fail.get('stop')

    def extension_proxy(self):
        self.calls.append('extension_proxy')
        return not self.fail.get('extension')


@pytest.fixture
def paths(tmp_path):
    return types.SimpleNamespace(home=tmp_path, state=tmp_path / 'state', local=tmp_path / 'local')


def run(paths, fake, **kwargs):
    return inst.run(paths, deps=fake, build_dir=Path('b'), **kwargs)


def names(report):
    return [s['step'] for s in report['steps']]


def test_full_run_follows_the_safe_order_and_ends_installed(paths):
    fake = Fake()
    report = run(paths, fake, confirmed=True)
    assert report['status'] == 'installed' and report['finished']
    assert fake.calls == ['check', 'package', 'consent:True', 'build', 'autostart', 'start', 'wait_relay', 'check']
    assert names(report) == ['check', 'extension_decision', 'package', 'consent', 'build', 'autostart', 'start', 'verify']


def test_extension_is_excluded_by_default_and_the_flag_is_written(paths):
    report = run(paths, Fake(), confirmed=True)
    assert report['extension_protection'] == 'excluded'
    assert (paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG).is_file()


def test_protecting_the_extension_removes_the_flag_and_applies_its_proxy_after_the_relay_is_up(paths):
    flag = paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG
    flag.parent.mkdir(parents=True)
    flag.write_text('x')
    fake = Fake()
    report = run(paths, fake, confirmed=True, protect_extension=True)
    assert report['status'] == 'installed' and not flag.exists()
    assert fake.calls.index('wait_relay') < fake.calls.index('extension_proxy')


def test_failing_extension_proxy_is_reported_with_the_manual_step(paths):
    report = run(paths, Fake(extension=True), confirmed=True, protect_extension=True)
    assert report['status'] == 'extension_proxy_failed' and report['steps'][-1]['next'] == NextAction.SET_EXTENSION_PROXY


def test_blocked_pc_stops_before_anything_changes(paths):
    fake = Fake(initial={'can_install': False, 'blockers': ['base_filtering_engine'], 'checks': []})
    report = run(paths, fake)
    assert report['status'] == 'blocked' and fake.calls == ['check']
    # Only the mutation journal is created, before the read-only preflight.
    files = list((paths.state / 'strict-guard').iterdir())
    assert len(files) == 1 and files[0].name.startswith('expected-requests-')
    assert json.loads(files[0].read_text())['requests'] == []


def test_missing_exit_profile_stops_with_the_command_to_run(paths):
    fake = Fake(initial=state(connection_profile='missing'))
    report = run(paths, fake, confirmed=True)
    assert report['status'] == 'needs_connection_profile' and report['steps'][-1]['next'] == NextAction.SAVE_CONNECTION_PROFILE and fake.calls == ['check']


def test_missing_backend_stops_with_the_command_to_run(paths):
    fake = Fake(initial=state(backend_task='missing', backend_listening='missing'))
    report = run(paths, fake, confirmed=True)
    assert report['status'] == 'needs_backend' and report['steps'][-1]['next'] == NextAction.INSTALL_BACKEND and fake.calls == ['check']


def test_without_confirmation_it_registers_the_package_then_stops_with_the_boundaries(paths):
    fake = Fake()
    report = run(paths, fake)
    assert report['status'] == 'needs_consent' and report['steps'][-1]['open_boundaries'][0] == 'dns_service_delegation'
    assert fake.calls == ['check', 'package', 'consent:False']                        # nothing was built, nothing was started


def test_existing_consent_and_package_are_not_asked_for_again(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok'))
    report = run(paths, fake)
    assert report['status'] == 'installed' and 'package' not in fake.calls and not any(c.startswith('consent') for c in fake.calls)


@pytest.mark.parametrize('failure, status, last_call', [
    ('package', 'package_failed', 'package'),
    ('build', 'failed', 'build'),
    ('autostart', 'autostart_failed', 'autostart'),
    ('start', 'start_failed', 'start'),
])
def test_a_failed_step_stops_everything_after_it(paths, failure, status, last_call):
    fake = Fake(**{failure: True})
    report = run(paths, fake, confirmed=True)
    assert report['status'] == status and fake.calls[-1] == last_call and report['finished']


def test_relay_that_does_not_open_reports_the_controllers_reason(paths):
    report = run(paths, Fake(relay=True), confirmed=True)
    assert report['status'] == 'relay_not_open'
    last = report['steps'][-1]
    assert last['controller_state'] == 'blocked_error' and last['reason'] == 'exception'


def installed(**more):
    return state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', **more)


def test_an_installed_controller_keeps_a_protected_extension_when_no_choice_is_given(paths):
    fake = Fake(initial=installed(relay_listening='ok'))
    report = run(paths, fake)                         # protect_extension=None: keep
    assert report['extension_protection'] == 'protected' and not (paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG).exists()


def test_an_installed_controller_keeps_an_excluded_extension_when_no_choice_is_given(paths):
    flag = paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG
    flag.parent.mkdir(parents=True)
    flag.write_text('x')
    report = run(paths, Fake(initial=installed()))
    assert report['extension_protection'] == 'excluded' and flag.exists()


def test_a_first_install_without_a_choice_excludes_the_extension(paths):
    assert run(paths, Fake(), confirmed=True)['extension_protection'] == 'excluded'


def test_an_explicit_exclusion_wins_even_over_an_installed_protected_state(paths):
    report = run(paths, Fake(initial=installed()), protect_extension=False)
    assert report['extension_protection'] == 'excluded' and (paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG).exists()


def test_installed_controller_is_reused_without_a_build_or_a_uac(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok'))
    report = run(paths, fake)
    assert report['status'] == 'installed' and 'build' not in fake.calls and 'autostart' not in fake.calls
    assert 'start' in fake.calls and 'controller_reused' in names(report)


def test_reinstall_flag_forces_the_build_and_the_uac_again(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok'))
    report = run(paths, fake, reinstall_controller=True)
    assert report['status'] == 'installed' and 'build' in fake.calls and 'autostart' in fake.calls


def test_reinstalling_a_running_controller_stops_it_before_the_swap(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', relay_listening='ok'))
    report = run(paths, fake, reinstall_controller=True)
    assert report['status'] == 'installed'
    assert fake.calls == ['check', 'stop_controller', 'build', 'autostart', 'start', 'wait_relay', 'extension_proxy', 'check']


@pytest.mark.parametrize('existing', [
    installed(),
    state(controller_task='ok'),
    state(controller_files='ok'),
    state(relay_listening='ok'),
])
def test_replacement_stop_failure_preserves_files_and_blocks_retry(paths, existing):
    from claude_reset.elevation import request as uac_request
    flag = paths.state / 'strict-guard' / layout.EXTENSION_EXCLUDED_FLAG
    flag.parent.mkdir(parents=True)
    flag.write_bytes(b'original decision')
    fake = Fake(initial=existing, stop=True)
    result = run(paths, fake, reinstall_controller=True, protect_extension=True)
    assert result['status'] == 'controller_not_stopped'
    assert result['retry_blocked'] is True and claims.blocked(paths)
    assert flag.read_bytes() == b'original decision'
    assert fake.calls == ['check', 'stop_controller']


def test_replacement_closed_port_stops_before_package_and_consent(paths):
    fake = Fake(initial=state(controller_files='ok'))
    result = run(paths, fake, confirmed=True)
    assert result['status'] == 'installed'
    assert fake.calls == ['check', 'stop_controller', 'package', 'consent:True',
                          'build', 'autostart', 'start', 'wait_relay', 'check']


def test_the_replaced_controllers_instance_is_never_mistaken_for_the_new_one(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', relay_listening='ok'))
    run(paths, fake, reinstall_controller=True)
    assert fake.stale_at_start == 'old-instance' and fake.stale_at_wait == 'old-instance'


def test_a_failed_start_after_a_stop_tells_the_owner_how_to_restore_the_network(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', relay_listening='ok'), start=True)
    report = run(paths, fake, reinstall_controller=True)
    last = report['steps'][-1]
    assert report['status'] == 'start_failed' and last['clients_without_network'] is True and last['next'] == NextAction.START_CONTROLLER_THEN_INSTALL


def test_a_controller_that_will_not_stop_aborts_before_the_start(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', relay_listening='ok'), stop=True)
    report = run(paths, fake, reinstall_controller=True)
    assert report['status'] == 'controller_not_stopped' and 'start' not in fake.calls


def test_a_running_installed_controller_is_not_started_again(paths):
    fake = Fake(initial=state(isolation_package='ok', consent='ok', controller_task='ok', controller_files='ok', relay_listening='ok'))
    report = run(paths, fake)
    assert report['status'] == 'installed' and 'start' not in fake.calls and 'wait_relay' not in fake.calls


def test_run_autostart_waits_for_exact_delayed_receipt(paths):
    import json
    from dataclasses import asdict

    from claude_reset.elevation import request as uac
    launched = []
    now = [0]
    def dispatch(request, *, executable):
        assert claims.blocked(paths)
        assert executable == Path('x.exe')
        assert request.state_root == str(paths.state)
        launched.append(request)
        return 42
    folder = paths.state / 'strict-guard'
    folder.mkdir(parents=True)
    (folder / 'autostart-foreign.json').write_text(json.dumps({'finished': True, 'registered': True}))
    def sleep(seconds):
        now[0] += 10
        if now[0] >= 140:
            request = launched[0]
            row = asdict(request) | {'finished': True, 'registered': True}
            Path(request.receipt).write_text(json.dumps(row))
    result = inst.run_autostart(Path('x.exe'), paths, sleep=sleep, clock=lambda: now[0], dispatch=dispatch)
    assert result['passed'] and now[0] == 140
    assert not claims.blocked(paths)


@pytest.mark.parametrize('status', ['unknown', 'reconcile_required', 'denied'])
def test_run_autostart_outcomes_block_following_install_steps(paths, status):
    fake = Fake()
    fake.autostart = lambda exe, selected: {'status': status, 'passed': False,
                                           'retry_blocked': status != 'denied'}
    report = run(paths, fake, confirmed=True)
    assert report['status'] == 'autostart_failed'
    assert report['steps'][-1]['detail'] == status
    assert report['steps'][-1]['retry_blocked'] == (status != 'denied')
    assert 'start' not in fake.calls and 'extension_proxy' not in fake.calls


def test_run_autostart_missing_receipt_prevents_second_dispatch(paths):
    from claude_reset.elevation import request as uac
    calls = []
    dispatch = lambda *a, **k: calls.append(a) or 42
    result = inst.run_autostart(Path('x.exe'), paths, wait_seconds=0, dispatch=dispatch)
    assert result['status'] == 'unknown' and claims.blocked(paths)
    with pytest.raises(FileExistsError):
        inst.run_autostart(Path('x.exe'), paths, wait_seconds=0, dispatch=dispatch)
    assert len(calls) == 1


@pytest.mark.parametrize('entry', ['install', 'restart', 'nested'])
@pytest.mark.parametrize('published', ['relay_open', 'blocked_controller_stopped'])
def test_scheduler_status_never_releases_claim_or_continues_mutations(paths, entry, published):
    from dataclasses import asdict

    from claude_reset.elevation import request as uac
    from claude_reset.safeio import SafetyError
    calls = []

    def start(folder, stale, **kwargs):
        def scheduler(*args, **kwargs):
            calls.append('scheduler')
            request = claims.chain.get().start_request
            row = asdict(request) | {'instance': 'new', 'state': published,
                                    'passed': True, 'persistent_boundary': True,
                                    'live_permit_session': True}
            (folder / 'status.json').write_text(json.dumps(row))
            Path(request.receipt).write_text(json.dumps(row))
            return types.SimpleNamespace(returncode=0)
        return inst.start_controller(folder, stale, run=scheduler, clock=lambda: 0)

    fake = Fake(initial=installed())
    fake.start = start
    if entry == 'install':
        result = run(paths, fake, protect_extension=True)
    elif entry == 'restart':
        result = inst.restart(paths, deps=fake)
    else:
        @claims.serialized('outer', completed={'completed'})
        def chain(p):
            assert start(p.state / 'strict-guard', 'old')
            assert claims.blocked(p)
            # A later receipt and a successful outer return cannot clear this.
            request = claims.chain.get().start_request
            Path(request.receipt).write_text(json.dumps(asdict(request) | {
                'finished': True, 'passed': True}))
            with pytest.raises(SafetyError):
                uac.prepare(p, 'remove')
            return {'status': 'completed'}
        result = chain(paths)
    assert result['retry_blocked'] and claims.blocked(paths)
    assert 'wait_relay' not in fake.calls and 'extension_proxy' not in fake.calls
    assert fake.checks <= 1
    if entry != 'nested':
        assert result['status'] == 'reconcile_required'
    assert calls == ['scheduler']
    assert inst.restart(paths, deps=fake)['status'] == 'pending_elevation'
    assert calls == ['scheduler']

@pytest.mark.parametrize('mode', ['proxy', 'extension', 'unchecked', 'exclude', 'exclude_failed', 'stop_failed', 'save_failed', 'extension_failed'])
def test_restart_configuration_before_new_instance(paths, mode):
    calls = []
    folder = layout.controller(paths)
    folder.mkdir(parents=True)
    flag = folder / layout.EXTENSION_EXCLUDED_FLAG
    flag.write_text('excluded')
    def save(p, *, confirmed):
        calls.append('save')
        assert confirmed and p is paths
        if mode == 'save_failed':
            raise RuntimeError('private-password 9.9.9.9')
        return {'status': 'proxy_saved'}
    draft = types.SimpleNamespace(expected=None if mode == 'unchecked' else {}, save=save)
    fake = types.SimpleNamespace(
        current_instance=lambda _: 'old',
        check=lambda _: state(controller_task='ok', controller_files='ok'),
        stop_controller=lambda _: calls.append('stop') or mode != 'stop_failed',
        extension_proxy=lambda: calls.append('extension') or mode != 'extension_failed',
        exclude_extension=lambda _: calls.append('exclude') or {'passed': mode != 'exclude_failed'},
        start=lambda *a, **kw: calls.append('start') or True,
        wait_relay=lambda *a: (True, {'state': 'relay_open'}))
    kwargs = {'protect_extension': mode not in ('exclude', 'exclude_failed')} if mode in ('extension', 'exclude', 'exclude_failed', 'extension_failed') else {'proxy_draft': draft}
    report = inst.restart(paths, deps=fake, **kwargs)
    if mode == 'unchecked':
        assert not calls and flag.exists()
    elif mode == 'stop_failed':
        assert calls == ['stop'] and flag.exists()
    elif mode == 'save_failed':
        assert calls == ['stop', 'save'] and report['retry_blocked']
    elif mode == 'exclude_failed':
        assert calls == ['stop', 'exclude'] and report['retry_blocked']
    elif mode == 'exclude':
        assert calls == ['stop', 'exclude', 'start'] and flag.exists()
        assert report['extension_protection'] == 'excluded'
    elif mode == 'extension_failed':
        assert calls == ['stop', 'extension'] and report['retry_blocked']
    else:
        assert calls == ['stop', 'extension' if mode == 'extension' else 'save', 'start']
        assert report['status'] == 'restarted'
        assert flag.exists() == (mode != 'extension')


def test_an_interrupt_is_not_reported_as_a_failed_install(paths):
    class Interrupted(Fake):
        def check(self, paths):
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        run(paths, Interrupted(), confirmed=True)
