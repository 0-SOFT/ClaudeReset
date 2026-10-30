import copy

import pytest

from claude_reset.network import l1_check as check

GOOD = {
    'os_build': 26200, 'os_caption': 'Windows 11 Pro', 'cpu_architecture': 9, 'elevated': False,
    'dev_mode': {'allow_development': None, 'allow_all_trusted': None}, 'bfe': 'Running',
    'desktop': {'version': '3.6556.2.0', 'family': 'Claude_pzs8sxrjxfjjc'}, 'isolation_package': None,
    'tasks': {}, 'listeners': {'25080': False, '25081': False, '25082': False},
    'wininet_proxy': False, 'proxy_variables': [], 'program_files': [], 'free_gb': 40.0,
    'cowork_service': 'Running', 'allow_unsigned': True, 'cli': {'present': False, 'reviewed_hash': False},
    'extensions': ['2.1.311'], 'consent': False, 'connection_profile': False, 'frozen': False, 'python': '3.12.10',
}
INSTALLED = dict(GOOD, isolation_package='ClaudeReset.NetworkIsolation_79st3xwgefr0c', consent=True, connection_profile=True,
                 tasks={'ClaudeReset-SnowProxy': 'Running', 'ClaudeReset L1 Controller': 'Running'},
                 listeners={'25080': True, '25081': True, '25082': True}, program_files=['ClaudeReset.exe'])


def facts(**changes):
    result = copy.deepcopy(GOOD)
    result.update(changes)
    return result


def status(report, identifier):
    return next(r['status'] for r in report['checks'] if r['id'] == identifier)


def test_clean_pc_is_ready_to_install_and_nothing_is_claimed_installed():
    report = check.evaluate(GOOD)
    assert report['status'] == 'ready_to_install' and report['can_install'] and report['protection'] == 'not_installed'
    assert report['blockers'] == [] and report['changes_system'] is False and report['network_requests'] == 0
    assert status(report, 'client_standalone_cli') == 'info'          # an absent CLI is not an obstacle
    assert status(report, 'isolation_package') == 'missing'


def test_fully_installed_pc_reports_installed():
    report = check.evaluate(INSTALLED)
    assert report['status'] == 'installed' and report['protection'] == 'installed' and report['next_steps'] == []


def test_half_installed_pc_is_partial_not_installed():
    report = check.evaluate(facts(isolation_package='ClaudeReset.NetworkIsolation_x'))
    assert report['protection'] == 'partial' and report['status'] == 'partial'


@pytest.mark.parametrize('changes, blocker', [
    ({'os_build': 19045}, 'windows'),
    ({'cpu_architecture': 12}, 'windows'),
    ({'bfe': 'Stopped'}, 'base_filtering_engine'),
    ({'bfe': None}, 'base_filtering_engine'),
    ({'free_gb': 0.2}, 'disk_space'),
    ({'desktop': None, 'extensions': []}, 'claude_client'),
])
def test_preconditions_no_install_step_can_create_block(changes, blocker):
    report = check.evaluate(facts(**changes))
    assert report['can_install'] is False and blocker in report['blockers'] and report['status'] == 'blocked'
    assert report['next_steps'] and report['next_steps'][0] == 'check.fix'


def test_low_but_usable_disk_is_a_warning_only():
    report = check.evaluate(facts(free_gb=1.2))
    assert status(report, 'disk_space') == 'warn' and report['can_install']


def test_unreviewed_cli_hash_warns_and_does_not_block():
    report = check.evaluate(facts(cli={'present': True, 'reviewed_hash': False}))
    assert status(report, 'client_standalone_cli') == 'warn' and report['can_install']


def test_one_client_is_enough():
    assert check.evaluate(facts(desktop=None))['can_install']
    assert check.evaluate(facts(extensions=[]))['can_install']
    assert check.evaluate(facts(desktop=None, extensions=[], cli={'present': True, 'reviewed_hash': True}))['can_install']


def test_general_proxy_is_reported_but_never_blocks():
    report = check.evaluate(facts(wininet_proxy=True, proxy_variables=['User:HTTPS_PROXY']))
    assert status(report, 'ordinary_proxy') == 'warn' and report['can_install']


def test_failed_inspection_concludes_nothing():
    report = check.evaluate({'inspection_failed': True})
    assert report['status'] == 'unknown' and report['can_install'] is None and report['protection'] == 'unknown'


def test_unreadable_disk_is_unknown_not_ok():
    assert status(check.evaluate(facts(free_gb=None)), 'disk_space') == 'unknown'


def test_cli_exit_semantics_follow_can_install():
    class Paths:
        pass
    original = check.collect
    check.collect = lambda paths: copy.deepcopy(GOOD)
    try:
        assert check.check(Paths())['passed'] is True
        check.collect = lambda paths: dict(copy.deepcopy(GOOD), bfe='Stopped')
        assert check.check(Paths())['passed'] is False
    finally:
        check.collect = original


def test_missing_unsigned_registration_blocks_only_while_the_package_is_absent():
    blocked = check.evaluate(facts(allow_unsigned=False))
    assert blocked['can_install'] is False and 'unsigned_package_registration' in blocked['blockers']
    assert check.evaluate(facts(allow_unsigned=None))['can_install'] is True
    assert check.evaluate(facts(allow_unsigned=False, isolation_package='ClaudeReset.NetworkIsolation_x'))['can_install'] is True
