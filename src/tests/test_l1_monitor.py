import json

from claude_reset import l1_monitor as monitor


def failed(status):
    return {'passed': False, 'measurements': {'router': {'status': 'not_requested'}, 'local': {'status': status}}}


def test_a_passing_probe_resets_the_failure_count():
    assert monitor.probe_verdict({'passed': True}, 4) == (0, None)


def test_single_failed_measurement_is_tolerated():
    assert monitor.probe_verdict(failed('measurement_failed'), 0) == (1, None)


def test_consecutive_failed_measurements_stop_after_the_tolerance():
    failures, reason = 0, None
    for _ in range(monitor.PROBE_TOLERANCE - 1):
        failures, reason = monitor.probe_verdict(failed('measurement_failed'), failures)
        assert reason is None
    assert monitor.probe_verdict(failed('measurement_failed'), failures)[1] == 'exit_probe_failed'


def test_a_measured_wrong_exit_stops_at_once():
    assert monitor.probe_verdict(failed('exit_mismatch'), 0)[1] == 'exit_mismatch'


def test_an_unrecognised_result_is_not_tolerated():
    assert monitor.probe_verdict({'passed': False}, 0)[1] == 'exit_mismatch'
    assert monitor.probe_verdict({'passed': False, 'measurements': {'local': {'status': 'surprise'}}}, 0)[1] == 'exit_mismatch'


def test_monitor_errors_are_tolerated_then_stop():
    failures, reason = 0, None
    for _ in range(monitor.PROBE_TOLERANCE - 1):
        failures, reason = monitor.monitor_error(failures)
        assert reason is None
    assert monitor.monitor_error(failures) == (monitor.PROBE_TOLERANCE, 'monitor_error')


def test_exit_record_is_bounded_and_has_only_the_named_fields(tmp_path):
    monitor.record_exit(tmp_path, {'instance': 'a' * 32, 'state': 'blocked_controller_stopped', 'stop_reason': 'exit_probe_failed',
                                   'proxy_url': 'http://secret', 'error_type': None})
    row = json.loads((tmp_path / monitor.HISTORY).read_text('ascii'))
    assert set(row) == {'utc', 'instance', 'state', 'stop_reason', 'error_type'} and row['stop_reason'] == 'exit_probe_failed'
    (tmp_path / monitor.HISTORY).write_bytes(b'x' * (monitor.HISTORY_LIMIT + 1))
    monitor.record_exit(tmp_path, {'state': 'x'})
    assert (tmp_path / monitor.HISTORY).stat().st_size < 1000


def test_unwritable_folder_never_raises(tmp_path):
    monitor.record_exit(tmp_path / 'missing', {'state': 'x'})
