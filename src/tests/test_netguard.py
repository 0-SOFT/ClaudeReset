import base64
import ctypes
import hashlib
import json
import re
import socket
import threading
from pathlib import Path
import pytest
from test_reset import FakeCrypto
from claude_reset import netguard, wfp
from claude_reset.safeio import SafetyError


def guard_layout(tmp_path):
    base = tmp_path / 'work/snow-isolation'
    base.mkdir(parents=True)
    (base / 'proxy_worker.py').write_text('', encoding='utf-8')
    python = tmp_path / '.venv/Scripts/pythonw.exe'
    return base, python


def task(python, arguments, **extra):
    return {'state': 'Running', 'enabled': True, 'run_level': 'Limited',
            'actions': [{'execute': str(python), 'arguments': arguments}], **extra}


@pytest.mark.skipif(not hasattr(ctypes, 'windll'), reason='needs Windows PowerShell')
def test_absent_guard_task_reports_not_installed_instead_of_inspection_failure(monkeypatch):
    monkeypatch.setattr(netguard, 'TASK_NAME', 'ClaudeReset-NoSuchTask-for-tests')
    assert netguard.locate_guard() is None
    report = netguard.status(None)
    assert report['status'] == 'not_installed' and report['installed'] is False


def test_guard_is_located_only_from_the_reviewed_task_action(tmp_path):
    base, python = guard_layout(tmp_path)
    guard = netguard.guard_from_task(task(python, str(base / 'proxy_worker.py')))
    assert guard.base == base and guard.work == base.parent
    assert guard.task == {'state': 'Running', 'enabled': True, 'run_level': 'Limited'}


@pytest.mark.parametrize('change', ['extra_argument', 'console_python', 'other_script', 'relative', 'two_actions'])
def test_unexpected_task_actions_are_refused(tmp_path, change):
    base, python = guard_layout(tmp_path)
    script = str(base / 'proxy_worker.py')
    value = {'extra_argument': task(python, f'"{script}" --direct'),
             'console_python': task(python.with_name('python.exe'), script),
             'other_script': task(python, str(base / 'other.py')),
             'relative': task(python, 'proxy_worker.py'),
             'two_actions': {'actions': [{'execute': str(python), 'arguments': script}] * 2}}[change]
    with pytest.raises(SafetyError, match='task actions'):
        netguard.guard_from_task(value)


def reviewed_config():
    return {'outbounds': [{'type': 'vless', 'tag': 'snow-only', 'server': '203.0.113.7', 'uuid': 'secret'}],
            'route': {'final': 'snow-only'},
            'inbounds': [{'type': 'http', 'tag': 'claude-loopback', 'listen': '127.0.0.1', 'listen_port': 25080}],
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:25081', 'secret': 'x'}},
            'log': {'disabled': True}}


def test_proxy_config_shape_never_returns_server_or_credentials():
    result = netguard.check_proxy_config(reviewed_config())
    assert result['passed'] is True
    assert all(isinstance(v, bool) for v in result.values())
    assert 'secret' not in json.dumps(result) and '203.0.113.7' not in json.dumps(result)


@pytest.mark.parametrize('change', ['direct_outbound', 'direct_final', 'public_inbound', 'public_controller', 'logging'])
def test_proxy_config_without_fail_closed_shape_is_rejected(change):
    cfg = reviewed_config()
    if change == 'direct_outbound':
        cfg['outbounds'].append({'type': 'direct', 'tag': 'direct'})
    elif change == 'direct_final':
        cfg['route'] = {'final': 'direct'}
    elif change == 'public_inbound':
        cfg['inbounds'][0]['listen'] = '0.0.0.0'
    elif change == 'public_controller':
        cfg['experimental']['clash_api']['external_controller'] = '0.0.0.0:25081'
    else:
        cfg['log'] = {'level': 'debug'}
    assert netguard.check_proxy_config(cfg)['passed'] is False


def test_listeners_must_be_loopback_and_owned_by_engine():
    good = [{'port': 25080, 'address': '127.0.0.1', 'pid': 7}, {'port': 25081, 'address': '127.0.0.1', 'pid': 7}]
    assert netguard.check_listeners(good, 7)['passed'] is True
    assert netguard.check_listeners(good + [{'port': 25080, 'address': '0.0.0.0', 'pid': 7}], 7)['loopback_only'] is False
    assert netguard.check_listeners(good, 8)['owned_by_engine'] is False
    assert netguard.check_listeners(good[:1], 7)['passed'] is False


def sealed_guard(tmp_path, plain):
    base, python = guard_layout(tmp_path)
    engine = base / 'engine/sing-box.exe'
    engine.parent.mkdir()
    engine.write_bytes(b'engine')
    (base / 'snow-config.dpapi').write_bytes(FakeCrypto().encrypt(plain))
    profile = {'engine_path': str(engine), 'engine_sha256': hashlib.sha256(b'engine').hexdigest(),
               'config_sha256': hashlib.sha256(json.dumps(reviewed_config()).encode()).hexdigest(), 'proxy_url': netguard.PROXY_URL}
    (base / 'profile.json').write_text(json.dumps(profile), encoding='utf-8')
    return netguard.guard_from_task(task(python, str(base / 'proxy_worker.py')))


def test_sealed_config_is_checked_against_reviewed_hash(tmp_path):
    guard = sealed_guard(tmp_path, json.dumps(reviewed_config()).encode())
    assert netguard.check_engine_and_config(guard, crypto=FakeCrypto())['passed'] is True


def test_modified_sealed_config_fails_even_with_valid_shape(tmp_path):
    cfg = reviewed_config()
    cfg['outbounds'][0]['server'] = '198.51.100.1'
    guard = sealed_guard(tmp_path / 'changed', json.dumps(cfg).encode())
    result = netguard.check_engine_and_config(guard, crypto=FakeCrypto())
    assert result['config_reviewed'] is False and result['passed'] is False


def fake_worker(replies, *, token_override=None, wrong_peer_first=False):
    seen = {}

    def start(port, token):
        def run():
            if wrong_peer_first:
                with socket.create_connection(('127.0.0.1', port)) as foreign:
                    foreign.sendall(b'0' * 32 + b'\n')
            with socket.create_connection(('127.0.0.1', port)) as peer, peer.makefile('rwb') as stream:
                stream.write((token_override or token).encode() + b'\n')
                stream.flush()
                seen['script'] = base64.b64decode(stream.readline()).decode()
                stream.write(json.dumps(replies).encode() + b'\n')
                stream.flush()
        threading.Thread(target=run, daemon=True).start()
    return start, seen


def test_loopback_exchange_ignores_foreign_peers():
    start, seen = fake_worker({'family': 'Owned', 'tcp_v4': '10013'}, wrong_peer_first=True)
    assert netguard.exchange(start, 'Write-Output 1', timeout=5) == {'family': 'Owned', 'tcp_v4': '10013'}
    assert seen['script'] == 'Write-Output 1'


def test_loopback_exchange_rejects_unexpected_fields():
    start, _ = fake_worker({'family': 'Owned', 'token': 'secret'})
    with pytest.raises(SafetyError, match='invalid result'):
        netguard.exchange(start, 'x', timeout=5)


def test_loopback_exchange_times_out_without_worker():
    with pytest.raises(SafetyError, match='did not report'):
        netguard.exchange(lambda port, token: None, 'x', timeout=0.3)


def test_bootstrap_carries_only_port_and_token():
    stub = netguard.bootstrap(40000, 'a' * 32)
    assert "'127.0.0.1',40000" in stub and "'" + 'a' * 32 + "'" in stub and len(stub) < 600


@pytest.mark.parametrize('args,expected', [
    (['--user-data-dir=C:\\Work\\Profile'], True), (['--user-data-dir', 'c:\\work\\profile'], True),
    (['--user-data-dir=C:\\Work\\Profile2'], False), (['--profile-directory=Default'], False)])
def test_running_instance_matches_exact_user_data_dir(args, expected):
    assert netguard.uses_directory(args, Path('C:/Work/Profile')) is expected


def test_command_line_split_handles_quoted_paths():
    assert netguard.split_command_line('"C:\\Program Files\\x.exe" --user-data-dir="C:\\a b"') == ['C:\\Program Files\\x.exe', '--user-data-dir=C:\\a b']


def chrome_profile(guard, run='a' * 32, geolocation=2, exceptions=None):
    directory = guard.work / 'claude-only-chrome' / run
    (directory / 'Default').mkdir(parents=True)
    (directory / 'claude-reset-profile.json').write_text(json.dumps({'created_by': 'ClaudeReset', 'run': run}), encoding='utf-8')
    marker = hashlib.sha256((directory / 'claude-reset-profile.json').read_bytes()).hexdigest()
    (directory / netguard.CHROME_MARK).write_text(json.dumps({'run': run, 'scope': 'claude_only', 'source_was_closed': True,
                                                             'source_marker_sha256': marker}), encoding='utf-8')
    prefs = {'profile': {'default_content_setting_values': {'geolocation': geolocation},
                         'content_settings': {'exceptions': {'geolocation': exceptions or {}}}}}
    (directory / 'Default/Preferences').write_text(json.dumps(prefs), encoding='utf-8')
    return directory


def test_dedicated_chrome_requires_single_reviewed_profile(tmp_path):
    base, python = guard_layout(tmp_path)
    guard = netguard.guard_from_task(task(python, str(base / 'proxy_worker.py')))
    directory = chrome_profile(guard)
    (guard.work / 'claude-only-chrome/selftest-1').mkdir()
    assert netguard.check_dedicated_chrome(guard) == directory
    chrome_profile(guard, run='b' * 32)
    with pytest.raises(SafetyError, match='exactly one'):
        netguard.check_dedicated_chrome(guard)


def test_dedicated_chrome_with_allowed_geolocation_is_refused(tmp_path):
    base, python = guard_layout(tmp_path)
    guard = netguard.guard_from_task(task(python, str(base / 'proxy_worker.py')))
    chrome_profile(guard, exceptions={'https://claude.ai:443,*': {'setting': 1}})
    with pytest.raises(SafetyError, match='geolocation'):
        netguard.check_dedicated_chrome(guard)


@pytest.mark.parametrize('target', ['chrome', 'vscode'])
def test_legacy_launch_is_closed_even_if_diagnostic_gate_would_pass(monkeypatch, target):
    from claude_reset import connections
    monkeypatch.setattr(connections, 'launch_gate', lambda _: {'passed': True})
    def forbidden(*args, **kwargs):
        raise AssertionError('Blocked launch must not inspect profiles, probe, or start processes')
    for name in ('locate_guard', 'launch_executable', 'check_dedicated_chrome',
                 'check_dedicated_editor', 'running_instances', 'in_package', 'ps_json', 'https_status'):
        monkeypatch.setattr(netguard, name, forbidden)
    result = netguard.guarded_launch(object(), target)
    assert result['status'] == 'blocked_installed_acceptance_required'
    assert result['passed'] is False and result['client_admission'] is False
    assert result['process_started'] is False and result['settings_changed'] is False
    assert result['network_requests'] == 0 and result['current_sessions_closed'] is False
    assert result['functional_acceptance_pending'] is True


def test_legacy_launch_rejects_unknown_target_without_side_effects():
    with pytest.raises(SafetyError, match='Unknown guarded launch target'):
        netguard.guarded_launch(None, 'ordinary-browser')


SYSTEM_SID = bytes([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])


def synthetic_filter(expected, *, identity, mark=None, loopback_match=wfp.FWP_MATCH_FLAGS_NONE_SET, flags=wfp.FWPM_FILTER_FLAG_PERSISTENT):
    keep = []
    f = wfp.FILTER()
    f.filterKey, f.subLayerKey, f.layerKey = wfp.GUID.of(expected.key), wfp.GUID.of(expected.sublayer), wfp.LAYERS[expected.family]
    f.action.type, f.flags, f.filterId = wfp.FWP_ACTION_BLOCK, flags, 99
    data = mark if mark is not None else expected.mark
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    keep.append(buffer)
    f.providerData = wfp.BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    conditions = (wfp.CONDITION * 2)()
    keep.append(conditions)
    if expected.kind == 'package':
        sid = ctypes.create_string_buffer(identity, len(identity))
        keep.append(sid)
        conditions[0].fieldKey, conditions[0].conditionValue.type = wfp.FIELD_PACKAGE_ID, wfp.FWP_SID
        conditions[0].conditionValue.value.ptr = ctypes.cast(sid, ctypes.c_void_p).value
    else:
        raw = (identity + '\0').encode('utf-16-le')
        text = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        blob = wfp.BLOB(len(raw), ctypes.cast(text, ctypes.POINTER(ctypes.c_ubyte)))
        keep += [text, blob]
        conditions[0].fieldKey, conditions[0].conditionValue.type = wfp.FIELD_APP_ID, wfp.FWP_BYTE_BLOB_TYPE
        conditions[0].conditionValue.value.ptr = ctypes.cast(ctypes.pointer(blob), ctypes.c_void_p).value
    conditions[1].fieldKey, conditions[1].matchType = wfp.FIELD_FLAGS, loopback_match
    conditions[1].conditionValue.type, conditions[1].conditionValue.value.u32 = wfp.FWP_UINT32, wfp.FWP_CONDITION_FLAG_IS_LOOPBACK
    f.numFilterConditions, f.filterCondition = 2, conditions
    return f, keep


def owned(target, family='v4'):
    return next(x for x in wfp.OWNED_FILTERS if x.target == target and x.family == family)


def test_ten_owned_filters_have_distinct_keys():
    assert len(wfp.OWNED_FILTERS) == 10 and len({x.key for x in wfp.OWNED_FILTERS}) == 10
    assert {x.group for x in wfp.OWNED_FILTERS} == {'desktop', 'native_cli', 'owned_package'}


def test_package_filter_is_matched_to_derived_sid():
    expected = owned('owned_package')
    f, keep = synthetic_filter(expected, identity=SYSTEM_SID)
    row = wfp.describe(f, expected, sid_of=lambda family: SYSTEM_SID)
    assert row['package_family'] == expected.package_family and row['action'] == 'block_non_loopback'
    with pytest.raises(SafetyError, match='unexpected package'):
        wfp.describe(f, expected, sid_of=lambda family: bytes([1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0]))


def test_app_filter_reports_covered_path():
    kernel = ctypes.WinDLL('kernel32')
    buffer = ctypes.create_unicode_buffer(1024)
    assert kernel.QueryDosDeviceW('C:', buffer, 1024)
    expected = owned('standalone_cli', 'v6')
    f, keep = synthetic_filter(expected, identity=buffer.value.lower() + '\\windows\\system32\\cmd.exe')
    row = wfp.describe(f, expected)
    assert row['covered_path'].lower() == 'c:\\windows\\system32\\cmd.exe' and row['covered_path_exists'] is True


@pytest.mark.parametrize('change', ['mark', 'loopback', 'disabled'])
def test_altered_owned_filter_is_not_accepted(change):
    expected = owned('desktop_package')
    f, keep = synthetic_filter(expected, identity=SYSTEM_SID, mark=b'Other' if change == 'mark' else None,
                               loopback_match=wfp.FWP_MATCH_EQUAL if change == 'loopback' else wfp.FWP_MATCH_FLAGS_NONE_SET,
                               flags=wfp.FWPM_FILTER_FLAG_PERSISTENT | (wfp.FWPM_FILTER_FLAG_DISABLED if change == 'disabled' else 0))
    with pytest.raises(SafetyError):
        wfp.describe(f, expected, sid_of=lambda family: SYSTEM_SID)


def test_filter_read_without_elevation_reports_requirement(monkeypatch):
    monkeypatch.setattr(ctypes.windll.shell32, 'IsUserAnAdmin', lambda: 0)
    result = wfp.inspect_owned_filters()
    assert result == {'administrator': False, 'read_only': True, 'filters_changed': False, 'firewall_profiles_changed': False,
                      'status': 'administrator_required', 'passed': False}


def test_cli_guard_status_exit_code_reflects_result(monkeypatch, capsys, tmp_path):
    from claude_reset import app
    from claude_reset.core import Paths
    paths = Paths(tmp_path/'home', tmp_path/'roaming', tmp_path/'local', tmp_path/'state')
    monkeypatch.setattr(app.Paths, 'current', lambda: paths)
    monkeypatch.setattr(netguard, 'status', lambda paths: {'status': 'protection_degraded', 'passed': False})
    assert app.main(['--network-guard-status']) == 2
    assert json.loads(capsys.readouterr().out)['status'] == 'protection_degraded'
