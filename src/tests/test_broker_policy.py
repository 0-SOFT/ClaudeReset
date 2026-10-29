import pytest
from claude_reset import broker_policy as policy
from claude_reset.safeio import SafetyError


def test_closed_policy_is_provider_independent_and_keeps_whole_local_drives():
    result = policy.closed_policy('ClaudeReset.Tools', ['D:\\', 'C:\\'])
    assert 'NetworkAccess=*,Block\n' in result and 'Allow;' not in result
    assert 'OpenFilePath=C:\\*' in result and 'OpenFilePath=D:\\*' in result
    assert 'snow' not in result.lower() and 'GlobalSettings' not in result
    assert 'NoSecurityIsolation=n' in result and 'DisableObjectFilter=n' in result
    assert 'ClosedIpcPath=\\RPC Control\\DNSResolver' in result
    assert 'UseRuleSpecificity=n' in result and 'RestrictDevices=n' in result
    assert 'ClosedFilePath=\\Device\\Nsi*' in result
    assert 'ClaudeResetStrictBroker=y\n' in result


@pytest.mark.parametrize('box,roots', [('DefaultBox', ['C:\\']), ('ClaudeReset.Bad\nEnabled=n', ['C:\\']),
    ('ClaudeReset.Test', ['C:\\work\\']), ('ClaudeReset.Test', ['\\\\server\\share']),
    ('ClaudeReset.Test', ['C:\\\nNetworkAccess=Allow']), ('ClaudeReset.Test', []),
    ('ClaudeReset.Test', ['C:\\', 'c:\\'])])
def test_policy_cannot_expand_to_foreign_boxes_or_injected_scope(box, roots):
    with pytest.raises(SafetyError):policy.closed_policy(box, roots)


def test_readback_rejects_inherited_allow_and_never_becomes_full_permission():
    with pytest.raises(SafetyError):policy.verify_network_rules(['*,Block', '*,Allow'])
    result = policy.verify_network_rules(['*,Block', policy.gate_rule(12345)], gateway_port=12345)
    assert not result['full_tunnel_verified'] and not result['production_open_supported']
    with pytest.raises(SafetyError):policy.verify_network_rules(['*,Block', policy.gate_rule(12346)], gateway_port=12345)


@pytest.mark.parametrize('port', [True, 0, 65536, '443'])
def test_gateway_port_must_be_one_exact_integer(port):
    with pytest.raises(SafetyError):policy.gate_rule(port)


def effective_settings():
    result={key:[value] for key,value in policy.ISOLATION_SETTINGS.items()}
    result.update(NetworkEnableWFP=['y'],NetworkAccess=['*,Block'])
    for key in policy.FORBIDDEN_SETTINGS:result[key]=[]
    return result


@pytest.mark.parametrize('key,value',[('OriginalToken',['y']),('NoSecurityIsolation',['y']),
    ('ClaudeResetStrictBroker',['n']),('ClaudeResetStrictBroker',[]),
    ('UnfilteredToken',['y']),('ReplicateToken',['y']),('UnstrippedToken',['y']),('KeepTokenIntegrity',['y']),
    ('Template',['WindowsExplorer']),('IncludeBox',['C:\\external.ini']),
    ('DropAdminRights',[]),('NetworkEnableWFP',['n']),('OpenPipePath',['*']),
    ('BreakoutProcess',['chrome.exe']),('OpenWinClass',['*']),('DisableWinNtHook',['NtConnectPort'])])
def test_inherited_escape_or_missing_readback_cannot_pass(key,value):
    actual=effective_settings();actual[key]=value
    with pytest.raises(SafetyError):policy.verify_effective_settings(actual,runtime_open_windows=[])


def test_matching_readback_keeps_broker_and_client_acceptance_required():
    r=policy.verify_effective_settings(effective_settings(),runtime_open_windows=[])
    assert not r['full_tunnel_verified'] and not r['production_open_supported']
    assert 'lsa_lookup_bootstrap' in r['remaining']


@pytest.mark.parametrize('key',['OpenIpcPath','ReadIpcPath','ApproveWinNtSysCall'])
def test_extra_ipc_or_syscall_permissions_refused(key):
    actual=effective_settings();actual[key]=['*']
    with pytest.raises(SafetyError):
        policy.verify_effective_settings(actual,runtime_open_windows=[])


@pytest.mark.parametrize('runtime',[None,['Shell_TrayWnd'],{'status':-1},''])
def test_empty_queryconf_does_not_hide_runtime_default_window_exceptions(runtime):
    with pytest.raises(SafetyError):
        policy.verify_effective_settings(effective_settings(),runtime_open_windows=runtime)
