import json
import pytest
from claude_reset import gateway_profile as gp
from claude_reset.safeio import SafetyError


def profile():
    return dict(schema=2,protocol='socks5',backend_port=1080,listen_port=25083,engine_pid=1234,
        engine_start_utc_ticks=639285408000000000,engine_path=r'C:\Tunnel\engine.exe',
        engine_sha256='a'*64,engine_config_path=r'C:\Tunnel\config.json',engine_config_sha256='b'*64,
        generation='d'*32,controller_pid=4321,controller_start_utc_ticks=639285408000000001,
        controller_path=r'C:\Runtime\ClaudeResetRuntime.exe',controller_sha256='e'*64)


def test_provider_independent_profile_and_prepared_plan_never_open_clients():
    p=profile();assert gp.decode(gp.encode(p))==p
    plan=gp.installation_plan(p,'c'*64)
    assert plan['requires_administrator'] and not plan['client_network_opened']
    assert plan['backend_service']=='ClaudeResetBackend' and not plan['backend_service_installed_verified']
    assert not plan['backend_tunnel_attested'] and not plan['full_tunnel_verified']
    assert 'snow' not in json.dumps(plan)


@pytest.mark.parametrize('key,value',[('schema',True),('engine_pid',False),('backend_port',1.0),
    ('engine_start_utc_ticks','639285408000000000'),('protocol','direct'),('listen_port',1080),
    ('engine_pid',0),('listen_port',49152),('engine_sha256','a'*64+'\n'),('unknown',1),
    ('schema',1),('controller_pid',1234),('generation','../reuse'),('controller_path',r'C:\Runtime\other.exe')])
def test_ambiguous_or_expanding_configuration_is_rejected(key,value):
    p=profile();p[key]=value
    with pytest.raises(SafetyError):gp.validate(p)


@pytest.mark.parametrize('path',[r'\\host\share\config',r'\\?\C:\config',r'C:config',r'\config',
    r'C:\file:stream',r'C:\a\..\config',r'C:\a\.\config',r'C:\file.',r'C:\file ',
    'C:/config','C:\\config\n','C:\\',r'C:\\config',r'C:\CON.exe',r'C:\COM1\config',r'C:\NUL'])
def test_paths_cannot_trigger_remote_or_device_access(path):
    with pytest.raises(SafetyError):gp.local_path(path)


def test_duplicate_keys_and_oversized_config_rejected():
    data=gp.encode(profile())
    with pytest.raises(SafetyError):gp.decode(b'{"schema":1,'+data[1:])
    with pytest.raises(SafetyError):gp.decode(b' '*16385)
