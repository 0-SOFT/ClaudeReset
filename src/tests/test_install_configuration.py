import hashlib
import json
import pytest
from claude_reset import install_configuration as c
from claude_reset.install_payload import FILES
from claude_reset.safeio import SafetyError
from test_backend_spec import inputs


def fixture():
    spec,data=inputs()
    payload={name:dict(sha256='d'*64,bytes=1) for name in FILES}
    for field,name in [('engine_sha256','Engine/engine.exe'),('runtime_sha256','Runtime/ClaudeResetRuntime.exe'),
                       ('gateway_sha256','Gateway/ClaudeResetGateway.exe')]:payload[name]['sha256']=spec[field]
    return spec,data,payload


def test_complete_initial_configuration_is_closed_and_payload_bound():
    spec,data,payload=fixture()
    value=c.compile_configuration(json.dumps(spec).encode(),data,payload,['C:\\','D:\\'])
    files=dict(value.files())
    assert set(files)==set(c.FILES)
    assert files['Engine/engine.json']==data
    assert json.loads(files['Backend/backend.json'])==spec
    text=files['Policy/Sandboxie.ini'].decode('utf-16')
    assert text.startswith('[GlobalSettings]\nNetworkEnableWFP=y\nEnableObjectFiltering=y\n')
    assert text.count('NetworkAccess=*,Block')==len(c.BOXES)
    assert 'Allow;' not in text and 'Template=' not in text and 'IncludeBox=' not in text
    assert text.count('OpenFilePath=D:\\*')==len(c.BOXES)
    assert value.report()['effective_policy_verified'] is False
    assert value.report()['cowork_guest_boundary_verified'] is False
    assert not value.report()['client_admission']


@pytest.mark.parametrize('field',['engine_sha256','runtime_sha256','gateway_sha256'])
def test_mixed_payload_and_config_are_rejected(field):
    spec,data,payload=fixture();spec[field]='e'*64
    with pytest.raises(SafetyError):c.compile_configuration(json.dumps(spec).encode(),data,payload,['C:\\'])


@pytest.mark.parametrize('roots',[[],['C:\\work\\'],['\\\\server\\share'],['C:\\','c:\\'],['C:\\\nTemplate=bad']])
def test_no_folder_whitelist_network_share_or_policy_injection(roots):
    spec,data,payload=fixture()
    with pytest.raises(SafetyError):c.compile_configuration(json.dumps(spec).encode(),data,payload,roots)


def test_report_and_repr_do_not_contain_private_config():
    spec,data,payload=fixture()
    value=c.compile_configuration(json.dumps(spec).encode(),data,payload,['C:\\'])
    diagnostic=repr(value)+json.dumps(value.report())
    assert spec['peer_address'] not in diagnostic
    assert spec['profile_id'] not in diagnostic
    assert 'uuid' not in diagnostic and 'public_key' not in diagnostic
    assert value.report()['files']['Engine/engine.json']['sha256']==hashlib.sha256(data).hexdigest()


def test_modified_engine_bytes_fail_before_preparation():
    spec,data,payload=fixture()
    with pytest.raises(SafetyError):c.compile_configuration(json.dumps(spec).encode(),data+b' ',payload,['C:\\'])
