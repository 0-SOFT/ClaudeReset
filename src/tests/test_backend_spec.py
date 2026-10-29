import hashlib
import json
import pytest
from test_backend_attestation import config
from claude_reset import backend_spec as b
from claude_reset.safeio import SafetyError


def inputs():
    data = json.dumps(config()).encode()
    return {'schema': 1, 'profile_id': 'a'*32, 'engine_version': '1.14.4',
            'engine_sha256': b.ENGINES['1.14.4'], 'engine_config_sha256': hashlib.sha256(data).hexdigest(),
            'runtime_sha256': 'b'*64, 'gateway_sha256': 'c'*64, 'peer_address': '1.1.1.1',
            'peer_port': 443, 'backend_port': 1080, 'gateway_port': 1081, 'expected_exit_ips': ['8.8.8.8']}, data


def test_exact_bytes_and_endpoint_binding():
    spec, data = inputs()
    assert b.bind_config(b.decode(json.dumps(spec).encode()), data) == 'socks5'
    with pytest.raises(SafetyError): b.bind_config(spec, data + b' ')
    for key, value in [('peer_address', '9.9.9.9'), ('peer_port', 8443), ('backend_port', 2080)]:
        with pytest.raises(SafetyError): b.bind_config({**spec, key: value}, data)


@pytest.mark.parametrize('change', [
    {'engine_sha256': 'a'*64}, {'engine_version': '1.12.0'}, {'engine_version': []},
    {'schema': True}, {'gateway_port': 1080}, {'peer_port': True}, {'backend_port': 80},
    {'peer_address': 'proxy.invalid'}, {'peer_address': '127.0.0.1'},
    {'expected_exit_ips': []}, {'expected_exit_ips': ['8.8.8.8', '8.8.8.8']},
    {'expected_exit_ips': [123]}, {'expected_exit_ips': ['fe80::1%1']},
    {'command': 'cmd.exe'}, {'engine_path': 'C:\\other.exe'}, {'profile_id': '../other'},
])
def test_no_self_authorized_engine_or_implicit_endpoint(change):
    spec, _ = inputs()
    with pytest.raises(SafetyError): b.decode(json.dumps({**spec, **change}).encode())


def test_service_does_not_allow_extra_controller_listener():
    spec, _ = inputs(); value = config()
    value['experimental'] = {'clash_api': {'external_controller': '127.0.0.1:2080', 'secret': 'fixture'}}
    data = json.dumps(value).encode(); spec['engine_config_sha256'] = hashlib.sha256(data).hexdigest()
    with pytest.raises(SafetyError): b.bind_config(spec, data)


@pytest.mark.parametrize('data', [b'{"x":1,"x":2}', b'NaN', b'Infinity', b'{'*2000, b'x'*65537], ids=['duplicate','nan','infinity','deep','oversize'])
def test_strict_document_decoder(data):
    with pytest.raises(SafetyError): b.document(data)
