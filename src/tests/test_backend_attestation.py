import json
import pytest
from claude_reset.backend_attestation import inspect_sing_box
from claude_reset.safeio import SafetyError


def config():
    return {'log':{'disabled':True},'inbounds':[{'type':'socks','tag':'local-any-provider','listen':'127.0.0.1','listen_port':1080}],
        'outbounds':[{'type':'vless','tag':'chosen-by-user','server':'1.1.1.1','server_port':443,
                     'uuid':'12345678-1234-1234-1234-123456789abc','tls':{'enabled':True,'server_name':'fixture.invalid',
                     'utls':{'enabled':True,'fingerprint':'chrome'},
                     'reality':{'enabled':True,'public_key':'A'*43,'short_id':'aabb'}}}],
        'route':{'final':'chosen-by-user'}}


def test_tag_is_user_selected_and_evidence_contains_no_credentials_or_runtime_permission():
    c=config();r=inspect_sing_box(c)
    assert r['passed'] and r['single_encrypted_route']
    assert not r['runtime_engine_verified'] and not r['client_network_opened']
    for secret in ('1.1.1.1','12345678','fixture.invalid','chosen-by-user','AAAA'):assert secret not in json.dumps(r)


@pytest.mark.parametrize('change',[
    lambda c:c.update(dns={'servers':[{'type':'local'}]}),
    lambda c:c.update(ntp={'enabled':True}),
    lambda c:c['outbounds'].append({'type':'direct','tag':'bypass'}),
    lambda c:c['route'].update(rules=[]),
    lambda c:c['outbounds'][0].update(detour='another'),
    lambda c:c['outbounds'][0].update(domain_resolver='local'),
    lambda c:c['outbounds'][0].update(server='proxy.invalid'),
    lambda c:c['outbounds'][0].update(server='127.0.0.1'),
    lambda c:c['outbounds'][0].update(server_port=True),
    lambda c:c['outbounds'][0]['tls'].update(insecure=True),
    lambda c:c['outbounds'][0]['tls'].pop('utls'),
    lambda c:c['outbounds'][0]['tls']['utls'].update(fingerprint='unknown'),
    lambda c:c['outbounds'][0]['tls']['reality'].update(enabled=False),
    lambda c:c['outbounds'][0]['tls']['reality'].update(public_key='bad'),
    lambda c:c['inbounds'][0].update(listen='0.0.0.0'),
    lambda c:c['inbounds'][0].update(type='tun'),
    lambda c:c.update(experimental={'clash_api':{'external_controller':'0.0.0.0:1081','secret':'fixture'}}),
    lambda c:c.update(experimental={'clash_api':{'external_controller':'127.0.0.1:1081','secret':''}}),
    lambda c:c['outbounds'][0].update(transport={'type':'ws','path':'/unreviewed'}),
])
def test_unreviewed_feature_or_another_network_path_is_rejected(change):
    c=config();change(c)
    with pytest.raises(SafetyError):inspect_sing_box(c)


def test_reviewed_grpc_shape_and_authenticated_local_controller():
    c=config();c['outbounds'][0]['transport']={'type':'grpc','service_name':'fixture'}
    c['experimental']={'clash_api':{'external_controller':'127.0.0.1:1081','secret':'fixture-only'}}
    assert inspect_sing_box(c)['passed']
