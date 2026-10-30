import pytest
from claude_reset.backend.service_store import validate_acl
from claude_reset.network.gateway_reservation import Reservation, service_descriptor
from claude_reset.safeio import SafetyError


def protected():
    return {'owner':'S-1-5-32-544','reparse':False,'protected':True,'rules':[
        {'sid':'S-1-5-18','rights':2032127,'type':'Allow'},
        {'sid':'S-1-5-32-544','rights':2032127,'type':'Allow'},
        {'sid':'S-1-5-32-545','rights':1179817,'type':'Allow'}]}


def test_read_execute_for_users_is_compatible_with_protected_gateway():
    validate_acl(protected(),directory=True)


@pytest.mark.parametrize('mask',[2,4,16,64,256,65536,262144,524288,0x10000000,0x40000000])
def test_any_user_write_or_replacement_authority_rejects_gateway(mask):
    row=protected();row['rules'][-1]['rights']|=mask
    with pytest.raises(SafetyError):validate_acl(row,directory=True)


@pytest.mark.parametrize('field,value',[('owner','S-1-5-21-1-2-3-1000'),('reparse',True),('protected',False),('rules',None)])
def test_owner_reparse_or_unverifiable_policy_is_not_a_protected_store(field,value):
    row=protected();row[field]=value
    with pytest.raises(SafetyError):validate_acl(row,directory=True)


@pytest.mark.parametrize('port',[0,443,49152,65536,True,'25083'])
def test_reservation_cannot_target_common_privileged_or_dynamic_ports(tmp_path,port):
    image=tmp_path/'ClaudeResetGateway.exe';image.write_bytes(b'fixture')
    with pytest.raises(SafetyError):Reservation(image,'ClaudeResetGatewayFixture',port)


@pytest.mark.parametrize('name',['Dnscache','BITS','LocalSystem','ClaudeResetGateway\nInjected'])
def test_no_other_windows_service_can_be_selected(name):
    with pytest.raises(SafetyError):service_descriptor(name)
