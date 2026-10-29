"""Pending creation checks never relax completed-service acceptance."""
import pytest
from claude_reset.install_creation_security import validate_pending_service,validate_pending_key
from claude_reset.install_scm import specification,validate_snapshot
from claude_reset.install_registry import validate_security
from claude_reset.safeio import SafetyError


def service():
    spec=specification('ClaudeResetBackend')
    return spec,dict(spec,owner='S-1-5-32-544',dacl_present=True,dacl_null=False,state=1,pid=0,sid_type=0,
                     rules=[dict(sid=sid,mask=mask,type=0,flags=0) for sid,mask in
                            [('S-1-5-18',0x201FD),('S-1-5-32-544',0xF01FF),('S-1-5-11',0x2018D)]])


def key():
    return dict(owner='S-1-5-18',dacl_present=True,dacl_null=False,protected=False,
                rules=[dict(sid=sid,mask=mask,type=0,flags=18) for sid,mask in
                       [('S-1-5-18',0xF003F),('S-1-5-32-544',0xF003F),('S-1-5-11',0x20019)]])


def test_documented_pending_shapes_are_not_completed_security():
    spec,value=service();assert validate_pending_service(spec,value)
    with pytest.raises(SafetyError):validate_snapshot(spec,value)
    value=key();assert validate_pending_key(value)
    with pytest.raises(SafetyError):validate_security(value)


@pytest.mark.parametrize('field,value',[('state',4),('pid',1),('start',3),('sid_type',2),('sid_type',True),
    ('owner',[]),('owner','S-1-5-11'),('dacl_null',True),('dacl_present',False),('binary','changed.exe')])
def test_pending_service_never_accepts_running_changed_or_unowned_object(field,value):
    spec,actual=service();actual[field]=value
    with pytest.raises(SafetyError):validate_pending_service(spec,actual)


@pytest.mark.parametrize('mask',[2,16,32,64,0x10000,0x40000,0x80000,0x10000000,0x20000000,0x40000000,0x80000000])
def test_pending_service_rejects_untrusted_mutating_or_unmapped_generic_rights(mask):
    spec,actual=service();actual['rules'][-1]['mask']|=mask
    with pytest.raises(SafetyError):validate_pending_service(spec,actual)


@pytest.mark.parametrize('mask',[2,4,32,0x10000,0x40000,0x80000,0x10000000,0x40000000])
def test_inherited_pending_key_still_excludes_every_untrusted_write(mask):
    value=key();value['rules'][-1]['mask']|=mask
    with pytest.raises(SafetyError):validate_pending_key(value)


@pytest.mark.parametrize('flags',[1,4,8,10,24,True])
def test_pending_key_refuses_inherit_only_or_unsupported_aces(flags):
    value=key();value['rules'][0]['flags']=flags
    with pytest.raises(SafetyError):validate_pending_key(value)


@pytest.mark.parametrize('target',['system','administrators'])
def test_pending_objects_retain_required_administrative_access(target):
    index=0 if target=='system' else 1
    spec,value=service();value['rules'][index]['mask']=0
    with pytest.raises(SafetyError):validate_pending_service(spec,value)
    value=key();value['rules'][index]['mask']=0
    with pytest.raises(SafetyError):validate_pending_key(value)
