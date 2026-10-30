import ctypes as C
from dataclasses import asdict
import hashlib
import json
import uuid
import pytest
from claude_reset.network import strict_wfp as s, gateway_reservation
from claude_reset.windows import wfp
from claude_reset.safeio import SafetyError
from wfp_fakes import fake


def image(tmp_path):
    p = tmp_path / 'engine.exe'; p.write_bytes(b'fixture')
    return s.Identity('app', str(p))


def test_legacy_filter_keys_and_serialization_remain_unchanged(tmp_path):
    ident = image(tmp_path)
    rule = s.Rule(ident, 'connect_v4')
    old = dict(identity=asdict(ident), layer='connect_v4', action=s.BLOCK, address=None, port=None, persistent=True)
    assert asdict(rule) == old
    assert rule.key.value() == str(uuid.uuid5(s.NAMESPACE, json.dumps(old, sort_keys=True)))
    old_pin = dict(identity=asdict(ident), role='pinned_endpoint', layer='connect_v4')
    assert s.Rule(ident, 'connect_v4', s.PERMIT, '1.1.1.1', 443).key.value() == str(uuid.uuid5(s.NAMESPACE, json.dumps(old_pin, sort_keys=True)))


@pytest.mark.parametrize('layer,address', [('connect_v4','1.1.1.1'),('recv_v4','127.0.0.1')])
def test_service_permit_native_conditions_include_exact_image_and_token(tmp_path, monkeypatch, layer, address):
    rule = s.ServiceRule(image(tmp_path), layer, s.PERMIT, address, 25080, False, 'ClaudeResetBackend')
    data = (C.c_ubyte * 4)(1,2,3,4); blob = wfp.BLOB(4, data)
    engine = fake(s.Engine)(dynamic=True)
    def call(name, *args, **kwargs):
        assert name == 'FwpmGetAppIdFromFileName0'
        C.cast(args[-1], C.POINTER(C.POINTER(wfp.BLOB)))[0] = C.pointer(blob)
    engine.native = call; engine.free = lambda pointer: None
    descriptor = b'fixture-security-descriptor'
    monkeypatch.setattr(s, 'service_descriptor', lambda name: descriptor if name=='ClaudeResetBackend' else pytest.fail('Wrong service'))
    native, keep = engine._native(rule)
    assert native.numFilterConditions == 5
    fields = [c.fieldKey.value() for c in native.filterCondition[:5]]
    expected = [wfp.FIELD_APP_ID, s.LOCAL_ADDRESS if layer=='recv_v4' else s.REMOTE,
                s.LOCAL_PORT if layer=='recv_v4' else s.PORT, s.PROTOCOL, s.SERVICE_USER]
    assert fields == [f.value() for f in expected]
    assert [c.conditionValue.type for c in native.filterCondition[:5]] == [12,3,2,1,14]
    actual = C.cast(native.filterCondition[4].conditionValue.value.ptr, C.POINTER(wfp.BLOB)).contents
    assert C.string_at(actual.data, actual.size) == descriptor
    marker = s.MARK + hashlib.sha256(json.dumps(asdict(rule), sort_keys=True).encode()).digest()
    assert C.string_at(native.providerData.data, native.providerData.size) == marker
    assert rule.key.value() != s.Rule(rule.identity, 'connect_v4', s.PERMIT, address, 25080, False).key.value()


@pytest.mark.parametrize('service,layer,address,action', [
    ('BITS','connect_v4','1.1.1.1',s.PERMIT),
    ('ClaudeResetBackend','recv_v4','0.0.0.0',s.PERMIT),
    ('ClaudeResetBackend','recv_v6','::1',s.PERMIT),
    ('ClaudeResetBackend','connect_v4',None,s.BLOCK)])
def test_service_scope_cannot_expand(tmp_path,service,layer,address,action):
    with pytest.raises(SafetyError): s.ServiceRule(image(tmp_path),layer,action,address,443,False,service).validate()


def test_service_and_direction_have_separate_stable_slots(tmp_path):
    ident = image(tmp_path)
    a=s.ServiceRule(ident,'connect_v4',s.PERMIT,'1.1.1.1',443,False,'ClaudeResetBackend')
    changed=s.ServiceRule(ident,'connect_v4',s.PERMIT,'8.8.8.8',444,False,'ClaudeResetBackend')
    other=s.ServiceRule(ident,'connect_v4',s.PERMIT,'1.1.1.1',443,False,'ClaudeResetGateway')
    assert a.key.value()==changed.key.value() and a.key.value()!=other.key.value()
