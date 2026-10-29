import ctypes as C
from copy import deepcopy
import pytest
from claude_reset import install_registry as r
from claude_reset.safeio import SafetyError


def security():
    return dict(owner='S-1-5-32-544',dacl_present=True,dacl_null=False,protected=True,
        rules=[dict(sid=sid,mask=r.ALL,type=0,flags=2) for sid in sorted(r.OWNERS)])


def test_literal_private_path():
    path=r.expected_path()
    assert r.decode_string(1,(path+'\0').encode('utf-16-le'))==path
    assert r.validate_security(security())


@pytest.mark.parametrize('kind,data',[(2,b'xx'),(True,b'xx'),(1,b'x'),(1,b''),
    (1,b'x'*522),(1,'abc'.encode('utf-16-le')),(1,'a\0b\0'.encode('utf-16-le')),
    (1,b'\x00\xd8\x00\x00')])
def test_ambiguous_or_expandable_path_rejected(kind,data):
    with pytest.raises(SafetyError):r.decode_string(kind,data)


@pytest.mark.parametrize('mask',[2,4,32,0x10000,0x40000,0x80000,0x10000000,0x40000000])
def test_each_untrusted_mutation_right_rejected(mask):
    row=security();row['rules'].append(dict(sid='S-1-5-11',mask=mask,type=0,flags=0))
    with pytest.raises(SafetyError):r.validate_security(row)


@pytest.mark.parametrize('change',[lambda v:v.update(protected=False),lambda v:v.update(owner=[]),
    lambda v:v.update(dacl_null=True),lambda v:v.update(rules=[]),
    lambda v:v['rules'][0].update(flags=16),lambda v:v['rules'][0].update(flags=8),
    lambda v:v['rules'][0].update(mask=0x20019)])
def test_registry_descriptor_drift_rejected(change):
    row=deepcopy(security());change(row)
    with pytest.raises(SafetyError):r.validate_security(row)


def test_read_only_users_do_not_get_mutation_authority():
    row=security();row['rules'].append(dict(sid='S-1-5-11',mask=0x20019,type=0,flags=2))
    assert r.validate_security(row)


@pytest.mark.parametrize('outcome',['missing','denied','link','valid','wrong_path'])
def test_native_fixed_key_read_never_creates_or_changes_registry(monkeypatch,outcome):
    from claude_reset import wfp_security
    native=r.Native.__new__(r.Native);native.reader=object();events=[]
    class Api:
        def RegOpenKeyExW(self,root,key,options,access,result):
            assert key==r.KEY and options==8 and access==r.ACCESS
            events.append('open')
            if outcome=='missing':return 2
            if outcome=='denied':return 5
            C.cast(result,C.POINTER(C.c_void_p))[0]=17
            return 0
        def RegGetKeySecurity(self,handle,info,buffer,size):
            assert info==5
            C.cast(size,C.POINTER(r.W.DWORD))[0]=32
            return 0 if buffer is not None else 122
        def RegCloseKey(self,handle):events.append('close');return 0
    native.api=Api()
    def value(handle,name):
        if name=='SymbolicLinkValue':return (6,b'link') if outcome=='link' else None
        assert name=='IniPath'
        path=r.expected_path() if outcome=='valid' else 'C:\\foreign.ini'
        return 1,(path+'\0').encode('utf-16-le')
    native.value=value
    monkeypatch.setattr(wfp_security,'decode',lambda *args:security())
    if outcome in ('denied','link'):
        with pytest.raises(SafetyError):native.inspect()
    else:
        report=native.inspect()
        assert report['policy_binding_matches']==(outcome=='valid')
        assert report['settings_changed'] is report['may_mutate'] is report['client_admission'] is False
    assert events==(['open'] if outcome in ('missing','denied') else ['open','close'])
