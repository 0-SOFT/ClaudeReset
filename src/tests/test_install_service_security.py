import ctypes as C
import os
import pytest
from claude_reset.windows.service_security import Reader, validate, ALL_ACCESS, MUTATE
from claude_reset.safeio import SafetyError


def row():
    return {'name':'ClaudeResetBackend','owner':'S-1-5-18','sid_type':1,
            'dacl_present':True,'dacl_null':False,
            'rules':[{'sid':sid,'mask':ALL_ACCESS,'type':0,'flags':0}
                     for sid in ('S-1-5-18','S-1-5-32-544')]}


def test_exact_service_authority():
    assert validate(row())
    value=row()
    value['rules'].append({'sid':'S-1-5-11','mask':0x2008D,'type':0,'flags':0})
    assert validate(value)


@pytest.mark.parametrize('mask',[2,16,32,64,256,0x10000,0x40000,0x80000,
                                0x10000000,0x20000000,0x40000000])
def test_untrusted_control_is_rejected(mask):
    value=row();value['rules'].append({'sid':'S-1-1-0','mask':mask,'type':0,'flags':0})
    with pytest.raises(SafetyError):validate(value)


@pytest.mark.parametrize('change',[
    lambda v:v.update(owner='S-1-5-11'),
    lambda v:v.update(owner=[]),
    lambda v:v.update(dacl_null=True),
    lambda v:v.update(dacl_present=False),
    lambda v:v.update(sid_type=0),
    lambda v:v.update(sid_type=True),
    lambda v:v.update(rules=[]),
    lambda v:v['rules'].pop(),
    lambda v:v['rules'][0].update(type=1),
    lambda v:v['rules'][0].update(flags=8),
    lambda v:v['rules'][0].update(mask=True),
])
def test_unknown_or_incomplete_descriptor_fails(change):
    value=row();change(value)
    with pytest.raises(SafetyError):validate(value)


@pytest.mark.skipif(os.name!='nt',reason='Windows descriptor conversion')
def test_actual_windows_descriptor_is_parsed_without_changing_service():
    reader=Reader();pointer=C.c_void_p();size=C.c_uint32()
    fn=reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    fn.argtypes=[C.c_wchar_p,C.c_uint32,C.POINTER(C.c_void_p),C.POINTER(C.c_uint32)]
    fn.restype=C.c_int
    assert fn('O:SYG:SYD:(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)(A;;0x2008d;;;AU)',
              1,C.byref(pointer),C.byref(size))
    try:
        value=reader.descriptor(pointer)
        value.update(name='ClaudeResetBackend',sid_type=1)
        assert validate(value)
        assert len(value['rules'])==3
    finally:reader.kernel.LocalFree(pointer)


@pytest.mark.parametrize('system_mask,local_mask',[(0x201FD,0x2018D),(ALL_ACCESS,0x2018D),(0x201FD,0x2008D)])
def test_documented_creation_defaults_are_not_completed_service_security(system_mask,local_mask):
    # Microsoft documents these default access sets; parse an in-memory model,
    # never create a service or assume the installed OS has this exact DACL.
    reader=Reader();pointer=C.c_void_p()
    convert=reader.api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes=[C.c_wchar_p,C.c_uint32,C.POINTER(C.c_void_p),C.c_void_p]
    convert.restype=C.c_int
    sddl=f'O:BAG:BAD:(A;;0x{system_mask:x};;;SY)(A;;0xf01ff;;;BA)(A;;0x{local_mask:x};;;AU)'
    assert convert(sddl,1,C.byref(pointer),None)
    try:
        value=reader.descriptor(pointer);value.update(name='ClaudeResetBackend',sid_type=1)
        with pytest.raises(SafetyError):validate(value)
    finally:reader.kernel.LocalFree(pointer)
