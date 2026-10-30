import hashlib
import json
import os
import pytest
from claude_reset.backend import payload as p
from claude_reset.safeio import SafetyError


def catalog():
    value={name:{'sha256':'a'*64,'bytes':7} for name in p.FILES}
    value['Engine/engine.exe']['sha256']=next(iter(p.ENGINES.values()))
    return value


def test_exact_catalog_and_engine_anchor():
    assert set(p.catalog(catalog()))==p.FILES
    value=catalog();value['Engine/engine.exe']['sha256']='b'*64
    with pytest.raises(SafetyError):p.catalog(value)


@pytest.mark.parametrize('change',[
    lambda v:v.pop('Sandboxie/x64/SbieDrv.sys'),
    lambda v:v.update({'Engine/libcronet.dll':{'sha256':'b'*64,'bytes':5}}),
    lambda v:v['Runtime/ClaudeResetRuntime.exe'].update(bytes=True),
    lambda v:v['Runtime/ClaudeResetRuntime.exe'].update(bytes=0),
    lambda v:v['Runtime/ClaudeResetRuntime.exe'].update(sha256='unknown'),
    lambda v:v['Runtime/ClaudeResetRuntime.exe'].update(command='cmd.exe'),
])
def test_incomplete_or_extended_catalog_is_rejected(change):
    value=catalog();change(value)
    with pytest.raises(SafetyError):p.catalog(value)


def fixture(tmp_path,monkeypatch):
    data=b'fixture';digest=hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(p,'ENGINES',{'fixture':digest})
    value={name:{'sha256':digest,'bytes':len(data)} for name in p.FILES}
    for name in value:
        path=tmp_path/'payload'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    raw=json.dumps({'payload':value}).encode()
    (tmp_path/'bundle-manifest.json').write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


@pytest.mark.skipif(os.name!='nt',reason='Actual Windows file sharing')
def test_all_payload_bytes_and_manifest_stay_pinned_without_execution(tmp_path,monkeypatch):
    digest=fixture(tmp_path,monkeypatch)
    with p.PinnedPayload(tmp_path,digest) as bundle:
        assert bundle.report()['payload_files']==len(p.FILES)
        assert bundle.report()['manifest_authenticity_verified'] is False
        for path in (tmp_path/'bundle-manifest.json',tmp_path/'payload/Engine/engine.exe'):
            with pytest.raises(OSError):path.write_bytes(b'replacement')
    (tmp_path/'payload/Engine/engine.exe').write_bytes(b'now released')
    with pytest.raises(SafetyError):bundle.report()


@pytest.mark.skipif(os.name!='nt',reason='Actual Windows file sharing')
def test_partial_verification_failure_releases_earlier_pins(tmp_path,monkeypatch):
    digest=fixture(tmp_path,monkeypatch)
    last=sorted(p.FILES)[-1]
    (tmp_path/'payload'/last).write_bytes(b'corrupt')
    with pytest.raises(SafetyError):p.PinnedPayload(tmp_path,digest)
    (tmp_path/'payload'/sorted(p.FILES)[0]).write_bytes(b'now released')
    (tmp_path/'bundle-manifest.json').write_bytes(b'now released')


@pytest.mark.skipif(os.name!='nt',reason='Actual Windows file sharing')
@pytest.mark.parametrize('name',['manifest','Engine/engine.exe'])
def test_individually_closed_pin_invalidates_bundle_report(tmp_path,monkeypatch,name):
    digest=fixture(tmp_path,monkeypatch)
    with p.PinnedPayload(tmp_path,digest) as bundle:
        pin=bundle.manifest if name=='manifest' else bundle.pins[name]
        pin.close()
        pin.path.write_bytes(b'replacement after releasing the sharing lock')
        with pytest.raises(SafetyError,match='pins are closed'):bundle.report()


@pytest.mark.skipif(os.name!='nt',reason='Windows package path validation')
@pytest.mark.parametrize('extra',['Engine/extra.dll','unknown/private.txt'])
def test_unlisted_payload_is_not_silently_adopted(tmp_path,monkeypatch,extra):
    digest=fixture(tmp_path,monkeypatch)
    path=tmp_path/'payload'/extra;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'unlisted')
    with pytest.raises(SafetyError):p.PinnedPayload(tmp_path,digest)
