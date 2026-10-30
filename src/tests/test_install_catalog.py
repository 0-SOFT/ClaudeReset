import ctypes as C
from pathlib import Path
import pytest
from claude_reset.windows import catalog as cat
from claude_reset.safeio import SafetyError
from claude_reset.windows.pin import PinnedFile
from test_release_catalog import generate,generated
from contextlib import contextmanager
import hashlib
import json
from claude_reset.backend import payload


@contextmanager
def pinned_payload(tmp_path, monkeypatch):
    """A synthetic signed-bundle payload, pinned the way the release check reads it."""
    bundle = tmp_path / 'bundle'
    data = b'synthetic inert payload'
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(payload, 'ENGINES', {'fixture': digest})
    files = {name: {'sha256': digest, 'bytes': len(data)} for name in payload.FILES}
    for name in files:
        target = bundle / 'payload' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    raw = json.dumps({'payload': files}).encode()
    (bundle / 'bundle-manifest.json').write_bytes(raw)
    with payload.PinnedPayload(bundle, hashlib.sha256(raw).hexdigest()) as source:
        yield source


def test_native_exact_memory_membership_and_wrong_digest(generated):
    path,digest=generated;raw=path.read_bytes()
    cat.require_manifest_member(raw,digest)
    with pytest.raises(SafetyError,match='exactly one'):cat.require_manifest_member(raw,'0'*64)
    for changed in (raw+b'padding',raw+raw,raw[:-1]):
        with pytest.raises(SafetyError,match='Trailing or truncated'):
            cat.require_manifest_member(changed,digest)


def test_native_sha1_catalog_is_not_a_sha256_release_catalog(tmp_path):
    path,digest=generate(tmp_path,sha1=True)
    with pytest.raises(SafetyError,match='Unsupported'):cat.require_manifest_member(path.read_bytes(),digest)


@pytest.mark.parametrize('raw,digest',[(b'', '0'*64),(b'x'*1048577,'0'*64),(b'invalid','0'*64),(b'x','bad')],
                         ids=['empty','oversized','invalid-encoding','invalid-digest'])
def test_malformed_catalog_inputs_fail_closed(raw,digest):
    with pytest.raises(SafetyError):cat.require_manifest_member(raw,digest)


@pytest.mark.parametrize('mode',['unsigned','modeled-signature','changed-member','closed-catalog'])
def test_composed_release_evidence_never_authorizes_installation(tmp_path,monkeypatch,mode):
    with pinned_payload(tmp_path,monkeypatch) as source:
        directory=tmp_path/'catalog';directory.mkdir()
        path,digest=generate(directory,source.manifest.data if mode!='changed-member' else b'{"other":true}')
        with PinnedFile(path) as pin:
            if mode=='closed-catalog':pin.close()
            if mode in ('modeled-signature','changed-member'):
                monkeypatch.setattr(payload,'inspect_signature',lambda value:{'signer_certificate_sha256':'a'*64})
            if mode=='modeled-signature':
                report=payload.inspect_release_catalog(pin,source)
                assert report['manifest_sha256']==digest and report['manifest_membership_verified']
                assert report['catalog_authenticode_verified']  # Modeled trust only in this branch.
                assert not report['release_authority_verified'] and not report['kernel_load_verified']
                assert not report['installable'] and not report['client_admission']
            else:
                with pytest.raises(SafetyError):payload.inspect_release_catalog(pin,source)


@pytest.mark.parametrize('fault',['usage','algorithm','count','duplicate-entry','attributes','duplicate-digest','invalid-der','free-failure'])
def test_native_decode_model_bounds_and_always_frees_context(monkeypatch,fault):
    native,kernel=cat.libraries();digest='12'*32
    raw_digest=C.create_string_buffer(bytes.fromhex(digest))
    der=bytes.fromhex('30453010060a2b060104018237020119a20280003031300d060960864801650304020105000420'+digest)
    encoded=C.create_string_buffer(b'invalid' if fault=='invalid-der' else der)
    values=(cat.Blob*1)(cat.Blob(len(encoded.raw)-1,C.cast(encoded,C.c_void_p)))
    attribute=cat.Attribute(cat.INDIRECT,1,values)
    attributes=(cat.Attribute*2)(attribute,attribute)
    entry=cat.Entry(cat.Blob(32,C.cast(raw_digest,C.c_void_p)),1,attributes)
    entries=(cat.Entry*2)(entry,entry)
    oids=(C.c_char_p*1)(b'1.3.6.1.4.1.311.12.1.1')
    info=cat.Info();info.usage=cat.Usage(1,oids);info.algorithm.oid=b'1.3.6.1.4.1.311.12.1.3'
    info.count=1;info.entries=entries
    context=cat.Context();context.info=C.pointer(info)
    if fault=='usage':info.usage.count=0
    if fault=='algorithm':info.algorithm.oid=b'1.3.14.3.2.26'
    if fault=='count':info.count=4097
    if fault=='duplicate-entry':info.count=2
    if fault=='attributes':entries[0].count=33
    if fault=='duplicate-digest':entries[0].count=2
    freed=[]
    class Model:
        def CertCreateCTLContext(self,*args):return C.pointer(context)
        def CertFreeCTLContext(self,value):freed.append(value);return fault!='free-failure'
        def CryptDecodeObjectEx(self,*args):return native.CryptDecodeObjectEx(*args)
    with pytest.raises(SafetyError):cat.require_manifest_member(b'\x30\x00',digest,native=(Model(),kernel))
    assert len(freed)==1
