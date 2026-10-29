"""Real held inert files, modeled trust-provider evidence; no certificates approved."""
from contextlib import contextmanager
import hashlib
import json
import pytest
from claude_reset import install_authority as a
from claude_reset.safeio import SafetyError
from test_install_payload import fixture as payload_fixture


@contextmanager
def fixture(tmp_path,monkeypatch,change=None):
    manifest=payload_fixture(tmp_path,monkeypatch)
    cat=tmp_path/'release.cat';cat.write_bytes(b'inert catalog')
    value=dict(schema=1,product='ClaudeReset',kind='exact_release_authority',manifest_sha256=manifest,
               catalog_sha256=hashlib.sha256(cat.read_bytes()).hexdigest(),catalog_signers=['a'*64],
               payload_signers={name:['b'*64] for name in a.SIGNED_FILES})
    if change:change(value)
    policy=tmp_path/'authority.json';policy.write_bytes(json.dumps(value).encode())
    anchor=hashlib.sha256(policy.read_bytes()).hexdigest()
    calls=[]
    def catalog(pin,payload):
        calls.append('catalog')
        return dict(catalog_authenticode_verified=True,manifest_membership_verified=True,
                    catalog_sha256=pin.sha256,manifest_sha256=payload.manifest_sha256,
                    signer_certificate_sha256='a'*64)
    def signature(pin):
        calls.append(pin.path.name)
        return dict(authenticode_verified=True,file_sha256=pin.sha256,signer_certificate_sha256='b'*64)
    monkeypatch.setattr(a,'inspect_release_catalog',catalog)
    monkeypatch.setattr(a,'inspect_signature',signature)
    with a.PinnedPayload(tmp_path,manifest) as payload,a.PinnedFile(cat) as catpin,a.PinnedFile(policy,limit=65536) as policypin:
        yield payload,catpin,policypin,anchor,calls,value


def test_no_default_authority_and_no_self_authorizing_policy(tmp_path,monkeypatch):
    assert a.TRUSTED_POLICY_SHA256 is None
    with fixture(tmp_path,monkeypatch) as (payload,cat,policy,anchor,calls,_):
        with pytest.raises(SafetyError,match='No independently approved'):a.verify_release_authority(payload,cat,policy)
        assert not calls


def test_explicit_test_anchor_checks_every_component_without_admission(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (payload,cat,policy,anchor,calls,_):
        monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',anchor)
        result=a.verify_release_authority(payload,cat,policy)
        assert result['release_authority_verified'] is True
        assert set(result['payload_signers'])==a.SIGNED_FILES and len(calls)==1+len(a.SIGNED_FILES)
        assert all(result[k] is False for k in ('kernel_load_verified','installable','client_admission','settings_changed'))
        for pin in (cat,policy,payload.manifest):
            with pytest.raises(OSError):pin.path.write_bytes(b'changed')


@pytest.mark.parametrize('field',['manifest_sha256','catalog_sha256'])
def test_approved_policy_cannot_be_reused_for_other_release_bytes(tmp_path,monkeypatch,field):
    with fixture(tmp_path,monkeypatch,lambda v:v.update({field:'d'*64})) as (payload,cat,policy,anchor,calls,_):
        monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',anchor)
        with pytest.raises(SafetyError,match='different release bytes'):a.verify_release_authority(payload,cat,policy)
        assert not calls


def test_component_authority_does_not_transfer_to_the_driver(tmp_path,monkeypatch):
    def change(value):value['payload_signers']['Sandboxie/x64/SbieDrv.sys']=['c'*64]
    with fixture(tmp_path,monkeypatch,change) as (payload,cat,policy,anchor,calls,_):
        monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',anchor)
        with pytest.raises(SafetyError,match='exact component'):a.verify_release_authority(payload,cat,policy)
        assert 'SbieDrv.sys' in calls


@pytest.mark.parametrize('fault',['anchor','closed-policy','closed-catalog','closed-payload','catalog-signer',
    'catalog-trust','catalog-member','catalog-digest','manifest-digest','payload-signer','payload-trust',
    'payload-digest','anchor-during-check','cached-policy-bytes'])
def test_unapproved_or_stale_evidence_is_refused(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (payload,cat,policy,anchor,calls,_):
        monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256','c'*64 if fault=='anchor' else anchor)
        if fault=='closed-policy':policy.close()
        if fault=='closed-catalog':cat.close()
        if fault=='closed-payload':payload.close()
        if fault=='cached-policy-bytes':policy.data=b'{}'
        catalog=a.inspect_release_catalog;signature=a.inspect_signature
        def cat_result(*args):
            row=catalog(*args)
            fields={'catalog-signer':('signer_certificate_sha256','b'*64),
                    'catalog-trust':('catalog_authenticode_verified',1),'catalog-member':('manifest_membership_verified',False),
                    'catalog-digest':('catalog_sha256','c'*64),'manifest-digest':('manifest_sha256','c'*64)}
            if fault in fields:key,value=fields[fault];row[key]=value
            return row
        def sig_result(*args):
            row=signature(*args)
            if fault=='payload-signer':row['signer_certificate_sha256']='a'*64
            if fault=='payload-trust':row['authenticode_verified']=1
            if fault=='payload-digest':row['file_sha256']='c'*64
            if fault=='anchor-during-check':monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',None)
            return row
        monkeypatch.setattr(a,'inspect_release_catalog',cat_result);monkeypatch.setattr(a,'inspect_signature',sig_result)
        with pytest.raises(SafetyError):a.verify_release_authority(payload,cat,policy)


@pytest.mark.parametrize('fault',['schema','extra','manifest','missing-component','extra-component','empty',
                                 'duplicate','wildcard','uppercase','too-many','wrong-kind'])
def test_policy_schema_has_no_wildcards_or_implicit_component_authority(tmp_path,monkeypatch,fault):
    with fixture(tmp_path,monkeypatch) as (*_,value):
        if fault=='schema':value['schema']=True
        if fault=='extra':value['command']='anything'
        if fault=='manifest':value['manifest_sha256']='latest'
        if fault=='missing-component':value['payload_signers'].pop(next(iter(a.SIGNED_FILES)))
        if fault=='extra-component':value['payload_signers']['*.exe']=['a'*64]
        if fault=='empty':value['catalog_signers']=[]
        if fault=='duplicate':value['catalog_signers']=['a'*64]*2
        if fault=='wildcard':value['catalog_signers']=['*']
        if fault=='uppercase':value['catalog_signers']=['A'*64]
        if fault=='too-many':value['catalog_signers']=[f'{n:064x}' for n in range(9)]
        if fault=='wrong-kind':value['kind']='test_authority'
        with pytest.raises(SafetyError):a.validate_policy(value)
