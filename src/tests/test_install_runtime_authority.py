"""Ephemeral real CNG signatures; modeled Authenticode and test-only policy anchor."""
from contextlib import contextmanager
import hashlib
import json

import pytest
from claude_reset import install_authority as a
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile
from test_install_runtime_signature import signed
from test_install_runtime_signature_set import fixture as runtime_fixture


@contextmanager
def fixture(tmp_path, monkeypatch, signed, change=None):
    with runtime_fixture(tmp_path, monkeypatch, signed) as (payload, signatures, key, key_hash, hashes):
        cat=tmp_path/'release.cat';cat.write_bytes(b'inert catalog')
        value=dict(schema=2,product='ClaudeReset',kind='exact_release_authority',
            manifest_sha256=payload.manifest_sha256,catalog_sha256=hashlib.sha256(cat.read_bytes()).hexdigest(),
            catalog_signers=['a'*64],payload_signers={name:['b'*64] for name in a.SIGNED_FILES},
            runtime_public_key_sha256=key_hash,runtime_signatures=hashes)
        if change:change(value)
        policy=tmp_path/'authority.json';policy.write_bytes(json.dumps(value).encode())
        monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',hashlib.sha256(policy.read_bytes()).hexdigest())
        monkeypatch.setattr(a,'inspect_release_catalog',lambda pin,p:dict(
            catalog_authenticode_verified=True,manifest_membership_verified=True,
            catalog_sha256=pin.sha256,manifest_sha256=p.manifest_sha256,signer_certificate_sha256='a'*64))
        monkeypatch.setattr(a,'inspect_signature',lambda pin:dict(authenticode_verified=True,
            file_sha256=pin.sha256,signer_certificate_sha256='b'*64))
        with PinnedFile(cat) as catalog,PinnedFile(policy,limit=65536) as approved:
            yield (payload,catalog,approved),dict(runtime_signatures=signatures,runtime_public_key=key),value


def test_exact_runtime_policy_checks_real_cng_but_does_not_authorize_installation(tmp_path,monkeypatch,signed):
    with fixture(tmp_path,monkeypatch,signed) as (args,kwargs,_):
        row=a.verify_release_authority(*args,**kwargs)
        assert row['release_authority_verified'] is True
        assert row['runtime_key_authority_verified'] is True
        assert len(row['runtime_signature_evidence']['runtime_images'])==11
        for field in ('embedded_key_binding_verified','staged_sidecars_verified','kernel_load_verified',
                      'installable','client_admission','settings_changed'):
            assert row[field] is False


@pytest.mark.parametrize('fault',['missing-key','missing-signatures','wrong-key','wrong-signature',
    'missing-entry','extra-entry','uppercase-key','uppercase-signature','boolean-schema','extra-field',
    'absent-anchor','closed-key','closed-sidecar'])
def test_runtime_policy_has_no_implicit_authority(tmp_path,monkeypatch,signed,fault):
    def change(value):
        name=sorted(a.RUNTIME_IMAGES)[0]
        if fault=='wrong-key':value['runtime_public_key_sha256']='f'*64
        if fault=='wrong-signature':value['runtime_signatures'][name]='f'*64
        if fault=='missing-entry':value['runtime_signatures'].pop(name)
        if fault=='extra-entry':value['runtime_signatures']['extra.exe']='f'*64
        if fault=='uppercase-key':value['runtime_public_key_sha256']='A'*64
        if fault=='uppercase-signature':value['runtime_signatures'][name]='A'*64
        if fault=='boolean-schema':value['schema']=True
        if fault=='extra-field':value['runtime_installable']=True
    with fixture(tmp_path,monkeypatch,signed,change) as (args,kwargs,_):
        if fault=='missing-key':kwargs.pop('runtime_public_key')
        if fault=='missing-signatures':kwargs.pop('runtime_signatures')
        if fault=='absent-anchor':monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',None)
        if fault=='closed-key':kwargs['runtime_public_key'].close()
        if fault=='closed-sidecar':next(iter(kwargs['runtime_signatures'].values())).close()
        with pytest.raises(SafetyError):a.verify_release_authority(*args,**kwargs)


def test_legacy_policy_cannot_silently_ignore_runtime_inputs(tmp_path,monkeypatch,signed):
    def legacy(value):
        value['schema']=1
        del value['runtime_public_key_sha256'],value['runtime_signatures']
    with fixture(tmp_path,monkeypatch,signed,legacy) as (args,kwargs,_):
        with pytest.raises(SafetyError,match='Legacy'):a.verify_release_authority(*args,**kwargs)
        row=a.verify_release_authority(*args)
        assert row['runtime_key_authority_verified'] is False
        assert row['runtime_signature_evidence'] is None


@pytest.mark.parametrize('fault',['manifest','catalog','policy','earlier-dll','anchor','replace-image'])
def test_late_drift_after_real_runtime_verification_refuses_success(tmp_path,monkeypatch,signed,fault):
    with fixture(tmp_path,monkeypatch,signed) as (args,kwargs,_):
        payload,cat,policy=args
        original_pins=dict(payload.pins)
        verify=a.inspect_runtime_signature_set
        def inspect(*inputs):
            row=verify(*inputs)
            if fault=='manifest':payload.manifest.close()
            if fault=='catalog':cat.close()
            if fault=='policy':policy.close()
            if fault=='earlier-dll':payload.pins['Sandboxie/x64/SbieDll.dll'].close()
            if fault=='anchor':monkeypatch.setattr(a,'TRUSTED_POLICY_SHA256',None)
            if fault=='replace-image':payload.pins['Sandboxie/x64/SbieSvc.exe']=payload.pins['Sandboxie/x64/Start.exe']
            return row
        monkeypatch.setattr(a,'inspect_runtime_signature_set',inspect)
        try:
            with pytest.raises(SafetyError):a.verify_release_authority(*args,**kwargs)
        finally:
            payload.pins=original_pins
