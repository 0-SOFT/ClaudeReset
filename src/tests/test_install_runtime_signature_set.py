from contextlib import contextmanager, ExitStack
import hashlib
import json

import pytest
from test_install_runtime_signature import signed
from claude_reset import install_runtime_signature as runtime, install_payload
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile


@contextmanager
def fixture(tmp_path, monkeypatch, signed):
    digest = hashlib.sha256(signed['image']).hexdigest()
    monkeypatch.setattr(install_payload, 'ENGINES', {'fixture': digest})
    catalog = {name: dict(sha256=digest, bytes=len(signed['image'])) for name in install_payload.FILES}
    for name in catalog:
        path = tmp_path / 'payload' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(signed['image'])
    raw = json.dumps({'payload': catalog}).encode()
    (tmp_path / 'bundle-manifest.json').write_bytes(raw)
    key = tmp_path / 'public.blob'; key.write_bytes(signed['key'])
    expected = {}; sidecars = {}
    with ExitStack() as stack:
        payload = stack.enter_context(install_payload.PinnedPayload(tmp_path, hashlib.sha256(raw).hexdigest()))
        public = stack.enter_context(PinnedFile(key, limit=72))
        for name in sorted(runtime.RUNTIME_IMAGES):
            path = tmp_path / 'signatures' / (name + '.sig')
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(signed['signature'])
            sidecars[name] = stack.enter_context(PinnedFile(path, limit=64))
            expected[name] = sidecars[name].sha256
        yield payload, sidecars, public, public.sha256, expected


def test_complete_real_cng_set_does_not_authorize_or_claim_staging(tmp_path, monkeypatch, signed):
    with fixture(tmp_path, monkeypatch, signed) as args:
        result = runtime.inspect_runtime_signature_set(*args)
        assert len(result['runtime_images']) == 11
        assert result['complete_signature_set_verified'] is True
        assert all(row['detached_signature_verified'] is True for row in result['runtime_images'].values())
        assert result['manifest_sha256'] == args[0].manifest_sha256
        for field in ('key_authority_verified', 'embedded_key_binding_verified', 'staged_sidecars_verified',
                      'loaded_image_verified', 'installable', 'client_admission'):
            assert result[field] is False


@pytest.mark.parametrize('fault', ['missing-sidecar', 'extra-sidecar', 'missing-digest', 'extra-digest',
    'wrong-digest', 'noncanonical-digest', 'wrong-key', 'noncanonical-key', 'closed-key', 'closed-manifest',
    'closed-image', 'closed-sidecar'])
def test_incomplete_or_mismatched_set_refused(tmp_path, monkeypatch, signed, fault):
    with fixture(tmp_path, monkeypatch, signed) as original:
        args = list(original); payload, sidecars, key, _, expected = args
        name = sorted(runtime.RUNTIME_IMAGES)[0]
        if fault == 'missing-sidecar': sidecars.pop(name)
        elif fault == 'extra-sidecar': sidecars['unexpected.exe'] = sidecars[name]
        elif fault == 'missing-digest': expected.pop(name)
        elif fault == 'extra-digest': expected['unexpected.exe'] = 'a' * 64
        elif fault == 'wrong-digest': expected[name] = 'a' * 64
        elif fault == 'noncanonical-digest': expected[name] = 'A' * 64
        elif fault == 'wrong-key': args[3] = 'a' * 64
        elif fault == 'noncanonical-key': args[3] = True
        elif fault == 'closed-key': key.close()
        elif fault == 'closed-manifest': payload.manifest.close()
        elif fault == 'closed-image': payload.pins[name].close()
        elif fault == 'closed-sidecar': sidecars[name].close()
        with pytest.raises(SafetyError): runtime.inspect_runtime_signature_set(*args)


@pytest.mark.parametrize('fault', ['close-earlier-image', 'close-earlier-sidecar', 'close-manifest',
    'drop-sidecar', 'replace-sidecar', 'change-catalog', 'change-manifest-hash'])
def test_final_readback_refuses_late_catalog_drift(tmp_path, monkeypatch, signed, fault):
    with fixture(tmp_path, monkeypatch, signed) as args:
        payload, sidecars, key, _, expected = args
        first, last = sorted(runtime.RUNTIME_IMAGES)[0], sorted(runtime.RUNTIME_IMAGES)[-1]
        verify = runtime.inspect_runtime_signature
        calls = []
        def inspect(image, signature, public):
            result = verify(image, signature, public); calls.append(image)
            if len(calls) == len(runtime.RUNTIME_IMAGES):
                if fault == 'close-earlier-image': payload.pins[first].close()
                elif fault == 'close-earlier-sidecar': sidecars[first].close()
                elif fault == 'close-manifest': payload.manifest.close()
                elif fault == 'drop-sidecar': sidecars.pop(first)
                elif fault == 'replace-sidecar': sidecars[first] = sidecars[last]
                elif fault == 'change-catalog': expected[first] = 'a' * 64
                elif fault == 'change-manifest-hash': payload.manifest_sha256 = 'a' * 64
            return result
        monkeypatch.setattr(runtime, 'inspect_runtime_signature', inspect)
        with pytest.raises(SafetyError): runtime.inspect_runtime_signature_set(*args)
        assert len(calls) == 11
