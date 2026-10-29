"""Preparation only: public key fixtures never authorize installation."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('runtime_trust_tool', ROOT / 'tools/prepare_runtime_trust.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

# Public NIST P-256 generator point in CNG encoding; no signing key is stored.
KEY = bytes.fromhex('4543533120000000'
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
DRIVER = '''NTSTATUS KphVerifySignature() { KphpTrustedPublicKey; }
NTSTATUS KphVerifyFile() { KphVerifySignature(); }
NTSTATUS KphVerifyBuffer() { KphVerifySignature(); }
'''
SERVICE = '''static UCHAR KphpTrustedPublicKey[] = {0};
static NTSTATUS VerifyHashSignature() { import(KphpTrustedPublicKey, sizeof(KphpTrustedPublicKey)); }
NTSTATUS VerifyFileSignature() { VerifyHashSignature(); }
'''


def fixture(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    for relative, text, constant in ((tool.RELATIVE, DRIVER, 'UPSTREAM_SHA256'),
                                      (tool.SERVICE_RELATIVE, SERVICE, 'SERVICE_UPSTREAM_SHA256')):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode())
        monkeypatch.setattr(tool, constant, hashlib.sha256(target.read_bytes()).hexdigest())
    key = tmp_path / 'key.blob'
    key.write_bytes(KEY)
    return source, tmp_path / 'output', key, hashlib.sha256(KEY).hexdigest()


def test_both_runtime_verifiers_prepared_without_changing_buffer_trust(tmp_path, monkeypatch):
    args = fixture(tmp_path, monkeypatch)
    result = tool.prepare(*args)
    driver = (args[1] / 'prepared' / tool.RELATIVE).read_text()
    service = (args[1] / 'prepared' / tool.SERVICE_RELATIVE).read_text()
    assert DRIVER.splitlines()[0] in driver
    assert DRIVER.splitlines()[2] in driver
    assert 'KphVerifyFile() { KphVerifyRuntimeSignature(); }' in driver
    assert 'KphpTrustedPublicKey' not in service
    assert SERVICE[SERVICE.index('NTSTATUS VerifyFileSignature'): ] in service
    assert result['service_runtime_key_matches_driver'] is True
    for field in ('key_authority_verified', 'installed', 'production_clients_permitted',
                  'upstream_certificate_trust_changed', 'runtime_signatures_supplied'):
        assert result[field] is False


@pytest.mark.parametrize('relative', [tool.RELATIVE, tool.SERVICE_RELATIVE])
def test_changed_input_refuses_before_output(tmp_path, monkeypatch, relative):
    args = fixture(tmp_path, monkeypatch)
    (args[0] / relative).write_bytes(b'changed')
    with pytest.raises(ValueError, match='Unexpected upstream'):
        tool.prepare(*args)
    assert not args[1].exists()


def test_wrong_key_fingerprint_refuses_before_output(tmp_path, monkeypatch):
    source, output, key, _ = fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match='fingerprint'):
        tool.prepare(source, output, key, '0' * 64)
    assert not output.exists()


@pytest.mark.parametrize('blob', [b'', KEY + b'private', b'ECS2' + KEY[4:], KEY[:8] + bytes(64)])
def test_invalid_keys_refused(blob):
    with pytest.raises(ValueError):
        tool.validate_public_key(blob)


def test_existing_output_preserved(tmp_path, monkeypatch):
    args = fixture(tmp_path, monkeypatch)
    args[1].mkdir()
    marker = args[1] / 'keep'
    marker.write_bytes(b'preserve')
    with pytest.raises(RuntimeError, match='preserved'):
        tool.prepare(*args)
    assert marker.read_bytes() == b'preserve'


def test_unknown_service_structure_refused():
    with pytest.raises(ValueError, match='structure'):
        tool.transform_service(SERVICE + 'KphpTrustedPublicKey;', KEY)
