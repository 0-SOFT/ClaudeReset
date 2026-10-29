"""Real CNG signatures over inert bytes; an ephemeral key is never exported."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import subprocess

import pytest
from claude_reset import install_runtime_signature as runtime
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile


@pytest.fixture(scope='module')
def signed(tmp_path_factory):
    root = tmp_path_factory.mktemp('detached-runtime')
    source = root / 'Fixture.cs'
    source.write_text('''using System;using System.IO;using System.Security.Cryptography;
class Fixture {static void Main(string[] args) {
  byte[] data=System.Text.Encoding.ASCII.GetBytes("inert synthetic runtime fixture");
  using(var key=new ECDsaCng(256))using(var other=new ECDsaCng(256))using(var hash=SHA256.Create()) {
    File.WriteAllBytes(Path.Combine(args[0],"key"),key.Key.Export(CngKeyBlobFormat.EccPublicBlob));
    File.WriteAllBytes(Path.Combine(args[0],"other"),other.Key.Export(CngKeyBlobFormat.EccPublicBlob));
    File.WriteAllBytes(Path.Combine(args[0],"image"),data);
    File.WriteAllBytes(Path.Combine(args[0],"signature"),key.SignHash(hash.ComputeHash(data)));
  }
}}''')
    compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    exe = root / 'Fixture.exe'
    for command in ([str(compiler), '/nologo', '/out:' + str(exe), str(source)], [str(exe), str(root)]):
        subprocess.run(command, check=True, capture_output=True, timeout=30, creationflags=0x08000000)
    return {name: (root / name).read_bytes() for name in ('image', 'signature', 'key', 'other')}


def pins(stack, tmp_path, values):
    result = []
    for name in ('image', 'signature', 'key'):
        path = tmp_path / name
        path.write_bytes(values[name])
        result.append(stack.enter_context(PinnedFile(path, limit=65536)))
    return result


def test_real_signature_matches_but_grants_no_authority(tmp_path, signed):
    with ExitStack() as stack:
        result = runtime.inspect_runtime_signature(*pins(stack, tmp_path, signed))
        assert result['detached_signature_verified'] is True
        assert result['file_sha256'] == hashlib.sha256(signed['image']).hexdigest()
        for field in ('key_authority_verified', 'authenticode_verified', 'loaded_image_verified',
                      'installable', 'client_admission'):
            assert result[field] is False


@pytest.mark.parametrize('change', ['image', 'signature', 'other-key', 'short-signature',
    'long-signature', 'private-key', 'invalid-point', 'long-key'])
def test_invalid_signature_inputs_refused(tmp_path, signed, change):
    values = dict(signed)
    if change in ('image', 'signature'):
        values[change] = bytes([values[change][0] ^ 1]) + values[change][1:]
    elif change == 'other-key': values['key'] = values['other']
    elif change == 'short-signature': values['signature'] = values['signature'][:-1]
    elif change == 'long-signature': values['signature'] += b'\0'
    elif change == 'private-key': values['key'] = b'ECS2' + values['key'][4:]
    elif change == 'invalid-point': values['key'] = values['key'][:8] + bytes(64)
    elif change == 'long-key': values['key'] += b'\0'
    with ExitStack() as stack, pytest.raises(SafetyError):
        runtime.inspect_runtime_signature(*pins(stack, tmp_path, values))


@pytest.mark.parametrize('index', range(3))
def test_closed_pin_refused(tmp_path, signed, index):
    with ExitStack() as stack:
        inputs = pins(stack, tmp_path, signed)
        inputs[index].close()
        with pytest.raises(SafetyError, match='Open'):
            runtime.inspect_runtime_signature(*inputs)


@pytest.mark.parametrize('index', [1, 2])
def test_cached_bytes_must_match_held_file(tmp_path, signed, index):
    with ExitStack() as stack:
        inputs = pins(stack, tmp_path, signed)
        data = inputs[index].data
        inputs[index].data = bytes([data[0] ^ 1]) + data[1:]
        with pytest.raises(SafetyError, match='bounded'):
            runtime.inspect_runtime_signature(*inputs)


@pytest.mark.parametrize('operation', ['BCryptOpenAlgorithmProvider', 'BCryptImportKeyPair',
    'BCryptVerifySignature', 'BCryptDestroyKey', 'BCryptCloseAlgorithmProvider'])
def test_provider_failures_refused_and_resources_closed(tmp_path, signed, monkeypatch, operation):
    native = runtime._native()
    calls = []
    class Provider:
        def __getattr__(self, name):
            def call(*args):
                calls.append(name)
                if name == operation and name not in ('BCryptDestroyKey', 'BCryptCloseAlgorithmProvider'):
                    return -1
                status = getattr(native, name)(*args)
                return -1 if name == operation else status
            return call
    monkeypatch.setattr(runtime, '_native', Provider)
    with ExitStack() as stack, pytest.raises(SafetyError):
        runtime.inspect_runtime_signature(*pins(stack, tmp_path, signed))
    if operation != 'BCryptOpenAlgorithmProvider':
        assert calls.count('BCryptCloseAlgorithmProvider') == 1
    if operation not in ('BCryptOpenAlgorithmProvider', 'BCryptImportKeyPair'):
        assert calls.count('BCryptDestroyKey') == 1


def test_provider_exception_still_closes_resources(tmp_path, signed, monkeypatch):
    native = runtime._native()
    calls = []
    class Provider:
        def __getattr__(self, name):
            def call(*args):
                calls.append(name)
                if name == 'BCryptVerifySignature': raise OSError('fixture provider failure')
                return getattr(native, name)(*args)
            return call
    monkeypatch.setattr(runtime, '_native', Provider)
    with ExitStack() as stack, pytest.raises(OSError, match='fixture'):
        runtime.inspect_runtime_signature(*pins(stack, tmp_path, signed))
    assert calls[-2:] == ['BCryptDestroyKey', 'BCryptCloseAlgorithmProvider']


@pytest.mark.parametrize('index', range(3))
def test_pin_closed_during_verification_refuses_success(tmp_path, signed, monkeypatch, index):
    native = runtime._native()
    with ExitStack() as stack:
        inputs = pins(stack, tmp_path, signed)
        class Provider:
            def __getattr__(self, name):
                def call(*args):
                    status = getattr(native, name)(*args)
                    if name == 'BCryptVerifySignature': inputs[index].close()
                    return status
                return call
        monkeypatch.setattr(runtime, '_native', Provider)
        with pytest.raises(SafetyError, match='Open'):
            runtime.inspect_runtime_signature(*inputs)
