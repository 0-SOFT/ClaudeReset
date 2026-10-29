"""Prepare a separate runtime-signing trust root; preserve upstream certificate verification.

Accepts only a public Windows CNG ECDSA P-256 blob, never a private key.
The output is not installed, signed, or an assertion of key authority.
"""
import argparse
import ctypes as C
import difflib
import hashlib
import json
import re
from pathlib import Path

UPSTREAM_SHA256 = '600dc7bfc10da2b3ef25f9abe3c3d9f137fa1bc667770306c5d9f7a3cf84ebcb'
RELATIVE = 'Sandboxie/core/drv/verify.c'
SERVICE_RELATIVE = 'Sandboxie/common/verify.c'
SERVICE_UPSTREAM_SHA256 = 'd9f2fcb41cc0bc86f86a37e9f29ba5c416a53a1fdc4b52228e52eee2ac898dce'


def transform_service(original, public_key):
    """Use the same runtime key for the service's detached caller signatures."""
    validate_public_key(public_key)
    pattern = r'static UCHAR KphpTrustedPublicKey\[\]\s*=\s*\{.*?\};'
    array = 'static UCHAR CrRuntimePublicKey[] = {\n'
    for offset in range(0, len(public_key), 12):
        array += '    ' + ', '.join('0x%02X' % v for v in public_key[offset:offset+12]) + ',\n'
    array += '};'
    changed, count = re.subn(pattern, lambda _: array, original, flags=re.S)
    if count != 1 or changed.count('KphpTrustedPublicKey') != 2:
        raise ValueError('Unexpected service verifier structure')
    return changed.replace('KphpTrustedPublicKey', 'CrRuntimePublicKey')


def validate_public_key(blob):
    if len(blob) != 72 or blob[:8] != b'ECS1\x20\x00\x00\x00':
        raise ValueError('Only an ECDSA P-256 public blob is accepted')
    api = C.WinDLL('bcrypt')
    api.BCryptOpenAlgorithmProvider.argtypes = [C.POINTER(C.c_void_p), C.c_wchar_p, C.c_wchar_p, C.c_ulong]
    api.BCryptImportKeyPair.argtypes = [C.c_void_p, C.c_void_p, C.c_wchar_p, C.POINTER(C.c_void_p), C.c_void_p, C.c_ulong, C.c_ulong]
    api.BCryptDestroyKey.argtypes = [C.c_void_p]
    api.BCryptCloseAlgorithmProvider.argtypes = [C.c_void_p, C.c_ulong]
    algorithm, key = C.c_void_p(), C.c_void_p()
    try:
        if api.BCryptOpenAlgorithmProvider(C.byref(algorithm), 'ECDSA_P256', None, 0):
            raise RuntimeError('Windows ECDSA provider unavailable')
        data = C.create_string_buffer(blob)
        if api.BCryptImportKeyPair(algorithm, None, 'ECCPUBLICBLOB', C.byref(key), data, len(blob), 0):
            raise ValueError('Windows rejected the public curve point')
    finally:
        if key: api.BCryptDestroyKey(key)
        if algorithm: api.BCryptCloseAlgorithmProvider(algorithm, 0)


def transform(original, public_key):
    validate_public_key(public_key)
    start = original.index('NTSTATUS KphVerifySignature(')
    file_start = original.index('NTSTATUS KphVerifyFile(')
    buffer_start = original.index('NTSTATUS KphVerifyBuffer(')
    verifier = original[start:file_start]
    runtime = verifier.replace('KphVerifySignature(', 'KphVerifyRuntimeSignature(', 1)
    runtime = runtime.replace('KphpTrustedPublicKey', 'CrRuntimePublicKey')
    file_verifier = original[file_start:buffer_start]
    if file_verifier.count('KphVerifySignature(') != 1:
        raise ValueError('Unexpected upstream verifier structure')
    file_verifier = file_verifier.replace('KphVerifySignature(', 'KphVerifyRuntimeSignature(')
    array = '// Separate code-integrity key. Upstream certificate/buffer trust is unchanged.\n'
    array += 'static const UCHAR CrRuntimePublicKey[] = {\n'
    for offset in range(0, len(public_key), 12):
        array += '    ' + ', '.join('0x%02X' % value for value in public_key[offset:offset+12]) + ',\n'
    array += '};\n\n'
    return original[:file_start] + array + runtime + file_verifier + original[buffer_start:]


def prepare(source, output, key_file, expected_hash):
    if output.exists(): raise RuntimeError('Existing candidate preserved; use a fresh output directory')
    with key_file.open('rb') as stream: key = stream.read(73)
    if hashlib.sha256(key).hexdigest() != expected_hash:
        raise ValueError('Public-key fingerprint mismatch')
    data = (source / RELATIVE).read_bytes()
    if hashlib.sha256(data).hexdigest() != UPSTREAM_SHA256:
        raise ValueError('Unexpected upstream verify.c')
    original = data.decode('utf-8-sig').replace('\r\n', '\n')
    changed = transform(original, key)
    service_data = (source / SERVICE_RELATIVE).read_bytes()
    if hashlib.sha256(service_data).hexdigest() != SERVICE_UPSTREAM_SHA256:
        raise ValueError('Unexpected upstream service verify.c')
    service_original = service_data.decode('utf-8-sig').replace('\r\n', '\n')
    service_changed = transform_service(service_original, key)
    target = output / 'prepared' / RELATIVE
    target.parent.mkdir(parents=True)
    target.write_text(changed, encoding='utf-8', newline='\n')
    service_target = output / 'prepared' / SERVICE_RELATIVE
    service_target.parent.mkdir(parents=True)
    service_target.write_text(service_changed, encoding='utf-8', newline='\n')
    patch = ''.join(difflib.unified_diff(original.splitlines(True), changed.splitlines(True), fromfile='a/'+RELATIVE, tofile='b/'+RELATIVE))
    patch += ''.join(difflib.unified_diff(service_original.splitlines(True), service_changed.splitlines(True), fromfile='a/'+SERVICE_RELATIVE, tofile='b/'+SERVICE_RELATIVE))
    (output / 'runtime-trust.patch').write_text(patch, encoding='utf-8', newline='\n')
    (output / 'runtime-public-key.blob').write_bytes(key)
    receipt = {'schema': 1, 'upstream_sha256': UPSTREAM_SHA256,
        'prepared_sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'public_key_sha256': expected_hash,
        'service_upstream_sha256': SERVICE_UPSTREAM_SHA256,
        'service_prepared_sha256': hashlib.sha256(service_target.read_bytes()).hexdigest(),
        'service_runtime_key_matches_driver': True,
        'upstream_certificate_trust_changed': False, 'key_authority_verified': False,
        'runtime_signatures_supplied': False, 'windows_driver_signing_complete': False,
        'installed': False, 'production_clients_permitted': False}
    (output / 'manifest.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--public-key-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_root, args.output_root, args.public_key, args.public_key_sha256)))
