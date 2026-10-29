"""Offline detached runtime-signature evidence, never approval of a signing key.

This verifies the raw P-256/SHA-256 format consumed by the prepared Sandboxie
driver and service. Authenticode, release authority and loaded-image identity
remain separate requirements. No signing or key persistence is implemented.
"""
import ctypes as C
import hashlib
import os
from pathlib import Path
import re
import stat
from .safeio import SafetyError,guarded,local_volume
from .windows_pin import PinnedFile
from .install_signature import _check_digest
from .install_payload import FILES, PinnedPayload

RUNTIME_IMAGES = frozenset(name for name in FILES
                          if name.startswith('Sandboxie/') and name.endswith('.exe'))
RUNTIME_SIDECARS = frozenset(name+'.sig' for name in RUNTIME_IMAGES)


class PinnedRuntimeSignatures:
    """Read an exact sidecar tree; this does not stage files or approve its key."""
    def __init__(self,root,expected_key_sha256,expected_signatures):
        self.signatures={};self.public_key=None
        self.root=Path(root)
        self.expected_key_sha256=expected_key_sha256
        self.expected_signatures=dict(expected_signatures) if type(expected_signatures) is dict else None
        if (not isinstance(expected_key_sha256,str) or re.fullmatch('[a-f0-9]{64}',expected_key_sha256) is None
                or self.expected_signatures is None or set(self.expected_signatures)!=RUNTIME_IMAGES
                or any(not isinstance(v,str) or re.fullmatch('[a-f0-9]{64}',v) is None
                       for v in self.expected_signatures.values())):
            raise SafetyError('Exact bounded runtime signature catalog required')
        try:
            self._tree()
            self.public_key=PinnedFile(self.root/'runtime-public-key.blob',
                expected_sha256=expected_key_sha256,limit=72)
            _check_pin(self.public_key,72)
            for name in sorted(RUNTIME_IMAGES):
                pin=PinnedFile(self.root/(name+'.sig'),expected_sha256=self.expected_signatures[name],limit=64)
                self.signatures[name]=pin
                _check_pin(pin,64)
            self._tree()
        except BaseException:
            self.close();raise

    def _tree(self):
        root=self.root
        guarded(local_volume(root),root,allow_root=True)
        names=RUNTIME_SIDECARS|{'runtime-public-key.blob'}
        directories={p.as_posix() for name in names for p in Path(name).parents if p!=Path('.')}
        pending=[root];found=set()
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    info=entry.stat(follow_symlinks=False)
                    name=Path(entry.path).relative_to(root).as_posix()
                    if entry.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
                        raise SafetyError('Reparse point in runtime signature tree')
                    if stat.S_ISDIR(info.st_mode):
                        if name not in directories:raise SafetyError('Unexpected runtime signature directory')
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(info.st_mode):
                        if name not in names:raise SafetyError('Unexpected runtime signature file')
                        found.add(name)
                    else:raise SafetyError('Nonregular runtime signature input')
        if found!=names:raise SafetyError('Incomplete runtime signature tree')

    def inspect(self,payload):
        self._tree()
        row=inspect_runtime_signature_set(payload,self.signatures,self.public_key,
            self.expected_key_sha256,self.expected_signatures)
        self._tree()
        return row

    def close(self):
        for pin in reversed(list(self.signatures.values())):pin.close()
        self.signatures.clear()
        if self.public_key is not None:self.public_key.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def _native():
    api = C.WinDLL('bcrypt')
    pointer = C.c_void_p
    signatures = {
        'BCryptOpenAlgorithmProvider': ([C.POINTER(pointer), C.c_wchar_p, C.c_wchar_p, C.c_ulong], C.c_long),
        'BCryptImportKeyPair': ([pointer, pointer, C.c_wchar_p, C.POINTER(pointer), pointer, C.c_ulong, C.c_ulong], C.c_long),
        'BCryptVerifySignature': ([pointer, pointer, pointer, C.c_ulong, pointer, C.c_ulong, C.c_ulong], C.c_long),
        'BCryptDestroyKey': ([pointer], C.c_long),
        'BCryptCloseAlgorithmProvider': ([pointer, C.c_ulong], C.c_long),
    }
    for name, (args, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes, function.restype = args, result
    return api


def _check_pin(pin, size=None):
    if not isinstance(pin, PinnedFile) or not pin.handle:
        raise SafetyError('Open detached-signature input pins required')
    _check_digest(pin)
    if size is not None and (not isinstance(pin.data, bytes) or len(pin.data) != size
            or hashlib.sha256(pin.data).hexdigest() != pin.sha256):
        raise SafetyError('Exact bounded detached-signature input required')


def inspect_runtime_signature(image, signature, public_key):
    """Caller retains all three file pins; supplied public key is not trusted."""
    def check():
        _check_pin(image)
        _check_pin(signature, 64)
        _check_pin(public_key, 72)
        if public_key.data[:8] != b'ECS1\x20\x00\x00\x00':
            raise SafetyError('Only a public CNG ECDSA P-256 blob is supported')
    check()
    identities = image.sha256, signature.sha256, public_key.sha256
    api = _native()
    algorithm, key = C.c_void_p(), C.c_void_p()
    try:
        if api.BCryptOpenAlgorithmProvider(C.byref(algorithm), 'ECDSA_P256', None, 0) != 0:
            raise SafetyError('Cannot open runtime-signature algorithm')
        blob = C.create_string_buffer(public_key.data)
        if api.BCryptImportKeyPair(algorithm, None, 'ECCPUBLICBLOB', C.byref(key), blob, 72, 0) != 0:
            raise SafetyError('Invalid runtime public key')
        digest = C.create_string_buffer(bytes.fromhex(image.sha256))
        signed = C.create_string_buffer(signature.data)
        if api.BCryptVerifySignature(key, None, digest, 32, signed, 64, 0) != 0:
            raise SafetyError('Detached runtime signature does not match')
    finally:
        try:
            key_status = api.BCryptDestroyKey(key) if key else 0
        finally:
            provider_status = api.BCryptCloseAlgorithmProvider(algorithm, 0) if algorithm else 0
        if key_status != 0 or provider_status != 0:
            raise SafetyError('Cannot close runtime-signature provider resources')
    check()
    if identities != (image.sha256, signature.sha256, public_key.sha256):
        raise SafetyError('Detached-signature inputs changed during verification')
    return dict(schema=1, file_sha256=identities[0], signature_sha256=identities[1],
                public_key_sha256=identities[2], detached_signature_verified=True,
                key_authority_verified=False, authenticode_verified=False,
                loaded_image_verified=False, installable=False, client_admission=False)


def inspect_runtime_signature_set(payload, signatures, public_key, expected_key_sha256, expected_signatures):
    """Verify all compiled runtime EXE slots against one supplied integrity catalog.

    The caller must independently approve this catalog/key and bind it to the
    compiled driver/service trust root. This function does neither. Sidecars are
    separately held inputs; they are not silently added to the review payload.
    """
    def digest(value): return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None
    if (not isinstance(payload, PinnedPayload) or type(signatures) is not dict
            or set(signatures) != RUNTIME_IMAGES or type(expected_signatures) is not dict
            or set(expected_signatures) != RUNTIME_IMAGES or not digest(expected_key_sha256)
            or any(not digest(value) for value in expected_signatures.values())):
        raise SafetyError('An exact complete runtime signature catalog is required')
    expected = dict(expected_signatures)
    sidecars = dict(signatures)
    payload.report()
    manifest = payload.manifest
    manifest_hash = payload.manifest_sha256
    images = dict(payload.pins)
    image_hashes = {name: pin.sha256 for name, pin in images.items()}

    def stable():
        payload.report()
        if (payload.manifest is not manifest or payload.manifest_sha256 != manifest_hash
                or manifest.sha256 != manifest_hash or set(payload.pins) != set(images)
                or any(payload.pins[name] is not pin for name, pin in images.items())
                or set(signatures) != RUNTIME_IMAGES
                or any(signatures[name] is not pin for name, pin in sidecars.items())
                or expected_signatures != expected):
            raise SafetyError('Held runtime signature catalog changed')
        _check_digest(manifest)
        _check_pin(public_key, 72)
        if public_key.sha256 != expected_key_sha256:
            raise SafetyError('Runtime public key fingerprint differs from catalog')
        for name in sorted(RUNTIME_IMAGES):
            _check_pin(images[name])
            _check_pin(sidecars[name], 64)
            if (images[name].sha256 != image_hashes[name]
                    or sidecars[name].sha256 != expected[name]):
                raise SafetyError('Runtime signature inputs differ from catalog')

    stable()
    checked = {}
    for name in sorted(RUNTIME_IMAGES):
        checked[name] = inspect_runtime_signature(images[name], sidecars[name], public_key)
    stable()
    return dict(schema=1, manifest_sha256=manifest_hash, public_key_sha256=expected_key_sha256,
                runtime_images=checked, complete_signature_set_verified=True,
                key_authority_verified=False, embedded_key_binding_verified=False,
                staged_sidecars_verified=False, loaded_image_verified=False,
                installable=False, client_admission=False)
