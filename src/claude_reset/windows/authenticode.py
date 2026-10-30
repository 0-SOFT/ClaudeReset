"""Offline Authenticode evidence for a held file, never release authorization.

Only embedded signatures are supported. Cached revocation failures are fatal;
no fallback to network retrieval, catalog lookup, or weaker trust policy.
The caller must separately authenticate the release catalog and its authority.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
import uuid
from ..errors import SafetyError
from types import MappingProxyType
from .api import Library
from .pin import PinnedFile

__all__ = ['CertContext', 'ProviderCert', 'ProviderSigner', 'TrustData', 'check_digest', 'inspect_signature', 'wintrust']


class FileInfo(C.Structure):
    _fields_ = [('size', W.DWORD), ('path', W.LPCWSTR), ('handle', W.HANDLE),
                ('subject', C.c_void_p)]


class TrustData(C.Structure):
    _fields_ = [('size', W.DWORD), ('policy', C.c_void_p), ('sip', C.c_void_p),
                ('ui', W.DWORD), ('revocation', W.DWORD), ('choice', W.DWORD),
                ('file', C.POINTER(FileInfo)), ('action', W.DWORD),
                ('state', W.HANDLE), ('url', W.LPWSTR), ('flags', W.DWORD),
                ('context', W.DWORD), ('settings', C.c_void_p)]


class CertContext(C.Structure):
    _fields_ = [('encoding', W.DWORD), ('encoded', C.c_void_p), ('length', W.DWORD),
                ('info', C.c_void_p), ('store', W.HANDLE)]


class ProviderCert(C.Structure):
    _fields_ = [('size', W.DWORD), ('cert', C.POINTER(CertContext)),
                ('commercial', W.BOOL), ('root', W.BOOL), ('self_signed', W.BOOL),
                ('test', W.BOOL), ('revoked', W.DWORD), ('confidence', W.DWORD),
                ('error', W.DWORD), ('trust_list', C.c_void_p),
                ('trust_list_signer', W.BOOL), ('ctl', C.c_void_p),
                ('ctl_error', W.DWORD), ('cyclic', W.BOOL), ('chain', C.c_void_p)]


class ProviderSigner(C.Structure):
    _fields_ = [('size', W.DWORD), ('time', W.FILETIME), ('count', W.DWORD),
                ('certs', C.POINTER(ProviderCert)), ('kind', W.DWORD),
                ('signer', C.c_void_p), ('error', W.DWORD), ('counter_count', W.DWORD),
                ('counters', C.c_void_p), ('chain', C.c_void_p)]


# wintrust (windows/api.py has the shared table).
PROTOTYPES = MappingProxyType({'wintrust': MappingProxyType({
    'WinVerifyTrust': (W.LONG, [W.HWND, C.c_void_p, C.POINTER(TrustData)]),
    'WTHelperProvDataFromStateData': (C.c_void_p, [W.HANDLE]),
    'WTHelperGetProvSignerFromChain': (C.POINTER(ProviderSigner), [C.c_void_p, W.DWORD, W.BOOL, W.DWORD]),
})})


def wintrust() -> Library:
    """The wintrust functions the signature check calls."""
    return Library('wintrust', PROTOTYPES)


def _signer_digest(api, state):
    if not state:
        raise SafetyError('Missing Authenticode provider state')
    provider = api.WTHelperProvDataFromStateData(state)
    if not provider:
        raise SafetyError('Missing Authenticode provider data')
    pointer = api.WTHelperGetProvSignerFromChain(provider, 0, False, 0)
    if not pointer:
        raise SafetyError('Missing Authenticode signer')
    signer = pointer.contents
    if (signer.size < C.sizeof(ProviderSigner) or signer.error or signer.kind
            or not 1 <= signer.count <= 64 or not signer.certs):
        raise SafetyError('Invalid Authenticode signer chain')
    leaf = signer.certs[0]
    if leaf.size < C.sizeof(ProviderCert) or leaf.error or leaf.test or not leaf.cert:
        raise SafetyError('Invalid Authenticode signer certificate')
    cert = leaf.cert.contents
    if not cert.encoded or not 1 <= cert.length <= 1048576:
        raise SafetyError('Invalid signer certificate encoding')
    return hashlib.sha256(C.string_at(cert.encoded, cert.length)).hexdigest()


def check_digest(pin: PinnedFile) -> None:
    if not pin.rewind():
        raise SafetyError('Cannot rewind signature input')
    digest = hashlib.sha256()
    total = 0
    for chunk in pin.chunks('Cannot rehash signature input'):
        total += len(chunk)
        if total > 268435456:
            raise SafetyError('Signature input exceeds size bound')
        digest.update(chunk)
    if digest.hexdigest() != pin.sha256:
        raise SafetyError('Signature input differs from pinned catalog digest')


def inspect_signature(pin: PinnedFile, *, api=None, check=check_digest) -> dict:
    """Return evidence while caller keeps the same PinnedFile open.

    WinVerifyTrust success is exactly zero, not HRESULT success. Provider state
    is closed on every verification path, including exceptions and refusals.
    api is the wintrust library (loaded only after the digest check) and check the digest check of the pin.
    """
    if not isinstance(pin, PinnedFile) or not pin.handle:
        raise SafetyError('An open payload pin is required')
    check(pin)
    api = api or wintrust()
    info = FileInfo(C.sizeof(FileInfo), str(pin.path), pin.handle, None)
    data = TrustData()
    data.size = C.sizeof(data)
    data.ui = 2
    data.choice = 1
    data.file = C.pointer(info)
    data.action = 1
    # Cached revocation for the chain excluding its trust root; no URL fetches.
    data.flags = 0x80 | 0x1000 | 0x2000
    guid = (C.c_ubyte * 16).from_buffer_copy(
        uuid.UUID('00aac56b-cd44-11d0-8cc2-00c04fc295ee').bytes_le)
    try:
        status = api.WinVerifyTrust(C.c_void_p(-1), C.byref(guid), C.byref(data))
        if status != 0:
            raise SafetyError(f'Offline Authenticode verification failed: 0x{status & 0xffffffff:08x}')
        signer = _signer_digest(api, data.state)
    finally:
        data.action = 2
        closed = api.WinVerifyTrust(C.c_void_p(-1), C.byref(guid), C.byref(data))
        if closed != 0:
            raise SafetyError(f'Cannot close Authenticode state: 0x{closed & 0xffffffff:08x}')
    check(pin)
    return {'schema': 1, 'file_sha256': pin.sha256, 'signer_certificate_sha256': signer,
            'authenticode_verified': True, 'revocation_policy': 'cached_chain_exclude_root',
            'release_authority_verified': False, 'kernel_load_verified': False,
            'installable': False, 'client_admission': False}
