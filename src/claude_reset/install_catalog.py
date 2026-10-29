"""Offline evidence binding an authenticated CAT file to a pinned JSON manifest.

The catalog is verified as a file by handle; membership is decoded from its
same hashed bytes. WTD_CHOICE_CATALOG/path lookup is deliberately not used.
Approved product publisher policy and kernel acceptance are separate gates.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import re
from .install_payload import PinnedPayload
from .install_signature import inspect_signature,_check_digest
from .windows_pin import PinnedFile
from .safeio import SafetyError

SHA256=b'2.16.840.1.101.3.4.2.1'
INDIRECT=b'1.3.6.1.4.1.311.2.1.4'


class Blob(C.Structure):
    _fields_=[('size',W.DWORD),('data',C.c_void_p)]


class Algorithm(C.Structure):
    _fields_=[('oid',C.c_char_p),('parameters',Blob)]


class Attribute(C.Structure):
    _fields_=[('oid',C.c_char_p),('count',W.DWORD),('values',C.POINTER(Blob))]


class Entry(C.Structure):
    _fields_=[('subject',Blob),('count',W.DWORD),('attributes',C.POINTER(Attribute))]


class Usage(C.Structure):
    _fields_=[('count',W.DWORD),('oids',C.POINTER(C.c_char_p))]


class Info(C.Structure):
    _fields_=[('version',W.DWORD),('usage',Usage),('identifier',Blob),('sequence',Blob),
              ('this_update',W.FILETIME),('next_update',W.FILETIME),('algorithm',Algorithm),
              ('count',W.DWORD),('entries',C.POINTER(Entry)),('extension_count',W.DWORD),
              ('extensions',C.c_void_p)]


class Context(C.Structure):
    _fields_=[('encoding',W.DWORD),('encoded',C.c_void_p),('encoded_size',W.DWORD),
              ('info',C.POINTER(Info)),('store',W.HANDLE),('message',W.HANDLE),
              ('content',C.c_void_p),('content_size',W.DWORD)]


class Indirect(C.Structure):
    _fields_=[('data',Algorithm),('algorithm',Algorithm),('digest',Blob)]


def _blob(value,limit):
    if not value.data or not 1<=value.size<=limit:raise SafetyError('Invalid catalog blob bound')
    return C.string_at(value.data,value.size)


def _native():
    api=C.WinDLL('crypt32',use_last_error=True)
    for name,args,result in (
        ('CertCreateCTLContext',[W.DWORD,C.c_void_p,W.DWORD],C.POINTER(Context)),
        ('CertFreeCTLContext',[C.POINTER(Context)],W.BOOL),
        ('CryptDecodeObjectEx',[W.DWORD,C.c_char_p,C.c_void_p,W.DWORD,W.DWORD,
                                C.c_void_p,C.c_void_p,C.POINTER(W.DWORD)],W.BOOL),
    ):
        fn=getattr(api,name);fn.argtypes,fn.restype=args,result
    kernel=C.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[C.c_void_p];kernel.LocalFree.restype=C.c_void_p
    return api,kernel


def _single_der_container(raw):
    # Reject concatenated/padded containers so signature and membership parsers
    # cannot select different top-level objects from the same file bytes.
    if len(raw)<2 or raw[0]!=0x30:raise SafetyError('A single DER catalog container is required')
    length=raw[1];header=2
    if length&0x80:
        count=length&0x7f
        if not 1<=count<=3 or len(raw)<2+count or raw[2]==0:
            raise SafetyError('Invalid DER catalog length')
        length=int.from_bytes(raw[2:2+count],'big');header+=count
        if length<128:raise SafetyError('Noncanonical DER catalog length')
    if header+length!=len(raw):raise SafetyError('Trailing or truncated catalog content')


def _require_manifest_member(raw,expected):
    """Membership only, never an authenticity decision for these input bytes."""
    if not isinstance(raw,bytes) or not 0<len(raw)<=1048576:
        raise SafetyError('Catalog encoding exceeds its bound')
    _single_der_container(raw)
    if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):
        raise SafetyError('A SHA256 manifest digest is required')
    expected=bytes.fromhex(expected)
    api,kernel=_native();encoded=C.create_string_buffer(raw)
    context=api.CertCreateCTLContext(0x10001,encoded,len(raw))
    if not context:raise SafetyError('Cannot decode catalog context')
    try:
        if not context.contents.info:raise SafetyError('Catalog information is missing')
        info=context.contents.info.contents
        if (info.version!=0 or info.algorithm.oid!=b'1.3.6.1.4.1.311.12.1.3'
                or info.usage.count!=1 or not info.usage.oids
                or info.usage.oids[0]!=b'1.3.6.1.4.1.311.12.1.1'
                or not 1<=info.count<=4096 or not info.entries):
            raise SafetyError('Unsupported SHA256 catalog structure')
        matches=[]
        for index in range(info.count):
            entry=info.entries[index]
            if _blob(entry.subject,64)==expected:matches.append(entry)
        if len(matches)!=1:raise SafetyError('Catalog must contain exactly one manifest member')
        entry=matches[0]
        if not 1<=entry.count<=32 or not entry.attributes:
            raise SafetyError('Invalid manifest member attributes')
        values=[]
        for index in range(entry.count):
            attribute=entry.attributes[index]
            if attribute.oid==INDIRECT:
                if attribute.count!=1 or not attribute.values:
                    raise SafetyError('Ambiguous manifest indirect data')
                values.append(_blob(attribute.values[0],65536))
        if len(values)!=1:raise SafetyError('Exactly one manifest indirect digest is required')
        value=C.create_string_buffer(values[0]);decoded=C.c_void_p();size=W.DWORD()
        try:
            if not api.CryptDecodeObjectEx(0x10001,INDIRECT,value,len(values[0]),0x8000,
                                          None,C.byref(decoded),C.byref(size)):
                raise SafetyError('Cannot decode manifest indirect digest')
            if not decoded or size.value<C.sizeof(Indirect):raise SafetyError('Incomplete indirect digest')
            indirect=C.cast(decoded,C.POINTER(Indirect)).contents
            if (indirect.algorithm.oid!=SHA256 or indirect.data.oid!=b'1.3.6.1.4.1.311.2.1.25'
                    or _blob(indirect.digest,32)!=expected):
                raise SafetyError('Manifest full-file SHA256 does not match the catalog')
        finally:
            if decoded and kernel.LocalFree(decoded):raise SafetyError('Cannot free catalog digest')
    finally:
        if not api.CertFreeCTLContext(context):raise SafetyError('Cannot free catalog context')


def _catalog_bytes(pin):
    seek=pin.api.SetFilePointerEx
    seek.argtypes=[W.HANDLE,C.c_int64,C.POINTER(C.c_int64),W.DWORD];seek.restype=W.BOOL
    if not seek(pin.handle,0,None,0):raise SafetyError('Cannot rewind catalog input')
    chunks=[];total=0;buffer=C.create_string_buffer(65536)
    while True:
        count=W.DWORD()
        if not pin.api.ReadFile(pin.handle,buffer,len(buffer),C.byref(count),None):
            raise SafetyError('Cannot read held catalog input')
        if not count.value:break
        total+=count.value
        if total>1048576:raise SafetyError('Catalog input exceeds size bound')
        chunks.append(buffer.raw[:count.value])
    raw=b''.join(chunks)
    if not raw or hashlib.sha256(raw).hexdigest()!=pin.sha256:
        raise SafetyError('Catalog input differs from its pinned digest')
    return raw


def inspect_release_catalog(catalog_pin,payload):
    if not isinstance(catalog_pin,PinnedFile) or not catalog_pin.handle or not isinstance(payload,PinnedPayload):
        raise SafetyError('Held catalog and exact payload required')
    payload.report()
    raw=_catalog_bytes(catalog_pin)
    signature=inspect_signature(catalog_pin)
    _require_manifest_member(raw,payload.manifest_sha256)
    _check_digest(catalog_pin);_check_digest(payload.manifest)
    return {'schema':1,'catalog_sha256':catalog_pin.sha256,'manifest_sha256':payload.manifest_sha256,
            'catalog_authenticode_verified':True,'manifest_membership_verified':True,
            'signer_certificate_sha256':signature['signer_certificate_sha256'],
            'release_authority_verified':False,'kernel_load_verified':False,
            'installable':False,'client_admission':False}
