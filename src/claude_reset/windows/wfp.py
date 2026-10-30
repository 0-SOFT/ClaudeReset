"""Read-only inspection of the owned Claude-only WFP filters.

The filters are installed outside the program. This module never adds, changes or
deletes WFP objects and never touches firewall profiles. Reading requires elevation.
"""
from __future__ import annotations

import ctypes
import string
import uuid
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .. import config
from ..errors import SafetyError
from ..safeio import guarded, local_volume
from .api import Library

__all__ = ['BLOB', 'CONDITION', 'DISPLAY', 'FIELD_APP_ID', 'FIELD_FLAGS', 'FIELD_PACKAGE_ID', 'FILTER',
           'FWP_ACTION_BLOCK', 'FWP_ACTION_PERMIT', 'FWP_CONDITION_FLAG_IS_LOOPBACK', 'FWP_E_FILTER_NOT_FOUND', 'GUID', 'Identity', 'LAYERS', 'describe', 'package_sid', 'sid_at']


FWP_UINT32, FWP_BYTE_BLOB_TYPE, FWP_SID = 3, 12, 13
FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET = 0, 8
FWP_CONDITION_FLAG_IS_LOOPBACK = 1
FWP_ACTION_BLOCK = 0x1001
FWP_ACTION_PERMIT = 0x1002
FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER_FLAG_DISABLED = 1, 32
FWP_E_FILTER_NOT_FOUND = 0x80320003


@dataclass(frozen=True)
class Identity:
    kind: str
    value: str

    def validate(self) -> None:
        if self.kind == 'package':
            if self.value not in (config.DESKTOP_PACKAGE[0], config.OWNED_PACKAGE[0]):
                raise SafetyError('Unknown protected package')
        elif self.kind == 'app':
            path = Path(self.value)
            if not path.is_absolute() or path.suffix.lower() != '.exe':
                raise SafetyError('An exact existing executable is required')
            if (path.name.lower() in ('chrome.exe', 'code.exe', 'python.exe', 'pythonw.exe', 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'discord.exe', 'svchost.exe')
                    or 'codex' in path.name.casefold()
                    or any(part.casefold().startswith('openai.codex_') for part in path.parts)):
                raise SafetyError('Shared application identities cannot be restricted')
            local_volume(path)
            guarded(path, path.parent)
            if not path.is_file():
                raise SafetyError('An exact existing executable is required')
        else:
            raise SafetyError('Every filter needs an exact protected identity')


class GUID(ctypes.Structure):
    _fields_ = [('data', ctypes.c_ubyte * 16)]

    @classmethod
    def of(cls, value: str | uuid.UUID) -> GUID:
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)

    def value(self) -> str:
        return str(uuid.UUID(bytes_le=bytes(self.data)))


class DISPLAY(ctypes.Structure):
    _fields_ = [('name', wintypes.LPWSTR), ('description', wintypes.LPWSTR)]


class BLOB(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


class DATA(ctypes.Union):
    _fields_ = [('u8', ctypes.c_ubyte), ('u32', wintypes.DWORD), ('ptr', ctypes.c_void_p)]


class VALUE(ctypes.Structure):
    _fields_ = [('type', ctypes.c_uint32), ('value', DATA)]


class CONDITION(ctypes.Structure):
    _fields_ = [('fieldKey', GUID), ('matchType', ctypes.c_uint32), ('conditionValue', VALUE)]


class ACTION(ctypes.Structure):
    _fields_ = [('type', ctypes.c_uint32), ('key', GUID)]


class CONTEXT(ctypes.Union):
    _fields_ = [('raw', ctypes.c_uint64), ('key', GUID)]


class FILTER(ctypes.Structure):
    _fields_ = [('filterKey', GUID), ('displayData', DISPLAY), ('flags', wintypes.DWORD), ('providerKey', ctypes.POINTER(GUID)),
                ('providerData', BLOB), ('layerKey', GUID), ('subLayerKey', GUID), ('weight', VALUE),
                ('numFilterConditions', wintypes.DWORD), ('filterCondition', ctypes.POINTER(CONDITION)), ('action', ACTION),
                ('context', CONTEXT), ('reserved', ctypes.POINTER(GUID)), ('filterId', ctypes.c_uint64), ('effectiveWeight', VALUE)]


LAYERS = MappingProxyType({'v4': GUID.of('c38d57d1-05a7-4c33-904f-7fbceee60e82'),
                           'v6': GUID.of('4a72393b-319f-44bc-84c3-ba54dcb3b6b4')})
FIELD_APP_ID = GUID.of('d78e1e87-8644-4ea5-9437-d809ecefc971')
FIELD_PACKAGE_ID = GUID.of('71bc78fa-f17c-4997-a602-6abb261f351c')
FIELD_FLAGS = GUID.of('632ce23b-5167-435c-86d7-e903684aa80c')


@dataclass(frozen=True)
class OwnedFilter:
    group: str
    target: str
    family: str
    key: str
    sublayer: str
    mark: bytes
    kind: str  # 'app' (executable path) or 'package' (package SID)
    package_family: str | None = None


def package_sid(family_name: str) -> bytes:
    advapi = Library('advapi32')
    derive = Library('userenv').DeriveAppContainerSidFromAppContainerName
    sid = ctypes.c_void_p()
    if derive(family_name, ctypes.byref(sid)) or not sid.value:
        raise SafetyError('Package identity could not be derived', code='package_identity_underived')
    try:
        return ctypes.string_at(sid, advapi.GetLengthSid(sid))
    finally:
        advapi.FreeSid(sid)


def sid_at(pointer: ctypes.c_void_p) -> bytes:
    advapi = Library('advapi32')
    if not pointer or not advapi.IsValidSid(pointer):
        raise SafetyError('Filter package condition is not a valid SID')
    size = advapi.GetLengthSid(pointer)
    if not 8 <= size <= 68:
        raise SafetyError('Filter package condition is not a valid SID')
    return ctypes.string_at(pointer, size)


def device_to_dos(device_path: str) -> str | None:
    """Map a WFP application ID (lower-case NT device path) to a drive path."""
    kernel = Library('kernel32')
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in string.ascii_uppercase:
        if kernel.QueryDosDeviceW(letter + ':', buffer, len(buffer)):
            prefix = buffer.value.lower().rstrip('\\') + '\\'
            if device_path.lower().startswith(prefix):
                return letter + ':\\' + device_path[len(prefix):]
    return None


def describe(f: FILTER, expected: OwnedFilter, *, sid_of: Callable[[str], bytes]=package_sid) -> dict:
    """Validate one owned filter structure; raise SafetyError on any deviation."""
    checks = [
        f.filterKey.value() == expected.key,
        f.subLayerKey.value() == expected.sublayer,
        f.layerKey.value() == LAYERS[expected.family].value(),
        f.action.type == FWP_ACTION_BLOCK,
        bool(f.flags & FWPM_FILTER_FLAG_PERSISTENT) and not f.flags & FWPM_FILTER_FLAG_DISABLED,
        not f.providerKey,
        f.numFilterConditions == 2,
        f.providerData.size == len(expected.mark) and ctypes.string_at(f.providerData.data, f.providerData.size) == expected.mark,
    ]
    if not all(checks):
        raise SafetyError('Owned WFP filter does not match the reviewed structure')
    identity, loopback = f.filterCondition[0], f.filterCondition[1]
    if not (loopback.fieldKey.value() == FIELD_FLAGS.value() and loopback.matchType == FWP_MATCH_FLAGS_NONE_SET
            and loopback.conditionValue.type == FWP_UINT32 and loopback.conditionValue.value.u32 == FWP_CONDITION_FLAG_IS_LOOPBACK):
        raise SafetyError('Owned WFP filter is not limited to non-loopback traffic')
    row = {'group': expected.group, 'target': expected.target, 'family': expected.family, 'filter_id': int(f.filterId),
           'persistent': True, 'action': 'block_non_loopback'}
    if identity.matchType != FWP_MATCH_EQUAL:
        raise SafetyError('Owned WFP filter identity condition is not an exact match')
    if expected.kind == 'package':
        if identity.fieldKey.value() != FIELD_PACKAGE_ID.value() or identity.conditionValue.type != FWP_SID:
            raise SafetyError('Owned WFP filter identity condition is not a package SID')
        if sid_at(identity.conditionValue.value.ptr) != sid_of(expected.package_family):
            raise SafetyError('Owned WFP filter is bound to an unexpected package')
        row['package_family'] = expected.package_family
    else:
        if identity.fieldKey.value() != FIELD_APP_ID.value() or identity.conditionValue.type != FWP_BYTE_BLOB_TYPE:
            raise SafetyError('Owned WFP filter identity condition is not an application ID')
        blob = ctypes.cast(identity.conditionValue.value.ptr, ctypes.POINTER(BLOB)).contents
        if not 2 < blob.size < 32768 or blob.size % 2:
            raise SafetyError('Owned WFP filter application ID is invalid')
        device = ctypes.string_at(blob.data, blob.size).decode('utf-16-le').rstrip('\0')
        path = device_to_dos(device)
        row.update(covered_path=path, covered_path_exists=bool(path) and Path(path).is_file())
    return row
