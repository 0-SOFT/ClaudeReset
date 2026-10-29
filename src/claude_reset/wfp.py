"""Read-only inspection of the owned Claude-only WFP filters.

The filters are installed outside the program. This module never adds, changes or
deletes WFP objects and never touches firewall profiles. Reading requires elevation.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import string
import uuid
from .safeio import SafetyError

FWP_UINT32, FWP_BYTE_BLOB_TYPE, FWP_SID = 3, 12, 13
FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET = 0, 8
FWP_CONDITION_FLAG_IS_LOOPBACK = 1
FWP_ACTION_BLOCK = 0x1001
FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER_FLAG_DISABLED = 1, 32
RPC_C_AUTHN_WINNT = 10
FWP_E_FILTER_NOT_FOUND = 0x80320003


class GUID(ctypes.Structure):
    _fields_ = [('data', ctypes.c_ubyte * 16)]

    @classmethod
    def of(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)

    def value(self):
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


LAYERS = {'v4': GUID.of('c38d57d1-05a7-4c33-904f-7fbceee60e82'), 'v6': GUID.of('4a72393b-319f-44bc-84c3-ba54dcb3b6b4')}
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


def _owned():
    rows = []
    desktop = uuid.UUID('b6579ff4-041c-4ab0-a376-7e2545a99e47')
    code = uuid.UUID('64ed9ea1-ea20-43db-a920-74bcb13e8203')
    owned = uuid.UUID('17766f36-f6d0-4dcb-b32b-9f5ca482678c')
    for family in LAYERS:
        rows.append(OwnedFilter('desktop', 'desktop_executable', family, str(uuid.uuid5(desktop, 'program-' + family)),
                                str(uuid.uuid5(desktop, 'sublayer')), b'ClaudeReset-Snow-Desktop-v1', 'app'))
        rows.append(OwnedFilter('desktop', 'desktop_package', family, str(uuid.uuid5(desktop, 'package-' + family)),
                                str(uuid.uuid5(desktop, 'sublayer')), b'ClaudeReset-Snow-Desktop-v1', 'package', 'Claude_pzs8sxrjxfjjc'))
        for name in ('vscode_cli', 'standalone_cli'):
            rows.append(OwnedFilter('native_cli', name, family, str(uuid.uuid5(code, name + '-' + family)),
                                    str(uuid.uuid5(code, 'sublayer')), b'ClaudeReset-Code-Snow-v1', 'app'))
        rows.append(OwnedFilter('owned_package', 'owned_package', family, str(uuid.uuid5(owned, family)),
                                str(uuid.uuid5(owned, 'sublayer')), b'ClaudeReset-Owned-Identity-Snow-v1', 'package',
                                'ClaudeReset.NetworkIsolation_79st3xwgefr0c'))
    return tuple(rows)


OWNED_FILTERS = _owned()


def package_sid(family_name: str) -> bytes:
    userenv = ctypes.WinDLL('userenv')
    advapi = ctypes.WinDLL('advapi32')
    derive = userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    derive.restype = ctypes.c_long
    advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi.GetLengthSid.restype = wintypes.DWORD
    advapi.FreeSid.argtypes = [ctypes.c_void_p]
    advapi.FreeSid.restype = ctypes.c_void_p
    sid = ctypes.c_void_p()
    if derive(family_name, ctypes.byref(sid)) or not sid.value:
        raise SafetyError('Package identity could not be derived')
    try:
        return ctypes.string_at(sid, advapi.GetLengthSid(sid))
    finally:
        advapi.FreeSid(sid)


def sid_at(pointer) -> bytes:
    advapi = ctypes.WinDLL('advapi32')
    advapi.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi.IsValidSid.restype = wintypes.BOOL
    advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi.GetLengthSid.restype = wintypes.DWORD
    if not pointer or not advapi.IsValidSid(pointer):
        raise SafetyError('Filter package condition is not a valid SID')
    size = advapi.GetLengthSid(pointer)
    if not 8 <= size <= 68:
        raise SafetyError('Filter package condition is not a valid SID')
    return ctypes.string_at(pointer, size)


def device_to_dos(device_path: str) -> str | None:
    """Map a WFP application ID (lower-case NT device path) to a drive path."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.QueryDosDeviceW.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in string.ascii_uppercase:
        if kernel.QueryDosDeviceW(letter + ':', buffer, len(buffer)):
            prefix = buffer.value.lower().rstrip('\\') + '\\'
            if device_path.lower().startswith(prefix):
                return letter + ':\\' + device_path[len(prefix):]
    return None


def describe(f: FILTER, expected: OwnedFilter, *, sid_of=package_sid) -> dict:
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


def inspect_owned_filters() -> dict:
    """Read the ten owned filters. Fails closed: missing or altered filters are reported."""
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise SafetyError('This operation requires 64-bit Windows')
    if (ctypes.sizeof(VALUE), ctypes.sizeof(CONDITION), ctypes.sizeof(FILTER)) != (16, 40, 200):
        raise SafetyError('Unexpected WFP structure layout')
    fw = ctypes.WinDLL('fwpuclnt')

    def api(name, args):
        fn = getattr(fw, name)
        fn.argtypes, fn.restype = args, wintypes.DWORD
        return fn
    open_engine = api('FwpmEngineOpen0', [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)])
    close_engine = api('FwpmEngineClose0', [wintypes.HANDLE])
    get_filter = api('FwpmFilterGetByKey0', [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.POINTER(FILTER))])
    fw.FwpmFreeMemory0.argtypes, fw.FwpmFreeMemory0.restype = [ctypes.POINTER(ctypes.c_void_p)], None
    administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
    report = {'administrator': administrator, 'read_only': True, 'filters_changed': False, 'firewall_profiles_changed': False}
    if not administrator:
        return {**report, 'status': 'administrator_required', 'passed': False}
    engine = wintypes.HANDLE()
    code = open_engine(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(engine))
    if code:
        return {**report, 'status': 'engine_unavailable', 'passed': False, 'error_code': '0x%08x' % code}
    rows, problems = [], []
    try:
        for expected in OWNED_FILTERS:
            found = ctypes.POINTER(FILTER)()
            key = GUID.of(expected.key)
            code = get_filter(engine, ctypes.byref(key), ctypes.byref(found))
            if code:
                problems.append({'target': expected.target, 'family': expected.family,
                                 'status': 'missing' if code == FWP_E_FILTER_NOT_FOUND else 'unreadable', 'error_code': '0x%08x' % code})
                continue
            try:
                rows.append(describe(found.contents, expected))
            except SafetyError as exc:
                problems.append({'target': expected.target, 'family': expected.family, 'status': 'unexpected_structure', 'reason': str(exc)})
            finally:
                pointer = ctypes.cast(found, ctypes.c_void_p)
                fw.FwpmFreeMemory0(ctypes.byref(pointer))
    finally:
        close_engine(engine)
    stale = [r for r in rows if r.get('covered_path_exists') is False]
    return {**report, 'filters': rows, 'problems': problems, 'expected_count': len(OWNED_FILTERS),
            'verified_count': len(rows), 'passed': not problems,
            'status': 'owned_filters_verified' if not problems else 'owned_filters_incomplete',
            'filters_covering_missing_binaries': [{'target': r['target'], 'family': r['family'], 'covered_path': r['covered_path']} for r in stale]}
