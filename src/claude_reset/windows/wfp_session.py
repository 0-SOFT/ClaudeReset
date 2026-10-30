"""An owned session with the Windows Filtering Platform: transactions, sublayers, filters and their readback.

Only this package names fwpuclnt functions. Code outside it uses the typed methods and transaction();
a session that is not inside transaction() never holds an open WFP transaction.
"""
from __future__ import annotations
from collections import namedtuple
from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes as W
import json
import os

from ..errors import SafetyError
from . import wfp
from . import wfp_security
from .api import Library
from types import MappingProxyType
from ..errors import WfpError
from collections.abc import Collection, Iterator
from pathlib import Path

__all__ = ['APP_ID', 'PROTOTYPES', 'SECURITY_DESCRIPTOR', 'SESSION', 'SID', 'SUBLAYER', 'Session', 'Sublayer', 'blob',
           'condition_blob', 'condition_sid', 'condition_u32', 'inspect_owned_filters']

SUBLAYER_NOT_FOUND = 0x80320007   # FWP_E_SUBLAYER_NOT_FOUND
READ_ONLY = 1                     # FWPM_TXN_READ_ONLY
INDEXED = 0x40                    # FWPM_FILTER_FLAG_INDEXED: BFE adds it on modern Windows
PERSISTENT = 1                    # FWPM_SUBLAYER_FLAG_PERSISTENT / FWPM_FILTER_FLAG_PERSISTENT
SID, APP_ID, SECURITY_DESCRIPTOR = 13, 12, 14   # FWP_DATA_TYPE values with pointer data
U32 = 3

Sublayer = namedtuple('Sublayer', 'flags weight provider data')


class SESSION(C.Structure):
    _fields_ = [('key', wfp.GUID), ('display', wfp.DISPLAY), ('flags', W.DWORD),
                ('timeout', W.DWORD), ('pid', W.DWORD), ('sid', C.c_void_p),
                ('username', W.LPWSTR), ('kernel', W.BOOL)]


class SUBLAYER(C.Structure):
    _fields_ = [('key', wfp.GUID), ('display', wfp.DISPLAY), ('flags', W.DWORD),
                ('provider', C.c_void_p), ('data', wfp.BLOB), ('weight', C.c_uint16)]


_GUID, _FILTER, _VOID = C.POINTER(wfp.GUID), C.POINTER(wfp.FILTER), C.c_void_p
_SECURITY_INFO = (W.DWORD, [W.HANDLE, _GUID, W.DWORD, _VOID, _VOID, _VOID, _VOID, C.POINTER(_VOID)])
# Every fwpuclnt function the program calls (windows/api.py has the shared table).
PROTOTYPES = MappingProxyType({'fwpuclnt': MappingProxyType({
    'FwpmEngineClose0': (W.DWORD, [W.HANDLE]),
    'FwpmEngineOpen0': (W.DWORD, [W.LPCWSTR, W.DWORD, _VOID, C.POINTER(SESSION), C.POINTER(W.HANDLE)]),
    'FwpmFilterAdd0': (W.DWORD, [W.HANDLE, _FILTER, _VOID, C.POINTER(C.c_uint64)]),
    'FwpmFilterCreateEnumHandle0': (W.DWORD, [W.HANDLE, _VOID, C.POINTER(W.HANDLE)]),
    'FwpmFilterDeleteByKey0': (W.DWORD, [W.HANDLE, _GUID]),
    'FwpmFilterDestroyEnumHandle0': (W.DWORD, [W.HANDLE, W.HANDLE]),
    'FwpmFilterEnum0': (W.DWORD, [W.HANDLE, W.HANDLE, W.DWORD, C.POINTER(C.POINTER(_FILTER)), C.POINTER(W.DWORD)]),
    'FwpmFilterGetByKey0': (W.DWORD, [W.HANDLE, _GUID, C.POINTER(_FILTER)]),
    'FwpmFilterGetSecurityInfoByKey0': _SECURITY_INFO,
    'FwpmFreeMemory0': (None, [C.POINTER(_VOID)]),
    'FwpmGetAppIdFromFileName0': (W.DWORD, [W.LPCWSTR, C.POINTER(C.POINTER(wfp.BLOB))]),
    'FwpmSubLayerAdd0': (W.DWORD, [W.HANDLE, C.POINTER(SUBLAYER), _VOID]),
    'FwpmSubLayerDeleteByKey0': (W.DWORD, [W.HANDLE, _GUID]),
    'FwpmSubLayerGetByKey0': (W.DWORD, [W.HANDLE, _GUID, C.POINTER(C.POINTER(SUBLAYER))]),
    'FwpmSubLayerGetSecurityInfoByKey0': _SECURITY_INFO,
    'FwpmTransactionAbort0': (W.DWORD, [W.HANDLE]),
    'FwpmTransactionBegin0': (W.DWORD, [W.HANDLE, W.DWORD]),
    'FwpmTransactionCommit0': (W.DWORD, [W.HANDLE]),
})})


def blob(data: bytes, keep: list) -> wfp.BLOB:
    """A byte blob over a copy of data (a condition value, a filter's provider data); keep holds the copy."""
    buffer = (C.c_ubyte * len(data)).from_buffer_copy(data)
    keep.append(buffer)
    return wfp.BLOB(len(data), buffer)


def condition_blob(condition: wfp.CONDITION, field: wfp.GUID, data_type: int, data: bytes, keep: list) -> None:
    """Point a condition at a copy of data; keep holds the buffers while the filter is in use."""
    value = blob(data, keep)
    keep.append(value)
    condition.fieldKey, condition.matchType, condition.conditionValue.type = field, 0, data_type
    condition.conditionValue.value.ptr = C.cast(C.pointer(value), C.c_void_p).value


def condition_sid(condition: wfp.CONDITION, field: wfp.GUID, sid: bytes, keep: list) -> None:
    """Point a condition at a copy of a SID (FWP_SID: the pointer is the SID itself)."""
    buffer = (C.c_ubyte * len(sid)).from_buffer_copy(sid)
    keep.append(buffer)
    condition.fieldKey, condition.matchType, condition.conditionValue.type = field, 0, SID
    condition.conditionValue.value.ptr = C.cast(buffer, C.c_void_p).value


def condition_u32(condition: wfp.CONDITION, field: wfp.GUID, data_type: int, value: int) -> None:
    condition.fieldKey, condition.matchType = field, 0
    condition.conditionValue.type = data_type
    condition.conditionValue.value.u32 = value


def _weight_group(f):
    if f.weight.type == 4 and f.weight.value.ptr:   # FWP_UINT64: BFE stores the effective weight
        return C.cast(f.weight.value.ptr, C.POINTER(C.c_uint64)).contents.value >> 60
    return f.weight.value.u8 if f.weight.type == 1 else -1


def _bytes(pointer, size):
    return C.string_at(pointer, size) if size and pointer else b''


def _difference(actual, wanted, system_flags):
    """Why a filter read back from BFE differs from the one we built, or None when it is the same."""
    if not (actual.layerKey.value() == wanted.layerKey.value() and actual.subLayerKey.value() == wanted.subLayerKey.value()
            and actual.action.type == wanted.action.type and (actual.flags & ~system_flags) == wanted.flags
            and not actual.providerKey and _weight_group(actual) == wanted.weight.value.u8
            and actual.numFilterConditions == wanted.numFilterConditions
            and _bytes(actual.providerData.data, actual.providerData.size) == _bytes(wanted.providerData.data, wanted.providerData.size)):
        return 'differs from the requested boundary: ' + json.dumps(
            {'flags': actual.flags, 'weight_type': actual.weight.type, 'weight_group': _weight_group(actual),
             'conditions': actual.numFilterConditions, 'action': actual.action.type, 'provider_present': bool(actual.providerKey)})
    for a, b in zip(actual.filterCondition[:actual.numFilterConditions], wanted.filterCondition[:wanted.numFilterConditions]):
        if a.fieldKey.value() != b.fieldKey.value() or a.matchType != b.matchType or a.conditionValue.type != b.conditionValue.type:
            return 'condition was changed'
        if a.conditionValue.type == SID:
            equal = wfp.sid_at(a.conditionValue.value.ptr) == wfp.sid_at(b.conditionValue.value.ptr)
        elif a.conditionValue.type in (APP_ID, SECURITY_DESCRIPTOR):
            x, y = (C.cast(v.conditionValue.value.ptr, C.POINTER(wfp.BLOB)).contents for v in (a, b))
            equal = x.size == y.size and _bytes(x.data, x.size) == _bytes(y.data, y.size)
        else:
            equal = a.conditionValue.value.u32 == b.conditionValue.value.u32
        if not equal:
            return 'target was changed'
    return None


class Session:
    """An owned engine session: persistent, or dynamic when its objects must die with the process.

    A borrowed session uses the handle of an open persistent parent; closing it never closes the parent."""

    def __init__(self, *, dynamic: bool=False, borrow: Session | None=None) -> None:
        self._transaction = False
        self._parent = borrow
        if borrow is not None:
            if not isinstance(borrow, Session) or borrow.dynamic is not False or not borrow.handle:
                raise SafetyError('An open persistent parent WFP session is required')
            self.dynamic, self.handle = False, borrow.handle
            return
        if os.name != 'nt' or not C.windll.shell32.IsUserAnAdmin():
            raise SafetyError('Administrator rights are required for Windows network protection')
        if (C.sizeof(SESSION), C.sizeof(SUBLAYER), C.sizeof(wfp.FILTER)) != (72, 72, 200):
            raise SafetyError('Unsupported Windows WFP layout')
        self.dynamic = dynamic
        self.fw = Library('fwpuclnt', PROTOTYPES)
        self.handle = W.HANDLE()
        session = SESSION(flags=1 if dynamic else 0)
        self.call('FwpmEngineOpen0', None, 10, None, C.byref(session), C.byref(self.handle))

    # --- the native boundary ----------------------------------------------------------------------

    def call(self, name: str, *args: object, allowed: Collection[int]=()) -> int:
        """One fwpuclnt function (prototype in PROTOTYPES); a result code outside `allowed` raises."""
        if self._parent is not None:
            if not self.handle or not self._parent.handle:
                raise SafetyError('Borrowed WFP session is closed')
            return self._parent.call(name, *args, allowed=allowed)
        code = getattr(self.fw, name)(*args)
        if code and code not in allowed:
            raise WfpError(f'Windows filtering operation {name} failed: 0x{code:08x}', api=name, status=code)
        return code

    def free(self, pointer: object) -> None:
        if self._parent is not None:
            return self._parent.free(pointer)
        value = C.cast(pointer, C.c_void_p)
        self.fw.FwpmFreeMemory0(C.byref(value))

    # --- lifetime and transactions ----------------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def in_transaction(self) -> bool:
        return self._transaction

    def close(self) -> None:
        if self._parent is not None:
            self.handle = W.HANDLE()
            return
        if self.handle:
            abort_error = None
            if self._transaction:
                try:
                    self._end('FwpmTransactionAbort0')
                except BaseException as error:
                    # Abort failure must not skip closing the owned session.
                    # Preserve the error even if the close itself succeeds.
                    abort_error = error
            self.call('FwpmEngineClose0', self.handle)
            self.handle = W.HANDLE()
            self._transaction = False
            if abort_error is not None:
                raise abort_error

    def _end(self, name):
        self.call(name, self.handle)
        self._transaction = False

    @contextmanager
    def transaction(self, *, read_only: bool=False) -> Iterator[Session]:
        """Changes inside commit together or not at all; a read-only snapshot is always aborted."""
        if self._transaction:
            raise SafetyError('A Windows filtering transaction is already open')
        self.call('FwpmTransactionBegin0', self.handle, READ_ONLY if read_only else 0)
        self._transaction = True
        try:
            yield self
            if not read_only:
                self._end('FwpmTransactionCommit0')
        except BaseException:
            self._end('FwpmTransactionAbort0')
            raise
        if read_only:
            self._end('FwpmTransactionAbort0')

    # --- sublayers --------------------------------------------------------------------------------

    def sublayer(self, key: wfp.GUID) -> Sublayer | None:
        """The sublayer's flags, weight, provider presence and data, or None when it does not exist."""
        ptr = C.POINTER(SUBLAYER)()
        code = self.call('FwpmSubLayerGetByKey0', self.handle, C.byref(key), C.byref(ptr), allowed=(SUBLAYER_NOT_FOUND,))
        if code:
            return None
        try:
            s = ptr.contents
            return Sublayer(s.flags, s.weight, bool(s.provider), _bytes(s.data.data, s.data.size))
        finally:
            self.free(ptr)

    def owned_sublayer(self, key: wfp.GUID, mark: bytes, weights: Collection[int], *, changed: str) -> bool:
        """Whether our exact persistent sublayer exists; one changed by someone else raises `changed`."""
        found = self.sublayer(key)
        if found is None:
            return False
        if found.flags != PERSISTENT or found.weight not in weights or found.provider or found.data != mark:
            raise SafetyError(changed)
        wfp_security.verify(self, 'sublayer', key)
        return True

    def add_sublayer(self, key: wfp.GUID, name: str, mark: bytes, weight: int) -> None:
        data = (C.c_ubyte * len(mark)).from_buffer_copy(mark)
        sublayer = SUBLAYER(key=key, display=wfp.DISPLAY(name, None), flags=PERSISTENT,
                            data=wfp.BLOB(len(mark), data), weight=weight)
        with wfp_security.Descriptor() as security:
            self.call('FwpmSubLayerAdd0', self.handle, C.byref(sublayer), security.pointer)

    def delete_sublayer(self, key: wfp.GUID, *, missing_ok: bool=False) -> None:
        self.call('FwpmSubLayerDeleteByKey0', self.handle, C.byref(key), allowed=(SUBLAYER_NOT_FOUND,) if missing_ok else ())

    # --- filters ----------------------------------------------------------------------------------

    def app_id(self, executable: Path | str) -> bytes:
        """The WFP application identity of an executable path."""
        ptr = C.POINTER(wfp.BLOB)()
        self.call('FwpmGetAppIdFromFileName0', str(executable), C.byref(ptr))
        try:
            return C.string_at(ptr.contents.data, ptr.contents.size)
        finally:
            self.free(ptr)

    def add_filter(self, f: wfp.FILTER) -> None:
        identifier = C.c_uint64()
        with wfp_security.Descriptor() as security:
            self.call('FwpmFilterAdd0', self.handle, C.byref(f), security.pointer, C.byref(identifier))

    def delete_filter(self, key: wfp.GUID) -> None:
        self.call('FwpmFilterDeleteByKey0', self.handle, C.byref(key))

    def matches(self, wanted: wfp.FILTER, *, label: str, system_flags: int=INDEXED) -> bool:
        """Whether the filter with wanted's key exists exactly as built; a changed one raises."""
        ptr = C.POINTER(wfp.FILTER)()
        code = self.call('FwpmFilterGetByKey0', self.handle, C.byref(wanted.filterKey), C.byref(ptr),
                         allowed=(wfp.FWP_E_FILTER_NOT_FOUND,))
        if code:
            return False
        try:
            problem = _difference(ptr.contents, wanted, system_flags)
            if problem:
                raise SafetyError(f'{label} {problem}')
            wfp_security.verify(self, 'filter', wanted.filterKey)
            return True
        finally:
            self.free(ptr)

    def filter_keys(self, sublayer: wfp.GUID) -> set[str]:
        """Keys of the filters in one sublayer; filters of other sublayers are never reported."""
        enum = W.HANDLE()
        self.call('FwpmFilterCreateEnumHandle0', self.handle, None, C.byref(enum))
        result = set()
        try:
            while True:
                entries = C.POINTER(C.POINTER(wfp.FILTER))()
                count = W.DWORD()
                self.call('FwpmFilterEnum0', self.handle, enum, 256, C.byref(entries), C.byref(count))
                try:
                    for index in range(count.value):
                        item = entries[index].contents
                        if item.subLayerKey.value() == sublayer.value():
                            result.add(item.filterKey.value())
                finally:
                    if entries:
                        self.free(entries)
                if count.value < 256:
                    return result
        finally:
            self.call('FwpmFilterDestroyEnumHandle0', self.handle, enum)

    def security_descriptor(self, kind: str, key: wfp.GUID) -> C.c_void_p:
        """The security descriptor pointer of an owned filter or sublayer; the caller frees it with free()."""
        functions = {'filter': 'FwpmFilterGetSecurityInfoByKey0', 'sublayer': 'FwpmSubLayerGetSecurityInfoByKey0'}
        pointer = C.c_void_p()
        self.call(functions[kind], self.handle, C.byref(key), 5, None, None, None, None, C.byref(pointer))
        return pointer


def inspect_owned_filters() -> dict:
    """Read the ten owned filters. Fails closed: missing or altered filters are reported."""
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        raise SafetyError('This operation requires 64-bit Windows', code='needs_64_bit')
    if (C.sizeof(wfp.VALUE), C.sizeof(wfp.CONDITION), C.sizeof(wfp.FILTER)) != (16, 40, 200):
        raise SafetyError('Unexpected WFP structure layout', code='wfp_layout')
    fw = Library('fwpuclnt', PROTOTYPES)
    open_engine, close_engine, get_filter = fw.FwpmEngineOpen0, fw.FwpmEngineClose0, fw.FwpmFilterGetByKey0
    administrator = bool(C.windll.shell32.IsUserAnAdmin())
    report = {'administrator': administrator, 'read_only': True, 'filters_changed': False, 'firewall_profiles_changed': False}
    if not administrator:
        return {**report, 'status': wfp.Inspection.ADMINISTRATOR_REQUIRED, 'passed': False}
    engine = W.HANDLE()
    code = open_engine(None, wfp.RPC_C_AUTHN_WINNT, None, None, C.byref(engine))
    if code:
        return {**report, 'status': wfp.Inspection.ENGINE_UNAVAILABLE, 'passed': False, 'error_code': '0x%08x' % code}
    rows, problems = [], []
    try:
        for expected in wfp.OWNED_FILTERS:
            found = C.POINTER(wfp.FILTER)()
            key = wfp.GUID.of(expected.key)
            code = get_filter(engine, C.byref(key), C.byref(found))
            if code:
                problems.append({'target': expected.target, 'family': expected.family,
                                 'status': wfp.Inspection.MISSING if code == wfp.FWP_E_FILTER_NOT_FOUND
                                 else wfp.Inspection.UNREADABLE, 'error_code': '0x%08x' % code})
                continue
            try:
                rows.append(wfp.describe(found.contents, expected))
            except SafetyError as exc:
                problems.append({'target': expected.target, 'family': expected.family,
                                 'status': wfp.Inspection.UNEXPECTED_STRUCTURE, 'reason': str(exc)})
            finally:
                pointer = C.cast(found, C.c_void_p)
                fw.FwpmFreeMemory0(C.byref(pointer))
    finally:
        close_engine(engine)
    stale = [r for r in rows if r.get('covered_path_exists') is False]
    return {**report, 'filters': rows, 'problems': problems, 'expected_count': len(wfp.OWNED_FILTERS),
            'verified_count': len(rows), 'passed': not problems,
            'status': wfp.Inspection.OWNED_FILTERS_VERIFIED if not problems else wfp.Inspection.OWNED_FILTERS_INCOMPLETE,
            'filters_covering_missing_binaries': [{'target': r['target'], 'family': r['family'], 'covered_path': r['covered_path']} for r in stale]}
