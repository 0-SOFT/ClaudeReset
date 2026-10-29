"""Claude-scoped persistent deny and process-lifetime WFP permits.

No firewall profiles, routes, DNS or router operations. Every rule has an exact
application/package identity. The dynamic session must remain owned by the relay.
"""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import uuid
from . import wfp
from .safeio import SafetyError, guarded, local_volume

NAMESPACE = uuid.UUID('ba7c80bc-4fea-45a3-9266-f2c7b78be1ae')
SUBKEY = wfp.GUID.of(uuid.uuid5(NAMESPACE, 'strict-gate-v1'))
MARK = b'ClaudeReset-Strict-Gate-v1'
SUBWEIGHT = 61000  # disposable fixtures use another weight; BFE shifts a duplicate weight
PERMIT, BLOCK = 0x1002, 0x1001
LAYERS = {f'connect_{k}': v for k, v in wfp.LAYERS.items()}
LAYERS.update(recv_v4=wfp.GUID.of('e1cd9fe7-f4b5-4273-96c0-592e487b8650'),
              recv_v6=wfp.GUID.of('a3b42c97-9f04-4672-b87e-cee9c483257f'))
REMOTE = wfp.GUID.of('b235ae9a-1d64-49b8-a44c-5ff3d9095045')
PORT = wfp.GUID.of('c35a604d-d22b-4e1a-91b4-68f674ee674b')
PROTOCOL = wfp.GUID.of('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7')
LOCAL_ADDRESS = wfp.GUID.of('d9ee00de-c1ef-4617-bfe3-ffd8f5a08957')
LOCAL_PORT = wfp.GUID.of('0c1ba1af-5765-453f-af22-a8f791ac775b')
SERVICE_USER = wfp.GUID.of('af043a0a-b34d-4f86-979c-c90371af6e66')


class SESSION(C.Structure):
    _fields_ = [('key', wfp.GUID), ('display', wfp.DISPLAY), ('flags', W.DWORD),
                ('timeout', W.DWORD), ('pid', W.DWORD), ('sid', C.c_void_p),
                ('username', W.LPWSTR), ('kernel', W.BOOL)]


class SUBLAYER(C.Structure):
    _fields_ = [('key', wfp.GUID), ('display', wfp.DISPLAY), ('flags', W.DWORD),
                ('provider', C.c_void_p), ('data', wfp.BLOB), ('weight', C.c_uint16)]


@dataclass(frozen=True)
class Identity:
    kind: str
    value: str

    def validate(self):
        if self.kind == 'package':
            from .netguard import DESKTOP_PACKAGE, OWNED_PACKAGE
            if self.value not in (DESKTOP_PACKAGE[0], OWNED_PACKAGE[0]):
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


@dataclass(frozen=True)
class Rule:
    identity: Identity
    layer: str
    action: int = BLOCK
    address: str | None = None
    port: int | None = None
    persistent: bool = True

    def validate(self):
        self.identity.validate()
        if self.layer not in LAYERS or self.action not in (BLOCK, PERMIT):
            raise SafetyError('Unknown scoped filtering operation')
        if self.action == PERMIT:
            # Current backend is IPv4 TCP only; IPv6 remains denied.
            if self.layer != 'connect_v4' or type(self.port) is not int or not 1 <= self.port <= 65535:
                raise SafetyError('Permit must constrain direction, protocol, address and port')
            if ipaddress.ip_address(self.address).version != 4:
                raise SafetyError('This backend requires an exact IPv4 endpoint')
        elif self.address is not None or self.port is not None or not self.persistent:
            raise SafetyError('The default deny must be persistent and unconditional for its identity')

    @property
    def key(self):
        # One persistent endpoint slot per engine. A changed endpoint must fail
        # readback, never accumulate an extra surviving permit beside the old one.
        value = ({'identity': asdict(self.identity), 'role': 'pinned_endpoint', 'layer': self.layer}
                 if self.persistent and self.action == PERMIT else asdict(self))
        canonical = json.dumps(value, sort_keys=True)
        return wfp.GUID.of(uuid.uuid5(NAMESPACE, canonical))


def deny_rules(identities):
    return [Rule(identity, layer) for identity in identities for layer in LAYERS]


@dataclass(frozen=True)
class ServiceRule(Rule):
    """An endpoint permit usable only by the dedicated service token."""
    service: str = ''

    def validate(self):
        if (self.service not in ('ClaudeResetBackend', 'ClaudeResetGateway',
                                'ClaudeResetBackendFixture', 'ClaudeResetGatewayFixture')
                or self.identity.kind != 'app' or self.action != PERMIT):
            raise SafetyError('Only owned service endpoint permits are supported')
        if self.layer == 'recv_v4':
            if self.address != '127.0.0.1':
                raise SafetyError('Service listeners must use IPv4 loopback')
            Rule(self.identity, 'connect_v4', self.action, self.address, self.port, self.persistent).validate()
        else:
            super().validate()

    @property
    def key(self):
        # Stable slot per service/image/direction. Changing an endpoint requires
        # explicit replacement; it must not accumulate additional permits.
        value = {'identity': asdict(self.identity), 'role': 'service_endpoint',
                 'layer': self.layer, 'service': self.service, 'persistent': self.persistent}
        return wfp.GUID.of(uuid.uuid5(NAMESPACE, json.dumps(value, sort_keys=True)))


def relay_permits(identities, port):
    return [Rule(identity, 'connect_v4', PERMIT, '127.0.0.1', port, False) for identity in identities]


class Engine:
    """Transaction wrapper. Never deletes foreign objects or broadens a deny."""
    def __init__(self, *, dynamic=False):
        if os.name != 'nt' or not C.windll.shell32.IsUserAnAdmin():
            raise SafetyError('Administrator rights are required for Windows network protection')
        if (C.sizeof(SESSION), C.sizeof(SUBLAYER), C.sizeof(wfp.FILTER)) != (72, 72, 200):
            raise SafetyError('Unsupported Windows WFP layout')
        self.dynamic = dynamic
        self.fw = C.WinDLL('fwpuclnt')
        self.handle = W.HANDLE()
        self._transaction = False
        session = SESSION(flags=1 if dynamic else 0)
        self._call('FwpmEngineOpen0', [W.LPCWSTR, W.DWORD, C.c_void_p, C.POINTER(SESSION), C.POINTER(W.HANDLE)],
                   None, 10, None, C.byref(session), C.byref(self.handle))

    def _call(self, name, signature, *args, allowed=()):
        fn = getattr(self.fw, name)
        fn.argtypes, fn.restype = signature, W.DWORD
        code = fn(*args)
        if code and code not in allowed:
            raise SafetyError(f'Windows filtering operation {name} failed: 0x{code:08x}')
        return code

    def _free(self, ptr):
        value = C.cast(ptr, C.c_void_p)
        fn = self.fw.FwpmFreeMemory0
        fn.argtypes, fn.restype = [C.POINTER(C.c_void_p)], None
        fn(C.byref(value))

    def __enter__(self):
        return self

    def close(self):
        if self.handle:
            abort_error = None
            if self._transaction:
                try:
                    self._call('FwpmTransactionAbort0', [W.HANDLE], self.handle)
                    self._transaction = False
                except BaseException as error:
                    # Abort failure must not skip closing the owned session.
                    # Preserve the error even if the close itself succeeds.
                    abort_error = error
            self._call('FwpmEngineClose0', [W.HANDLE], self.handle)
            self.handle = W.HANDLE()
            self._transaction = False
            if abort_error is not None:
                raise abort_error

    def __exit__(self, *args):
        self.close()

    def existing_sublayer(self):
        """Read the exact owned sublayer; absence never creates it."""
        ptr = C.POINTER(SUBLAYER)()
        code = self._call('FwpmSubLayerGetByKey0', [W.HANDLE, C.POINTER(wfp.GUID), C.POINTER(C.POINTER(SUBLAYER))],
                          self.handle, C.byref(SUBKEY), C.byref(ptr), allowed=(0x80320007,))
        if not code:
            try:
                s = ptr.contents
                if not (s.flags == 1 and s.weight == SUBWEIGHT and not s.provider and s.data.size == len(MARK)
                        and C.string_at(s.data.data, s.data.size) == MARK):
                    raise SafetyError('The strict sublayer was changed outside this program')
            finally:
                self._free(ptr)
            from .wfp_security import verify
            verify(self,'sublayer',SUBKEY)
            return True
        return False

    def ensure_sublayer(self):
        if self.dynamic:
            raise SafetyError('A dynamic session cannot install the persistent boundary')
        if self.existing_sublayer():
            return
        keep = (C.c_ubyte * len(MARK)).from_buffer_copy(MARK)
        sub = SUBLAYER(key=SUBKEY, display=wfp.DISPLAY('ClaudeReset strict boundary', None), flags=1,
                       data=wfp.BLOB(len(MARK), keep), weight=SUBWEIGHT)
        from .wfp_security import Descriptor
        with Descriptor() as security:
            self._call('FwpmSubLayerAdd0', [W.HANDLE, C.POINTER(SUBLAYER), C.c_void_p], self.handle, C.byref(sub), security.pointer)
        if not self.existing_sublayer():raise SafetyError('New strict sublayer readback failed')

    def _native(self, rule):
        rule.validate()
        if not rule.persistent and not self.dynamic:
            raise SafetyError('A permit must belong to the lifetime of its controller')
        if rule.persistent and self.dynamic:
            raise SafetyError('Persistent objects cannot belong to a dynamic session')
        keep = []
        service = getattr(rule, 'service', None)
        conditions = (wfp.CONDITION * ((4 if rule.action == PERMIT else 1) + bool(service)))()
        identity = conditions[0]
        identity.matchType = 0
        if rule.identity.kind == 'package':
            data = wfp.package_sid(rule.identity.value)
            buffer = (C.c_ubyte * len(data)).from_buffer_copy(data)
            keep.append(buffer)
            identity.fieldKey, identity.conditionValue.type = wfp.FIELD_PACKAGE_ID, 13
            identity.conditionValue.value.ptr = C.cast(buffer, C.c_void_p).value
        else:
            ptr = C.POINTER(wfp.BLOB)()
            self._call('FwpmGetAppIdFromFileName0', [W.LPCWSTR, C.POINTER(C.POINTER(wfp.BLOB))], rule.identity.value, C.byref(ptr))
            try:
                data = C.string_at(ptr.contents.data, ptr.contents.size)
            finally:
                self._free(ptr)
            buffer = (C.c_ubyte * len(data)).from_buffer_copy(data)
            blob = wfp.BLOB(len(data), buffer)
            keep.extend((buffer, blob))
            identity.fieldKey, identity.conditionValue.type = wfp.FIELD_APP_ID, 12
            identity.conditionValue.value.ptr = C.cast(C.pointer(blob), C.c_void_p).value
        if rule.action == PERMIT:
            fields = (LOCAL_ADDRESS, LOCAL_PORT, PROTOCOL) if rule.layer == 'recv_v4' else (REMOTE, PORT, PROTOCOL)
            for condition, field, dtype, value in zip(conditions[1:], fields,
                                                     (3, 2, 1), (int(ipaddress.ip_address(rule.address)), rule.port, 6)):
                condition.fieldKey, condition.matchType = field, 0
                condition.conditionValue.type = dtype
                condition.conditionValue.value.u32 = value
        if service:
            from .gateway_reservation import service_descriptor
            descriptor = service_descriptor(service)
            data = (C.c_ubyte * len(descriptor)).from_buffer_copy(descriptor)
            blob = wfp.BLOB(len(descriptor), data)
            keep.extend((data, blob))
            condition = conditions[-1]
            condition.fieldKey, condition.matchType, condition.conditionValue.type = SERVICE_USER, 0, 14
            condition.conditionValue.value.ptr = C.cast(C.pointer(blob), C.c_void_p).value
        mark = MARK + hashlib.sha256(json.dumps(asdict(rule), sort_keys=True).encode()).digest()
        buffer = (C.c_ubyte * len(mark)).from_buffer_copy(mark)
        keep.extend((conditions, buffer))
        f = wfp.FILTER(filterKey=rule.key, displayData=wfp.DISPLAY('ClaudeReset strict ' + ('deny' if rule.action == BLOCK else 'permit'), None),
                       flags=1 if rule.persistent else 0, providerData=wfp.BLOB(len(mark), buffer),
                       layerKey=LAYERS[rule.layer], subLayerKey=SUBKEY, numFilterConditions=len(conditions), filterCondition=conditions)
        f.weight.type, f.weight.value.u8 = 1, 15 if rule.action == PERMIT else 1
        f.action.type = rule.action
        return f, keep

    def exists_verified(self, rule):
        wanted, keep = self._native(rule)
        ptr = C.POINTER(wfp.FILTER)()
        code = self._call('FwpmFilterGetByKey0', [W.HANDLE, C.POINTER(wfp.GUID), C.POINTER(C.POINTER(wfp.FILTER))],
                          self.handle, C.byref(wanted.filterKey), C.byref(ptr), allowed=(wfp.FWP_E_FILTER_NOT_FOUND,))
        if code:
            return False
        try:
            actual = ptr.contents
            weight_group = (C.cast(actual.weight.value.ptr, C.POINTER(C.c_uint64)).contents.value >> 60
                            if actual.weight.type == 4 and actual.weight.value.ptr else actual.weight.value.u8 if actual.weight.type == 1 else -1)
            # Build 26200 adds RESERVED2 to exact package-SID filters on readback.
            # Permit it only for that identity kind; action, SID, layer, weight,
            # conditions and all effective flags still have to match exactly.
            system_flags = 0x40 | (0x4000 if rule.identity.kind == 'package' else 0)
            if not (actual.layerKey.value() == wanted.layerKey.value() and actual.subLayerKey.value() == SUBKEY.value()
                    # BFE adds FWPM_FILTER_FLAG_INDEXED (0x40) on modern Windows.
                    and actual.action.type == wanted.action.type and (actual.flags & ~system_flags) == wanted.flags and not actual.providerKey
                    and weight_group == wanted.weight.value.u8
                    and actual.numFilterConditions == wanted.numFilterConditions and actual.providerData.size == wanted.providerData.size
                    and C.string_at(actual.providerData.data, actual.providerData.size) == C.string_at(wanted.providerData.data, wanted.providerData.size)):
                raise SafetyError('Strict Windows filter differs from the requested boundary: ' +
                                  json.dumps({'flags': actual.flags, 'weight_type': actual.weight.type, 'weight_group': weight_group,
                                              'conditions': actual.numFilterConditions, 'action': actual.action.type,
                                              'provider_present': bool(actual.providerKey)}))
            for a, b in zip(actual.filterCondition[:actual.numFilterConditions], wanted.filterCondition[:wanted.numFilterConditions]):
                if a.fieldKey.value() != b.fieldKey.value() or a.matchType != b.matchType or a.conditionValue.type != b.conditionValue.type:
                    raise SafetyError('Strict Windows filter condition was changed')
                if a.conditionValue.type == 13:
                    equal = wfp.sid_at(a.conditionValue.value.ptr) == wfp.sid_at(b.conditionValue.value.ptr)
                elif a.conditionValue.type in (12, 14):
                    x, y = (C.cast(v.conditionValue.value.ptr, C.POINTER(wfp.BLOB)).contents for v in (a, b))
                    equal = x.size == y.size and C.string_at(x.data, x.size) == C.string_at(y.data, y.size)
                else:
                    equal = a.conditionValue.value.u32 == b.conditionValue.value.u32
                if not equal:
                    raise SafetyError('Strict Windows filter target was changed')
            from .wfp_security import verify
            verify(self,'filter',wanted.filterKey)
            return True
        finally:
            self._free(ptr)

    def install(self, rules):
        for rule in rules:
            rule.validate()
        self._call('FwpmTransactionBegin0', [W.HANDLE, W.DWORD], self.handle, 0)
        self._transaction = True
        try:
            for rule in rules:
                if self.exists_verified(rule):
                    continue
                f, keep = self._native(rule)
                identifier = C.c_uint64()
                from .wfp_security import Descriptor
                with Descriptor() as security:
                    self._call('FwpmFilterAdd0', [W.HANDLE, C.POINTER(wfp.FILTER), C.c_void_p, C.POINTER(C.c_uint64)],
                               self.handle, C.byref(f), security.pointer, C.byref(identifier))
                if not self.exists_verified(rule):
                    raise SafetyError('Windows filter readback failed')
            self._call('FwpmTransactionCommit0', [W.HANDLE], self.handle)
            self._transaction = False
        except BaseException:
            self._call('FwpmTransactionAbort0', [W.HANDLE], self.handle)
            self._transaction = False
            raise

    def install_new_denies(self,rules,verify_closed):
        """Fresh boundary only: sublayer and unconditional denies commit together."""
        if self.dynamic is not False or self._transaction is not False:
            raise SafetyError('Fresh persistent boundary requires an idle persistent session')
        if not isinstance(rules,list) or not rules:raise SafetyError('Explicit initial denies required')
        keys=set()
        for rule in rules:
            if type(rule) is not Rule or rule.action!=BLOCK or rule.persistent is not True:
                raise SafetyError('Initial boundary accepts only persistent unconditional denies')
            rule.validate()
            key=rule.key.value()
            if key in keys:raise SafetyError('Duplicate initial deny')
            keys.add(key)
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        if self.existing_sublayer():raise SafetyError('Existing strict boundary requires separate recovery')
        self._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],self.handle,0)
        self._transaction=True
        try:
            self.ensure_sublayer()
            for rule in rules:
                if self.exists_verified(rule):raise SafetyError('An initial filter key is already occupied')
                f,keep=self._native(rule);identifier=C.c_uint64()
                from .wfp_security import Descriptor
                with Descriptor() as security:
                    self._call('FwpmFilterAdd0',[W.HANDLE,C.POINTER(wfp.FILTER),C.c_void_p,C.POINTER(C.c_uint64)],
                        self.handle,C.byref(f),security.pointer,C.byref(identifier))
                if not self.exists_verified(rule):raise SafetyError('Initial deny readback failed')
            if verify_closed() is not True:raise SafetyError('Client boundary changed before WFP commit')
            self._call('FwpmTransactionCommit0',[W.HANDLE],self.handle)
            self._transaction=False
        except BaseException:
            self._call('FwpmTransactionAbort0',[W.HANDLE],self.handle)
            self._transaction=False
            raise

    def remove_recorded_denies(self,rules,verify_closed):
        """Installer-only exact deny set; caller must authenticate its receipt."""
        if self.dynamic is not False or self._transaction is not False:
            raise SafetyError('Deny cleanup requires an idle persistent session')
        if not isinstance(rules,list) or not rules:raise SafetyError('Recorded deny set required')
        keys=set()
        for rule in rules:
            if type(rule) is not Rule or rule.action!=BLOCK or rule.persistent is not True:
                raise SafetyError('Only recorded persistent denies may be removed')
            rule.validate()
            if rule.key.value() in keys:raise SafetyError('Duplicate recorded deny')
            keys.add(rule.key.value())
        def verify_set():
            if not self.existing_sublayer() or self.own_keys()!=keys or not all(self.exists_verified(r) for r in rules):
                raise SafetyError('Recorded deny boundary changed or has additional filters')
        if verify_closed() is not True:raise SafetyError('Client boundary is not verified closed')
        verify_set()
        self._call('FwpmTransactionBegin0',[W.HANDLE,W.DWORD],self.handle,0);self._transaction=True
        try:
            verify_set()
            for rule in rules:
                self._call('FwpmFilterDeleteByKey0',[W.HANDLE,C.POINTER(wfp.GUID)],self.handle,C.byref(rule.key))
            self._call('FwpmSubLayerDeleteByKey0',[W.HANDLE,C.POINTER(wfp.GUID)],self.handle,C.byref(SUBKEY))
            if self.existing_sublayer() or any(self.exists_verified(r) for r in rules):
                raise SafetyError('Deny cleanup readback failed')
            if verify_closed() is not True:raise SafetyError('Client boundary changed before deny removal commit')
            self._call('FwpmTransactionCommit0',[W.HANDLE],self.handle);self._transaction=False
        except BaseException:
            self._call('FwpmTransactionAbort0',[W.HANDLE],self.handle);self._transaction=False
            raise

    def own_keys(self):
        """Enumerate only keys in our sublayer; never report foreign filters."""
        return self._keys_in_sublayer(SUBKEY)

    def _keys_in_sublayer(self,sublayer):
        enum = W.HANDLE()
        self._call('FwpmFilterCreateEnumHandle0', [W.HANDLE, C.c_void_p, C.POINTER(W.HANDLE)], self.handle, None, C.byref(enum))
        result = set()
        try:
            while True:
                entries = C.POINTER(C.POINTER(wfp.FILTER))()
                count = W.DWORD()
                self._call('FwpmFilterEnum0', [W.HANDLE, W.HANDLE, W.DWORD, C.POINTER(C.POINTER(C.POINTER(wfp.FILTER))), C.POINTER(W.DWORD)],
                           self.handle, enum, 256, C.byref(entries), C.byref(count))
                try:
                    for index in range(count.value):
                        item = entries[index].contents
                        if item.subLayerKey.value() == sublayer.value():
                            result.add(item.filterKey.value())
                finally:
                    if entries:
                        self._free(entries)
                if count.value < 256:
                    return result
        finally:
            self._call('FwpmFilterDestroyEnumHandle0', [W.HANDLE, W.HANDLE], self.handle, enum)

    def remove_test_rules(self, rules, *, test_root):
        """Only for synthetic fixture cleanup; cannot remove real Claude rules."""
        for rule in rules:
            p = Path(rule.identity.value)
            if rule.identity.kind != 'app' or not p.is_relative_to(test_root) or p.name != 'ClaudeResetFixture.exe':
                raise SafetyError('Only the isolated native fixture can be cleaned up')
            if not self.exists_verified(rule):
                raise SafetyError('Missing fixture filter')
        for rule in rules:
            self._call('FwpmFilterDeleteByKey0', [W.HANDLE, C.POINTER(wfp.GUID)], self.handle, C.byref(rule.key))
