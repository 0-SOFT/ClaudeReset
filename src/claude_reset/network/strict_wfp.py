"""Claude-scoped persistent deny and process-lifetime WFP permits.

No firewall profiles, routes, DNS or router operations. Every rule has an exact
application/package identity. The dynamic session must remain owned by the relay.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType

from .. import config
from ..errors import SafetyError
from ..windows import wfp
from ..windows.wfp import Identity
from ..windows.wfp_session import (
    APP_ID,
    FWP_UINT8,
    FWP_UINT16,
    FWP_UINT32,
    IPPROTO_TCP,
    Session,
    blob,
    condition_blob,
    condition_sid,
    condition_u32,
)

__all__ = ['Engine', 'LAYERS', 'MARK', 'NAMESPACE', 'Rule', 'SUBKEY', 'SUBWEIGHT', 'deny_rules', 'relay_permits']

NAMESPACE = uuid.UUID('ba7c80bc-4fea-45a3-9266-f2c7b78be1ae')
SUBKEY = wfp.GUID.of(uuid.uuid5(NAMESPACE, 'strict-gate-v1'))
MARK = b'ClaudeReset-Strict-Gate-v1'
SUBWEIGHT = 61000  # disposable fixtures use another weight; BFE shifts a duplicate weight
PERMIT, BLOCK = wfp.FWP_ACTION_PERMIT, wfp.FWP_ACTION_BLOCK
LAYERS = MappingProxyType({**{f'connect_{k}': v for k, v in wfp.LAYERS.items()},
                           'recv_v4': wfp.GUID.of('e1cd9fe7-f4b5-4273-96c0-592e487b8650'),
                           'recv_v6': wfp.GUID.of('a3b42c97-9f04-4672-b87e-cee9c483257f')})
REMOTE = wfp.GUID.of('b235ae9a-1d64-49b8-a44c-5ff3d9095045')
PORT = wfp.GUID.of('c35a604d-d22b-4e1a-91b4-68f674ee674b')
PROTOCOL = wfp.GUID.of('3971ef2b-623e-4f9a-8cb1-6e79b806b9a7')
LOCAL_ADDRESS = wfp.GUID.of('d9ee00de-c1ef-4617-bfe3-ffd8f5a08957')
LOCAL_PORT = wfp.GUID.of('0c1ba1af-5765-453f-af22-a8f791ac775b')


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


def relay_permits(identities, port):
    return [Rule(identity, 'connect_v4', PERMIT, config.LOOPBACK, port, False) for identity in identities]


class Engine(Session):
    """The strict gate's session. Never deletes foreign objects or broadens a deny."""
    sublayer_key = SUBKEY
    sublayer_weights = (SUBWEIGHT,)

    def existing_sublayer(self):
        """Read the exact owned sublayer; absence never creates it."""
        return self.owned_sublayer(self.sublayer_key, MARK, self.sublayer_weights,
                                   changed='The strict sublayer was changed outside this program')

    def ensure_sublayer(self):
        if self.dynamic:
            raise SafetyError('A dynamic session cannot install the persistent boundary')
        if self.existing_sublayer():
            return
        self.add_sublayer(self.sublayer_key, 'ClaudeReset strict boundary', MARK, self.sublayer_weights[0])
        if not self.existing_sublayer():
            raise SafetyError('New strict sublayer readback failed')

    def _native(self, rule):
        rule.validate()
        if not rule.persistent and not self.dynamic:
            raise SafetyError('A permit must belong to the lifetime of its controller')
        if rule.persistent and self.dynamic:
            raise SafetyError('Persistent objects cannot belong to a dynamic session')
        keep = []
        conditions = (wfp.CONDITION * (4 if rule.action == PERMIT else 1))()
        if rule.identity.kind == 'package':
            condition_sid(conditions[0], wfp.FIELD_PACKAGE_ID, wfp.package_sid(rule.identity.value), keep)
        else:
            condition_blob(conditions[0], wfp.FIELD_APP_ID, APP_ID, self.app_id(rule.identity.value), keep)
        if rule.action == PERMIT:
            fields = (LOCAL_ADDRESS, LOCAL_PORT, PROTOCOL) if rule.layer == 'recv_v4' else (REMOTE, PORT, PROTOCOL)
            for condition, field, dtype, value in zip(conditions[1:], fields,
                                                     (FWP_UINT32, FWP_UINT16, FWP_UINT8),
                                                     (int(ipaddress.ip_address(rule.address)), rule.port, IPPROTO_TCP)):
                condition_u32(condition, field, dtype, value)
        mark = MARK + hashlib.sha256(json.dumps(asdict(rule), sort_keys=True).encode()).digest()
        keep.append(conditions)
        f = wfp.FILTER(filterKey=rule.key, displayData=wfp.DISPLAY('ClaudeReset strict ' + ('deny' if rule.action == BLOCK else 'permit'), None),
                       flags=1 if rule.persistent else 0, providerData=blob(mark, keep),
                       layerKey=LAYERS[rule.layer], subLayerKey=self.sublayer_key, numFilterConditions=len(conditions),
                       filterCondition=conditions)
        f.weight.type, f.weight.value.u8 = FWP_UINT8, 15 if rule.action == PERMIT else 1
        f.action.type = rule.action
        return f, keep

    def exists_verified(self, rule):
        wanted, keep = self._native(rule)
        # Build 26200 adds RESERVED2 to exact package-SID filters on readback. Permit it only for that
        # identity kind; action, SID, layer, weight, conditions and all effective flags still match exactly.
        system_flags = 0x40 | (0x4000 if rule.identity.kind == 'package' else 0)
        return self.matches(wanted, label='Strict Windows filter', system_flags=system_flags)

    def _add(self, rule, failure):
        f, keep = self._native(rule)
        self.add_filter(f)
        if not self.exists_verified(rule):
            raise SafetyError(failure)

    def install(self, rules):
        for rule in rules:
            rule.validate()
        with self.transaction():
            for rule in rules:
                if not self.exists_verified(rule):
                    self._add(rule, 'Windows filter readback failed')

    def _exact_denies(self, rules, *, invalid, duplicate):
        if self.dynamic is not False or self.in_transaction:
            raise SafetyError('This boundary change requires an idle persistent session')
        if not isinstance(rules, list) or not rules:
            raise SafetyError('An explicit deny set is required')
        keys = set()
        for rule in rules:
            if type(rule) is not Rule or rule.action != BLOCK or rule.persistent is not True:
                raise SafetyError(invalid)
            rule.validate()
            if rule.key.value() in keys:
                raise SafetyError(duplicate)
            keys.add(rule.key.value())
        return keys

    def install_new_denies(self, rules, verify_closed):
        """Fresh boundary only: sublayer and unconditional denies commit together."""
        self._exact_denies(rules, invalid='Initial boundary accepts only persistent unconditional denies',
                           duplicate='Duplicate initial deny')
        if verify_closed() is not True:
            raise SafetyError('Client boundary is not verified closed')
        if self.existing_sublayer():
            raise SafetyError('Existing strict boundary requires separate recovery')
        with self.transaction():
            self.ensure_sublayer()
            for rule in rules:
                if self.exists_verified(rule):
                    raise SafetyError('An initial filter key is already occupied')
                self._add(rule, 'Initial deny readback failed')
            if verify_closed() is not True:
                raise SafetyError('Client boundary changed before WFP commit')

    def remove_recorded_denies(self, rules, verify_closed):
        """Installer-only exact deny set; caller must authenticate its receipt."""
        keys = self._exact_denies(rules, invalid='Only recorded persistent denies may be removed',
                                  duplicate='Duplicate recorded deny')

        def verify_set():
            if not self.existing_sublayer() or self.own_keys() != keys or not all(self.exists_verified(r) for r in rules):
                raise SafetyError('Recorded deny boundary changed or has additional filters')
        if verify_closed() is not True:
            raise SafetyError('Client boundary is not verified closed')
        verify_set()
        with self.transaction():
            verify_set()
            for rule in rules:
                self.delete_filter(rule.key)
            self.delete_sublayer(self.sublayer_key)
            if self.existing_sublayer() or any(self.exists_verified(r) for r in rules):
                raise SafetyError('Deny cleanup readback failed')
            if verify_closed() is not True:
                raise SafetyError('Client boundary changed before deny removal commit')

    def own_keys(self):
        """Enumerate only keys in our sublayer; never report foreign filters."""
        return self.filter_keys(self.sublayer_key)

    def remove_owned(self, keys, *, missing_sublayer_ok=False):
        """Delete these filters of our sublayer and the sublayer itself in one transaction."""
        with self.transaction():
            for key in keys:
                self.delete_filter(key)
            self.delete_sublayer(self.sublayer_key, missing_ok=missing_sublayer_ok)

    def remove_test_rules(self, rules, *, test_root):
        """Only for synthetic fixture cleanup; cannot remove real Claude rules."""
        for rule in rules:
            p = Path(rule.identity.value)
            if rule.identity.kind != 'app' or not p.is_relative_to(test_root) or p.name != 'ClaudeResetFixture.exe':
                raise SafetyError('Only the isolated native fixture can be cleaned up')
            if not self.exists_verified(rule):
                raise SafetyError('Missing fixture filter')
        for rule in rules:
            self.delete_filter(rule.key)
