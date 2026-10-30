"""Mutation ownership and the files that carry it: the pending claim, the expected requests and their markers.

The pending file is an exclusive claim, not a cache. A crash, malformed file, dispatch exception or partial
failure never authorizes replay. `chain` is the owner of the synchronous call chain that holds the claim.
"""
from __future__ import annotations

import json
import os
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from functools import wraps
from pathlib import Path

from .. import layout
from ..errors import SafetyError
from ..model.ids import new_id
from ..model.records import RequestInventory, exact
from ..model.status import Elevation
from ..safeio import guarded
from .locks import AdmissionUnavailable, locked

__all__ = ['OPERATIONS', 'ChildAdmissionRefused', 'Owner', 'Request', 'blocked', 'chain', 'claim_matches', 'inventory',
           'inventory_path', 'pending_path', 'receipt_identity', 'request_marker', 'require_expected',
           'require_generation_open', 'require_not_revoked', 'save_exclusive', 'serialized', 'serialized_effect']


class ChildAdmissionRefused(SafetyError):
    """No child effect began; callers must preserve existing receipts."""


OPERATIONS = frozenset({'start', 'remove', 'autostart', 'autostart-off', 'package-register', 'package-remove'})


chain = ContextVar('mutation_owner', default=None)


@dataclass
class Owner:
    claim: dict
    pending: Path
    uncertain: bool = False
    start_request: object = None


def serialized(operation, *, completed, nested=False,
               nested_completed=None):   # None: the same as completed
    """Own the existing arbitration file for the entire synchronous chain.

    Failure is conservatively retained: a returned failure cannot establish
    that earlier effects were undone. No recovery or replay is automatic.
    nested_completed may acknowledge submission within an owning chain;
    that chain must verify completion before releasing its own claim.
    """
    def decorate(function):
        @wraps(function)
        def call(paths, *args, **kwargs):
            pending = pending_path(paths)
            existing = chain.get()
            if nested and existing is not None:
                root = str(guarded(paths.state, paths.state, allow_root=True))
                if (existing.pending != pending or existing.claim['state_root'] != root
                        or existing.uncertain or not claim_matches(pending, existing.claim)):
                    raise SafetyError('Mutation ownership mismatch')
                try:
                    result = function(paths, *args, **kwargs)
                    if not claim_matches(pending, existing.claim):
                        raise SafetyError('Mutation claim changed')
                    accepted = completed if nested_completed is None else nested_completed
                    if result.get('status') not in accepted or existing.uncertain:
                        existing.uncertain = True
                        result['retry_blocked'] = True
                    return result
                except BaseException:
                    existing.uncertain = True
                    raise
            claim = {'schema': 2, 'operation': operation,
                     'owner_id': new_id(),
                     'state_root': str(guarded(paths.state, paths.state, allow_root=True))}
            try:
                with locked(paths):
                    save_exclusive(pending, claim)
                    save_exclusive(inventory_path(claim),
                                    {'schema': 1, 'claim': claim, 'requests': []})
            except (FileExistsError, AdmissionUnavailable):
                return {'schema': 1, 'action': operation, 'finished': True,
                        'status': Elevation.PENDING_ELEVATION, 'retry_blocked': True}
            owner = Owner(claim, pending)
            token = chain.set(owner)
            try:
                result = function(paths, *args, **kwargs)
                if result.get('status') in completed and not owner.uncertain:
                    with locked(paths):
                        if not claim_matches(pending, claim):
                            raise SafetyError('Mutation claim changed')
                        require_generation_open(claim)
                        pending.unlink()
                else:
                    result['retry_blocked'] = True
                return result
            finally:
                chain.reset(token)
        return call
    return decorate


def serialized_effect(operation, *, succeeded):
    """Serialize synchronous primitives without changing their return contracts.

    Busy is an exception: a status dictionary would be truthy to legacy bool
    callers, and None-returning callers could silently continue after refusal.
    Exceptions retain ownership because partial writes cannot be ruled out.
    """
    def decorate(function):
        @serialized(operation, completed={Elevation.COMPLETED}, nested=True)
        def invoke(paths, *args, **kwargs):
            value = function(paths, *args, **kwargs)
            return {'status': Elevation.COMPLETED if succeeded(value) else Elevation.INCOMPLETE,
                    'value': value}

        @wraps(function)
        def call(paths, *args, **kwargs):
            result = invoke(paths, *args, **kwargs)
            if result.get('retry_blocked'):
                raise SafetyError('Mutation incomplete or ownership unavailable')
            return result['value']
        return call
    return decorate


def claim_matches(path, claim):
    try:
        return json.loads(path.read_text('utf-8')) == claim
    except (OSError, ValueError):
        return False


def save_exclusive(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())


def inventory_path(claim):
    root = Path(claim['state_root'])
    owner_id = claim['owner_id']
    if (not isinstance(owner_id, str) or len(owner_id) != 32
            or any(c not in '0123456789abcdef' for c in owner_id)):
        raise SafetyError('Request inventory unavailable')
    return guarded(layout.controller_folder(root) / ('expected-requests-' + owner_id + '.json'), root)


def listed_request(item: dict, claim: dict, seen: set[str]) -> Request:
    """The request of one inventory row, when it belongs to this claim and was not listed before."""
    request = Request(**item)
    if (asdict(request) != item or type(request.schema) is not int or request.schema != 1
            or request.owner_id != claim['owner_id']
            or request.state_root != claim['state_root']
            or request.operation not in OPERATIONS
            or not isinstance(request.request_id, str) or len(request.request_id) != 32
            or any(c not in '0123456789abcdef' for c in request.request_id)
            or request.request_id in seen
            or request.receipt != str(layout.controller_folder(request.state_root) /
                                      ('uac-' + request.request_id + '.json'))):
        raise SafetyError('Request inventory unavailable')
    return request


def inventory(claim):
    path = inventory_path(claim)
    with path.open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise SafetyError('Request inventory unavailable')
    try:
        row = json.loads(raw)
    except RecursionError:
        # A size-bounded journal can still exceed the JSON parser's depth.
        # Treat it as unavailable for both admission and read-only inspection.
        raise SafetyError('Request inventory unavailable') from None
    if (not exact(row, RequestInventory)
            or type(row['schema']) is not int or row['schema'] != 1
            or row['claim'] != claim or not isinstance(row['requests'], list)):
        raise SafetyError('Request inventory unavailable')
    seen = set()
    for item in row['requests']:
        request = listed_request(item, claim, seen)
        seen.add(request.request_id)
    return row


def require_expected(claim, request):
    # The standalone claim is itself its one-request inventory. Nested legacy
    # claims without an inventory cannot authorize new effects.
    try:
        require_generation_open(claim)
        if request.owner_id is not None and asdict(request) not in inventory(claim)['requests']:
            raise SafetyError('Request not expected')
    except (OSError, ValueError, TypeError, KeyError):
        raise SafetyError('Request inventory unavailable') from None


@dataclass(frozen=True)
class Request:
    request_id: str
    operation: str
    state_root: str
    receipt: str
    schema: int = 1
    owner_id: str | None = None


def pending_path(paths):
    # Shared by windows using different archive selections for this user.
    return layout.app_local(paths, 'uac-pending.json')


def _generation_marker(claim):
    root = Path(claim['state_root'])
    identifier = claim.get('owner_id') if claim.get('schema') == 2 else claim.get('request_id')
    if (not isinstance(identifier, str) or len(identifier) != 32
            or any(c not in '0123456789abcdef' for c in identifier)):
        raise SafetyError('Admission generation unavailable')
    return guarded(layout.controller_folder(root) / ('closed-generation-' + identifier + '.json'), root)


def require_generation_open(claim):
    # A torn closure also fences admission; its contents never authorize release.
    if _generation_marker(claim).exists():
        raise SafetyError('Admission generation closed')


def blocked(paths):
    try:
        owner = chain.get()
        if owner is not None and owner.pending == pending_path(paths):
            return owner.uncertain or not claim_matches(owner.pending, owner.claim)
        return pending_path(paths).exists()
    except (OSError, SafetyError):
        return True


def receipt_identity(paths, operation, request_id):
    """Identity echoed by the child, never inferred from an arbitrary filename."""
    if (operation not in OPERATIONS or not isinstance(request_id, str)
            or len(request_id) != 32 or any(c not in '0123456789abcdef' for c in request_id)):
        raise ChildAdmissionRefused('Invalid elevation identity')
    return {'request_id': request_id, 'operation': operation,
            'state_root': str(guarded(paths.state, paths.state, allow_root=True))}


def request_marker(request, kind):
    root = Path(request.state_root)
    return guarded(layout.controller_folder(root) / (kind + '-' + request.request_id + '.json'), root)


def require_not_revoked(request):
    # Even an empty/torn tombstone forbids effects. Never repair it by deletion.
    if request_marker(request, 'revoked').exists():
        raise SafetyError('Elevation request revoked')
