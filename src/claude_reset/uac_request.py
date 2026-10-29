"""Durable, single-owner elevation requests; no Windows calls in this module.

The pending file is an exclusive claim, not a cache. A crash, malformed file,
dispatch exception or partial failure never authorizes replay. Only its original
owner may release it after a definitive denial or an exact successful receipt.
"""
from dataclasses import asdict, dataclass
from contextvars import ContextVar
from functools import wraps
import json
import os
from pathlib import Path
import time
import uuid

from .safeio import SafetyError, guarded
from .admission import locked, AdmissionUnavailable


class ChildAdmissionRefused(SafetyError):
    """No child effect began; callers must preserve existing receipts."""


OPERATIONS = {'start', 'remove', 'autostart', 'autostart-off', 'package-register', 'package-remove', 'filters'}
_chain = ContextVar('mutation_owner', default=None)


@dataclass
class Owner:
    claim: dict
    pending: Path
    uncertain: bool = False
    start_request: object = None


def serialized(operation, *, completed, nested=False, nested_completed=None):
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
            existing = _chain.get()
            if nested and existing is not None:
                root = str(guarded(paths.state, paths.state, allow_root=True))
                if (existing.pending != pending or existing.claim['state_root'] != root
                        or existing.uncertain or not _claim_matches(pending, existing.claim)):
                    raise SafetyError('Mutation ownership mismatch')
                try:
                    result = function(paths, *args, **kwargs)
                    if not _claim_matches(pending, existing.claim):
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
                     'owner_id': uuid.uuid4().hex,
                     'state_root': str(guarded(paths.state, paths.state, allow_root=True))}
            try:
                with locked(paths):
                    _save_exclusive(pending, claim)
                    _save_exclusive(_inventory_path(claim),
                                    {'schema': 1, 'claim': claim, 'requests': []})
            except (FileExistsError, AdmissionUnavailable):
                return {'schema': 1, 'action': operation, 'finished': True,
                        'status': 'pending_elevation', 'retry_blocked': True}
            owner = Owner(claim, pending)
            token = _chain.set(owner)
            try:
                result = function(paths, *args, **kwargs)
                if result.get('status') in completed and not owner.uncertain:
                    with locked(paths):
                        if not _claim_matches(pending, claim):
                            raise SafetyError('Mutation claim changed')
                        require_generation_open(claim)
                        pending.unlink()
                else:
                    result['retry_blocked'] = True
                return result
            finally:
                _chain.reset(token)
        return call
    return decorate


def serialized_effect(operation, *, succeeded):
    """Serialize synchronous primitives without changing their return contracts.

    Busy is an exception: a status dictionary would be truthy to legacy bool
    callers, and None-returning callers could silently continue after refusal.
    Exceptions retain ownership because partial writes cannot be ruled out.
    """
    def decorate(function):
        @serialized(operation, completed={'completed'}, nested=True)
        def invoke(paths, *args, **kwargs):
            value = function(paths, *args, **kwargs)
            return {'status': 'completed' if succeeded(value) else 'incomplete',
                    'value': value}

        @wraps(function)
        def call(paths, *args, **kwargs):
            result = invoke(paths, *args, **kwargs)
            if result.get('retry_blocked'):
                raise SafetyError('Mutation incomplete or ownership unavailable')
            return result['value']
        return call
    return decorate


def _claim_matches(path, claim):
    try:
        return json.loads(path.read_text('utf-8')) == claim
    except (OSError, ValueError):
        return False


def _save_exclusive(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _inventory_path(claim):
    root = Path(claim['state_root'])
    owner_id = claim['owner_id']
    if (not isinstance(owner_id, str) or len(owner_id) != 32
            or any(c not in '0123456789abcdef' for c in owner_id)):
        raise SafetyError('Request inventory unavailable')
    return guarded(root / 'strict-guard' / ('expected-requests-' + owner_id + '.json'), root)


def _inventory(claim):
    path = _inventory_path(claim)
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
    if (not isinstance(row, dict) or set(row) != {'schema', 'claim', 'requests'}
            or type(row['schema']) is not int or row['schema'] != 1
            or row['claim'] != claim or not isinstance(row['requests'], list)):
        raise SafetyError('Request inventory unavailable')
    seen = set()
    for item in row['requests']:
        request = Request(**item)
        if (asdict(request) != item or type(request.schema) is not int or request.schema != 1
                or request.owner_id != claim['owner_id']
                or request.state_root != claim['state_root']
                or request.operation not in OPERATIONS
                or not isinstance(request.request_id, str) or len(request.request_id) != 32
                or any(c not in '0123456789abcdef' for c in request.request_id)
                or request.request_id in seen
                or request.receipt != str(Path(request.state_root) / 'strict-guard' /
                                          ('uac-' + request.request_id + '.json'))):
            raise SafetyError('Request inventory unavailable')
        seen.add(request.request_id)
    return row


def require_expected(claim, request):
    # The standalone claim is itself its one-request inventory. Nested legacy
    # claims without an inventory cannot authorize new effects.
    try:
        require_generation_open(claim)
        if request.owner_id is not None and asdict(request) not in _inventory(claim)['requests']:
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
    return guarded(paths.local / 'ClaudeReset' / 'uac-pending.json', paths.local)


def _generation_marker(claim):
    root = Path(claim['state_root'])
    identifier = claim.get('owner_id') if claim.get('schema') == 2 else claim.get('request_id')
    if (not isinstance(identifier, str) or len(identifier) != 32
            or any(c not in '0123456789abcdef' for c in identifier)):
        raise SafetyError('Admission generation unavailable')
    return guarded(root / 'strict-guard' / ('closed-generation-' + identifier + '.json'), root)


def require_generation_open(claim):
    # A torn closure also fences admission; its contents never authorize release.
    if _generation_marker(claim).exists():
        raise SafetyError('Admission generation closed')


def close_admission(paths, expected_claim):
    """Fence the exact persisted generation for recovery, without releasing it.

    Does not require the old in-memory owner or a complete request inventory.
    Children admitted before this lock may still run: resource/exit verification
    remains mandatory. A failed write is uncertainty, never recovery success.
    """
    with locked(paths):
        root = str(guarded(paths.state, paths.state, allow_root=True))
        claim = expected_claim.copy()
        if (type(claim.get('schema')) is not int or claim['schema'] not in (1, 2)
                or claim.get('state_root') != root
                or not _claim_matches(pending_path(paths), claim)):
            raise SafetyError('Mutation claim changed')
        if claim['schema'] == 2:
            if (set(claim) != {'schema', 'operation', 'owner_id', 'state_root'}
                    or not isinstance(claim['operation'], str) or not claim['operation']):
                raise SafetyError('Admission generation unavailable')
        else:
            request = Request(**claim)
            if (asdict(request) != claim or request.owner_id is not None
                    or request.operation not in OPERATIONS
                    or request.receipt != str(Path(root) / 'strict-guard' /
                                              ('uac-' + request.request_id + '.json'))):
                raise SafetyError('Admission generation unavailable')
        marker = _generation_marker(claim)
        record = {'schema': 1, 'claim': claim}
        if marker.exists():
            if not _claim_matches(marker, record):
                raise SafetyError('Admission closure uncertain')
        else:
            _save_exclusive(marker, record)
        owner = _chain.get()
        if owner is not None and owner.pending == pending_path(paths) and owner.claim == claim:
            owner.uncertain = True
    return {'status': 'admission_closed', 'retry_blocked': True,
            'requires_live_verification': True}


def blocked(paths):
    try:
        owner = _chain.get()
        if owner is not None and owner.pending == pending_path(paths):
            return owner.uncertain or not _claim_matches(owner.pending, owner.claim)
        return pending_path(paths).exists()
    except (OSError, SafetyError):
        return True


def inspect_pending(paths):
    """Read a persisted claim after reopening, without replay or release.

    A receipt is evidence for one child, never proof that the outer chain or
    controller has finished. Return only fixed public labels, no stored paths
    or exception text. Missing status is deliberately irrelevant here.
    """
    result = {'status': 'reconcile_required', 'retry_blocked': True,
              'requires_live_verification': True, 'requests': []}

    def read(path):
        with path.open('rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('Oversized claim')
        return raw

    def identifier(value):
        return (isinstance(value, str) and len(value) == 32
                and all(c in '0123456789abcdef' for c in value))

    try:
        pending = pending_path(paths)
        try:
            snapshot = read(pending)
        except FileNotFoundError:
            return {**result, 'status': 'no_claim', 'retry_blocked': False}
        claim = json.loads(snapshot)
        root = guarded(paths.state, paths.state, allow_root=True)
        if not isinstance(claim, dict) or claim.get('state_root') != str(root):
            return {**result, 'status': 'claim_unavailable'}
        schema = claim.get('schema')
        if type(schema) is not int or schema not in (1, 2):
            return {**result, 'status': 'claim_unavailable'}
        records = []
        if schema == 1:
            records.append((pending, snapshot, claim))
        else:
            if (set(claim) != {'schema', 'operation', 'owner_id', 'state_root'}
                    or not identifier(claim['owner_id'])
                    or not isinstance(claim['operation'], str) or not claim['operation']):
                return {**result, 'status': 'claim_unavailable'}
            inventory = _inventory(claim)
            for expected in inventory['requests']:
                path = guarded(root / 'strict-guard' / ('request-' + expected['request_id'] + '.json'), root)
                raw = read(guarded(path, root))
                row = json.loads(raw)
                if row != expected:
                    raise ValueError('Invalid request')
                records.append((path, raw, row))
        for path, raw, row in records:
            request = Request(**row)
            if (type(request.schema) is not int or request.schema != 1
                    or request.operation not in OPERATIONS
                    or not identifier(request.request_id)
                    or request.state_root != str(root)
                    or request.owner_id != (claim['owner_id'] if schema == 2 else None)
                    or request.receipt != str(root / 'strict-guard' / ('uac-' + request.request_id + '.json'))
                    or (schema == 2 and path.name != 'request-' + request.request_id + '.json')):
                raise ValueError('Invalid request identity')
            receipt = read_receipt(request)
            result['requests'].append(verdict(request, receipt) if receipt is not None else None)
            if read(path) != raw:
                raise ValueError('Request changed')
        if read(pending) != snapshot:
            raise ValueError('Claim changed')
        if schema == 2 and _inventory(claim) != inventory:
            raise ValueError('Request inventory changed')
        return result
    except (OSError, ValueError, TypeError, KeyError, SafetyError):
        return {**result, 'status': 'claim_unavailable', 'requests': []}


def prepare(paths, operation, *, scheduler=False):
    owner = _chain.get()
    try:
        with locked(paths):
            request = _prepare(paths, operation)
            if operation == 'start':
                from .controller_admission import grant
                grant(paths, request, scheduler=scheduler)
            return request
    except BaseException:
        # Preparation can fail after the request or permit reached disk.
        # Even if the caller catches this failure, it cannot release the
        # chain or issue another permit as though nothing was prepared.
        if owner is not None:
            owner.uncertain = True
        raise


def _prepare(paths, operation):
    if operation not in OPERATIONS:
        raise SafetyError('Unsupported elevation operation')
    root = guarded(paths.state, paths.state, allow_root=True)
    request_id = uuid.uuid4().hex
    receipt = guarded(root / 'strict-guard' / ('uac-' + request_id + '.json'), root)
    request = Request(request_id, operation, str(root), str(receipt))
    pending = pending_path(paths)
    owner = _chain.get()
    if owner is not None:
        if (owner.pending != pending or owner.claim['state_root'] != str(root)
                or owner.uncertain or not _claim_matches(pending, owner.claim)):
            raise SafetyError('Mutation ownership mismatch')
        request = Request(request_id, operation, str(root), str(receipt), owner_id=owner.claim['owner_id'])
        require_generation_open(owner.claim)
        from .safeio import atomic_json
        inventory = _inventory(owner.claim)
        inventory['requests'].append(asdict(request))
        atomic_json(_inventory_path(owner.claim), inventory, root)
        # Preserve the exact nested request before dispatch, without releasing
        # or replacing the outer arbitration file between receipts.
        _save_exclusive(guarded(root / 'strict-guard' / ('request-' + request_id + '.json'), root), asdict(request))
        return request
    pending.parent.mkdir(parents=True, exist_ok=True)
    guarded(pending, paths.local)
    # Exclusive creation arbitrates independent processes. Even an empty or
    # torn claim left by a failed write must prevent a later dispatch.
    with pending.open('x', encoding='utf-8') as stream:
        json.dump(asdict(request), stream)
        stream.flush()
        os.fsync(stream.fileno())
    return request


def _owned(paths, request):
    if request.owner_id is not None:
        owner = _chain.get()
        return (owner is not None and not owner.uncertain
                and owner.pending == pending_path(paths)
                and owner.claim['owner_id'] == request.owner_id
                and owner.claim['state_root'] == request.state_root
                and _claim_matches(owner.pending, owner.claim)
                and _claim_matches(guarded(Path(request.state_root) / 'strict-guard' /
                                          ('request-' + request.request_id + '.json'),
                                          Path(request.state_root)), asdict(request)))
    try:
        return json.loads(pending_path(paths).read_text('utf-8')) == asdict(request)
    except (OSError, ValueError):
        return False


def _release(paths, request):
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        require_generation_open(json.loads(pending_path(paths).read_text('utf-8')))
        if request.owner_id is None:
            pending_path(paths).unlink()


def receipt_identity(paths, operation, request_id):
    """Identity echoed by the child, never inferred from an arbitrary filename."""
    if (operation not in OPERATIONS or not isinstance(request_id, str)
            or len(request_id) != 32 or any(c not in '0123456789abcdef' for c in request_id)):
        raise ChildAdmissionRefused('Invalid elevation identity')
    return {'request_id': request_id, 'operation': operation,
            'state_root': str(guarded(paths.state, paths.state, allow_root=True))}


def _request_marker(request, kind):
    root = Path(request.state_root)
    return guarded(root / 'strict-guard' / (kind + '-' + request.request_id + '.json'), root)


def require_not_revoked(request):
    # Even an empty/torn tombstone forbids effects. Never repair it by deletion.
    if _request_marker(request, 'revoked').exists():
        raise SafetyError('Elevation request revoked')


def revoke(paths, request):
    """Fence an unconsumed request, without releasing its mutation claim.

    Admission and revocation share the same lock. A consumed or ambiguous
    request cannot be revoked as if no effect had begun.
    """
    from .controller_admission import permit_path
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        marker = _request_marker(request, 'revoked')
        record = {'schema': 1, 'request': asdict(request)}
        if marker.exists():
            if not _claim_matches(marker, record):
                raise SafetyError('Elevation revocation uncertain')
            return
        if _request_marker(request, 'admitted').exists():
            raise SafetyError('Elevation already admitted')
        if request.operation == 'start':
            try:
                permit = json.loads(permit_path(paths).read_text('utf-8'))
                valid = (permit.get('request') == asdict(request)
                         and permit.get('consumed') is False
                         and _claim_matches(pending_path(paths), permit.get('claim')))
            except (OSError, ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise SafetyError('Controller revocation uncertain')
        _save_exclusive(marker, record)


def _event(paths, request, kind):
    # Append-only fixed labels; never persist dispatch exception text.
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        require_expected(json.loads(pending_path(paths).read_text('utf-8')), request)
        if kind.startswith('scheduler-') and kind.endswith('-dispatch'):
            _expect_scheduler_attempt(request, kind)
        _save_exclusive(_request_marker(request, kind),
                        {'schema': 1, 'request': asdict(request), 'event': kind})


def _scheduler_count(request):
    path = _request_marker(request, 'expected-scheduler')
    if path.stat().st_size > 65536:
        raise SafetyError('Scheduler inventory unavailable')
    row = json.loads(path.read_text('utf-8'))
    if (not isinstance(row, dict) or set(row) != {'schema', 'request', 'attempts'}
            or type(row['schema']) is not int or row['schema'] != 1
            or row['request'] != asdict(request)
            or type(row['attempts']) is not int or row['attempts'] < 1):
        raise SafetyError('Scheduler inventory unavailable')
    return row['attempts']


def _expect_scheduler_attempt(request, kind):
    """Write the high-water mark under admission.lock, before dispatch evidence.

    This detects lost event tails, not rollback of the entire storage or child
    exit. A crash between these writes leaves an incomplete history.
    """
    from .safeio import atomic_json
    number = kind[len('scheduler-'):-len('-dispatch')]
    if not number.isascii() or not number.isdecimal() or str(int(number)) != number:
        raise SafetyError('Invalid scheduler attempt')
    attempt = int(number)
    record = {'schema': 1, 'request': asdict(request), 'attempts': attempt}
    path = _request_marker(request, 'expected-scheduler')
    if attempt == 1:
        _save_exclusive(path, record)
    else:
        if attempt < 1 or _scheduler_count(request) != attempt - 1:
            raise SafetyError('Scheduler attempt out of order')
        atomic_json(path, record, Path(request.state_root))


def inspect_scheduler_history(request):
    """Validate recorded attempts only; never prove child exit or full recovery.

    Legacy journals without an inventory and missing, torn or conflicting
    records are incomplete. The inventory is not a seal against future dispatch,
    a revocation, or evidence that any child exited.
    """
    import re
    try:
        root = Path(request.state_root)
        folder = guarded(root / 'strict-guard', root)
        expected = _scheduler_count(request)
        rows = {}
        for path in folder.glob('scheduler-*-' + request.request_id + '.json'):
            guarded(path, root)
            match = re.fullmatch(r'scheduler-([1-9][0-9]*)-(dispatch|accepted|nonzero|error|observed|unobserved)-'
                                 + re.escape(request.request_id) + r'\.json', path.name)
            if match is None or path.stat().st_size > 65536:
                return 'incomplete'
            kind = path.name[:-(len(request.request_id) + 6)]
            if json.loads(path.read_text('utf-8')) != {
                    'schema': 1, 'request': asdict(request), 'event': kind}:
                return 'incomplete'
            rows.setdefault(int(match[1]), set()).add(match[2])
        if (len(rows) != expected or not rows
                or sorted(rows) != list(range(1, len(rows) + 1))):
            return 'incomplete'
        allowed = ({'dispatch', 'nonzero'}, {'dispatch', 'error'},
                   {'dispatch', 'accepted', 'observed'},
                   {'dispatch', 'accepted', 'unobserved'})
        if any(events not in allowed for events in rows.values()):
            return 'incomplete'
        if any('observed' in rows[n] for n in rows if n != max(rows)):
            return 'incomplete'
        return 'recorded' if _scheduler_count(request) == expected else 'incomplete'
    except (OSError, ValueError, SafetyError):
        return 'incomplete'


def child_event(paths, identity, kind):
    """Durable handler evidence, never proof of process exit or recovery authority.

    Attempt-specific names preserve a replay refusal alongside the original
    child's finish. Torn files remain visible; no writer repairs or replaces them.
    No caller-supplied error text or result data is persisted.
    """
    if kind != 'finish':
        raise SafetyError('Unsupported child event')
    expected = receipt_identity(paths, identity['operation'], identity['request_id'])
    if identity != expected:
        raise SafetyError('Child event identity mismatch')
    root = Path(expected['state_root'])
    path = guarded(root / 'strict-guard' /
                   ('child-' + expected['request_id'] + '-' + uuid.uuid4().hex + '.json'), root)
    _save_exclusive(path, {'schema': 1, 'identity': expected, 'event': kind})


def admission_denied(paths, operation, request_id, *, verified_identity=None):
    """Record even unidentifiable attempts without persisting untrusted input.

    A missing scheduler ID is not inferred from the current permit: it could
    belong to a different attempt. This evidence never authorizes recovery.
    """
    # Only admission code may supply the identity it verified while locked.
    # Never look up a newer claim/permit after the failed attempt.
    if verified_identity is not None:
        if verified_identity != receipt_identity(paths, operation, request_id):
            raise SafetyError('Child event identity mismatch')
    root = guarded(paths.state, paths.state, allow_root=True)
    attempt_id = uuid.uuid4().hex
    prefix = ('denied-unknown-' if verified_identity is None else
              'child-' + verified_identity['request_id'] + '-')
    _save_exclusive(guarded(root / 'strict-guard' / (prefix + attempt_id + '.json'), root),
                    {'schema': 2, 'event': 'admission-denied',
                     'identity': verified_identity, 'attempt_id': attempt_id})


def admit_child(paths, operation, request_id):
    """Consume a non-controller request before the child's first effect.

    The durable consumption record survives crashes and forbids replay. It is
    not a completion receipt or permission to reconcile/release the claim.
    Controller starts have their separate permit and lifetime ownership.
    """
    try:
        identity = receipt_identity(paths, operation, request_id)
    except SafetyError:
        try:
            admission_denied(paths, operation, request_id)
        except (OSError, SafetyError):
            pass
        raise
    if operation == 'start':
        raise SafetyError('Controller requires start admission')
    root = Path(identity['state_root'])
    verified_identity = None
    try:
        with locked(paths):
            claim = json.loads(pending_path(paths).read_text('utf-8'))
            if (not isinstance(claim, dict) or type(claim.get('schema')) is not int
                    or claim['schema'] not in (1, 2)):
                raise SafetyError('Elevation admission refused')
            owner_id = None
            if type(claim.get('schema')) is int and claim['schema'] == 2:
                owner_id = claim.get('owner_id')
                if (set(claim) != {'schema', 'operation', 'owner_id', 'state_root'}
                        or not isinstance(owner_id, str) or len(owner_id) != 32
                        or any(c not in '0123456789abcdef' for c in owner_id)
                        or claim['state_root'] != str(root)):
                    raise SafetyError('Elevation admission refused')
            request = Request(request_id, operation, str(root),
                              str(root / 'strict-guard' / ('uac-' + request_id + '.json')),
                              owner_id=owner_id)
            record = (pending_path(paths) if owner_id is None else
                      guarded(root / 'strict-guard' / ('request-' + request_id + '.json'), root))
            if not _claim_matches(record, asdict(request)):
                raise SafetyError('Elevation admission refused')
            require_expected(claim, request)
            verified_identity = identity
            require_not_revoked(request)
            consumed = guarded(root / 'strict-guard' / ('admitted-' + request_id + '.json'), root)
            _save_exclusive(consumed, {'schema': 1, 'request': asdict(request), 'claim': claim})
            from .child_process import record
            record(request)
        return identity
    except (OSError, ValueError, TypeError, KeyError, SafetyError):
        try:
            admission_denied(paths, operation, request_id, verified_identity=verified_identity)
        except (OSError, SafetyError):
            pass  # Missing/torn evidence cannot authorize recovery.
        raise ChildAdmissionRefused('Elevation admission unavailable') from None


def read_receipt(request):
    try:
        path = guarded(Path(request.receipt), Path(request.state_root))
        if path.stat().st_size > 1024 * 1024:
            return None
        row = json.loads(path.read_text('utf-8'))
    except (OSError, ValueError, SafetyError):
        return None
    if not isinstance(row, dict) or type(row.get('schema')) is not int or row['schema'] != 1:
        return None
    if any(row.get(key) != getattr(request, key) for key in ('request_id', 'operation', 'state_root')):
        return None
    return row


def verdict(request, row):
    if request.operation == 'filters':
        # This describes a read result, not process exit or release authority.
        if (row.get('finished') is True and row.get('read_only') is True
                and row.get('filters_changed') is False):
            return 'inspection_finished'
        return None
    if 'error' in row or 'error_type' in row:
        return 'reconcile_required' if row.get('finished') is True else None
    if request.operation == 'start':
        if (row.get('finished') is not True
                and row.get('state') == 'relay_open' and row.get('passed') is True
                and row.get('persistent_boundary') is True and row.get('live_permit_session') is True):
            return 'observed_ready'
        return 'reconcile_required' if row.get('finished') is True else None
    if row.get('finished') is not True:
        return None
    if request.operation in ('package-register', 'package-remove'):
        success = (row.get('status') in ('registered', 'already_registered')
                   if request.operation == 'package-register' else
                   row.get('status') == 'removed' and row.get('registered_after') is False)
        return 'completed' if success else 'reconcile_required'
    success = (row.get('removed') is True if request.operation == 'remove' else
               row.get('registered') is True if request.operation == 'autostart' else
               row.get('task_present_after') is False and row.get('program_removed') is True)
    return 'completed' if success else 'reconcile_required'


def outcome(status):
    # Domain data and private paths never enter this public result.
    return {'status': status, 'passed': status == 'completed',
            'requires_live_verification': True,
            'retry_blocked': status in ('unknown', 'reconcile_required', 'inspection_finished',
                                       'observed_ready')}


def execute(paths, operation, dispatch, *, wait_seconds=300, clock=time.monotonic, sleep=time.sleep):
    request = prepare(paths, operation)
    status = None
    code = None
    finalized = False
    try:
        if not _owned(paths, request):
            return outcome('unknown')
        # dispatch returns only the ShellExecute result, never completion.
        _event(paths, request, 'dispatch')
        code = dispatch(request)
        if type(code) is not int or code < 0:
            return outcome('unknown')
        if code <= 32:
            revoke(paths, request)
            _event(paths, request, 'denial')
            _release(paths, request)
            finalized = True
            return outcome('denied')
        deadline = clock() + wait_seconds
        while True:
            row = read_receipt(request)
            status = verdict(request, row) if row is not None else None
            if status:
                _event(paths, request, 'receipt-observed')
                # A start receipt is a historical observation. Its live flags
                # do not attest current process ownership or resource state.
                if status == 'completed':
                    _release(paths, request)
                    finalized = True
                return outcome(status)
            if clock() >= deadline:
                return outcome('unknown')
            sleep(min(1, max(0, deadline - clock())))
    except Exception:
        # A failed wait or dispatch cannot prove that no effects happened.
        return outcome('unknown')
    finally:
        owner = _chain.get()
        # Success/denial leaves no unresolved child. All other exits prevent
        # another nested dispatch even if a caller ignores the failed result.
        if owner is not None and request.owner_id == owner.claim['owner_id']:
            if not finalized:
                owner.uncertain = True
