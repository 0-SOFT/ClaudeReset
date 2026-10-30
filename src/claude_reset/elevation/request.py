"""Durable, single-owner elevation requests; no Windows calls in this module.

Only the original owner of a claim (see claims) may release it after a definitive denial or an exact
successful receipt.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from .. import layout
from ..errors import SafetyError, error_kind
from ..model.ids import new_id
from ..model.records import Claim, SchedulerCount, exact
from ..model.status import Elevation, Package
from ..safeio import guarded
from . import admission as controller_admission
from . import child_process, claims
from .claims import (
    OPERATIONS,
    ChildAdmissionRefused,
    Request,
    chain,
    claim_matches,
    inventory,
    inventory_path,
    pending_path,
    receipt_identity,
    request_marker,
    require_expected,
    require_generation_open,
    require_not_revoked,
)
from .locks import locked

__all__ = ['admission_denied', 'admit_child', 'child_event', 'execute', 'prepare', 'read_receipt', 'record_event',
           'release', 'revoke', 'schedule', 'scheduler_count', 'verdict']




def prepare(paths, operation, *, scheduler=False):
    owner = chain.get()
    try:
        with locked(paths):
            request = _prepare(paths, operation)
            if operation == 'start':
                controller_admission.grant(paths, request, scheduler=scheduler)
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
    request_id = new_id()
    receipt = guarded(layout.controller_folder(root) / ('uac-' + request_id + '.json'), root)
    request = Request(request_id, operation, str(root), str(receipt))
    pending = pending_path(paths)
    owner = chain.get()
    if owner is not None:
        if (owner.pending != pending or owner.claim['state_root'] != str(root)
                or owner.uncertain or not claim_matches(pending, owner.claim)):
            raise SafetyError('Mutation ownership mismatch')
        request = Request(request_id, operation, str(root), str(receipt), owner_id=owner.claim['owner_id'])
        require_generation_open(owner.claim)
        from ..safeio import atomic_json
        expected = inventory(owner.claim)
        expected['requests'].append(asdict(request))
        atomic_json(inventory_path(owner.claim), expected, root)
        # Preserve the exact nested request before dispatch, without releasing
        # or replacing the outer arbitration file between receipts.
        claims.save_exclusive(guarded(layout.controller_folder(root) / ('request-' + request_id + '.json'), root),
                              asdict(request))
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
        owner = chain.get()
        return (owner is not None and not owner.uncertain
                and owner.pending == pending_path(paths)
                and owner.claim['owner_id'] == request.owner_id
                and owner.claim['state_root'] == request.state_root
                and claim_matches(owner.pending, owner.claim)
                and claim_matches(guarded(layout.controller_folder(request.state_root) /
                                          ('request-' + request.request_id + '.json'),
                                          Path(request.state_root)), asdict(request)))
    try:
        return json.loads(pending_path(paths).read_text('utf-8')) == asdict(request)
    except (OSError, ValueError):
        return False


def release(paths, request):
    """Remove the pending claim of this request; a claim that changed or belongs to an outer chain stays."""
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        require_generation_open(json.loads(pending_path(paths).read_text('utf-8')))
        if request.owner_id is None:
            pending_path(paths).unlink()


def revoke(paths, request):
    """Fence an unconsumed request, without releasing its mutation claim.

    Admission and revocation share the same lock. A consumed or ambiguous
    request cannot be revoked as if no effect had begun.
    """
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        marker = request_marker(request, 'revoked')
        record = {'schema': 1, 'request': asdict(request)}
        if marker.exists():
            if not claim_matches(marker, record):
                raise SafetyError('Elevation revocation uncertain')
            return
        if request_marker(request, 'admitted').exists():
            raise SafetyError('Elevation already admitted')
        if request.operation == 'start':
            try:
                permit = json.loads(controller_admission.permit_path(paths).read_text('utf-8'))
                valid = (permit.get('request') == asdict(request)
                         and permit.get('consumed') is False
                         and claim_matches(pending_path(paths), permit.get('claim')))
            except (OSError, ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise SafetyError('Controller revocation uncertain')
        claims.save_exclusive(marker, record)


def record_event(paths, request, kind):
    # Append-only fixed labels; never persist dispatch exception text.
    with locked(paths):
        if not _owned(paths, request):
            raise SafetyError('Elevation claim changed')
        require_expected(json.loads(pending_path(paths).read_text('utf-8')), request)
        if kind.startswith('scheduler-') and kind.endswith('-dispatch'):
            _expect_scheduler_attempt(request, kind)
        claims.save_exclusive(request_marker(request, kind),
                        {'schema': 1, 'request': asdict(request), 'event': kind})


def scheduler_count(request):
    """How many scheduler attempts the request expects so far; an unreadable record is refused."""
    path = request_marker(request, 'expected-scheduler')
    if path.stat().st_size > 65536:
        raise SafetyError('Scheduler inventory unavailable')
    row = json.loads(path.read_text('utf-8'))
    if (not exact(row, SchedulerCount)
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
    from ..safeio import atomic_json
    number = kind[len('scheduler-'):-len('-dispatch')]
    if not number.isascii() or not number.isdecimal() or str(int(number)) != number:
        raise SafetyError('Invalid scheduler attempt')
    attempt = int(number)
    record = {'schema': 1, 'request': asdict(request), 'attempts': attempt}
    path = request_marker(request, 'expected-scheduler')
    if attempt == 1:
        claims.save_exclusive(path, record)
    else:
        if attempt < 1 or scheduler_count(request) != attempt - 1:
            raise SafetyError('Scheduler attempt out of order')
        atomic_json(path, record, Path(request.state_root))


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
    path = guarded(layout.controller_folder(root) /
                   ('child-' + expected['request_id'] + '-' + new_id() + '.json'), root)
    claims.save_exclusive(path, {'schema': 1, 'identity': expected, 'event': kind})


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
    attempt_id = new_id()
    prefix = ('denied-unknown-' if verified_identity is None else
              'child-' + verified_identity['request_id'] + '-')
    claims.save_exclusive(guarded(layout.controller_folder(root) / (prefix + attempt_id + '.json'), root),
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
                if (not exact(claim, Claim)
                        or not isinstance(owner_id, str) or len(owner_id) != 32
                        or any(c not in '0123456789abcdef' for c in owner_id)
                        or claim['state_root'] != str(root)):
                    raise SafetyError('Elevation admission refused')
            request = Request(request_id, operation, str(root),
                              str(layout.controller_folder(root) / ('uac-' + request_id + '.json')),
                              owner_id=owner_id)
            record = (pending_path(paths) if owner_id is None else
                      guarded(layout.controller_folder(root) / ('request-' + request_id + '.json'), root))
            if not claim_matches(record, asdict(request)):
                raise SafetyError('Elevation admission refused')
            require_expected(claim, request)
            verified_identity = identity
            require_not_revoked(request)
            consumed = guarded(layout.controller_folder(root) / ('admitted-' + request_id + '.json'), root)
            claims.save_exclusive(consumed, {'schema': 1, 'request': asdict(request), 'claim': claim})
            child_process.record(request)
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


def start_verdict(row: dict) -> Elevation | None:
    if (row.get('finished') is not True and row.get('state') == 'relay_open' and row.get('passed') is True
            and row.get('persistent_boundary') is True and row.get('live_permit_session') is True):
        return Elevation.OBSERVED_READY
    return Elevation.RECONCILE_REQUIRED if row.get('finished') is True else None


# Whether the finished receipt of each operation proves its effect.
SUCCEEDED = MappingProxyType({
    'package-register': lambda row: row.get('status') in (Package.REGISTERED, Package.ALREADY_REGISTERED),
    'package-remove': lambda row: row.get('status') == Package.REMOVED and row.get('registered_after') is False,
    'remove': lambda row: row.get('removed') is True,
    'autostart': lambda row: row.get('registered') is True,
})


def autostart_removed(row: dict) -> bool:
    return row.get('task_present_after') is False and row.get('program_removed') is True


def verdict(request: Request, row: dict) -> Elevation | None:
    if 'error' in row or 'error_type' in row:
        return Elevation.RECONCILE_REQUIRED if row.get('finished') is True else None
    if request.operation == 'start':
        return start_verdict(row)
    if row.get('finished') is not True:
        return None
    succeeded = SUCCEEDED.get(request.operation, autostart_removed)
    return Elevation.COMPLETED if succeeded(row) else Elevation.RECONCILE_REQUIRED


def outcome(status):
    # Domain data and private paths never enter this public result.
    return {'status': status, 'passed': status == Elevation.COMPLETED,
            'requires_live_verification': True,
            'retry_blocked': status in (Elevation.UNKNOWN, Elevation.RECONCILE_REQUIRED, Elevation.INSPECTION_FINISHED,
                                       Elevation.OBSERVED_READY)}


def execute(paths, operation, dispatch, *, wait_seconds=300, clock=time.monotonic, sleep=time.sleep):
    request = prepare(paths, operation)
    status = None
    code = None
    finalized = False
    try:
        if not _owned(paths, request):
            return outcome(Elevation.UNKNOWN)
        # dispatch returns only the ShellExecute result, never completion.
        record_event(paths, request, 'dispatch')
        code = dispatch(request)
        if type(code) is not int or code < 0:
            return outcome(Elevation.UNKNOWN)
        if code <= 32:
            revoke(paths, request)
            record_event(paths, request, 'denial')
            release(paths, request)
            finalized = True
            return outcome('denied')
        deadline = clock() + wait_seconds
        while True:
            row = read_receipt(request)
            status = verdict(request, row) if row is not None else None
            if status:
                record_event(paths, request, 'receipt-observed')
                # A start receipt is a historical observation. Its live flags
                # do not attest current process ownership or resource state.
                if status == Elevation.COMPLETED:
                    release(paths, request)
                    finalized = True
                return outcome(status)
            if clock() >= deadline:
                return outcome(Elevation.UNKNOWN)
            sleep(min(1, max(0, deadline - clock())))
    except Exception as exc:
        # A failed wait or dispatch cannot prove that no effects happened.
        return {**outcome(Elevation.UNKNOWN), 'error_type': error_kind(exc)}
    finally:
        owner = chain.get()
        # Success/denial leaves no unresolved child. All other exits prevent
        # another nested dispatch even if a caller ignores the failed result.
        if owner is not None and request.owner_id == owner.claim['owner_id']:
            if not finalized:
                owner.uncertain = True


def schedule(folder):
    """Only the synchronous chain may authorize its scheduler invocation."""
    owner = chain.get()
    if owner is None or layout.controller_folder(owner.claim['state_root']) != folder:
        raise SafetyError('Controller start requires mutation ownership')
    paths = SimpleNamespace(local=owner.pending.parent.parent, state=Path(owner.claim['state_root']))
    request = prepare(paths, 'start', scheduler=True)
    owner.start_request = request
    return request
