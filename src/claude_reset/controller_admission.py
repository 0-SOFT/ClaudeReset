"""One-use start permission. All grant/consume calls hold admission.lock."""
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

from .safeio import guarded, atomic_json, SafetyError


def permit_path(paths):
    return guarded(paths.local / 'ClaudeReset' / 'controller-start.json', paths.local)


def grant(paths, request, *, scheduler):
    from .uac_request import pending_path
    claim = json.loads(pending_path(paths).read_text('utf-8'))
    atomic_json(permit_path(paths), {'schema': 1, 'claim': claim,
                'request': asdict(request), 'scheduler': scheduler, 'consumed': False}, paths.local)


def consume(paths, request_id):
    from .uac_request import pending_path, Request, _claim_matches, receipt_identity, require_not_revoked, require_expected, ChildAdmissionRefused
    verified_identity = None
    try:
        row = json.loads(permit_path(paths).read_text('utf-8'))
        request = Request(**row['request'])
        root = str(guarded(paths.state, paths.state, allow_root=True))
        if (type(row.get('schema')) is not int or row['schema'] != 1
                or type(request.schema) is not int or request.schema != 1
                or request.operation != 'start' or request.state_root != root
                or not _claim_matches(pending_path(paths), row['claim'])
                or (request_id is None and row.get('scheduler') is not True)
                or (request_id is not None and (row.get('scheduler') is not False
                                               or request.request_id != request_id))):
            raise SafetyError('Controller admission refused')
        claim = row['claim']
        if request.owner_id is None:
            valid = claim == asdict(request)
        else:
            valid = (claim.get('schema') == 2 and claim.get('owner_id') == request.owner_id
                     and claim.get('state_root') == root
                     and _claim_matches(guarded(Path(root) / 'strict-guard' /
                          ('request-' + request.request_id + '.json'), Path(root)), asdict(request)))
        if not valid:
            raise SafetyError('Controller admission refused')
        identity = receipt_identity(paths, 'start', request.request_id)
        require_expected(claim, request)
        # A bare scheduler invocation carries no identity of its own.
        if request_id is not None:
            verified_identity = identity
        if row.get('consumed') is not False:
            raise SafetyError('Controller admission refused')
        require_not_revoked(request)
        row['consumed'] = True
        atomic_json(permit_path(paths), row, paths.local)
        # Preserve the admitted process even if publishing status later fails
        # or another start replaces it. A failed witness never restores permit.
        from .child_process import record
        record(request)
        return identity
    except (OSError, ValueError, TypeError, KeyError, SafetyError):
        error = ChildAdmissionRefused('Controller admission unavailable')
        error.verified_identity = verified_identity
        raise error from None


def schedule(folder):
    """Only the synchronous chain may authorize its scheduler invocation."""
    from .uac_request import _chain, prepare
    owner = _chain.get()
    if owner is None or Path(owner.claim['state_root']) / 'strict-guard' != folder:
        raise SafetyError('Controller start requires mutation ownership')
    paths = SimpleNamespace(local=owner.pending.parent.parent, state=Path(owner.claim['state_root']))
    request = prepare(paths, 'start', scheduler=True)
    owner.start_request = request
    return request
