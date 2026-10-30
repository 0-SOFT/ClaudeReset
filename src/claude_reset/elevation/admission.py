"""One-use start permission. All grant/consume calls hold admission.lock."""
from dataclasses import asdict
import json
from pathlib import Path

from ..errors import SafetyError
from ..safeio import guarded, atomic_json
from .. import layout
from .claims import ChildAdmissionRefused, Request, claim_matches, pending_path, receipt_identity, require_expected, require_not_revoked
from . import child_process


def permit_path(paths):
    return layout.app_local(paths, 'controller-start.json')


def grant(paths, request, *, scheduler):
    claim = json.loads(pending_path(paths).read_text('utf-8'))
    atomic_json(permit_path(paths), {'schema': 1, 'claim': claim,
                'request': asdict(request), 'scheduler': scheduler, 'consumed': False}, paths.local)


def consume(paths, request_id):
    verified_identity = None
    try:
        row = json.loads(permit_path(paths).read_text('utf-8'))
        request = Request(**row['request'])
        root = str(guarded(paths.state, paths.state, allow_root=True))
        if (type(row.get('schema')) is not int or row['schema'] != 1
                or type(request.schema) is not int or request.schema != 1
                or request.operation != 'start' or request.state_root != root
                or not claim_matches(pending_path(paths), row['claim'])
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
                     and claim_matches(guarded(layout.controller_folder(root) /
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
        child_process.record(request)
        return identity
    except (OSError, ValueError, TypeError, KeyError, SafetyError):
        error = ChildAdmissionRefused('Controller admission unavailable')
        error.verified_identity = verified_identity
        raise error from None
