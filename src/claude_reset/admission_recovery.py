"""Recovery preparation, not permission to replay or release a mutation claim."""
from contextlib import ExitStack

from . import uac_request as uac
from .admission import locked
from .controller_process import observe_request
from .controller_boundary import hold as hold_boundary
from .child_process import observe as observe_child
from .safeio import SafetyError


def prepare_recovery(paths, expected_claim):
    """Fence the reviewed generation before observing its recorded controller.

    Resource reconciliation, complete child process inventory and legacy
    controller ownership remain unknown. Even an exited recorded controller
    cannot release the claim. This entry point is not scheduled automatically.
    """
    result = {'status': 'reconcile_required', 'retry_blocked': True,
              'requires_live_verification': True, 'admission': 'unknown',
              'inventory': 'unknown', 'controllers': [], 'children': [],
              'start_processes': [],
              'resources': 'unknown', 'child_exit': 'unknown',
              'controller_boundary': 'unknown',
              'controller_ownership': 'unknown'}
    boundary = None
    scope = ExitStack()
    try:
        uac.close_admission(paths, expected_claim)
        result['admission'] = 'closed'
        with locked(paths):
            if not uac._claim_matches(uac.pending_path(paths), expected_claim):
                raise SafetyError('Mutation claim changed')
            # Independent of status and inventory; never a release condition.
            boundary = scope.enter_context(hold_boundary())
            if not uac._claim_matches(uac.pending_path(paths), expected_claim):
                raise SafetyError('Mutation claim changed')
            inspection = uac.inspect_pending(paths)
            if inspection['status'] != 'reconcile_required':
                return result
            rows = (uac._inventory(expected_claim)['requests']
                    if expected_claim['schema'] == 2 else [expected_claim])
            requests = [uac.Request(**row) for row in rows]
        controllers = [observe_request(request) for request in requests
                       if request.operation == 'start']
        start_processes = [observe_child(request) for request in requests
                           if request.operation == 'start']
        children = [observe_child(request) for request in requests
                    if request.operation != 'start']
        # A second snapshot catches changed/missing records during observation.
        with locked(paths):
            if (not uac._claim_matches(uac.pending_path(paths), expected_claim)
                    or uac.inspect_pending(paths) != inspection
                    or (expected_claim['schema'] == 2
                        and uac._inventory(expected_claim)['requests'] != rows)):
                raise SafetyError('Recovery snapshot changed')
        result.update(inventory='recorded', controllers=controllers, children=children,
                      start_processes=start_processes)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SafetyError):
        pass  # Fixed public labels; no exception text or private identity.
    finally:
        # Keep the same thread's ownership through both journal snapshots and
        # process observation, including when status or inventory is missing.
        scope.close()
        if boundary is not None:
            result['controller_boundary'] = boundary.observation
    return result
