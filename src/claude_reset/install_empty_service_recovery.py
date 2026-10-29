"""Recover failure before the first service intent, without adopting services."""
from .install_service_receipts import ServiceReceipts
from .install_service_markers import MarkerReceipts
from .install_recovery_inputs import RecoveryInputs
from .install_boundary_confirmation import inspect_recovery_boundary
from .install_boundary_reconciliation import reconcile_committed_boundary
from .install_scm_cleanup import _confirm_absence
from .install_scm import SERVICES
from .install_boundary import _held_rules
from .install_boundary_receipts import BoundaryReceipt
from .install_cleanup_observation import require_cleanup_absence
from .service_store import verify_paths
from .safeio import SafetyError


def recover_empty_service_step(store,generation,verify_closed):
    if not callable(verify_closed):raise SafetyError('Closed-boundary verifier required')
    def closed():
        if verify_closed(generation) is not True:raise SafetyError('Client boundary is not verified closed')
        return True
    def empty():
        closed();source=ServiceReceipts(store.journal).load()
        if source is None:
            try:(store.journal.directory/MarkerReceipts.filename).lstat()
            except FileNotFoundError:markers=None
            else:raise SafetyError('Marker history exists without registration history')
        else:markers=MarkerReceipts(store.journal).load()
        if source is not None and source['services'] or markers is not None and markers['services']:
            raise SafetyError('Recorded registrations require their own ownership recovery')
        paths=[]
        for name in ('service-receipts.json',MarkerReceipts.filename):
            path=store.journal.directory/name
            try:path.lstat();paths.append(path)
            except FileNotFoundError:pass
        # Evidence of later stages is inconsistent with an empty creation log.
        for name in ('policy-binding-receipt.json','service-removal-receipts.json',
                     'pending-creation-cleanup.json','service-reconciliation-log.json'):
            try:(store.journal.directory/name).lstat()
            except FileNotFoundError:continue
            raise SafetyError('Later service evidence contradicts empty registration history')
        verify_paths(paths,[])
        _confirm_absence(list(reversed(SERVICES)),closed)
        return source,markers
    with RecoveryInputs(store,generation) as inputs:
        transaction=store.journal.load()
        if transaction['state']!='recovering':raise SafetyError('Ordered active recovery required')
        before=empty()
        keys=[r.key.value() for r in _held_rules(store,inputs.payload)]
        boundary=BoundaryReceipt(store.journal,keys)
        if boundary.load() is None:
            def no_creation():
                if store.journal.load()!=transaction or empty()!=before or boundary.load() is not None:
                    raise SafetyError('Unrecorded boundary recovery evidence changed')
                for name in ('reservation-receipt.json','reservation-reconciliation-log.json',
                             'boundary-reconciliation-log.json'):
                    try:(store.journal.directory/name).lstat()
                    except FileNotFoundError:continue
                    raise SafetyError('Later boundary evidence exists without initial intent')
                return closed()
            no_creation();require_cleanup_absence(keys,no_creation);no_creation()
            return dict(services_recovered=True,services_created=False,boundary_absent=True,
                        initial_boundary_recorded=False,payload_removed=False,client_admission=False)
        receipt,record,observed=inspect_recovery_boundary(store,inputs,generation,verify_closed)
        if empty()!=before or receipt.load()!=record:raise SafetyError('Empty service recovery evidence changed')
        phase=record.get('previous_state',record['state'])
        if phase in ('committed','remove_intent'):
            result=reconcile_committed_boundary(store,inputs,generation,verify_closed)
            if (not isinstance(result,dict) or result.get('boundary_absent') is not True
                    or result.get('client_admission') is not False or receipt.load()['state']!='removed'):
                raise SafetyError('Initial deny reconciliation result is unverified')
        elif observed['state']=='absent':
            receipt.confirm_absent(observed)
        else:
            raise SafetyError('Present denies with uncertain history cannot be adopted or replayed')
        empty();closed()
        return dict(services_recovered=True,services_created=False,boundary_absent=True,
                    payload_removed=False,client_admission=False)
