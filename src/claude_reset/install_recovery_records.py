"""Recovery-only records retaining an absent interrupted creation as intent."""
from .install_service_receipts import ServiceReceipts
from .install_service_attestation import _records
from .install_creation_attestation import creation_records
from .install_creation_cleanup_receipt import CreationCleanupReceipt
from .install_scm_cleanup import _confirm_absence
from .service_store import verify_paths
from .safeio import SafetyError


def recovery_records(store,generation,closed):
    if not callable(closed) or closed() is not True:raise SafetyError('Closed recovery boundary required')
    source=ServiceReceipts(store.journal).load()
    if source and source['services'] and source['services'][-1]['state']=='intent':
        records=creation_records(store,generation)
        receipt=CreationCleanupReceipt(store,generation)
        verify_paths([receipt.path],[])
        evidence=receipt.load()
        if evidence is None or evidence['absence_verified'] is not True:
            raise SafetyError('Interrupted creation needs independently confirmed absence')
        _confirm_absence([source['services'][-1]['name']],closed)
        if creation_records(store,generation)!=records or receipt.load()!=evidence:
            raise SafetyError('Pending creation absence evidence changed')
        return records
    records=_records(store,generation)
    if records[0]['state']!='recovering' or any(r['state']!='disabled' for r in records[1]['services']):
        raise SafetyError('Completed registrations in ordered recovery required')
    return records
