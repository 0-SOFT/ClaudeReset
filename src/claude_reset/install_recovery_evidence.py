"""Reject service evidence when the journal has no durable service intent."""
from .safeio import SafetyError

SERVICE_EVIDENCE=('service-receipts.json','service-marker-receipts.json','policy-binding-receipt.json',
    'boundary-receipt.json','reservation-receipt.json','service-removal-receipts.json',
    'pending-creation-cleanup.json','service-reconciliation-log.json',
    'boundary-reconciliation-log.json','reservation-reconciliation-log.json')


def require_no_service_evidence(journal):
    for name in SERVICE_EVIDENCE:
        try:(journal.directory/name).lstat()
        except FileNotFoundError:continue
        raise SafetyError('Service evidence without durable service intent requires separate recovery')
