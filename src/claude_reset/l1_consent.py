"""The owner's explicit acceptance of the named L1 limits; a measurement never implies it.

Consent covers exactly the boundaries listed in it. A boundary the controller
reports later that is not listed keeps the relay closed. Storage is DPAPI under
the strict-guard state folder, bound to the current user.
"""
import json
from datetime import datetime, timezone

from .safeio import SafetyError, atomic_bytes
from .windows import DPAPI

STATUS = 'blocked_incomplete_broker_isolation'
FILE = 'l1-consent.dpapi'
DNS = 'dns_service_delegation'


def required(coverage):
    """Boundaries the current coverage report says are still open."""
    if not isinstance(coverage, dict) or coverage.get('status') != STATUS:
        raise SafetyError('Unrecognised coverage report; the relay stays closed')
    names = coverage.get('remaining_boundaries')
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise SafetyError('Unrecognised coverage report; the relay stays closed')
    result = set(names)
    dns = coverage.get('dns')
    if not isinstance(dns, dict) or dns.get('passed') is not True:
        result.add(DNS)
    return sorted(result)


def record(folder, coverage):
    """Create consent for exactly the boundaries open right now."""
    accepted = required(coverage)
    document = {'schema': 1, 'level': 'L1', 'accepted': accepted,
                'utc': datetime.now(timezone.utc).isoformat()}
    atomic_bytes(folder / FILE, DPAPI().encrypt(json.dumps(document, sort_keys=True).encode('ascii')), folder)
    return document


def load(folder):
    path = folder / FILE
    if not path.exists():
        return None
    try:
        document = json.loads(DPAPI().decrypt(path.read_bytes()).decode('ascii'))
    except (OSError, ValueError, UnicodeError, SafetyError):
        return None
    if (not isinstance(document, dict) or document.get('schema') != 1 or document.get('level') != 'L1'
            or not isinstance(document.get('accepted'), list)):
        return None
    return document


def revoke(folder):
    path = folder / FILE
    if path.exists():
        path.unlink()
    return not path.exists()


def admits(coverage, consent):
    """True only when every currently open boundary is named in the consent."""
    if coverage.get('passed') is True:
        return True
    if consent is None:
        return False
    try:
        return set(required(coverage)) <= set(consent['accepted'])
    except SafetyError:
        return False
