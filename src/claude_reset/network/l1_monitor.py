"""What the L1 controller does with a failed poll, and the record it leaves when it stops.

A measured wrong exit or a changed backend is conclusive and stops the controller at once. A probe
that merely failed to measure (a refused or slow request, an unreadable status file) is tolerated for
a bounded number of consecutive polls, so one transient failure no longer takes every protected
client offline. Prevention of direct traffic never depends on this loop: it comes from the permanent
endpoint pin and the client deny rules.
"""
import json
from ..model.status import Measurement
from ..model.ids import utc_now

PROBE_TOLERANCE = 6  # consecutive 5 s polls
HISTORY = 'controller-history.log'
HISTORY_LIMIT = 100_000


def probe_verdict(result, failures):
    """Returns (consecutive failures, stop reason or None) for one connections.check() result."""
    if result.get('passed') is True:
        return 0, None
    row = (result.get('measurements') or {}).get('local') or {}
    if row.get('status') != Measurement.MEASUREMENT_FAILED:
        return failures + 1, 'exit_mismatch'
    failures += 1
    return failures, ('exit_probe_failed' if failures >= PROBE_TOLERANCE else None)


def monitor_error(failures):
    """An unreadable status file or failed engine query counts like a failed probe."""
    failures += 1
    return failures, ('monitor_error' if failures >= PROBE_TOLERANCE else None)


def record_exit(folder, state):
    """One bounded line per controller exit; the status file is overwritten by the next start."""
    try:
        path = folder / HISTORY
        if path.exists() and path.stat().st_size > HISTORY_LIMIT:
            path.write_text('', encoding='ascii')
        row = {'utc': utc_now(), 'instance': str(state.get('instance'))[:32],
               'state': str(state.get('state'))[:60], 'stop_reason': str(state.get('stop_reason'))[:60],
               'error_type': str(state.get('error_type'))[:60]}
        with open(path, 'a', encoding='ascii') as stream:
            stream.write(json.dumps(row) + '\n')
    except OSError:
        pass
