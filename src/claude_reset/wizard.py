"""Wizard progress from fresh read-only checks. Public results carry only fixed step states."""
from . import diagnostics, l1_check

STEPS = ('server', 'cleanup', 'connection', 'protection', 'checks')
FINISHED_RUNS = {'local_operations_completed_partial_coverage', 'fixed_locations_wiped'}


def progress(paths, *, server_done=False, check=l1_check.check, history=diagnostics.operation_history):
    """States: done, todo, unknown (could not be read). The checks step is ready only after the others."""
    try:
        report = check(paths)
        parts = {c['id']: c['status'] for c in report.get('checks', [])}
        protection = report.get('protection')
    except Exception:
        parts = protection = None
    try:
        runs = history(paths)
        cleaned = None if runs['collection'] == 'unavailable' else any(
            r['status'] in FINISHED_RUNS for r in runs['rows'])
    except Exception:
        cleaned = None

    def state(value):
        return 'unknown' if value is None else 'done' if value else 'todo'
    states = {
        'server': state(bool(server_done)),
        'cleanup': state(cleaned),
        'connection': state(None if parts is None else all(
            parts.get(k) == 'ok' for k in ('backend_task', 'backend_listening', 'connection_profile'))),
        'protection': state(None if protection is None else protection == 'installed'),
    }
    states['checks'] = 'todo' if all(v == 'done' for v in states.values()) else 'waiting'
    following = next((k for k in STEPS if states[k] != 'done'), 'checks')
    return {'steps': [{'key': k, 'state': states[k]} for k in STEPS], 'next': following}
