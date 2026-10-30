"""User-level recovery decisions; only the installed controller can issue permits."""
import re

__all__ = ['backoff', 'decide']

RETRY_STATES = frozenset({'blocked_controller_stopped', 'blocked_exit_mismatch', 'blocked_error'})


def decide(state, close, *, armed, task_running, relay_listening, consent_present):
    def result(reason, enabled=armed, restart=False):
        return dict(reason=reason, armed=enabled, restart=restart)
    if not consent_present:
        return result('consent_absent', False)
    instance = state.get('instance')
    if not isinstance(instance, str) or not re.fullmatch('[a-f0-9]{32}', instance):
        return result('invalid_controller_identity', False)
    if close.get('instance') == instance:
        return result('explicit_close_request', False)
    if (state.get('state') == 'relay_open' and state.get('live_permit_session') is True
            and relay_listening):
        return result('relay_available', True)
    if not armed:
        return result('not_armed', False)
    if task_running:
        return result('controller_task_running')
    if relay_listening:
        return result('unverified_listener_present')
    if state.get('state') not in RETRY_STATES:
        return result('requires_explicit_review')
    return result('retry_full_controller_checks', restart=True)


def backoff(attempt):
    return min(300, 15 * 2 ** min(max(attempt - 1, 0), 5))
