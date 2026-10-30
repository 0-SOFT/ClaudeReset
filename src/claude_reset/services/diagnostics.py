"""Read-only diagnostics with a closed public schema, using existing collectors."""

from ..reset import cleanup
from ..network import l1_check
from ..windows.system import inspect_windows
from ..safeio import guarded
from ..windows.pin import PinnedFile
import json
from types import MappingProxyType
from .. import layout
from ..model.status import Diagnosis, Location, ProtectionLevel
from ..model.notes import Note
from ..model.ids import utc_now
from collections.abc import Callable

__all__ = ['advise', 'collect', 'open_settings', 'operation_history']


KNOWN_LEVELS = frozenset(ProtectionLevel) - {ProtectionLevel.UNKNOWN}
ADVICE = MappingProxyType({
    'DE': ('W. Europe Standard Time', ('de-DE',), Note('advice.de')),
    'TR': ('Turkey Standard Time', ('tr-TR',), Note('advice.tr')),
    'GB': ('GMT Standard Time', ('en-GB',), Note('advice.gb')),
})


def advise(country: str, *, inspect: Callable[[], dict] = inspect_windows) -> dict:
    """Country is explicitly supplied by the user, never inferred from an IP.

    inspect reads this PC's time zone and language (windows.system.inspect_windows)."""
    choice = ADVICE.get(country.strip().upper()) if isinstance(country, str) else None
    if choice is None:
        return {'status': Diagnosis.UNSUPPORTED, 'text': Note('advice.unsupported'),
                'settings_changed': False, 'exit_country_verified': False}
    try:
        facts = inspect()
        zone, languages, text = choice
        actual_zone = facts.get('timezone', {}).get('id')
        actual_language = facts.get('locale')
        if not isinstance(actual_zone, str) or not actual_zone or not isinstance(actual_language, str) or not actual_language:
            raise ValueError('Missing comparison facts')
        return {'status': Diagnosis.COMPARED, 'text': text,
                'timezone_matches': facts['timezone']['id'] == zone,
                'language_matches': facts['locale'] in languages,
                'settings_changed': False, 'exit_country_verified': False,
                'note': Note('advice.note')}
    except Exception:
        return {'status': Diagnosis.UNAVAILABLE, 'text': Note('advice.unavailable'),
                'settings_changed': False, 'exit_country_verified': False}


def open_settings(kind: str) -> dict:
    import os
    from ..errors import SafetyError
    uris = {'timezone': 'ms-settings:dateandtime', 'language': 'ms-settings:regionlanguage',
            'startup': 'ms-settings:startupapps'}
    if kind not in uris:
        raise SafetyError('Unknown settings page', code='settings_page')
    try:
        os.startfile(uris[kind])
    except Exception:
        raise SafetyError('Windows settings did not open', code='windows_settings_failed') from None
    return {'opened': True, 'settings_changed': False}


LIMITATIONS = (
    Note('diagnostics.limit.l1'),
    Note('diagnostics.limit.files'),
    Note('diagnostics.limit.cowork'),
    Note('diagnostics.limit.resolve'),
    Note('diagnostics.limit.browsers'),
    Note('diagnostics.limit.browser_settings'),
    Note('diagnostics.limit.server'),
)


def operation_history(paths) -> dict:
    """Read existing reset/wipe reports; never read private recovery journals."""
    labels = {
        'started': Note('history.started'),
        'failed_or_partial': Note('history.failed_or_partial'),
        'local_operations_completed_partial_coverage': Note('history.partial_coverage'),
        'fixed_locations_wiped': Note('history.fixed_locations_wiped'),
    }
    result = {'schema': 1, 'collection': 'complete', 'rows': [], 'truncated': False,
              'live_result_verified': False,
              'note': Note('history.note')}
    try:
        root = guarded(paths.state / layout.RUNS, paths.state)
        try:
            root.stat()
        except FileNotFoundError:
            return result
        for index, entry in enumerate(root.iterdir()):
            if index == 100:
                result.update(truncated=True, collection='partial')
                break
            row = {'position': index + 1, 'status': Diagnosis.UNAVAILABLE, 'text': Note('history.unavailable')}
            try:
                target = guarded(entry / layout.RESULT_FILE, paths.state)
                with PinnedFile(target, limit=65536) as source:
                    raw = json.loads(source.data)
                status = raw.get('status')
                if isinstance(status, str) and status in labels:
                    row.update(status=status, text=labels[status])
                else:
                    result['collection'] = 'partial'
            except Exception:
                result['collection'] = 'partial'
            result['rows'].append(row)
    except Exception:
        result['collection'] = 'unavailable'
    return result


def collect(paths, *, check: Callable | None = None, audit: Callable | None = None) -> dict:
    """Never export collector strings, paths, exception text or arbitrary keys.

    check (the L1 readiness check) and audit (the reset's file audit) are the program's own unless given."""
    report = {'schema': 1, 'observed_utc': utc_now(),
              'network_measured': False, 'ready_for_new_account': False,
              'limitations': list(LIMITATIONS)}
    try:
        raw = (check or l1_check.check)(paths)
        state = raw.get('protection')
        report['protection'] = {
            'collection': 'complete' if state in KNOWN_LEVELS else 'unavailable',
            'components': state if state in KNOWN_LEVELS else ProtectionLevel.UNKNOWN,
            'live_protection_verified': False,
        }
    except Exception:
        report['protection'] = {'collection': 'unavailable', 'components': ProtectionLevel.UNKNOWN,
                                'live_protection_verified': False}
    try:
        raw = (audit or cleanup.audit)(paths)
        rows = raw['rows']
        complete = (raw.get('complete') is True and bool(rows)
                    and all(r.get('status') in (Location.ABSENT, Location.PRESENT) for r in rows))
        report['files'] = {
            'collection': 'complete' if complete else 'partial',
            'present_locations': sum(r.get('status') == Location.PRESENT for r in rows),
            'unavailable_locations': sum(r.get('status') not in (Location.ABSENT, Location.PRESENT) for r in rows),
            'zero_fixed_file_remainder': complete and all(r['status'] == Location.ABSENT for r in rows),
            'zero_total_remainder': False,
        }
    except Exception:
        report['files'] = {'collection': 'unavailable', 'zero_fixed_file_remainder': False,
                           'zero_total_remainder': False}
    report['collection_complete'] = all(report[k]['collection'] == 'complete'
                                        for k in ('protection', 'files'))
    return report
