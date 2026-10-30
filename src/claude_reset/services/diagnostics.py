"""Read-only diagnostics with a closed public schema, using existing collectors."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

from .. import layout
from ..errors import SafetyError, error_kind
from ..model.ids import utc_now
from ..model.notes import Note
from ..model.records import present
from ..model.status import Collected, Diagnosis, Location, ProtectionLevel, Reset
from ..network import l1_check
from ..reset import cleanup
from ..safeio import guarded
from ..windows.inventory import inspect_windows
from ..windows.pin import PinnedFile

__all__ = ['Advice', 'DiagnosticsReport', 'FileFacts', 'History', 'HistoryRow', 'ProtectionFacts', 'SettingsOpened',
           'advise', 'collect', 'open_settings', 'operation_history']


KNOWN_LEVELS = frozenset(ProtectionLevel) - {ProtectionLevel.UNKNOWN}
ADVICE = MappingProxyType({
    'DE': ('W. Europe Standard Time', ('de-DE',), Note('advice.de')),
    'TR': ('Turkey Standard Time', ('tr-TR',), Note('advice.tr')),
    'GB': ('GMT Standard Time', ('en-GB',), Note('advice.gb')),
})


@dataclass(frozen=True)
class Advice:
    """The time zone and language of this PC compared with a country the person chose; nothing is changed.

    The matches are given only when the comparison was made (status compared); error_type names the error that
    made it unavailable."""
    status: Diagnosis
    text: Note
    timezone_matches: bool | None = None
    language_matches: bool | None = None
    settings_changed: bool = False
    exit_country_verified: bool = False
    note: Note | None = None
    error_type: str | None = None

    def to_json(self) -> dict:
        return present(status=self.status, text=self.text, timezone_matches=self.timezone_matches,
                       language_matches=self.language_matches, settings_changed=self.settings_changed,
                       exit_country_verified=self.exit_country_verified, note=self.note, error_type=self.error_type)


def advise(country: str, *, inspect: Callable[[], dict] = inspect_windows) -> Advice:
    """Country is explicitly supplied by the user, never inferred from an IP.

    inspect reads this PC's time zone and language (windows.inventory.inspect_windows)."""
    choice = ADVICE.get(country.strip().upper()) if isinstance(country, str) else None
    if choice is None:
        return Advice(Diagnosis.UNSUPPORTED, Note('advice.unsupported'))
    try:
        facts = inspect()
        zone, languages, text = choice
        actual_zone = facts.get('timezone', {}).get('id')
        actual_language = facts.get('locale')
        if not isinstance(actual_zone, str) or not actual_zone or not isinstance(actual_language, str) or not actual_language:
            raise ValueError('Missing comparison facts')
        return Advice(Diagnosis.COMPARED, text, timezone_matches=facts['timezone']['id'] == zone,
                      language_matches=facts['locale'] in languages, note=Note('advice.note'))
    except Exception as exc:
        return Advice(Diagnosis.UNAVAILABLE, Note('advice.unavailable'), error_type=error_kind(exc))


@dataclass(frozen=True)
class SettingsOpened:
    """A Windows settings page was opened; no setting was changed."""
    opened: bool = True
    settings_changed: bool = False

    def to_json(self) -> dict:
        return {'opened': self.opened, 'settings_changed': self.settings_changed}


def open_settings(kind: str) -> SettingsOpened:
    import os
    uris = {'timezone': 'ms-settings:dateandtime', 'language': 'ms-settings:regionlanguage',
            'startup': 'ms-settings:startupapps'}
    if kind not in uris:
        raise SafetyError('Unknown settings page', code='settings_page')
    try:
        os.startfile(uris[kind])
    except OSError:
        raise SafetyError('Windows settings did not open', code='windows_settings_failed') from None
    return SettingsOpened()


LIMITATIONS = (
    Note('diagnostics.limit.l1'),
    Note('diagnostics.limit.files'),
    Note('diagnostics.limit.cowork'),
    Note('diagnostics.limit.resolve'),
    Note('diagnostics.limit.browsers'),
    Note('diagnostics.limit.browser_settings'),
    Note('diagnostics.limit.server'),
)
# The words for each status a reset or wipe report can end with.
RUN_LABELS = MappingProxyType({
    Reset.STARTED: Note('history.started'),
    Reset.FAILED_OR_PARTIAL: Note('history.failed_or_partial'),
    Reset.PARTIAL_COVERAGE: Note('history.partial_coverage'),
    Reset.FIXED_LOCATIONS_WIPED: Note('history.fixed_locations_wiped'),
})
HISTORY_LIMIT = 100


@dataclass(frozen=True)
class HistoryRow:
    """One reset or wipe report by its position: how it ended, or unavailable when it could not be read."""
    position: int
    status: Reset | Diagnosis
    text: Note

    def to_json(self) -> dict:
        return {'position': self.position, 'status': self.status, 'text': self.text}


@dataclass(frozen=True)
class History:
    """The reset and wipe reports found, at most HISTORY_LIMIT; truncated when there were more."""
    collection: Collected
    rows: tuple[HistoryRow, ...] = ()
    truncated: bool = False
    schema: int = 1
    live_result_verified: bool = False
    note: Note = Note('history.note')

    def to_json(self) -> dict:
        return {'schema': self.schema, 'collection': self.collection, 'rows': [row.to_json() for row in self.rows],
                'truncated': self.truncated, 'live_result_verified': self.live_result_verified, 'note': self.note}


def operation_history(paths) -> History:
    """Read existing reset/wipe reports; never read private recovery journals."""
    collection, rows, truncated = Collected.COMPLETE, [], False
    try:
        root = guarded(paths.state / layout.RUNS, paths.state)
        try:
            root.stat()
        except FileNotFoundError:
            return History(Collected.COMPLETE)
        for index, entry in enumerate(root.iterdir()):
            if index == HISTORY_LIMIT:
                truncated, collection = True, Collected.PARTIAL
                break
            row = HistoryRow(index + 1, Diagnosis.UNAVAILABLE, Note('history.unavailable'))
            try:
                target = guarded(entry / layout.RESULT_FILE, paths.state)
                with PinnedFile(target, limit=65536) as source:
                    raw = json.loads(source.data)
                status = raw.get('status') if isinstance(raw, dict) else None
                if isinstance(status, str) and status in RUN_LABELS:
                    row = HistoryRow(index + 1, Reset(status), RUN_LABELS[status])
                else:
                    collection = Collected.PARTIAL
            except (SafetyError, OSError, ValueError):
                collection = Collected.PARTIAL
            rows.append(row)
    except (SafetyError, OSError, ValueError):
        collection = Collected.UNAVAILABLE
    return History(collection, rows=tuple(rows), truncated=truncated)


@dataclass(frozen=True)
class ProtectionFacts:
    """Which protection components the readiness check found; error_type names the error that stopped it."""
    collection: Collected
    components: ProtectionLevel
    live_protection_verified: bool = False
    error_type: str | None = None

    def to_json(self) -> dict:
        return present(collection=self.collection, components=self.components,
                       live_protection_verified=self.live_protection_verified, error_type=self.error_type)


@dataclass(frozen=True)
class FileFacts:
    """What the reset's file audit found in the fixed locations; the counts are absent when it could not run."""
    collection: Collected
    present_locations: int | None = None
    unavailable_locations: int | None = None
    zero_fixed_file_remainder: bool = False
    zero_total_remainder: bool = False
    error_type: str | None = None

    def to_json(self) -> dict:
        return present(collection=self.collection, present_locations=self.present_locations,
                       unavailable_locations=self.unavailable_locations,
                       zero_fixed_file_remainder=self.zero_fixed_file_remainder,
                       zero_total_remainder=self.zero_total_remainder, error_type=self.error_type)


@dataclass(frozen=True)
class DiagnosticsReport:
    """The report the person saves: the protection and file facts and what the report cannot show."""
    observed_utc: str
    protection: ProtectionFacts
    files: FileFacts
    limitations: tuple[Note, ...] = LIMITATIONS
    schema: int = 1
    network_measured: bool = False
    ready_for_new_account: bool = False

    @property
    def collection_complete(self) -> bool:
        return self.protection.collection == Collected.COMPLETE and self.files.collection == Collected.COMPLETE

    def to_json(self) -> dict:
        return {'schema': self.schema, 'observed_utc': self.observed_utc, 'network_measured': self.network_measured,
                'ready_for_new_account': self.ready_for_new_account, 'limitations': list(self.limitations),
                'protection': self.protection.to_json(), 'files': self.files.to_json(),
                'collection_complete': self.collection_complete}


def _protection_facts(paths, check: Callable) -> ProtectionFacts:
    """The protection components the readiness check found; never its strings."""
    try:
        state = check(paths).get('protection')
        if state in KNOWN_LEVELS:
            return ProtectionFacts(Collected.COMPLETE, ProtectionLevel(state))
        return ProtectionFacts(Collected.UNAVAILABLE, ProtectionLevel.UNKNOWN)
    except Exception as exc:
        return ProtectionFacts(Collected.UNAVAILABLE, ProtectionLevel.UNKNOWN, error_type=error_kind(exc))


def _file_facts(paths, audit: Callable) -> FileFacts:
    """The counts of the reset's file audit; never its labels or paths."""
    known = (Location.ABSENT, Location.PRESENT)
    try:
        raw = audit(paths)
        rows = raw['rows']
        complete = raw.get('complete') is True and bool(rows) and all(r.get('status') in known for r in rows)
        return FileFacts(Collected.COMPLETE if complete else Collected.PARTIAL,
                         present_locations=sum(r.get('status') == Location.PRESENT for r in rows),
                         unavailable_locations=sum(r.get('status') not in known for r in rows),
                         zero_fixed_file_remainder=complete and all(r['status'] == Location.ABSENT for r in rows))
    except Exception as exc:
        return FileFacts(Collected.UNAVAILABLE, error_type=error_kind(exc))


def collect(paths, *, check: Callable = l1_check.check, audit: Callable = cleanup.audit) -> DiagnosticsReport:
    """Never export collector strings, paths, exception text or arbitrary keys.

    check is the L1 readiness check and audit the reset's file audit."""
    observed = utc_now()
    protection = _protection_facts(paths, check)
    return DiagnosticsReport(observed, protection, _file_facts(paths, audit))
