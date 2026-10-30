"""Wizard progress from fresh read-only checks. Public results carry only fixed step states."""
from dataclasses import dataclass

from ..errors import SafetyError
from ..model.status import Check, Collected, Progress, ProtectionLevel, Reset
from ..network import l1_check
from . import diagnostics

__all__ = ['StepProgress', 'WizardProgress', 'progress']

STEPS = ('server', 'cleanup', 'connection', 'protection', 'checks')
FINISHED_RUNS = frozenset({Reset.PARTIAL_COVERAGE, Reset.FIXED_LOCATIONS_WIPED})


@dataclass(frozen=True)
class StepProgress:
    """One step of the wizard by its key, and how far it is."""
    key: str
    state: Progress

    def to_json(self) -> dict:
        return {'key': self.key, 'state': self.state}


@dataclass(frozen=True)
class WizardProgress:
    """Every step in order and the key of the step to do next."""
    steps: tuple[StepProgress, ...]
    next: str

    def to_json(self) -> dict:
        return {'steps': [step.to_json() for step in self.steps], 'next': self.next}


def progress(paths, *, server_done: bool = False, check=l1_check.check,
             history=diagnostics.operation_history) -> WizardProgress:
    """States: done, todo, unknown (could not be read). The checks step is ready only after the others."""
    try:
        report = check(paths)
        parts = {c['id']: c['status'] for c in report.get('checks', [])}
        protection = report.get('protection')
    except (SafetyError, OSError, ValueError):
        parts = protection = None
    try:
        runs = history(paths)
        cleaned = None if runs.collection == Collected.UNAVAILABLE else any(
            r.status in FINISHED_RUNS for r in runs.rows)
    except (SafetyError, OSError, ValueError):
        cleaned = None

    def state(value: bool | None) -> Progress:
        return Progress.UNKNOWN if value is None else Progress.DONE if value else Progress.TODO
    states = {
        'server': state(bool(server_done)),
        'cleanup': state(cleaned),
        'connection': state(None if parts is None else all(
            parts.get(k) == Check.OK for k in ('backend_task', 'backend_listening', 'connection_profile'))),
        'protection': state(None if protection is None else protection == ProtectionLevel.INSTALLED),
    }
    states['checks'] = Progress.TODO if all(v == Progress.DONE for v in states.values()) else Progress.WAITING
    following = next((k for k in STEPS if states[k] != Progress.DONE), 'checks')
    return WizardProgress(steps=tuple(StepProgress(k, states[k]) for k in STEPS), next=following)
