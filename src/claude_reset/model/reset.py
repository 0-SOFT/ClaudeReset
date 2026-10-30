"""The reset plan: the approved scope, the actions with their fingerprints, blockers and observations."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
import re

from .. import __version__
from ..errors import SafetyError
from ..safeio import guarded

__all__ = ['Action', 'Plan', 'Selection', 'report_versions']


@dataclass
class Selection:
    """Exact approved paths; None means first interactive discovery/preview."""
    profiles: list[str] | None = None
    projects: list[str] = field(default_factory=list)
    privacy: str = 'compatible'

    def validate(self) -> None:
        if self.privacy not in ('compatible', 'strict'):
            raise SafetyError('Unknown privacy mode')
        for value in (self.profiles or []) + self.projects:
            p = Path(value)
            if not p.is_absolute():
                raise SafetyError('Profile and project paths must be absolute')
            guarded(p, p, allow_root=True)


@dataclass
class Action:
    kind: str
    target: str
    root: str
    component: str
    description: str
    before: str


def report_versions(value: object) -> dict:
    # Version resources and extension manifests are client-controlled input.
    # Keep exact values in the local plan for compatibility checks, but never
    # copy arbitrary manifest text or objects into the diagnostic export.
    def version(item: object) -> str | None:
        if item is None:
            return None
        if isinstance(item,str) and re.fullmatch(r'[0-9]{1,5}(?:\.[0-9]{1,5}){2,3}',item):
            return item
        return 'unknown'
    def versions(items: object) -> list[str | None]:
        return [version(item) for item in items] if isinstance(items,list) else ['unknown']
    if not isinstance(value,dict):
        value={}
    return {'cli':version(value.get('cli')),'extension':versions(value.get('extension',[])),
            'desktop':versions(value.get('desktop',[]))}


@dataclass(frozen=True)
class Plan:
    """A reset plan as the planner finished it. It never changes afterwards: a later finding makes a new plan
    (with_blockers), and a saved run restores it with from_json."""
    id: str
    created_utc: str
    components: tuple[str, ...]
    actions: tuple[Action, ...] = ()
    blockers: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    memory_count: int = 0
    memory_risks: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    complete_reset_supported: bool = False
    server_status: str = 'not_verified'
    network_status: str = 'not_verified'
    selection: object = None
    inventory: object = None
    data_size: dict = field(default_factory=lambda: {'files': 0, 'bytes': 0, 'complete': True})

    def __post_init__(self) -> None:
        for name in ('components', 'actions', 'blockers', 'observations'):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @classmethod
    def from_json(cls, obj: dict) -> Plan:
        """The plan a run manifest saved with to_json: its scope, actions, selection and versions."""
        if not isinstance(obj['components'], list) or not isinstance(obj['actions'], list):
            raise ValueError('Plan lists expected')
        return cls(obj['id'], obj['created_utc'], obj['components'], [Action(**a) for a in obj['actions']],
                   selection=Selection(**obj['selection']), versions=obj['versions'])

    def to_json(self) -> dict:
        return {'id': self.id, 'created_utc': self.created_utc, 'components': list(self.components),
                'actions': [asdict(a) for a in self.actions], 'selection': asdict(self.selection),
                'versions': self.versions}

    def with_blockers(self, *blockers: str) -> Plan:
        return replace(self, blockers=self.blockers + blockers)

    def redacted(self) -> dict:
        # No user paths, old identifiers, account names, tokens or stable hashes.
        return {'version': __version__, 'run': self.id, 'created_utc': self.created_utc,
                'components': list(self.components),
                'action_counts': {c: sum(a.component == c for a in self.actions) for c in self.components},
                'blockers': list(self.blockers), 'observations': list(self.observations),
                'memory_count': self.memory_count, 'memory_risks': self.memory_risks,
                'versions': report_versions(self.versions),
                'complete_reset_supported': False, 'server_status': self.server_status,
                'network_status': self.network_status,
                'data_size': self.data_size,
                'inventory': self.inventory.redacted() if self.inventory else {},
                'coverage': {'local_reset': 'planned' if not self.blockers else 'blocked',
                             'authorization': 'not_verified', 'desktop_keys': 'preserved_not_verified',
                             'environment': 'residual_fields_available', 'network': 'not_verified',
                             'ready_for_new_account': False}}
