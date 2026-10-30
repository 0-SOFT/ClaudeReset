from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from .core import snapshot_memory, db_keys, owned_vscode_key, vscode_databases
from ..model import jsonc
from ..network import l1_settings
from .catalog import (CLI_VERSIONS, EXTENSION_VERSIONS, DESKTOP_VERSIONS,
                       CODE_ENTRIES, DESKTOP_STATE, DESKTOP_PRESERVE, DESKTOP_WORK, code_recovery_file,
                       DESKTOP_JOURNAL_VERSIONS, DESKTOP_JOURNAL_STATE, DESKTOP_DEVELOPER_PRESERVE)
from .discovery import Inventory, discover
from ..errors import SafetyError
from ..safeio import guarded, fingerprint, walk_files
from ..windows.system import inspect_windows
from .. import config
from .. import layout
from ..model import clients
from ..model.status import Reset
from ..model.notes import Note, unique
from ..model.reset import Action, Plan, Selection
from ..model.ids import new_id, utc_now

COMPONENTS = ('code', 'vscode', 'chrome', 'desktop')


@dataclass
class PlanDraft:
    """The plan while the planner fills it in; freeze() hands out the finished, unchangeable Plan."""
    id: str
    created_utc: str
    components: list[str]
    actions: list[Action] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    memory_count: int = 0
    memory_risks: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    selection: Selection | None = None
    inventory: Inventory | None = None
    data_size: dict = field(default_factory=lambda: {'files': 0, 'bytes': 0, 'complete': True})

    def freeze(self) -> Plan:
        return Plan(self.id, self.created_utc, self.components, self.actions, self.blockers, self.observations,
                    memory_count=self.memory_count, memory_risks=self.memory_risks, versions=self.versions,
                    selection=self.selection, inventory=self.inventory, data_size=self.data_size)


def action_fingerprint(path, root, kind):
    value = fingerprint(path, root)
    if kind == 'vscode_db':
        # A new WAL or rollback journal invalidates a reviewed plan, too.
        value += ''.join(':' + fingerprint(Path(str(path) + suffix), root)
                         for suffix in ('-wal', '-shm', '-journal'))
    return value


class Planner:
    """Builds the actions of one reset plan, with every blocker and observation found on the way."""

    def __init__(self, paths: layout.Paths, plan: PlanDraft, state: dict, inventory: Inventory) -> None:
        self.paths, self.plan, self.state, self.inv = paths, plan, state, inventory

    def add(self, kind: str, target: Path | str, root: Path | str, component: str, description: Note) -> None:
        """One action, fingerprinted now; on a blocked plan it is listed but never hashed."""
        plan, paths = self.plan, self.paths
        target, root = Path(target), Path(root)
        try:
            guarded(target, root)
            if paths.state == target or paths.state.is_relative_to(target) or target.is_relative_to(paths.state):
                if kind != 'chrome_fresh':
                    raise SafetyError('Reset target overlaps application state')
            if plan.blockers:
                # A blocked preview cannot be applied. Avoid recursively hashing
                # live/unknown storage; a fresh unblocked plan is required later.
                plan.actions.append(Action(kind, str(target), str(root), component, description, 'blocked'))
                plan.data_size['complete'] = False
                return
            before = action_fingerprint(target, root, kind)
            files = list(walk_files(target, root))
            plan.actions.append(Action(kind, str(target), str(root), component, description, before))
            plan.data_size['files'] += len(files)
            plan.data_size['bytes'] += sum(p.stat().st_size for p in files)
        except (SafetyError, OSError):
            plan.blockers.append(Note('plan.target_uninventoried'))

    def code(self, target: Path) -> None:
        """A Claude Code profile: its data and memory, the adjacent configuration and the settings to drop."""
        plan, paths, state, add = self.plan, self.paths, self.state, self.add
        unknown = []
        adjacent_state = (target == layout.code_home(paths)
                          and any(p.name.startswith(layout.CODE_CONFIG) for p in paths.home.iterdir()))
        cli_version, ext_versions = state.get('cli_version'), state.get('extension_versions', [])
        # Without a standalone CLI the state in ~/.claude is written by the extension's bundled Claude Code,
        # whose version is the extension's; the profile-entry check below still applies.
        cli_known = cli_version in CLI_VERSIONS or (cli_version is None and bool(ext_versions)
                                                    and all(v in EXTENSION_VERSIONS for v in ext_versions))
        if (target.exists() or adjacent_state) and not cli_known:
            plan.blockers.append(Note('plan.code_version_unverified'))
        if target in (paths.home, paths.local, paths.roaming,
                      paths.state) or any(p.is_relative_to(target) for p in (paths.home, paths.local, paths.roaming)):
            raise SafetyError('Custom configuration directory overlaps shared data')
        if target.exists():
            unknown = [p for p in target.iterdir() if p.name not in CODE_ENTRIES and
                       not re.fullmatch(r'\.claude\.json\.(?:backup|bak)(?:\.[0-9-]+)?', p.name)]
            if unknown:
                plan.blockers.append(Note('plan.code_unknown_entries'))
        bundle, risks = snapshot_memory(target)
        plan.memory_count += len(bundle['files'])
        for k, v in risks.items():
            plan.memory_risks[k] = plan.memory_risks.get(k, 0) + v
        if not unknown:
            add('reset_code', target, target.parent, 'code', Note('action.reset_code'))
        # The standard adjacent file is version-proven; custom roots use
        # their own .claude.json, not a guessed sibling in a shared folder.
        if target == layout.code_home(paths):
            for p in paths.home.iterdir():
                if code_recovery_file(p.name):
                    add('delete', p, paths.home, 'code', Note('action.remove_code_config'))
        obj = jsonc.read(target / layout.CODE_SETTINGS, target)
        if obj.get('apiKeyHelper'):
            plan.observations.append(Note('plan.api_key_helper_dropped'))
        if obj.get('hooks'):
            plan.observations.append(Note('plan.hooks_dropped'))

    def vscode(self, target: Path) -> None:
        """A VS Code user folder: the extension's database record, storage, launch settings and telemetry."""
        plan, state, add = self.plan, self.state, self.add
        versions = state.get('extension_versions', [])
        if target.exists() and (not versions or any(v not in EXTENSION_VERSIONS for v in versions)):
            plan.blockers.append(Note('plan.extension_version_unverified'))
        for database in vscode_databases(target):
            keys = db_keys(database, target)
            if any('secret' in k.lower() and ('claude' in k.lower() or 'anthropic' in k.lower()) for k in keys):
                plan.blockers.append(Note('plan.secret_storage_entry'))
            if any(owned_vscode_key(k) for k in keys):
                add('vscode_db', database, target, 'vscode', Note('action.remove_extension_record'))
        profiles = [target]
        named = guarded(target / 'profiles', target)
        if named.exists():
            profiles.extend(p for p in named.iterdir() if p.is_dir())
        for editor in profiles:
            owned = editor / 'globalStorage/anthropic.claude-code'
            if owned.exists():
                add('delete', owned, target, 'vscode', Note('action.remove_extension_storage'))
            settings = editor / layout.EDITOR_SETTINGS
            obj = jsonc.read(settings, target)
            if obj.get(config.VSCODE_ENVIRONMENT) or obj.get(config.VSCODE_WRAPPER):
                if l1_settings.owned_launch_settings(obj):
                    plan.observations.append(Note('plan.l1_launch_settings_kept'))
                else:
                    plan.blockers.append(Note('plan.custom_launch_settings'))
            if obj.get('telemetry.telemetryLevel') != 'off':
                add('vscode_privacy', settings, target, 'vscode', Note('action.vscode_telemetry_off'))

    def desktop(self, target: Path) -> None:
        """A Desktop profile: version-verified state is reset; work and unknown entries block the plan."""
        plan, inv, add = self.plan, self.inv, self.add
        versions = plan.versions['desktop']
        if not versions or any(v not in DESKTOP_VERSIONS for v in versions):
            plan.blockers.append(Note('plan.desktop_version_unverified'))
        state_entries, preserved_entries = DESKTOP_STATE, DESKTOP_PRESERVE
        if versions and all(v in DESKTOP_JOURNAL_VERSIONS for v in versions):
            state_entries = state_entries | DESKTOP_JOURNAL_STATE
            preserved_entries = preserved_entries | DESKTOP_DEVELOPER_PRESERVE
        if target.exists():
            for child in target.iterdir():
                if (child.name == '.user-data-left.claude_pzs8sxrjxfjjc' and child.is_file()
                        and child.stat().st_size == 0):
                    continue  # Empty migration marker, never authentication state.
                if child.name in state_entries:
                    add('delete', child, target, 'desktop', Note('action.reset_desktop'))
                elif child.name in DESKTOP_WORK and any(walk_files(child, target)):
                    plan.blockers.append(Note('plan.desktop_work_export'))
                elif child.name not in preserved_entries:
                    plan.blockers.append(Note('plan.desktop_schema_unknown'))
            if any(p.name == 'sessiondata.vhdx' for p in walk_files(target / 'vm_bundles', target)):
                inv.environments.append({'kind': 'cowork_vm', 'status': Reset.NOT_COVERED})
        plan.observations.append(Note('plan.native_keys_kept'))

    COMPONENTS = {'code': code, 'vscode': vscode, 'desktop': desktop}

    def profiles(self) -> None:
        for profile in self.inv.profiles:
            if not profile.selected:
                continue
            target = Path(profile.path)
            component = self.COMPONENTS.get(profile.component)
            try:
                if component is not None:
                    component(self, target)
            except (SafetyError, OSError, ValueError, TypeError) as exc:
                self.plan.blockers.append(str(exc) if isinstance(exc,
                                                                 SafetyError) else Note('plan.profile_unprocessable'))

    def overlaps(self, components: list[str]) -> None:
        """A selected Desktop must have a profile; reset roots and action targets must not nest."""
        plan, inv = self.plan, self.inv
        if 'desktop' in components and not any(p.selected and p.component == 'desktop' for p in inv.profiles):
            plan.blockers.append(Note('plan.desktop_profile_missing'))
        # Reject nested reset roots, which otherwise undermine archive and freshness checks.
        resets = [Path(a.target) for a in plan.actions if a.kind == 'reset_code']
        if any(a != b and (a.is_relative_to(b) or b.is_relative_to(a)) for a in resets for b in resets):
            plan.blockers.append(Note('plan.profiles_overlap'))
        targets = [Path(a.target) for a in plan.actions]
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
               for i, a in enumerate(targets) for b in targets[i + 1:]):
            plan.blockers.append(Note('plan.profiles_overlap'))

    def finish(self, components: list[str], selection: Selection) -> None:
        """The fresh Chrome profile and the observations every plan carries."""
        plan, paths, add = self.plan, self.paths, self.add
        if 'chrome' in components:
            add('chrome_fresh', paths.state / layout.CHROME_PROFILES / plan.id, paths.state, 'chrome',
                Note('action.chrome_fresh'))
            plan.observations.append(Note('plan.old_chrome_profiles'))
            plan.observations.append(Note('plan.managed_chrome'))
        plan.observations.extend([
            Note('plan.server_steps_separate'),
            Note('plan.network_external'),
            Note('plan.memory_verbatim'),
            Note('plan.other_environments'),
            Note('plan.client_analytics'),
        ])
        if selection.privacy == 'compatible':
            plan.observations.append(Note('plan.telemetry_compatible'))
        else:
            plan.observations.append(Note('plan.telemetry_strict'))
        plan.blockers = unique(plan.blockers)
        plan.observations = unique(plan.observations)


def build_plan(paths, components=('code', 'vscode', 'chrome'), *, platform_state=None,
               env=None, selection=None):
    paths.validate()
    components = list(components)
    selection = selection or Selection()
    env = dict(os.environ if env is None else env)
    state = inspect_windows() if platform_state is None else platform_state
    plan = PlanDraft(new_id(), utc_now(), components)
    plan.selection = selection
    plan.versions = {'cli': state.get('cli_version'), 'extension': state.get('extension_versions', []),
                     'desktop': state.get('desktop_versions',
                                          []) or [p.get('Version') for p in state.get('packages', [])]}
    if not components or len(set(components)) != len(components) or any(c not in COMPONENTS for c in components):
        plan.blockers.append(Note('plan.components_invalid'))
        return plan.freeze()
    try:
        inv = discover(paths, components, selection, state, env)
    except (OSError, SafetyError, ValueError, TypeError):
        plan.blockers.append(Note('plan.discovery_failed'))
        return plan.freeze()
    plan.inventory = inv
    plan.blockers.extend(inv.blockers)
    plan.observations.extend(inv.observations)
    for process in state.get('processes', []):
        kind = process.get('kind', '')
        # Never require closing unrelated node.exe or all WSL distributions.
        if clients.blocking(kind, components):
            plan.blockers.append(Note('plan.processes_open', kind=kind))
    planner = Planner(paths, plan, state, inv)
    planner.profiles()
    planner.overlaps(components)
    planner.finish(components, selection)
    return plan.freeze()
