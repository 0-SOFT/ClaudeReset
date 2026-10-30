"""Read-only discovery. Paths stay local; reports expose categories and counts."""
from __future__ import annotations
from dataclasses import dataclass, field
import os
from pathlib import Path
from ..model import jsonc
from .catalog import AUTH_VARS, AUTH_SETTINGS
from ..safeio import guarded
from ..windows.environment import folded
from .secure_storage import indicators as secure_storage_indicators, BLOCKER as SECURE_STORAGE_BLOCKER
from .. import layout
from ..model.status import Reset
from ..model.notes import Note, unique
from ..model.reset import Selection


@dataclass
class Profile:
    component: str
    path: str
    source: str
    selected: bool = False


@dataclass
class Inventory:
    profiles: list[Profile] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    environments: list[dict] = field(default_factory=list)
    sources: list[dict] = field(default_factory=list)

    def redacted(self):
        return {'profiles': [{'component': p.component, 'source': p.source, 'selected': p.selected}
                             for p in self.profiles], 'environments': self.environments,
                'authentication_sources': self.sources}


class Discovery:
    """Finds the profiles of one discovery, with the blockers, observations and sources found on the way."""

    def __init__(self, paths: layout.Paths, components: list[str], selection: Selection, state: dict,
                 env: dict) -> None:
        selection.validate()
        env=folded(env)
        presence=folded(state.get('environment_presence',{}))
        directory_env=folded(state.get('directory_environment',{}))
        inv = Inventory()
        chosen = (None if selection.profiles is None
                  else {os.path.normcase(os.path.abspath(x)) for x in selection.profiles})
        self.paths, self.components, self.selection, self.state = paths, components, selection, state
        self.env, self.presence, self.directory_env, self.inv, self.chosen = env, presence, directory_env, inv, chosen

    def add(self, component: str, p: Path | str, source: str, default: bool = True,
            absent: bool = False) -> Profile | None:
        inv, components, chosen = self.inv, self.components, self.chosen
        p = Path(os.path.abspath(p))
        guarded(p, p, allow_root=True)
        if not absent and not p.exists():
            return None
        for item in inv.profiles:
            if item.component == component and Path(item.path) == p:
                return item
        selected = component in components and (default if chosen is None else os.path.normcase(str(p)) in chosen)
        inv.profiles.append(Profile(component, str(p), source, selected))
        return inv.profiles[-1]

    def standard(self) -> None:
        """Standard profiles, folders named by environment variables and folders from launch configurations."""
        paths, state, env, directory_env = self.paths, self.state, self.env, self.directory_env
        inv, add = self.inv, self.add
        add('code', layout.code_home(paths), 'standard', absent=True)
        add('vscode', paths.roaming / 'Code/User', 'standard', absent=True)
        add('vscode', paths.roaming / 'Code - Insiders/User', 'insiders')
        for name, component in [('CLAUDE_CONFIG_DIR', 'code'), ('CLAUDE_USER_DATA_DIR', 'desktop'),
                                ('ANTHROPIC_CONFIG_DIR', 'anthropic')]:
            value = env.get(name) or directory_env.get(name)
            if value:
                if not Path(value).is_absolute():
                    inv.blockers.append(Note('plan.custom_directory_relative', name=name))
                    continue
                item = add(component, Path(value), 'environment', default=False, absent=True)
                if not item.selected:
                    inv.blockers.append(Note('plan.custom_directory_unselected', name=name))
        for entry in state.get('custom_roots', []):
            if entry.get('component') in ('code', 'vscode', 'desktop', 'chrome') and entry.get('path'):
                add(entry['component'], Path(entry['path']), 'launch_configuration', default=False)

    def account_manager(self) -> None:
        """Profiles of the 0-code account manager."""
        paths, components, state, inv, add = self.paths, self.components, self.state, self.inv, self.add
        manager = paths.local / '0-code/accounts/profiles'
        if manager.exists():
            for p in guarded(manager, paths.local).iterdir():
                if p.is_dir():
                    add('code', p, 'account_manager', default=False)
        if (paths.local / '0-code/accounts').exists():
            if state.get('account_manager_active') and any(c in components for c in ('code', 'vscode', 'desktop')):
                inv.blockers.append(Note('plan.account_manager'))
            else:
                inv.observations.append(Note('plan.account_manager_profiles'))

    def anthropic(self) -> None:
        """Anthropic profiles outside .claude."""
        paths, components, inv, add = self.paths, self.components, self.inv, self.add
        add('anthropic', paths.roaming / 'Anthropic', 'provider_profiles', default=False)
        if (any(p.component == 'anthropic' for p in inv.profiles)
                and any(c in components for c in ('code', 'vscode', 'desktop'))):
            inv.blockers.append(Note('plan.anthropic_profiles'))

    def desktop(self) -> None:
        """Desktop profiles, including those of the MSIX packages."""
        paths, state, inv, add = self.paths, self.state, self.inv, self.add
        base = guarded(paths.local / layout.DESKTOP_DATA, paths.local)
        if base.exists():
            for p in base.iterdir():
                if p.is_dir():
                    add('desktop', p, 'desktop_data')
        add('desktop', paths.roaming / layout.DESKTOP_ROAMING, 'legacy_desktop')
        add('desktop', paths.local / layout.DESKTOP_3P, 'desktop_console')
        for package in state.get('packages', []):
            family = package.get('PackageFamilyName', '')
            if not family or Path(family).name != family or '/' in family or '\\' in family:
                inv.blockers.append(Note('plan.package_identity_invalid'))
                continue
            for name in (layout.DESKTOP_ROAMING, layout.DESKTOP_3P):
                add('desktop', paths.local / 'Packages' / family / 'LocalCache/Roaming' / name, 'msix')

    def chrome(self) -> None:
        """Existing Chrome profiles and the managed ones."""
        paths, inv, add = self.paths, self.inv, self.add
        chrome_bases = [paths.local / 'Google/Chrome/User Data']
        chrome_bases += [Path(p.path) for p in inv.profiles if p.component == 'chrome']
        for base in chrome_bases:
            if base.exists():
                for p in guarded(base, base, allow_root=True).iterdir():
                    if p.is_dir() and (p / 'Preferences').is_file():
                        add('chrome-existing', p, 'chrome', default=False)
        managed = paths.state / layout.CHROME_PROFILES
        if managed.exists():
            for p in guarded(managed, paths.state).iterdir():
                if p.is_dir() and (p / layout.PROFILE_MARKER).exists():
                    add('chrome-existing', p, 'managed_chrome', default=False)

    def chosen_profiles(self) -> None:
        """Chosen profiles must exist; unchosen ones are noted."""
        components, inv, chosen = self.components, self.inv, self.chosen
        if chosen is not None:
            found = {os.path.normcase(p.path) for p in inv.profiles}
            if chosen - found:
                inv.blockers.append(Note('plan.profile_not_found'))
        for profile in inv.profiles:
            if profile.component in components and not profile.selected:
                inv.observations.append(Note('plan.profile_excluded', component=profile.component))

    def sources(self) -> None:
        """Secure storage, authentication variables and OpenTelemetry."""
        paths, components, env, presence, inv = self.paths, self.components, self.env, self.presence, self.inv
        secure_sources = secure_storage_indicators(paths, inv.profiles, components, env, presence)
        if secure_sources:
            inv.blockers.append(SECURE_STORAGE_BLOCKER)
            inv.sources.extend({'kind': 'secure_storage', 'source': source, 'status': Reset.BLOCKING}
                               for source in secure_sources)
        for name in AUTH_VARS:
            present = bool(env.get(name)) or any(k.endswith(':' + name) and v for k, v in presence.items())
            if present and any(c in components for c in ('code', 'vscode', 'desktop')):
                inv.sources.append({'kind': 'environment', 'name': name, 'status': Reset.BLOCKING})
                inv.blockers.append(Note('plan.auth_source', name=name))
        if (any(k.startswith('OTEL_') and v for k, v in env.items())
                or any(':OTEL_' in k and v for k, v in presence.items())):
            inv.observations.append(Note('plan.opentelemetry'))

    def projects(self) -> None:
        """Settings and instructions of the chosen projects."""
        selection, inv = self.selection, self.inv
        # Project roots are explicitly chosen, never a keyword walk across the disk.
        for project in selection.projects:
            root = Path(project)
            if not root.is_dir():
                inv.blockers.append(Note('plan.project_unavailable'))
                continue
            for filename in ('.claude/settings.json', '.claude/settings.local.json', '.mcp.json'):
                p = root / filename
                obj = jsonc.read(p, root)
                project_env=folded(obj.get('env',{}))
                if obj and (filename == '.mcp.json' or AUTH_SETTINGS.intersection(obj) or obj.get('hooks')
                            or obj.get('mcpServers')
                            or any(k in AUTH_VARS or k.endswith('_CONFIG_DIR') for k in project_env)):
                    inv.sources.append({'kind': 'project_settings', 'status': Reset.BLOCKING})
                    inv.blockers.append(Note('plan.project_auth'))
            for filename in ('CLAUDE.md', '.claude/CLAUDE.md', '.claude/rules'):
                if guarded(root / filename, root).exists():
                    inv.observations.append(Note('plan.project_instructions'))

    def system(self) -> None:
        """Organization settings, restore sources and remote environments."""
        state, inv = self.state, self.inv
        for item in state.get('managed_settings', []):
            p = Path(item)
            obj = jsonc.read(p, p.parent)
            if obj:
                inv.blockers.append(Note('plan.organization_settings'))
        if state.get('restore_sources'):
            inv.blockers.append(Note('plan.restore_sources'))
        if state.get('task_inspection') == 'unavailable':
            inv.blockers.append(Note('plan.tasks_uninspected'))
        for kind in state.get('remote_environments', []):
            if kind in ('wsl', 'docker', 'ssh', 'devcontainer', 'cowork_vm'):
                inv.environments.append({'kind': kind, 'status': Reset.NOT_COVERED})

    def finish(self) -> Inventory:
        selection, inv = self.selection, self.inv
        if not selection.projects:
            inv.observations.append(Note('plan.project_settings_uninventoried'))
        inv.blockers = unique(inv.blockers)
        inv.observations = unique(inv.observations)
        return inv

    def run(self) -> Inventory:
        self.standard()
        self.account_manager()
        self.anthropic()
        self.desktop()
        self.chrome()
        self.chosen_profiles()
        self.sources()
        self.projects()
        self.system()
        return self.finish()


def discover(paths, components, selection: Selection, state, env):
    return Discovery(paths, components, selection, state, env).run()
