"""Read-only discovery. Paths stay local; reports expose categories and counts."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import os
from pathlib import Path
from . import jsonc
from .catalog import AUTH_VARS, AUTH_SETTINGS
from .safeio import SafetyError, guarded, walk_files
from .windows_environment import folded
from .secure_storage import indicators as secure_storage_indicators, BLOCKER as SECURE_STORAGE_BLOCKER


@dataclass
class Profile:
    component: str
    path: str
    source: str
    selected: bool = False


@dataclass
class Selection:
    """Exact approved paths; None means first interactive discovery/preview."""
    profiles: list[str] | None = None
    projects: list[str] = field(default_factory=list)
    privacy: str = 'compatible'

    def validate(self):
        if self.privacy not in ('compatible', 'strict'):
            raise SafetyError('Unknown privacy mode')
        for value in (self.profiles or []) + self.projects:
            p = Path(value)
            if not p.is_absolute():
                raise SafetyError('Profile and project paths must be absolute')
            guarded(p, p, allow_root=True)


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


def discover(paths, components, selection: Selection, state, env):
    selection.validate()
    env=folded(env)
    presence=folded(state.get('environment_presence',{}))
    directory_env=folded(state.get('directory_environment',{}))
    inv = Inventory()
    chosen = None if selection.profiles is None else {os.path.normcase(os.path.abspath(x)) for x in selection.profiles}

    def add(component, p, source, default=True, absent=False):
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

    add('code', paths.home / '.claude', 'standard', absent=True)
    add('vscode', paths.roaming / 'Code/User', 'standard', absent=True)
    add('vscode', paths.roaming / 'Code - Insiders/User', 'insiders')
    for name, component in [('CLAUDE_CONFIG_DIR', 'code'), ('CLAUDE_USER_DATA_DIR', 'desktop'),
                            ('ANTHROPIC_CONFIG_DIR', 'anthropic')]:
        value = env.get(name) or directory_env.get(name)
        if value:
            if not Path(value).is_absolute():
                inv.blockers.append('Relative custom data directory cannot be resolved safely: ' + name)
                continue
            item = add(component, Path(value), 'environment', default=False, absent=True)
            if not item.selected:
                inv.blockers.append('Custom data directory requires explicit profile selection: ' + name)
    for entry in state.get('custom_roots', []):
        if entry.get('component') in ('code', 'vscode', 'desktop', 'chrome') and entry.get('path'):
            add(entry['component'], Path(entry['path']), 'launch_configuration', default=False)
    manager = paths.local / '0-code/accounts/profiles'
    if manager.exists():
        for p in guarded(manager, paths.local).iterdir():
            if p.is_dir():
                add('code', p, 'account_manager', default=False)
    if (paths.local / '0-code/accounts').exists():
        if state.get('account_manager_active') and any(c in components for c in ('code', 'vscode', 'desktop')):
            inv.blockers.append('Account manager 0-code may restore previous credentials')
        else:
            inv.observations.append('Stored account-manager profiles remain excluded; their presence alone does not prove active restoration')
    add('anthropic', paths.roaming / 'Anthropic', 'provider_profiles', default=False)
    if any(p.component == 'anthropic' for p in inv.profiles) and any(c in components for c in ('code', 'vscode', 'desktop')):
        inv.blockers.append('Anthropic profiles outside .claude require review')
    base = guarded(paths.local / 'Claude-Data', paths.local)
    if base.exists():
        for p in base.iterdir():
            if p.is_dir():
                add('desktop', p, 'desktop_data')
    add('desktop', paths.roaming / 'Claude', 'legacy_desktop')
    add('desktop', paths.local / 'Claude-3p', 'desktop_console')
    for package in state.get('packages', []):
        family = package.get('PackageFamilyName', '')
        if not family or Path(family).name != family or '/' in family or '\\' in family:
            inv.blockers.append('Invalid MSIX package identity')
            continue
        for name in ('Claude', 'Claude-3p'):
            add('desktop', paths.local / 'Packages' / family / 'LocalCache/Roaming' / name, 'msix')
    chrome_bases = [paths.local / 'Google/Chrome/User Data']
    chrome_bases += [Path(p.path) for p in inv.profiles if p.component == 'chrome']
    for base in chrome_bases:
        if base.exists():
            for p in guarded(base, base, allow_root=True).iterdir():
                if p.is_dir() and (p / 'Preferences').is_file():
                    add('chrome-existing', p, 'chrome', default=False)
    managed = paths.state / 'ChromeProfiles'
    if managed.exists():
        for p in guarded(managed, paths.state).iterdir():
            if p.is_dir() and (p / 'claude-reset-profile.json').exists():
                add('chrome-existing', p, 'managed_chrome', default=False)
    if chosen is not None:
        found = {os.path.normcase(p.path) for p in inv.profiles}
        if chosen - found:
            inv.blockers.append('Selected profile was not discovered; review scope')
    for profile in inv.profiles:
        if profile.component in components and not profile.selected:
            inv.observations.append('Excluded profile remains outside reset scope: ' + profile.component)

    secure_sources = secure_storage_indicators(paths, inv.profiles, components, env, presence)
    if secure_sources:
        inv.blockers.append(SECURE_STORAGE_BLOCKER)
        inv.sources.extend({'kind': 'secure_storage', 'source': source, 'status': 'blocking'}
                           for source in secure_sources)
    for name in AUTH_VARS:
        present = bool(env.get(name)) or any(k.endswith(':' + name) and v for k, v in presence.items())
        if present and any(c in components for c in ('code', 'vscode', 'desktop')):
            inv.sources.append({'kind': 'environment', 'name': name, 'status': 'blocking'})
            inv.blockers.append('Alternative authentication source must be reviewed: ' + name)
    if any(k.startswith('OTEL_') and v for k, v in env.items()) or any(':OTEL_' in k and v for k, v in presence.items()):
        inv.observations.append('OpenTelemetry exporter configuration is present; CLI opt-out does not certify this channel')

    # Project roots are explicitly chosen, never a keyword walk across the disk.
    for project in selection.projects:
        root = Path(project)
        if not root.is_dir():
            inv.blockers.append('Selected project directory is unavailable')
            continue
        for filename in ('.claude/settings.json', '.claude/settings.local.json', '.mcp.json'):
            p = root / filename
            obj = jsonc.read(p, root)
            project_env=folded(obj.get('env',{}))
            if obj and (filename == '.mcp.json' or AUTH_SETTINGS.intersection(obj) or obj.get('hooks') or
                        obj.get('mcpServers') or any(k in AUTH_VARS or k.endswith('_CONFIG_DIR') for k in project_env)):
                inv.sources.append({'kind': 'project_settings', 'status': 'blocking'})
                inv.blockers.append('Project authentication, hooks or connectors require review; project files are preserved')
        for filename in ('CLAUDE.md', '.claude/CLAUDE.md', '.claude/rules'):
            if guarded(root / filename, root).exists():
                inv.observations.append('Project instructions remain accessible and can contain previous identity or geography')
    for item in state.get('managed_settings', []):
        p = Path(item)
        obj = jsonc.read(p, p.parent)
        if obj:
            inv.blockers.append('Organizational Claude settings require review; policies are not overwritten')
    if state.get('restore_sources'):
        inv.blockers.append('Active startup, task or wrapper may restore Claude state; disable or review it before reset')
    if state.get('task_inspection') == 'unavailable':
        inv.blockers.append('Scheduled task inspection was unavailable; restoration sources are not fully inventoried')
    for kind in state.get('remote_environments', []):
        if kind in ('wsl', 'docker', 'ssh', 'devcontainer', 'cowork_vm'):
            inv.environments.append({'kind': kind, 'status': 'not_covered'})
    if not selection.projects:
        inv.observations.append('Project-local settings were not inventoried; readiness does not extend to arbitrary projects')
    inv.blockers = list(dict.fromkeys(inv.blockers))
    inv.observations = list(dict.fromkeys(inv.observations))
    return inv
