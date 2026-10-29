from __future__ import annotations
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from .core import (Plan, Action, snapshot_memory, db_keys, owned_vscode_key,
                   vscode_databases, new_id)
from . import jsonc, l1_settings
from .catalog import (CLI_VERSIONS, EXTENSION_VERSIONS, DESKTOP_VERSIONS,
                       CODE_ENTRIES, DESKTOP_STATE, DESKTOP_PRESERVE, DESKTOP_WORK, code_recovery_file,
                       DESKTOP_JOURNAL_VERSIONS, DESKTOP_JOURNAL_STATE, DESKTOP_DEVELOPER_PRESERVE)
from .discovery import Selection, discover
from .safeio import SafetyError, guarded, fingerprint, walk_files
from .windows import inspect_windows

COMPONENTS = ('code', 'vscode', 'chrome', 'desktop')


def action_fingerprint(path, root, kind):
    value = fingerprint(path, root)
    if kind == 'vscode_db':
        # A new WAL or rollback journal invalidates a reviewed plan, too.
        value += ''.join(':' + fingerprint(Path(str(path) + suffix), root)
                         for suffix in ('-wal', '-shm', '-journal'))
    return value


def build_plan(paths, components=('code', 'vscode', 'chrome'), *, platform_state=None,
               env=None, selection=None):
    paths.validate()
    components = list(components)
    selection = selection or Selection()
    env = dict(os.environ if env is None else env)
    state = inspect_windows() if platform_state is None else platform_state
    plan = Plan(new_id(), datetime.now(timezone.utc).isoformat(), components)
    plan.selection = selection
    plan.versions = {'cli': state.get('cli_version'), 'extension': state.get('extension_versions', []),
                     'desktop': state.get('desktop_versions', []) or [p.get('Version') for p in state.get('packages', [])]}
    if not components or len(set(components)) != len(components) or any(c not in COMPONENTS for c in components):
        plan.blockers.append('Select supported, unique components')
        return plan
    try:
        inv = discover(paths, components, selection, state, env)
    except (OSError, SafetyError, ValueError, TypeError):
        plan.blockers.append('Profile discovery failed; no safe plan can be built')
        return plan
    plan.inventory = inv
    plan.blockers.extend(inv.blockers)
    plan.observations.extend(inv.observations)
    for process in state.get('processes', []):
        kind = process.get('kind', '')
        # Never require closing unrelated node.exe or all WSL distributions.
        relevant = ((kind in ('Claude.exe', 'claude-desktop.exe', 'cowork-svc.exe') and 'desktop' in components) or
                    (kind in ('Code.exe', 'Code - Insiders.exe') and 'vscode' in components) or
                    kind in ('claude.exe', 'claude-child') or
                    (kind == 'chrome-managed' and 'chrome' in components))
        if relevant:
            plan.blockers.append('Close related processes before applying: ' + kind)

    def add(kind, target, root, component, description):
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
            plan.blockers.append('Target cannot be safely inventoried; no deletion is permitted')

    for profile in inv.profiles:
        if not profile.selected:
            continue
        target = Path(profile.path)
        try:
            if profile.component == 'code':
                unknown = []
                adjacent_state = target == paths.home / '.claude' and any(p.name.startswith('.claude.json') for p in paths.home.iterdir())
                cli_version, ext_versions = state.get('cli_version'), state.get('extension_versions', [])
                # Without a standalone CLI the state in ~/.claude is written by the extension's bundled Claude Code,
                # whose version is the extension's; the profile-entry check below still applies.
                cli_known = cli_version in CLI_VERSIONS or (cli_version is None and bool(ext_versions)
                                                            and all(v in EXTENSION_VERSIONS for v in ext_versions))
                if (target.exists() or adjacent_state) and not cli_known:
                    plan.blockers.append('Claude Code version is unknown or has not been validated for this adapter')
                if target in (paths.home, paths.local, paths.roaming, paths.state) or any(p.is_relative_to(target) for p in (paths.home, paths.local, paths.roaming)):
                    raise SafetyError('Custom configuration directory overlaps shared data')
                if target.exists():
                    unknown = [p for p in target.iterdir() if p.name not in CODE_ENTRIES and
                               not re.fullmatch(r'\.claude\.json\.(?:backup|bak)(?:\.[0-9-]+)?', p.name)]
                    if unknown:
                        plan.blockers.append('Unknown entries in Claude Code profile; user work must be reviewed before reset')
                bundle, risks = snapshot_memory(target)
                plan.memory_count += len(bundle['files'])
                for k, v in risks.items():
                    plan.memory_risks[k] = plan.memory_risks.get(k, 0) + v
                if not unknown:
                    add('reset_code', target, target.parent, 'code', 'Reset Claude Code data, preserving memory in an encrypted archive')
                # The standard adjacent file is version-proven; custom roots use
                # their own .claude.json, not a guessed sibling in a shared folder.
                if target == paths.home / '.claude':
                    for p in paths.home.iterdir():
                        if code_recovery_file(p.name):
                            add('delete', p, paths.home, 'code', 'Remove active/recovery Claude Code configuration')
                obj = jsonc.read(target / 'settings.json', target)
                if obj.get('apiKeyHelper'):
                    plan.observations.append('apiKeyHelper in the reset profile will not be carried forward')
                if obj.get('hooks'):
                    plan.observations.append('Existing hooks will not be carried forward')
            elif profile.component == 'vscode':
                versions = state.get('extension_versions', [])
                if target.exists() and (not versions or any(v not in EXTENSION_VERSIONS for v in versions)):
                    plan.blockers.append('Claude extension version is unknown or has not been validated for this adapter')
                for database in vscode_databases(target):
                    keys = db_keys(database, target)
                    if any('secret' in k.lower() and ('claude' in k.lower() or 'anthropic' in k.lower()) for k in keys):
                        plan.blockers.append('Claude SecretStorage entry requires a version-specific adapter')
                    if any(owned_vscode_key(k) for k in keys):
                        add('vscode_db', database, target, 'vscode', 'Remove only the Claude extension record from the shared database')
                profiles = [target]
                named = guarded(target / 'profiles', target)
                if named.exists():
                    profiles.extend(p for p in named.iterdir() if p.is_dir())
                for editor in profiles:
                    owned = editor / 'globalStorage/anthropic.claude-code'
                    if owned.exists():
                        add('delete', owned, target, 'vscode', 'Remove Claude extension-owned storage')
                    settings = editor / 'settings.json'
                    obj = jsonc.read(settings, target)
                    if obj.get('claudeCode.environmentVariables') or obj.get('claudeCode.claudeProcessWrapper'):
                        if l1_settings.owned_launch_settings(obj):
                            plan.observations.append('ClaudeReset L1 launch settings are present and are kept')
                        else:
                            plan.blockers.append('Custom VS Code Claude launch settings require review')
                    if obj.get('telemetry.telemetryLevel') != 'off':
                        add('vscode_privacy', settings, target, 'vscode', 'Set VS Code telemetry.telemetryLevel to off; this affects the editor')
            elif profile.component == 'desktop':
                versions = plan.versions['desktop']
                if not versions or any(v not in DESKTOP_VERSIONS for v in versions):
                    plan.blockers.append('Desktop version is unknown or has not been validated for this adapter')
                state_entries, preserved_entries = DESKTOP_STATE, DESKTOP_PRESERVE
                if versions and all(v in DESKTOP_JOURNAL_VERSIONS for v in versions):
                    state_entries = state_entries | DESKTOP_JOURNAL_STATE
                    preserved_entries = preserved_entries | DESKTOP_DEVELOPER_PRESERVE
                if target.exists():
                    for child in target.iterdir():
                        if child.name == '.user-data-left.claude_pzs8sxrjxfjjc' and child.is_file() and child.stat().st_size == 0:
                            continue  # Empty migration marker, never authentication state.
                        if child.name in state_entries:
                            add('delete', child, target, 'desktop', 'Reset version-verified Desktop state; registration keys are preserved')
                        elif child.name in DESKTOP_WORK and any(walk_files(child, target)):
                            plan.blockers.append('Desktop or Cowork work requires memory extraction and work export before reset')
                        elif child.name not in preserved_entries:
                            plan.blockers.append('Unknown Desktop data schema; no broad profile deletion is allowed')
                    if any(p.name == 'sessiondata.vhdx' for p in walk_files(target / 'vm_bundles', target)):
                        inv.environments.append({'kind': 'cowork_vm', 'status': 'not_covered'})
                plan.observations.append('This file reset preserves native keys; use the separate MSIX key plan for deletion')
        except (SafetyError, OSError, ValueError, TypeError) as exc:
            plan.blockers.append(str(exc) if isinstance(exc, SafetyError) else 'Selected profile schema or path cannot be processed safely')

    if 'desktop' in components and not any(p.selected and p.component == 'desktop' for p in inv.profiles):
        plan.blockers.append('No selected Desktop profile was discovered')
    # Reject nested reset roots, which otherwise undermine archive and freshness checks.
    resets = [Path(a.target) for a in plan.actions if a.kind == 'reset_code']
    if any(a != b and (a.is_relative_to(b) or b.is_relative_to(a)) for a in resets for b in resets):
        plan.blockers.append('Selected reset profiles overlap')
    targets = [Path(a.target) for a in plan.actions]
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for i, a in enumerate(targets) for b in targets[i + 1:]):
        plan.blockers.append('Selected reset profiles overlap')
    if 'chrome' in components:
        add('chrome_fresh', paths.state / 'ChromeProfiles' / plan.id, paths.state, 'chrome',
            'Create a new isolated Chrome user-data directory; do not delete existing Chrome profiles')
        plan.observations.append('Old Chrome profiles remain; OAuth and browser bridges must use the new profile explicitly')
        plan.observations.append('Managed Chrome launches disable Chrome Sync; geolocation starts blocked in this dedicated profile')
    plan.observations.extend([
        'Server logout and Claude Code token revocation must be completed separately; not verified by this program',
        'Network configuration is external; no VPN, router or firewall changes are performed',
        'Memory is preserved verbatim; it may retain previous identity or geographic information',
        'WSL, remote hosts, containers, project-local overrides and cloud memory need separate verification',
        'Desktop and website analytics, environment fields and geolocation require client-specific verification',
    ])
    if selection.privacy == 'compatible':
        plan.observations.append('Global telemetry opt-out for CLI is not forced because maximum feature compatibility was requested')
    else:
        plan.observations.append('Strict CLI telemetry opt-out can reduce Remote Control functionality')
    plan.blockers = list(dict.fromkeys(plan.blockers))
    plan.observations = list(dict.fromkeys(plan.observations))
    return plan
