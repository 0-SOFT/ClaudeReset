"""Journaled execution with preflight, encrypted memory and conservative recovery."""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
from .core import Plan, Action, snapshot_memory, validate_memory_bundle, restore_memory, reset_vscode_db, _report_versions
from .discovery import Selection
from .planner import build_plan, action_fingerprint
from . import jsonc
from .safeio import SafetyError, guarded, remove_owned, atomic_json, atomic_bytes, walk_files
from .windows import DPAPI, inspect_windows, inspect_runtime


@contextmanager
def operation_lock(paths):
    guarded(paths.state, paths.state, allow_root=True).mkdir(parents=True, exist_ok=True)
    lock = guarded(paths.state / 'operation.lock', paths.state)
    with lock.open('a+b') as stream:
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SafetyError('Another reset or recovery operation is running') from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def _new_report(plan):
    return {'run': plan.id, 'status': 'started', 'completed': [], 'full_reset': False,
            'server': 'user_reported_complete_not_independently_verified', 'network': 'not_verified',
            'memory': 'not_processed', 'ready_for_new_account': False,
            'components': plan.components, 'versions': _report_versions(plan.versions)}


def serialize_plan(plan):
    return {'id': plan.id, 'created_utc': plan.created_utc, 'components': plan.components,
            'actions': [asdict(a) for a in plan.actions], 'selection': asdict(plan.selection),
            'versions': plan.versions}


def deserialize_plan(obj):
    try:
        plan = Plan(obj['id'], obj['created_utc'], obj['components'])
        plan.actions = [Action(**a) for a in obj['actions']]
        plan.selection = Selection(**obj['selection'])
        plan.versions = obj['versions']
        return plan
    except (KeyError, TypeError, ValueError):
        raise SafetyError('Invalid encrypted run manifest') from None


def archive_profiles(bundle):
    if bundle.get('schema') == 1:
        validate_memory_bundle(bundle)
        return [bundle]
    if bundle.get('schema') != 2 or not isinstance(bundle.get('profiles'), list):
        raise SafetyError('Invalid memory archive schema')
    total = 0
    for profile in bundle['profiles']:
        total += sum(len(data) for _, data in validate_memory_bundle(profile))
        if total > 64 * 1024 * 1024:
            raise SafetyError('Memory archive size limit exceeded')
    return bundle['profiles']


class Executor:
    def __init__(self, paths, crypto=None, inspect=inspect_windows):
        self.paths, self.crypto, self.inspect = paths, crypto or DPAPI(), inspect

    def _write_private(self, path, value):
        atomic_bytes(path, self.crypto.encrypt(json.dumps(value, ensure_ascii=False).encode('utf-8')), self.paths.state)
        if self._read_private(path) != value:
            raise SafetyError('Encrypted journal round-trip failed')

    def _read_private(self, path):
        guarded(path, self.paths.state)
        if path.stat().st_size > 150_000_000:
            raise SafetyError('Encrypted archive size limit exceeded')
        return json.loads(self.crypto.decrypt(path.read_bytes()))

    def _preflight(self, plan):
        if not re.fullmatch(r'[a-f0-9]{32}', plan.id):
            raise SafetyError('Invalid plan ID')
        if plan.blockers:
            raise SafetyError('Plan has unresolved blockers; nothing changed')
        current = build_plan(self.paths, plan.components, platform_state=self.inspect(), selection=plan.selection)
        if current.blockers:
            raise SafetyError('New blockers detected; nothing changed')
        key = lambda a: (a.kind, a.target, a.root, a.component)
        actual = [key(a) for a in current.actions if a.kind != 'chrome_fresh']
        original = [key(a) for a in plan.actions if a.kind != 'chrome_fresh']
        if actual != original or current.versions != plan.versions:
            raise SafetyError('Inventory changed; review a new plan')
        if sum(a.kind == 'chrome_fresh' for a in plan.actions) != int('chrome' in plan.components):
            raise SafetyError('Invalid Chrome action count')
        for action in plan.actions:
            if action.kind == 'chrome_fresh' and (Path(action.target) != self.paths.state / 'ChromeProfiles' / plan.id or
                    Path(action.root) != self.paths.state or action.component != 'chrome'):
                raise SafetyError('Chrome target was modified')
            if action_fingerprint(Path(action.target), Path(action.root), action.kind) != action.before:
                raise SafetyError('Data changed after planning; nothing changed')
        return current

    def _check_processes(self, plan):
        # The planner has the scoped owner filter; keep this check independent of
        # data reads because a completed action intentionally changed the data.
        state = inspect_runtime() if self.inspect is inspect_windows else self.inspect()
        for p in state.get('processes', []):
            kind = p.get('kind')
            if (kind in ('claude.exe', 'claude-child') or
                kind in ('Code.exe', 'Code - Insiders.exe') and 'vscode' in plan.components or
                kind in ('Claude.exe', 'claude-desktop.exe', 'cowork-svc.exe') and 'desktop' in plan.components or
                kind == 'chrome-managed' and 'chrome' in plan.components):
                raise SafetyError('Related application started; apply stopped')
        if state.get('restore_sources'):
            raise SafetyError('A state-restoration source became active')

    def _external_recheck(self, plan):
        current = build_plan(self.paths, plan.components, platform_state=self.inspect(), selection=plan.selection)
        if current.blockers or current.versions != plan.versions:
            raise SafetyError('External configuration or client version changed during reset')
        key = lambda a: (a.kind, a.target, a.root, a.component)
        approved = {key(a) for a in plan.actions if a.kind != 'chrome_fresh'}
        if any(key(a) not in approved for a in current.actions if a.kind != 'chrome_fresh'):
            raise SafetyError('A new reset target appeared; review a new plan')
        return current

    def apply(self, plan, *, consent_id, server_step_complete=False):
        if consent_id != plan.id:
            raise SafetyError('Apply requires the exact reviewed plan ID')
        if not server_step_complete:
            raise SafetyError('Complete the server revocation step before deleting the old local sign-in')
        self._preflight(plan)
        with operation_lock(self.paths):
            self._preflight(plan)
            run = guarded(self.paths.state / 'runs' / plan.id, self.paths.state)
            if run.exists():
                raise SafetyError('This plan has already been started; use its report')
            run.mkdir(parents=True)
            report = _new_report(plan)
            atomic_json(run / 'result.json', report, self.paths.state)
            journal = {'schema': 1, 'plan': serialize_plan(plan), 'next': 0, 'in_progress': None, 'after': []}
            try:
                profiles = [snapshot_memory(Path(a.target))[0] for a in plan.actions if a.kind == 'reset_code']
                archive = {'schema': 2, 'profiles': profiles}
                archive_profiles(archive)
                self._write_private(run / 'memory.dpapi', archive)
                from .identifiers import baseline
                self._write_private(run / 'identifier-baseline.dpapi', baseline(plan, self.paths))
                report['memory'] = 'encrypted_archive_verified'
                self._write_private(run / 'journal.dpapi', journal)
                self._preflight(plan)
                return self._execute(run, plan, journal, profiles, report)
            except Exception as exc:
                self._fail(run, report, exc)

    def _fail(self, run, report, exc):
        report.update(status='failed_or_partial', error_type=type(exc).__name__, ready_for_new_account=False)
        atomic_json(run / 'result.json', report, self.paths.state)
        raise SafetyError('Apply stopped. Inspect the redacted run report; encrypted memory archive is retained if created') from None

    def _execute(self, run, plan, journal, profiles, report):
        memory_index = sum(a.kind == 'reset_code' for a in plan.actions[:journal['next']])
        for index in range(journal['next'], len(plan.actions)):
            action = plan.actions[index]
            target, root = Path(action.target), Path(action.root)
            self._check_processes(plan)
            if action_fingerprint(target, root, action.kind) != action.before:
                raise SafetyError('Data changed during execution; operation stopped')
            journal['in_progress'] = index
            self._write_private(run / 'journal.dpapi', journal)
            if action.kind == 'delete':
                remove_owned(target, root)
            elif action.kind == 'reset_code':
                remove_owned(target, root)
                guarded(target, root).mkdir(parents=True)
                env = {'DISABLE_ERROR_REPORTING': '1'}
                if plan.selection.privacy == 'strict':
                    env['DISABLE_TELEMETRY'] = '1'
                atomic_json(target / 'settings.json', {'env': env}, target)
                restore_memory(profiles[memory_index], target)
                for name, data in validate_memory_bundle(profiles[memory_index]):
                    if guarded(target / name, target).read_bytes() != data:
                        raise SafetyError('Restored memory differs from verified archive')
                memory_index += 1
                report['memory'] = 'restored_verbatim'
            elif action.kind == 'vscode_db':
                reset_vscode_db(target, root)
            elif action.kind == 'vscode_privacy':
                jsonc.set_property(target, root, 'telemetry.telemetryLevel', 'off')
            elif action.kind == 'chrome_fresh':
                guarded(target, root).mkdir(parents=True)
                atomic_json(target / 'claude-reset-profile.json', {'created_by': 'ClaudeReset', 'run': plan.id}, root)
                atomic_json(target / 'Default/Preferences', {
                    'profile': {'default_content_setting_values': {'geolocation': 2}},
                    'session': {'restore_on_startup': 5}}, root)
                report['chrome_profile_run'] = plan.id
            else:
                raise SafetyError('Unknown action')
            after = action_fingerprint(target, root, action.kind)
            if action.kind == 'delete' and after != 'absent':
                raise SafetyError('Deleted state reappeared')
            journal['after'].append(after)
            journal['next'], journal['in_progress'] = index + 1, None
            report['completed'].append({'component': action.component, 'kind': action.kind})
            self._write_private(run / 'journal.dpapi', journal)
            atomic_json(run / 'result.json', report, self.paths.state)
        self._check_processes(plan)
        self._external_recheck(plan)
        for action, expected in zip(plan.actions, journal['after']):
            if action_fingerprint(Path(action.target), Path(action.root), action.kind) != expected:
                raise SafetyError('State changed after reset; verification failed')
        report.update(status='local_operations_completed_partial_coverage', local_reset='completed_for_selected_operations',
                      authorization='selected_local_sources_removed_live_check_pending',
                      desktop_keys='preserved_not_verified', environment='residual_fields_available',
                      remaining=['server_verification', 'network_verification', 'desktop_key_and_cowork_verification',
                                 'live_client_verification', 'project_and_remote_environment_verification'])
        atomic_json(run / 'result.json', report, self.paths.state)
        return report

    def resume(self, run_id):
        if not re.fullmatch(r'[a-f0-9]{32}', run_id):
            raise SafetyError('Invalid recovery run ID')
        with operation_lock(self.paths):
            run = guarded(self.paths.state / 'runs' / run_id, self.paths.state)
            journal = self._read_private(run / 'journal.dpapi')
            if journal.get('schema') != 1 or journal.get('in_progress') is not None:
                raise SafetyError('Interrupted action has an uncertain outcome; export memory and review a new plan')
            plan = deserialize_plan(journal['plan'])
            if plan.id != run_id or journal['next'] != len(journal['after']) or not 0 <= journal['next'] <= len(plan.actions):
                raise SafetyError('Invalid recovery checkpoint')
            self._check_processes(plan)
            # Completed and pending paths both must match the recorded checkpoint.
            for i, action in enumerate(plan.actions):
                expected = journal['after'][i] if i < journal['next'] else action.before
                if action_fingerprint(Path(action.target), Path(action.root), action.kind) != expected:
                    raise SafetyError('Data changed since interruption; recovery will not overwrite new work')
            # Recheck external authentication, versions and policy before continuation.
            self._external_recheck(plan)
            profiles = archive_profiles(self._read_private(run / 'memory.dpapi'))
            if len(profiles) != sum(a.kind == 'reset_code' for a in plan.actions):
                raise SafetyError('Memory archive does not match the recovery plan')
            # The public report is neither authority nor a recovery input.
            # Rebuild it from the verified private checkpoint, including when
            # the old report was lost, malformed, or claimed false readiness.
            report = _new_report(plan)
            report['memory'] = 'encrypted_archive_verified'
            # A power loss between private checkpoint and public report is repairable.
            report['completed'] = [{'component': a.component, 'kind': a.kind} for a in plan.actions[:journal['next']]]
            if any(a.kind == 'reset_code' for a in plan.actions[:journal['next']]):
                report['memory'] = 'restored_verbatim'
            if any(a.kind == 'chrome_fresh' for a in plan.actions[:journal['next']]):
                report['chrome_profile_run'] = plan.id
            try:
                return self._execute(run, plan, journal, profiles, report)
            except Exception as exc:
                self._fail(run, report, exc)
