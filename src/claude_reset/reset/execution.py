"""Journaled execution with preflight, encrypted memory and conservative recovery."""
from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from pathlib import Path

from .. import config, layout
from ..errors import SafetyError, error_kind
from ..model import clients, jsonc
from ..model.ids import new_id
from ..model.reset import Plan, report_versions
from ..model.status import Reset
from ..safeio import atomic_bytes, atomic_json, guarded, remove_owned
from ..windows.dpapi import DPAPI
from ..windows.inventory import inspect_runtime, inspect_windows
from .identifiers import baseline, compare
from .memory import MEMORY_LIMIT, restore_memory, snapshot_memory, validate_memory_bundle
from .planner import action_fingerprint, build_plan
from .vscode_db import reset_vscode_db

__all__ = ['Executor', 'archive_profiles', 'operation_lock', 'recover_memory', 'verify_run']


@contextmanager
def operation_lock(paths):
    guarded(paths.state, paths.state, allow_root=True).mkdir(parents=True, exist_ok=True)
    lock = guarded(paths.state / layout.OPERATION_LOCK, paths.state)
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
            raise SafetyError('Another reset or recovery operation is running', code='operation_running') from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def _new_report(plan):
    return {'run': plan.id, 'status': Reset.STARTED, 'completed': [], 'full_reset': False,
            'server': 'user_reported_complete_not_independently_verified', 'network': 'not_verified',
            'memory': 'not_processed', 'ready_for_new_account': False,
            'components': list(plan.components), 'versions': report_versions(plan.versions)}


def deserialize_plan(obj):
    try:
        return Plan.from_json(obj)
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


def action_key(action):
    """What makes two planned actions the same action: kind, target, root and component."""
    return action.kind, action.target, action.root, action.component


class Executor:
    def __init__(self, paths, crypto=DPAPI(), inspect=inspect_windows):
        self.paths, self.crypto, self.inspect = paths, crypto, inspect

    def write_private(self, path, value):
        atomic_bytes(path, self.crypto.encrypt(json.dumps(value, ensure_ascii=False).encode('utf-8')), self.paths.state)
        if self.read_private(path) != value:
            raise SafetyError('Encrypted journal round-trip failed')

    def read_private(self, path):
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
        actual = [action_key(a) for a in current.actions if a.kind != 'chrome_fresh']
        original = [action_key(a) for a in plan.actions if a.kind != 'chrome_fresh']
        if actual != original or current.versions != plan.versions:
            raise SafetyError('Inventory changed; review a new plan')
        if sum(a.kind == 'chrome_fresh' for a in plan.actions) != int('chrome' in plan.components):
            raise SafetyError('Invalid Chrome action count')
        for action in plan.actions:
            if action.kind == 'chrome_fresh' and (Path(action.target) != self.paths.state / layout.CHROME_PROFILES / plan.id or
                    Path(action.root) != self.paths.state or action.component != 'chrome'):
                raise SafetyError('Chrome target was modified')
            if action_fingerprint(Path(action.target), Path(action.root), action.kind) != action.before:
                raise SafetyError('Data changed after planning; nothing changed')
        return current

    def check_processes(self, plan):
        """The owners the plan needs closed are still closed; called before each step and again at the end."""
        # The planner has the scoped owner filter; keep this check independent of
        # data reads because a completed action intentionally changed the data.
        state = inspect_runtime() if self.inspect is inspect_windows else self.inspect()
        for p in state.get('processes', []):
            if clients.blocking(p.get('kind'), plan.components):
                raise SafetyError('Related application started; apply stopped')
        if state.get('restore_sources'):
            raise SafetyError('A state-restoration source became active')

    def _external_recheck(self, plan):
        current = build_plan(self.paths, plan.components, platform_state=self.inspect(), selection=plan.selection)
        if current.blockers or current.versions != plan.versions:
            raise SafetyError('External configuration or client version changed during reset')
        approved = {action_key(a) for a in plan.actions if a.kind != 'chrome_fresh'}
        if any(action_key(a) not in approved for a in current.actions if a.kind != 'chrome_fresh'):
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
            run = layout.run_folder(self.paths, layout.RUNS, plan.id)
            if run.exists():
                raise SafetyError('This plan has already been started; use its report')
            run.mkdir(parents=True)
            report = _new_report(plan)
            atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
            journal = {'schema': 1, 'plan': plan.to_json(), 'next': 0, 'in_progress': None, 'after': []}
            try:
                profiles = [snapshot_memory(Path(a.target))[0] for a in plan.actions if a.kind == 'reset_code']
                archive = {'schema': 2, 'profiles': profiles}
                archive_profiles(archive)
                self.write_private(run / layout.MEMORY_FILE, archive)
                self.write_private(run / 'identifier-baseline.dpapi', baseline(plan, self.paths))
                report['memory'] = 'encrypted_archive_verified'
                self.write_private(run / layout.JOURNAL_FILE, journal)
                self._preflight(plan)
                return self._execute(run, plan, journal, profiles, report)
            except Exception as exc:
                self._fail(run, report, exc)

    def _fail(self, run, report, exc):
        report.update(status=Reset.FAILED_OR_PARTIAL, error_type=error_kind(exc), ready_for_new_account=False)
        atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
        raise SafetyError('Apply stopped. Inspect the redacted run report; encrypted memory archive is retained if created', code='apply_stopped') from None

    def _execute(self, run, plan, journal, profiles, report):
        memory_index = sum(a.kind == 'reset_code' for a in plan.actions[:journal['next']])
        for index in range(journal['next'], len(plan.actions)):
            action = plan.actions[index]
            target, root = Path(action.target), Path(action.root)
            self.check_processes(plan)
            if action_fingerprint(target, root, action.kind) != action.before:
                raise SafetyError('Data changed during execution; operation stopped')
            journal['in_progress'] = index
            self.write_private(run / layout.JOURNAL_FILE, journal)
            if action.kind == 'delete':
                remove_owned(target, root)
            elif action.kind == 'reset_code':
                remove_owned(target, root)
                guarded(target, root).mkdir(parents=True)
                env = {'DISABLE_ERROR_REPORTING': '1'}
                if plan.selection.privacy == 'strict':
                    env['DISABLE_TELEMETRY'] = '1'
                atomic_json(target / layout.CODE_SETTINGS, {'env': env}, target)
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
                atomic_json(target / layout.PROFILE_MARKER, {'created_by': config.PRODUCT_NAME, 'run': plan.id}, root)
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
            self.write_private(run / layout.JOURNAL_FILE, journal)
            atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
        self.check_processes(plan)
        self._external_recheck(plan)
        for action, expected in zip(plan.actions, journal['after']):
            if action_fingerprint(Path(action.target), Path(action.root), action.kind) != expected:
                raise SafetyError('State changed after reset; verification failed')
        report.update(status=Reset.PARTIAL_COVERAGE, local_reset='completed_for_selected_operations',
                      authorization='selected_local_sources_removed_live_check_pending',
                      desktop_keys='preserved_not_verified', environment='residual_fields_available',
                      remaining=['server_verification', 'network_verification', 'desktop_key_and_cowork_verification',
                                 'live_client_verification', 'project_and_remote_environment_verification'])
        atomic_json(run / layout.RESULT_FILE, report, self.paths.state)
        return report

    def resume(self, run_id):
        if not re.fullmatch(r'[a-f0-9]{32}', run_id):
            raise SafetyError('Invalid recovery run ID')
        with operation_lock(self.paths):
            run = layout.run_folder(self.paths, layout.RUNS, run_id)
            journal = self.read_private(run / layout.JOURNAL_FILE)
            if journal.get('schema') != 1 or journal.get('in_progress') is not None:
                raise SafetyError('Interrupted action has an uncertain outcome; export memory and review a new plan', code='interrupted_uncertain')
            plan = deserialize_plan(journal['plan'])
            if plan.id != run_id or journal['next'] != len(journal['after']) or not 0 <= journal['next'] <= len(plan.actions):
                raise SafetyError('Invalid recovery checkpoint')
            self.check_processes(plan)
            # Completed and pending paths both must match the recorded checkpoint.
            for i, action in enumerate(plan.actions):
                expected = journal['after'][i] if i < journal['next'] else action.before
                if action_fingerprint(Path(action.target), Path(action.root), action.kind) != expected:
                    raise SafetyError('Data changed since interruption; recovery will not overwrite new work', code='changed_since_interruption')
            # Recheck external authentication, versions and policy before continuation.
            self._external_recheck(plan)
            profiles = archive_profiles(self.read_private(run / layout.MEMORY_FILE))
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


def recover_memory(paths: layout.Paths, run_id: str, crypto=DPAPI()):
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid recovery run ID')
    source = guarded(layout.run_folder(paths, layout.RUNS, run_id) / layout.MEMORY_FILE, paths.state)
    if source.stat().st_size > MEMORY_LIMIT * 2:
        raise SafetyError('Archive too large')
    bundle = json.loads(crypto.decrypt(source.read_bytes()))
    profiles = archive_profiles(bundle)
    # Recovery exports into its OWN directory, never overwrites a live Claude profile.
    destination = paths.state / 'recovered-memory' / new_id()
    with operation_lock(paths):
        guarded(destination, paths.state)
        destination.mkdir(parents=True)
        for i, profile in enumerate(profiles):
            root = destination if len(profiles) == 1 else destination / ('profile-' + str(i + 1))
            root.mkdir(parents=True, exist_ok=True)
            restore_memory(profile, root)
    return destination


def verify_run(paths, run_id, crypto=DPAPI()):
    if not re.fullmatch(r'[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid verification run ID')
    with operation_lock(paths):
        executor = Executor(paths, crypto)
        run = layout.run_folder(paths, layout.RUNS, run_id)
        journal = executor.read_private(run / layout.JOURNAL_FILE)
        plan = deserialize_plan(journal['plan'])
        if plan.id != run_id:
            raise SafetyError('Verification run mismatch')
        result = compare(plan, paths, executor.read_private(run / 'identifier-baseline.dpapi'))
        atomic_json(run / 'identifier-verification.json', result, paths.state)
        return result
