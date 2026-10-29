"""Explicit disposition of extra Code entries: source export or reviewed removal."""
from __future__ import annotations
import base64
import hashlib
import re
import uuid
from pathlib import Path
from .catalog import CODE_ENTRIES
from .cowork import SECRET
from .desktop_keys import private_read, private_write
from .execution import operation_lock
from .safeio import SafetyError, guarded, fingerprint, walk_files, remove_owned, atomic_json, atomic_bytes
from .windows import inspect_runtime


def extra_entries(profile):
    guarded(profile, profile, allow_root=True)
    return sorted(p.name for p in profile.iterdir() if p.name not in CODE_ENTRIES and
                  not re.fullmatch(r'\.claude\.json\.(?:backup|bak)(?:\.[0-9-]+)?', p.name))


def no_code_owners():
    state = inspect_runtime()
    if any(p.get('kind') in ('claude.exe', 'claude-child', 'Code.exe', 'Code - Insiders.exe') for p in state.get('processes', [])):
        raise SafetyError('Close Code and editor owners before processing customizations')


def _report(plan):
    return {'run':plan['id'],'status':'encrypted_source_export_verified',
            'source_entries':len(plan['source_entries']),
            'discard_entries':len(plan['snapshots'])-len(plan['source_entries']),
            'source_files':len(plan['bundle']),
            'source_bytes':sum(len(base64.b64decode(item['data'],validate=True)) for item in plan['bundle']),
            'automatic_restore':False,'ready_for_new_account':False}


def create_plan(paths, source_entries):
    profile = paths.home / '.claude'
    with operation_lock(paths):
        no_code_owners()
        extras = extra_entries(profile)
        if not extras or len(set(source_entries)) != len(source_entries) or set(source_entries) - set(extras):
            raise SafetyError('Select exact discovered customization entries for export')
        snapshots = {name: fingerprint(profile / name, profile) for name in extras}
        bundle, total = [], 0
        for name in source_entries:
            for file in walk_files(profile / name, profile):
                total += file.stat().st_size
                if total > 32 * 1024**2:
                    raise SafetyError('Customization source export exceeds 32 MiB')
                data = file.read_bytes()
                # Documentation placeholders are not live credentials. The
                # exported bytes are unchanged; this copy is only for detection.
                inspected = re.sub(rb'(?i)\b(?:your|example|replace)[_-][a-z0-9_-]+', b'PLACEHOLDER', data)
                if SECRET.search(inspected) or file.suffix.lower() in ('.pfx', '.p12', '.key'):
                    raise SafetyError('Selected source contains a possible credential; choose a narrower export')
                bundle.append({'path': file.relative_to(profile).as_posix(), 'data': base64.b64encode(data).decode(),
                               'sha256': hashlib.sha256(data).hexdigest()})
        if snapshots != {name: fingerprint(profile / name, profile) for name in extras}:
            raise SafetyError('Customization source changed during export')
        run_id = uuid.uuid4().hex
        run = guarded(paths.state / 'customization-runs' / run_id, paths.state)
        plan = {'schema': 1, 'id': run_id, 'snapshots': snapshots, 'source_entries': sorted(source_entries),
                'bundle': bundle, 'deleted': [], 'in_progress': None}
        private_write(paths, run / 'plan.dpapi', plan)
        report = _report(plan)
        atomic_json(run / 'result.json', report, paths.state)
        return report


def apply_plan(paths, run_id, *, server_step_complete=False):
    if not re.fullmatch('[a-f0-9]{32}', run_id) or not server_step_complete:
        raise SafetyError('Customization removal requires an exact reviewed plan and server confirmation')
    with operation_lock(paths):
        run = guarded(paths.state / 'customization-runs' / run_id, paths.state)
        plan = private_read(paths, run / 'plan.dpapi')
        if plan.get('schema') != 1 or plan.get('id') != run_id or plan.get('in_progress') is not None:
            raise SafetyError('Customization checkpoint requires a new review')
        profile = paths.home / '.claude'
        if set(extra_entries(profile)) != set(plan['snapshots']) - set(plan['deleted']):
            raise SafetyError('Customization scope changed')
        for item in plan['bundle']:
            if hashlib.sha256(base64.b64decode(item['data'], validate=True)).hexdigest() != item['sha256']:
                raise SafetyError('Customization archive integrity failed')
        no_code_owners()
        for name, expected in plan['snapshots'].items():
            if fingerprint(profile / name, profile) != ('absent' if name in plan['deleted'] else expected):
                raise SafetyError('Customization entry changed since review')
        report = _report(plan)
        try:
            for name in plan['snapshots']:
                if name in plan['deleted']:
                    continue
                no_code_owners()
                if fingerprint(profile / name, profile) != plan['snapshots'][name]:
                    raise SafetyError('Customization changed immediately before removal')
                plan['in_progress'] = name
                private_write(paths, run / 'plan.dpapi', plan)
                remove_owned(profile / name, profile)
                plan['deleted'].append(name)
                plan['in_progress'] = None
                private_write(paths, run / 'plan.dpapi', plan)
            no_code_owners()
            if extra_entries(profile):
                raise SafetyError('Customizations reappeared')
            report['status'] = 'completed'
        except Exception as exc:
            report.update(status='failed_or_partial', error_type=type(exc).__name__)
            atomic_json(run / 'result.json', report, paths.state)
            raise SafetyError('Customization removal stopped; source archive is retained') from None
        atomic_json(run / 'result.json', report, paths.state)
        return report


def recover(paths, run_id):
    if not re.fullmatch('[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid customization archive ID')
    with operation_lock(paths):
        plan = private_read(paths, paths.state / 'customization-runs' / run_id / 'plan.dpapi')
        destination = guarded(paths.state / 'recovered-customizations' / uuid.uuid4().hex, paths.state)
        for item in plan['bundle']:
            data = base64.b64decode(item['data'], validate=True)
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise SafetyError('Customization archive integrity failed')
            atomic_bytes(destination / item['path'], data, destination)
        return destination
