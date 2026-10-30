"""Bounded read-only Cowork inventory and DPAPI export; never mounts a VM disk."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath

from .. import layout
from ..errors import SafetyError, error_kind
from ..model.ids import new_id
from ..model.status import Export, Reset
from ..safeio import atomic_bytes, atomic_json, fingerprint, guarded, remove_owned, walk_files
from ..windows.dpapi import DPAPI
from ..windows.pin import locked_reader
from .catalog import DESKTOP_WORK
from .desktop_keys import no_owners, private_read, private_write
from .execution import operation_lock

__all__ = ['SECRET', 'category', 'create_export', 'export_all', 'inventory', 'open_extfs', 'profiles',
           'recover_export', 'reset_exported', 'verify_cleanup_exports', 'verify_export_for_cleanup', 'work_profiles']

IMAGE = 'vm_bundles/claudevm.bundle/sessiondata.vhdx'
LIMIT_FILES = 100000
LIMIT_BYTES = 1024 * 1024 * 1024
BUSY = 'Cowork file is busy or unreadable; close its owner before export'
ARTIFACT_TYPES = frozenset({'.pdf', '.docx', '.xlsx', '.pptx', '.md', '.txt', '.html', '.csv', '.tsv',
                            '.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg', '.mp3', '.mp4', '.wav', '.webm',
                            '.py', '.js', '.css'})


def profiles(paths):
    """Fixed Desktop data roots; no installation version or native code execution."""
    paths.validate()
    package = layout.desktop_package(paths)
    return (layout.desktop_data(paths),
            paths.roaming / layout.DESKTOP_ROAMING, paths.roaming / layout.DESKTOP_3P, package,
            package / 'LocalCache/Roaming/Claude', package / 'LocalCache/Roaming/Claude-3p')


def profile_path(paths, profile):
    profile = Path(profile)
    if profile not in profiles(paths):
        raise SafetyError('Unsupported Cowork location', code='cowork_location')
    return guarded(profile, paths.local if profile.is_relative_to(paths.local) else paths.roaming)


def work_profiles(paths):
    return tuple(p for p in profiles(paths)
                 if any((p / name).exists() for name in (*DESKTOP_WORK, IMAGE)))


def export_all(paths):
    reports = [create_export(paths, p, include_work=True) for p in work_profiles(paths)]
    ok = all(r['status'] == Export.ENCRYPTED_EXPORT_VERIFIED for r in reports)
    return {'status': Export.ENCRYPTED_EXPORT_VERIFIED if ok else Export.INCOMPLETE,
            'runs': [r['run'] for r in reports], 'profiles': len(reports),
            'ready_for_new_account': False}


def verify_cleanup_exports(paths, run_ids):
    try:
        _verify_cleanup_exports(paths, run_ids)
    except Exception:
        raise SafetyError('The Cowork export is unavailable, changed or does not cover every source', code='cowork_export_invalid') from None


def _verify_cleanup_exports(paths, run_ids):
    if isinstance(run_ids, str):
        run_ids = (run_ids,)
    covered = []
    for run_id in run_ids or ():
        verify_export_for_cleanup(paths, run_id)
        plan = private_read(paths, layout.run_folder(paths, layout.COWORK_RUNS, run_id) / layout.PLAN_FILE)
        covered.append(profile_path(paths, plan['profile']))
    if set(covered) != set(work_profiles(paths)) or len(covered) != len(set(covered)):
        raise SafetyError('Each Cowork source needs its own verified export', code='cowork_export_per_source')


FORBIDDEN_PARTS = frozenset({'.git', '.ssh', '.aws', '.azure', '.gnupg', 'cookies', 'network', 'local storage',
                             'session storage', 'indexeddb', 'secrets', 'credentials', '.credentials.json',
                             '.audit-key', 'config.json', layout.CODE_CONFIG, layout.CODE_SETTINGS,
                             layout.CODE_LOCAL_SETTINGS})
SECRET = re.compile(rb'sk-ant-[A-Za-z0-9_-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|'
                    rb'(?i:access[_-]?token|refresh[_-]?token|api[_-]?key)["\x27\s]*[:=]["\x27\s]*[A-Za-z0-9_-]{16,}')


class AnonymousReader:
    # Hide the disk path from the parser: a parent locator must never open an
    # arbitrary host path. Differencing disks are unsupported and rejected.
    def __init__(self, stream):
        self.stream = stream
    def read(self, *args):
        return self.stream.read(*args)
    def seek(self, *args):
        return self.stream.seek(*args)
    def tell(self):
        return self.stream.tell()


def open_extfs(stream):
    from dissect.extfs import ExtFS
    from dissect.hypervisor.disk.vhdx import VHDX
    from dissect.util.hash.crc32c import crc32c
    # The underlying parser does not validate these checksums itself.
    for offset, size, magic in ((65536, 4096, b'head'), (131072, 4096, b'head'),
                                 (196608, 65536, b'regi'), (262144, 65536, b'regi')):
        stream.seek(offset)
        data = stream.read(size)
        if len(data) != size or data[:4] != magic or crc32c(data[:4] + b'\0'*4 + data[8:]) != int.from_bytes(data[4:8], 'little'):
            raise SafetyError('VHDX metadata checksum failed; export cannot be certified')
    stream.seek(0)
    try:
        disk = VHDX(AnonymousReader(stream))
        if disk.has_parent or disk.header.version != 1 or any(disk.header.log_guid):
            raise SafetyError('VHDX requires recovery or an unsupported parent disk')
        if not 0 < disk.size <= 512 * 1024**3 or disk.block_size > 256 * 1024**2 or disk.sector_size not in (512, 4096):
            raise SafetyError('Unsupported VHDX geometry')
        fs = ExtFS(disk)
        if fs.block_size != 4096 or fs.sb.s_feature_incompat & ~0x2c6:
            raise SafetyError('Unsupported Cowork ext4 feature set')
        consistent = bool(fs.sb.s_state & 1) and not bool(fs.sb.s_state & 2) and not bool(fs.sb.s_feature_incompat & 4)
        if not consistent:
            from .journal import recovered_filesystem
            fs = recovered_filesystem(fs, disk)
            consistent = True
        return fs, consistent
    except SafetyError:
        raise
    except Exception:
        raise SafetyError('Cowork virtual disk schema cannot be read safely') from None


def vm_files(fs):
    stack, seen, count = [('', fs.get('/'))], set(), 0
    while stack:
        path, node = stack.pop()
        count += 1
        if count > LIMIT_FILES or len(PurePosixPath(path).parts) > 64:
            raise SafetyError('Cowork VM traversal limit exceeded')
        if node.filetype == stat.S_IFDIR:
            if node.inum in seen:
                raise SafetyError('Cowork VM directory cycle detected')
            seen.add(node.inum)
            children = list(node.iterdir())
            if len(children) > LIMIT_FILES:
                raise SafetyError('Cowork VM directory exceeds inventory limit')
            names = set()
            for child in children:
                name = child.filename
                if name in ('.', '..'):
                    continue
                if not name or '/' in name or '\x00' in name or name in names:
                    raise SafetyError('Invalid or duplicate Cowork VM entry')
                names.add(name)
                stack.append((path + '/' + name, child))
        elif node.filetype == stat.S_IFREG:
            yield path, node
        # Links and device files are never followed or exported.


def category(relative):
    p = PurePosixPath(relative)
    parts = {s.lower() for s in p.parts}
    if parts & FORBIDDEN_PARTS:
        return None
    if p.name == 'CLAUDE.md' or (p.suffix.lower() == '.md' and parts & {'memory', 'agent-memory'}):
        return 'memory'
    if parts & {'outputs', 'pending-uploads'} and p.suffix.lower() in ARTIFACT_TYPES:
        return 'work'
    if ('scratch-workspaces' in parts or (p.is_absolute() and len(p.parts) == 3)) and p.suffix.lower() in ARTIFACT_TYPES:
        return 'work'
    return None


def inventory(profile):
    entries, all_files, total = [], 0, 0
    snapshots = {}
    for folder in sorted(DESKTOP_WORK):
        path = guarded(profile / folder, profile)
        snapshots[folder] = fingerprint(path, profile)
        for file in walk_files(path, profile):
            all_files += 1
            total += file.stat().st_size
            if all_files > LIMIT_FILES:
                raise SafetyError('Cowork host inventory limit exceeded')
            relative = file.relative_to(profile).as_posix()
            role = category(relative)
            if role:
                entries.append({'source': 'host', 'path': relative, 'size': file.stat().st_size, 'category': role})
    image = guarded(profile / IMAGE, profile)
    snapshots[IMAGE] = fingerprint(image, profile)
    consistent = True
    replayed = {'transactions': 0, 'blocks': 0}
    if image.exists():
        with locked_reader(image, BUSY) as stream:
            fs, consistent = open_extfs(stream)
            replayed = {'transactions': getattr(fs, 'replayed_transactions', 0), 'blocks': getattr(fs, 'replayed_blocks', 0)}
            for relative, node in vm_files(fs):
                all_files += 1
                total += node.size
                role = category(relative)
                if role:
                    entries.append({'source': 'vm', 'path': relative, 'size': node.size, 'category': role})
    entries.sort(key=lambda e: (e['source'], e['path']))
    if snapshots != {name: fingerprint(profile / name, profile) for name in snapshots}:
        raise SafetyError('Cowork data changed during inventory')
    return {'entries': entries, 'snapshots': snapshots, 'consistent': consistent, 'journal_replay': replayed,
            'files': all_files, 'bytes': total}


def _report(plan):
    inv=plan['inventory']
    selected=plan['selected']
    return {'run':plan['id'],'status':Export.INVENTORY_COMPLETE,'files':inv['files'],'bytes':inv['bytes'],
            'memory_files':sum(e['category']=='memory' for e in selected),
            'work_files':sum(e['category']=='work' for e in selected),
            'vm_consistent':inv['consistent'],'ready_for_new_account':False,
            'journal_replay_in_memory':inv['journal_replay'],
            'blockers':[] if inv['consistent'] else ['Cowork ext4 journal requires recovery before certified export/reset']}


def create_export(paths, profile, *, include_work=False):
    profile = profile_path(paths, profile)
    with operation_lock(paths):
        no_owners()
        inv = inventory(profile)
        run_id = new_id()
        run = layout.run_folder(paths, layout.COWORK_RUNS, run_id)
        selected = [e for e in inv['entries'] if e['category'] == 'memory' or include_work]
        if sum(e['size'] for e in selected) > LIMIT_BYTES or any(e['size'] > 256 * 1024**2 for e in selected):
            raise SafetyError('Selected Cowork export exceeds the supported size')
        plan = {'schema': 1, 'id': run_id, 'profile': str(profile), 'inventory': inv,
                'selected': selected, 'include_work': include_work, 'exported': [], 'deleted': [], 'in_progress': None}
        private_write(paths, run / layout.PLAN_FILE, plan)
        report = _report(plan)
        atomic_json(run / layout.RESULT_FILE, report, paths.state)
        if not inv['consistent']:
            return report
        crypto = DPAPI()
        def save(entry, data):
            if len(data) != entry['size'] or (entry['category'] == 'work' and SECRET.search(data)):
                raise SafetyError('Cowork export size changed or selected material contains a credential; review required')
            index = len(plan['exported'])
            encrypted = crypto.encrypt(data)
            if crypto.decrypt(encrypted) != data:
                raise SafetyError('Cowork export encryption verification failed')
            atomic_bytes(run / 'files' / (str(index) + '.dpapi'), encrypted, paths.state)
            plan['exported'].append({'entry': entry, 'sha256': hashlib.sha256(data).hexdigest()})
        try:
            for entry in selected:
                if entry['source'] == 'host':
                    with locked_reader(guarded(profile / entry['path'], profile), BUSY) as stream:
                        save(entry, stream.read(entry['size'] + 1))
            if any(e['source'] == 'vm' for e in selected):
                with locked_reader(guarded(profile / IMAGE, profile), BUSY) as stream:
                    fs, consistent = open_extfs(stream)
                    if not consistent:
                        raise SafetyError('Cowork filesystem became dirty')
                    for entry in selected:
                        if entry['source'] == 'vm':
                            node = fs.get(entry['path'])
                            if node.filetype != stat.S_IFREG:
                                raise SafetyError('Cowork export target changed type')
                            save(entry, node.open().read(entry['size'] + 1))
            if inventory(profile) != inv:
                raise SafetyError('Cowork data changed while exporting')
            private_write(paths, run / layout.PLAN_FILE, plan)
            report.update(status=Export.ENCRYPTED_EXPORT_VERIFIED, memory='exported_verbatim_separate_archive')
        except Exception as exc:
            report.update(status=Export.FAILED_OR_PARTIAL, error_type=error_kind(exc), blockers=['Cowork export did not complete'])
            atomic_json(run / layout.RESULT_FILE, report, paths.state)
            raise SafetyError('Cowork export stopped; no source data was removed') from None
        atomic_json(run / layout.RESULT_FILE, report, paths.state)
        return report


def verify_export_for_cleanup(paths, run_id):
    """Recheck encrypted materials and their unchanged sources without removing them."""
    if not isinstance(run_id, str) or not re.fullmatch('[a-f0-9]{32}', run_id):
        raise SafetyError('A verified Cowork export is required', code='cowork_export_required')
    run = layout.run_folder(paths, layout.COWORK_RUNS, run_id)
    plan = private_read(paths, run / layout.PLAN_FILE)
    if (plan.get('id') != run_id or plan.get('schema') != 1
            or not plan['inventory']['consistent'] or not plan.get('include_work')
            or plan.get('deleted') or plan.get('in_progress') is not None
            or len(plan['exported']) != len(plan['selected'])
            or [item['entry'] for item in plan['exported']] != plan['selected']):
        raise SafetyError('The Cowork export is incomplete or already used', code='cowork_export_used')
    profile = profile_path(paths, plan['profile'])
    for index, item in enumerate(plan['exported']):
        data = DPAPI().decrypt(guarded(run / 'files' / (str(index) + '.dpapi'), paths.state).read_bytes())
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise SafetyError('The Cowork archive is damaged', code='cowork_archive_damaged')
    if inventory(profile) != plan['inventory']:
        raise SafetyError('Cowork data changed after the export', code='cowork_changed')
    return {'status': Export.COWORK_EXPORT_VERIFIED, 'ready_for_new_account': False}


def reset_exported(paths, run_id, *, server_step_complete=False):
    if not re.fullmatch('[a-f0-9]{32}', run_id) or not server_step_complete:
        raise SafetyError('Cowork reset requires a reviewed export and server confirmation')
    with operation_lock(paths):
        run = layout.run_folder(paths, layout.COWORK_RUNS, run_id)
        plan = private_read(paths, run / layout.PLAN_FILE)
        if plan.get('id') != run_id or plan.get('schema') != 1 or not plan['inventory']['consistent']:
            raise SafetyError('Cowork export cannot authorize deletion')
        if len(plan['exported']) != len(plan['selected']):
            raise SafetyError('Cowork export is incomplete')
        profile = profile_path(paths, plan['profile'])
        report = json.loads((run / layout.RESULT_FILE).read_text('utf8'))
        if report.get('status') == Reset.COMPLETED:
            raise SafetyError('Cowork reset already completed')
        # Keep the conservative completion guard, never copy public fields.
        report = _report(plan)
        # Verify every encrypted export before touching any source data.
        for index, item in enumerate(plan['exported']):
            file = guarded(run / 'files' / (str(index) + '.dpapi'), paths.state)
            data = DPAPI().decrypt(file.read_bytes())
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise SafetyError('Cowork archive integrity check failed')
        if plan['in_progress'] is not None:
            raise SafetyError('Interrupted Cowork deletion needs a new inventory; export remains available')
        no_owners()
        for name, expected in plan['inventory']['snapshots'].items():
            current = fingerprint(profile / name, profile)
            if current != ('absent' if name in plan['deleted'] else expected):
                raise SafetyError('Cowork data changed after export; no further deletion allowed')
        try:
            for name in plan['inventory']['snapshots']:
                if name in plan['deleted']:
                    continue
                no_owners()
                if fingerprint(profile / name, profile) != plan['inventory']['snapshots'][name]:
                    raise SafetyError('Cowork data changed immediately before deletion')
                plan['in_progress'] = name
                private_write(paths, run / layout.PLAN_FILE, plan)
                remove_owned(profile / name, profile)
                plan['deleted'].append(name)
                plan['in_progress'] = None
                private_write(paths, run / layout.PLAN_FILE, plan)
            no_owners()
            if any((profile / name).exists() for name in plan['inventory']['snapshots']):
                raise SafetyError('Cowork state reappeared')
            report.update(status=Reset.COMPLETED, local_reset='cowork_session_state_removed',
                          memory='exported_verbatim_separate_archive', system_vm_images='preserved')
            atomic_json(run / layout.RESULT_FILE, report, paths.state)
            return report
        except Exception as exc:
            report.update(status=Reset.FAILED_OR_PARTIAL, error_type=error_kind(exc))
            atomic_json(run / layout.RESULT_FILE, report, paths.state)
            raise SafetyError('Cowork reset stopped; verified exports remain available') from None


def recover_export(paths, run_id):
    if not re.fullmatch('[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid Cowork export ID')
    with operation_lock(paths):
        run = layout.run_folder(paths, layout.COWORK_RUNS, run_id)
        plan = private_read(paths, run / layout.PLAN_FILE)
        destination = guarded(paths.state / 'recovered-cowork' / new_id(), paths.state)
        for index, item in enumerate(plan['exported']):
            entry = item['entry']
            if category(entry['path']) != entry['category']:
                raise SafetyError('Unsupported archived Cowork material')
            file = guarded(run / 'files' / (str(index) + '.dpapi'), paths.state)
            data = DPAPI().decrypt(file.read_bytes())
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise SafetyError('Cowork export integrity failed')
            suffix = PurePosixPath(entry['path']).suffix.lower()
            if not re.fullmatch(r'\.[a-z0-9]{1,8}', suffix):
                raise SafetyError('Invalid Cowork export suffix')
            atomic_bytes(destination / entry['category'] / (f'{index:06d}' + suffix), data, paths.state)
        return destination
