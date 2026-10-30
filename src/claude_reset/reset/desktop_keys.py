"""Reviewable, journaled deletion of account-scoped Desktop CNG keys in MSIX."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from ..model import jsonc
from ..windows.cng import KEY_PATTERN
from ..model.compatibility import CLIENTS
from .execution import operation_lock
from .native import call_native
from .native_worker import FAMILY
from ..errors import SafetyError
from ..safeio import guarded, atomic_bytes, atomic_json
from ..windows.system import DPAPI, inspect_runtime, ps_json
from .. import layout
from ..model import clients
from ..model.status import Reset
from ..model.ids import new_id

VALIDATED_INSTALLATIONS = CLIENTS['desktop']['native_reset_hashes']
UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\Z')
FILES = ('ant-device-registry.json', 'ant-device-key-generation.json')


def verify_installation(*, package=None, validated=VALIDATED_INSTALLATIONS):
    """The installed Desktop is a validated version and its code files hash as reviewed.

    package is Windows' record of the installed package (read here when not given); validated maps versions to
    the hashes of the two code files."""
    if package is None:
        package = ps_json("Get-AppxPackage -Name Claude | Select-Object Version,PackageFamilyName,InstallLocation "
                          "| ConvertTo-Json -Compress")
    if (not isinstance(package, dict) or package.get('Version') not in validated
            or package.get('PackageFamilyName') != FAMILY):
        raise SafetyError('Desktop native adapter requires the validated MSIX installation')
    resources = Path(package['InstallLocation']) / 'app/resources'
    files = ('app.asar', 'app.asar.unpacked/node_modules/@ant/claude-native/claude-native-binding.node')
    for name, expected in zip(files, validated[package['Version']]):
        source = guarded(resources / name, resources)
        with source.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise SafetyError('Desktop application code changed; native adapter must be revalidated')


def profile_path(paths, profile):
    profile = Path(profile)
    expected = layout.desktop_data(paths)
    if profile != expected:
        raise SafetyError('This native adapter only supports the validated primary MSIX profile')
    return guarded(profile, paths.local)


def signature(profile):
    result = {}
    for name in FILES:
        file = guarded(profile / name, profile)
        if file.exists() and file.stat().st_size > 1_000_000:
            raise SafetyError('Desktop registration exceeds the supported size')
        result[name] = hashlib.sha256(file.read_bytes()).hexdigest() if file.exists() else None
    return result


def select_keys(registry, generations, inventory):
    if inventory.get('unknown_application_keys'):
        raise SafetyError('Unknown application key schema; native reset blocked')
    if not registry or any(not UUID.fullmatch(account) for account in registry):
        raise SafetyError('No supported account-scoped Desktop registrations')
    if any(not UUID.fullmatch(account) or type(value) is not int or not 0 < value <= 2147483647
           for account, value in generations.items()):
        raise SafetyError('Unknown Desktop key-generation schema')
    if set(generations) - set(registry):
        raise SafetyError('Unregistered key generations require separate review')
    keys = inventory['keys']
    selected = []
    for account, registration in registry.items():
        if not isinstance(registration, str) or not re.fullmatch(r'pk1:[a-f0-9]{64}:[0-9a-f-]{36}', registration):
            raise SafetyError('Unsupported Desktop registration schema')
        current = [key for key in keys if key['account'] == account and key['generation'] == generations.get(account, 0)]
        if len(current) != 1 or current[0]['public_digest'] != registration.split(':')[1]:
            raise SafetyError('Desktop registration does not match the current CNG public key')
        for key in keys:
            match = KEY_PATTERN.fullmatch(key['name'])
            if not match or key['account'] != match[1] or key['generation'] != int(match[2] or 0):
                raise SafetyError('Native key inventory is inconsistent')
            if key['account'] == account:
                selected.append(key)
    return sorted(selected, key=lambda key: key['name'])


def no_owners():
    state = inspect_runtime()
    if any(p.get('kind') in clients.owners('desktop') for p in state.get('processes', [])):
        raise SafetyError('Close Desktop and stop its Cowork service before resetting application keys')
    if state.get('restore_sources'):
        raise SafetyError('Active restoration source blocks native key reset')


def private_write(paths, file, obj):
    crypto = DPAPI()
    serialized = json.dumps(obj).encode()
    if len(serialized) > 60 * 1024**2:
        raise SafetyError('Encrypted checkpoint size limit exceeded')
    data = crypto.encrypt(serialized)
    if json.loads(crypto.decrypt(data)) != obj:
        raise SafetyError('Native checkpoint encryption verification failed')
    atomic_bytes(file, data, paths.state)


def private_read(paths, file):
    guarded(file, paths.state)
    if file.stat().st_size > 64 * 1024**2:
        raise SafetyError('Native checkpoint too large')
    return json.loads(DPAPI().decrypt(file.read_bytes()))


def _report(plan):
    return {'run':plan['id'],'status':Reset.PLANNED,'accounts':len(plan['accounts']),
            'keys':len(plan['keys']),
            'unselected_keys_preserved':len(plan['inventory']['keys'])-len(plan['keys']),
            'desktop_keys':'planned_not_deleted','ready_for_new_account':False,'server':'not_verified'}


class Desktop:
    """What the key reset asks of this PC: the validated installation, no running owner, the profile folder and
    the native worker inside the package. A test gives the reset a scripted one."""

    def verify_installation(self) -> None:
        verify_installation()

    def no_owners(self) -> None:
        no_owners()

    def profile(self, paths, profile) -> Path:
        return profile_path(paths, profile)

    def native(self, paths, operation: str, **args: object) -> dict:
        return call_native(paths, operation, **args)


def review_plan(paths, run_id):
    """Read planned confirmation counts; no key inventory or deletion is invoked."""
    if not re.fullmatch('[a-f0-9]{32}',run_id):
        raise SafetyError('Invalid native review run ID')
    with operation_lock(paths):
        plan=private_read(paths,layout.run_folder(paths, layout.KEY_RUNS, run_id) / layout.PLAN_FILE)
        if (not isinstance(plan,dict) or type(plan.get('schema')) is not int or plan['schema']!=1 or plan.get('id')!=run_id
                or not isinstance(plan.get('accounts'),list) or not isinstance(plan.get('keys'),list)
                or not isinstance(plan.get('inventory'),dict)
                or not isinstance(plan['inventory'].get('keys'),list)
                or len(plan['keys'])>len(plan['inventory']['keys'])):
            raise SafetyError('Invalid native reset checkpoint')
        return _report(plan)


def create_plan(paths, profile, *, desktop=None):
    desktop = desktop or Desktop()
    desktop.verify_installation()
    profile = desktop.profile(paths, profile)
    with operation_lock(paths):
        before = signature(profile)
        registry, generations = [jsonc.read(profile / name, profile) for name in FILES]
        inventory = desktop.native(paths, 'inventory')
        selected = select_keys(registry, generations, inventory)
        if signature(profile) != before:
            raise SafetyError('Desktop registration changed during native inventory')
        run_id = new_id()
        run = layout.run_folder(paths, layout.KEY_RUNS, run_id)
        plan = {'schema': 1, 'id': run_id, 'profile': str(profile), 'before': before,
                'keys': selected, 'accounts': sorted(registry), 'inventory': inventory,
                'next': 0, 'in_progress': None, 'files_done': []}
        private_write(paths, run / layout.PLAN_FILE, plan)
        report = _report(plan)
        atomic_json(run / layout.RESULT_FILE, report, paths.state)
        return report


def verify_after_reset(paths, run_id, *, desktop=None):
    desktop = desktop or Desktop()
    """Observe the client's new registration; never create or delete a key."""
    if not re.fullmatch('[a-f0-9]{32}', run_id):
        raise SafetyError('Invalid native verification run ID')
    desktop.verify_installation()
    with operation_lock(paths):
        run = layout.run_folder(paths, layout.KEY_RUNS, run_id)
        plan = private_read(paths, run / layout.PLAN_FILE)
        # The public result is neither completion authority nor a prerequisite
        # for read-only verification. Legacy plans without a durable private
        # completion remain unverified; never infer completion from result.json.
        if (not isinstance(plan, dict) or type(plan.get('schema')) is not int
                or plan['schema'] != 1 or plan.get('id') != run_id
                or plan.get('reset_completed') is not True
                or not isinstance(plan.get('keys'), list)
                or type(plan.get('next')) is not int or plan['next'] != len(plan['keys'])
                or 'in_progress' not in plan or plan['in_progress'] is not None
                or plan.get('files_done') != list(FILES)):
            raise SafetyError('Native verification requires a completed private key reset checkpoint')
        profile = desktop.profile(paths, plan['profile'])
        before = signature(profile)
        registry, generations = [jsonc.read(profile / name, profile) for name in FILES]
        inventory = desktop.native(paths, 'inventory')
        if inventory.get('unknown_application_keys'):
            raise SafetyError('Unknown application key schema during verification')
        if not registry and generations:
            raise SafetyError('Unregistered key generations require separate review')
        selected = select_keys(registry, generations, inventory) if registry else []
        if signature(profile) != before:
            raise SafetyError('Desktop registration changed during verification; retry observation')
        old_public = {key['public_digest'] for key in plan['keys']}
        old_present = any(key['public_digest'] in old_public for key in inventory['keys'])
        verified = bool(selected) and not old_present
        report = {'run': run_id, 'status': Reset.VERIFIED if verified else Reset.NOT_VERIFIED,
                  'source': 'observed_native_public_keys_and_local_registration',
                  'registrations': len(registry), 'registered_keys': len(selected),
                  'old_selected_public_key_present': old_present,
                  'new_registered_public_key_verified': verified,
                  'previous_account_registration_present': bool(set(plan['accounts']) & set(registry)),
                  'new_account_registration_observed': bool(set(registry) - set(plan['accounts'])),
                  'account_and_organization_verified': False, 'ready_for_new_account': False}
        atomic_json(run / 'key-verification.json', report, paths.state)
        return report


def apply_plan(paths, run_id, *, server_step_complete=False, desktop=None):
    desktop = desktop or Desktop()
    if not re.fullmatch('[a-f0-9]{32}', run_id) or not server_step_complete:
        raise SafetyError('Native apply requires an exact reviewed run and server revocation confirmation')
    desktop.verify_installation()
    with operation_lock(paths):
        run = layout.run_folder(paths, layout.KEY_RUNS, run_id)
        plan = private_read(paths, run / layout.PLAN_FILE)
        if plan.get('schema') != 1 or plan.get('id') != run_id:
            raise SafetyError('Invalid native reset checkpoint')
        if plan.get('reset_completed') is True:
            raise SafetyError('Native reset already completed; do not reuse this plan')
        profile = desktop.profile(paths, plan['profile'])
        report = jsonc.read(run / layout.RESULT_FILE, paths.state)
        if report.get('status') == Reset.COMPLETED:
            raise SafetyError('Native reset already completed; do not reuse this plan')
        # Public reports may stop reuse, but cannot supply status or counts.
        report = _report(plan)
        desktop.no_owners()
        try:
            current = desktop.native(paths, 'inventory')
            present = {item['name']: item for item in current['keys']}
            # No new or changed keys anywhere in this application namespace.
            original = {item['name']: item for item in plan['inventory']['keys']}
            if current['unknown_application_keys'] or any(original.get(n) != k for n, k in present.items()):
                raise SafetyError('Native key inventory changed; review is required')
            selected = {k['name'] for k in plan['keys']}
            if any(n not in present for n in original if n not in selected):
                raise SafetyError('An unselected native key disappeared')
            for name, expected in plan['before'].items():
                file = guarded(profile / name, profile)
                if name in plan['files_done']:
                    if file.exists():
                        raise SafetyError('Desktop registration reappeared')
                elif signature(profile)[name] != expected:
                    # A crash directly after unlink is recoverable only after every key is absent.
                    if file.exists() or any(k['name'] in present for k in plan['keys']):
                        raise SafetyError('Desktop registration changed since review')
            for index, key in enumerate(plan['keys']):
                if index < plan['next']:
                    if key['name'] in present:
                        raise SafetyError('Deleted native key reappeared')
                    continue
                if key['name'] not in present:
                    if plan['in_progress'] != index:
                        raise SafetyError('Unscheduled native key disappearance')
                else:
                    desktop.no_owners()
                    if signature(profile) != plan['before']:
                        raise SafetyError('Desktop registration changed before key deletion')
                    plan['in_progress'] = index
                    private_write(paths, run / layout.PLAN_FILE, plan)
                    desktop.native(paths, 'delete', name=key['name'], public_digest=key['public_digest'])
                plan['next'], plan['in_progress'] = index + 1, None
                private_write(paths, run / layout.PLAN_FILE, plan)
            desktop.no_owners()
            final_inventory = desktop.native(paths, 'inventory')
            expected_inventory = [k for k in plan['inventory']['keys'] if k['name'] not in selected]
            if final_inventory != {'keys': expected_inventory, 'unknown_application_keys': 0}:
                raise SafetyError('Native key deletion could not be verified')
            for name in FILES:
                file = guarded(profile / name, profile)
                if name not in plan['files_done']:
                    if file.exists():
                        if signature(profile)[name] != plan['before'][name]:
                            raise SafetyError('Desktop registration changed during reset')
                        file.unlink()
                    plan['files_done'].append(name)
                    private_write(paths, run / layout.PLAN_FILE, plan)
            desktop.no_owners()
            if any(signature(profile).values()):
                raise SafetyError('Desktop registration reappeared after reset')
            plan['reset_completed'] = True
            private_write(paths, run / layout.PLAN_FILE, plan)
            report.update(status=Reset.COMPLETED, desktop_keys='selected_keys_deleted_and_absence_verified',
                          registration='removed_after_all_selected_keys', server='user_reported_complete_not_independently_verified')
            atomic_json(run / layout.RESULT_FILE, report, paths.state)
            return report
        except Exception as exc:
            report.update(status=Reset.FAILED_OR_PARTIAL, desktop_keys='checkpoint_requires_verification', error_type=type(exc).__name__)
            atomic_json(run / layout.RESULT_FILE, report, paths.state)
            raise SafetyError('Native reset stopped; its encrypted checkpoint supports verified continuation') from None
