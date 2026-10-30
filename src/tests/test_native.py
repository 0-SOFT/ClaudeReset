import copy
import json
import hashlib
import pytest
from test_reset import paths, write, FakeCrypto
from claude_reset.reset import desktop_keys as dk
from claude_reset.safeio import SafetyError
from claude_reset.windows.cng import KEY_PATTERN
from scripted import Scripted

ACCOUNT = '10000000-0000-4000-8000-000000000001'
OTHER = '20000000-0000-4000-8000-000000000002'


@pytest.mark.parametrize('tamper', [None, 'asar', 'native', 'version', 'family'])
@pytest.mark.parametrize('version', tuple(dk.VALIDATED_INSTALLATIONS))
def test_installation_binds_package_and_both_code_files(tmp_path, monkeypatch, tamper, version):
    resources = tmp_path / 'app/resources'
    asar = resources / 'app.asar'
    native = resources / 'app.asar.unpacked/node_modules/@ant/claude-native/claude-native-binding.node'
    asar.parent.mkdir(parents=True)
    native.parent.mkdir(parents=True)
    asar.write_bytes(b'reviewed javascript')
    native.write_bytes(b'reviewed native binding')
    validated = {version: tuple(hashlib.sha256(p.read_bytes()).hexdigest() for p in (asar, native))}
    package = {'Version':version, 'PackageFamilyName':dk.FAMILY, 'InstallLocation':str(tmp_path)}
    if tamper in ('asar', 'native'):
        (asar if tamper == 'asar' else native).write_bytes(b'changed code')
    elif tamper == 'version':
        package['Version'] = '99.0.0.0'
    elif tamper == 'family':
        package['PackageFamilyName'] = 'OtherPackage'
    if tamper:
        with pytest.raises(SafetyError):
            dk.verify_installation(package=package, validated=validated)
    else:
        dk.verify_installation(package=package, validated=validated)


def test_unconfirmed_registration_cannot_authorize_key_deletion():
    with pytest.raises(SafetyError, match='registration schema'):
        dk.select_keys({ACCOUNT:'pku1:1234567890123:'+'a'*64+':'+OTHER}, {},
                       {'keys':[key()], 'unknown_application_keys':0})


def key(account=ACCOUNT, generation=0, digest='a' * 64):
    return {'name': 'Claude-HwKey-device-registry-' + account + (f':g{generation}' if generation else ''),
            'account': account, 'generation': generation, 'public_digest': digest}


@pytest.fixture
def native_setup(paths, monkeypatch):
    profile = paths.local / 'desktop'
    write(profile / dk.FILES[0], json.dumps({ACCOUNT: 'pk1:' + 'a' * 64 + ':' + OTHER}))
    inventory = {'keys': [key()], 'unknown_application_keys': 0}
    calls = []
    def call(paths, operation, **args):
        if operation == 'inventory':
            return copy.deepcopy(inventory)
        assert operation == 'delete'
        target = next(k for k in inventory['keys'] if k['name'] == args['name'])
        assert target['public_digest'] == args['public_digest']
        inventory['keys'].remove(target)
        calls.append(args['name'])
        return {'deleted_key_absent': True}
    desktop = Scripted(verify_installation=None, no_owners=None, profile=lambda paths, value: profile, native=call)
    return profile, inventory, calls, desktop


def test_native_plan_deletes_only_selected_generations(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    inventory['keys'] += [key(generation=1, digest='b'*64), key(OTHER)]
    inventory['keys'].sort(key=lambda k: k['name'])
    plan = dk.create_plan(paths, profile, desktop=desktop)
    assert plan['keys'] == 2 and plan['unselected_keys_preserved'] == 1
    assert ACCOUNT not in json.dumps(plan)
    result = dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    assert result['status'] == 'completed'
    assert inventory['keys'] == [key(OTHER)]
    assert len(calls) == 2 and not (profile / dk.FILES[0]).exists()


def test_native_requires_server_ack(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    with pytest.raises(SafetyError):
        dk.apply_plan(paths, plan['run'], desktop=desktop)
    assert not calls and len(inventory['keys']) == 1


def test_verify_new_client_key_redacts_accounts_and_preserves_receipt(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    receipt = paths.state / 'key-runs' / plan['run'] / 'result.json'
    original = receipt.read_bytes()
    inventory['keys'] = [key(OTHER, digest='b'*64)]
    write(profile / dk.FILES[0], json.dumps({OTHER: 'pk1:' + 'b'*64 + ':' + ACCOUNT}))
    result = dk.verify_after_reset(paths, plan['run'], desktop=desktop)
    assert result['status'] == 'verified' and result['new_account_registration_observed']
    assert not result['old_selected_public_key_present']
    assert not result['account_and_organization_verified'] and not result['ready_for_new_account']
    assert ACCOUNT not in json.dumps(result) and OTHER not in json.dumps(result)
    assert receipt.read_bytes() == original and len(calls) == 1


def test_verify_absent_new_registration_is_not_success(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    result = dk.verify_after_reset(paths, plan['run'], desktop=desktop)
    assert result['status'] == 'not_verified' and not result['new_registered_public_key_verified']


def test_verify_detects_returned_old_public_key(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    inventory['keys'] = [key()]
    write(profile / dk.FILES[0], json.dumps({ACCOUNT: 'pk1:' + 'a'*64 + ':' + OTHER}))
    result = dk.verify_after_reset(paths, plan['run'], desktop=desktop)
    assert result['status'] == 'not_verified' and result['old_selected_public_key_present']


def test_verify_requires_completed_reset_and_consistent_registration(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    with pytest.raises(SafetyError):
        dk.verify_after_reset(paths, plan['run'], desktop=desktop)
    dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    inventory['keys'] = [key(OTHER, digest='b'*64)]
    write(profile / dk.FILES[0], json.dumps({OTHER: 'pk1:' + 'c'*64 + ':' + ACCOUNT}))
    with pytest.raises(SafetyError):
        dk.verify_after_reset(paths, plan['run'], desktop=desktop)


def test_verify_allows_same_account_with_regenerated_key(paths, native_setup):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    inventory['keys'] = [key(digest='b'*64)]
    write(profile / dk.FILES[0], json.dumps({ACCOUNT: 'pk1:' + 'b'*64 + ':' + OTHER}))
    result = dk.verify_after_reset(paths, plan['run'], desktop=desktop)
    assert result['status'] == 'verified' and result['previous_account_registration_present']
    assert not result['new_account_registration_observed']


@pytest.mark.parametrize('change', ['registry', 'key', 'new_key', 'generation'])
def test_native_drift_blocks_before_deletion(paths, native_setup, change):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    if change == 'registry':
        write(profile / dk.FILES[0], '{}')
    elif change == 'generation':
        write(profile / dk.FILES[1], json.dumps({ACCOUNT: 1}))
    elif change == 'key':
        inventory['keys'][0]['public_digest'] = 'c' * 64
    else:
        inventory['keys'].append(key(OTHER))
    with pytest.raises(SafetyError):
        dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    assert not calls


def test_native_crash_after_delete_can_verify_and_resume(paths, native_setup, monkeypatch):
    profile, inventory, calls, desktop = native_setup
    plan = dk.create_plan(paths, profile, desktop=desktop)
    original = desktop.answers['native']
    def crash(paths, operation, **args):
        value = original(paths, operation, **args)
        if operation == 'delete':
            raise OSError('synthetic interrupted response')
        return value
    desktop.answers['native'] = crash
    with pytest.raises(SafetyError):
        dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)
    assert (profile / dk.FILES[0]).exists()
    desktop.answers['native'] = original
    assert dk.apply_plan(paths, plan['run'], server_step_complete=True, desktop=desktop)['status'] == 'completed'
    assert len(calls) == 1


@pytest.mark.parametrize('name', ['Windows Hello', 'Claude-HwKey-anything',
    'Claude-HwKey-device-registry-' + ACCOUNT + ':g0',
    'Claude-HwKey-device-registry-' + ACCOUNT + ':g1/other'])
def test_foreign_key_names_are_not_selectable(name):
    assert not KEY_PATTERN.fullmatch(name)


def test_unregistered_generation_cannot_be_removed():
    with pytest.raises(SafetyError):
        dk.select_keys({ACCOUNT:'pk1:'+'a'*64+':'+OTHER}, {OTHER:1}, {'keys':[key()], 'unknown_application_keys':0})


def test_registration_must_match_public_key():
    with pytest.raises(SafetyError):
        dk.select_keys({ACCOUNT:'pk1:'+'b'*64+':'+OTHER}, {}, {'keys':[key()], 'unknown_application_keys':0})
