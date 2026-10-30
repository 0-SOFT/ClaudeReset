import json
import pytest
from claude_reset.model.confirmation import Confirmation

from claude_reset.reset.cleanup import preview, audit, fixed_targets
from claude_reset.layout import Paths
from claude_reset.safeio import SafetyError
from claude_reset.reset.cleanup import prepare_wipe, WipeExecutor
from claude_reset.windows.system import DPAPI


def offline():
    return {'processes': []}


def test_credentials_removed_and_verified_without_public_names(paths):
    names = ['LegacyGeneric:target=Claude-secret-password-192.0.2.12']
    inspect = lambda: {'processes': [], 'credentials': tuple(names)}
    plan = prepare_wipe(paths, inspect=inspect)
    report = WipeExecutor(paths, inspect=inspect, delete_credential=names.remove).apply(
        plan, confirmation=Confirmation.ERASE, consent_id=plan.id, server_step_complete=True)
    assert not names and report['credentials_verified_absent'] and report['credentials_removed'] == 1
    assert 'secret-password' not in repr(plan) + json.dumps(report)
    saved = (paths.state / 'runs' / plan.id / 'result.json').read_text(encoding='utf8')
    assert all(value not in saved for value in ('secret-password', '192.0.2.12', 'private-user'))


def test_credential_change_refuses_before_file_delete(paths):
    names = []
    inspect = lambda: {'credentials': tuple(names)}
    target = paths.home / '.claude.json'
    target.write_text('keep')
    plan = prepare_wipe(paths, inspect=inspect, accept_unlisted=True)
    names.append('Claude-changed')
    with pytest.raises(SafetyError):
        WipeExecutor(paths, inspect=inspect).apply(plan, confirmation=Confirmation.ERASE,
            consent_id=plan.id, server_step_complete=True)
    assert target.read_text() == 'keep'


def test_credentials_remaining_are_partial(paths):
    inspect = lambda: {'credentials': ('Claude-token',)}
    plan = prepare_wipe(paths, inspect=inspect)
    with pytest.raises(SafetyError):
        WipeExecutor(paths, inspect=inspect, delete_credential=lambda _: None).apply(
            plan, confirmation=Confirmation.ERASE, consent_id=plan.id, server_step_complete=True)
    result = json.loads((paths.state / 'runs' / plan.id / 'result.json').read_text())
    assert result['status'] == 'failed_or_partial' and not result['credentials_verified_absent']


def test_cowork_export_required_and_rechecked(paths):
    from claude_reset.reset.native_worker import FAMILY
    profile = paths.local / 'Claude-Data' / FAMILY.lower()
    (profile / 'local-agent-mode-sessions').mkdir(parents=True)
    assert 'cowork_export' in prepared(paths).blockers
    calls = []
    plan = prepare_wipe(paths, inspect=offline, cowork_export='a' * 32)
    assert not plan.blockers
    execute(paths, plan, verify_exports=lambda *args: calls.append(args[1]))
    assert calls == ['a' * 32, 'a' * 32]
    target = paths.home / '.claude.json'
    target.write_text('keep')
    def refuse(*args):
        raise SafetyError('export changed')
    plan = prepare_wipe(paths, inspect=offline, accept_unlisted=True, cowork_export='a' * 32)
    with pytest.raises(SafetyError):
        execute(paths, plan, verify_exports=refuse)
    assert target.exists()


def test_uncovered_cowork_location_not_authorized_by_other_export(paths):
    work = paths.roaming / 'Claude/local-agent-mode-sessions'
    work.mkdir(parents=True)
    plan = prepare_wipe(paths, accept_unlisted=True, inspect=offline, cowork_export='a' * 32)
    assert not plan.blockers
    with pytest.raises(SafetyError):
        execute(paths, plan)
    assert work.exists()


def prepared(paths, mode='wipe'):
    return prepare_wipe(paths, mode, accept_unlisted=True, inspect=offline)


def execute(paths, plan, **options):
    return WipeExecutor(paths, inspect=offline, **options).apply(
        plan, confirmation=Confirmation.ERASE, consent_id=plan.id, server_step_complete=True)


@pytest.fixture
def paths(tmp_path):
    roots = [tmp_path / name for name in ('private-user', 'roaming', 'local', 'state')]
    for root in roots:
        root.mkdir()
    return Paths(*roots)


def test_fixed_inventory_sizes_and_no_secrets(paths):
    for target in fixed_targets(paths):
        if target.kind == 'file':
            target.path.write_bytes(b'secret-password 192.0.2.12')
        else:
            target.path.mkdir(parents=True)
            (target.path / 'secret-name').write_bytes(b'abc')
    (paths.home / '.claude.json.backup').write_bytes(b'ab')
    result = preview(paths, 'wipe_memory')
    assert result['complete'] and len(result['rows']) == 8
    assert result['bytes'] == 6 * 3 + len(b'secret-password 192.0.2.12') + 2
    public = json.dumps(result)
    for secret in ('secret-password', 'secret-name', '192.0.2.12', 'private-user'):
        assert secret not in public
    assert not audit(paths)['zero_file_remainder']


def test_audit_empty_contents_and_new_target(paths):
    package = fixed_targets(paths)[0].path
    package.mkdir(parents=True)
    assert audit(paths)['zero_file_remainder']
    assert not audit(paths)['zero_remainder']
    (paths.home / '.claude.json.new').write_text('new')
    assert not audit(paths)['zero_file_remainder']


def test_unreadable_is_not_zero(paths, monkeypatch):
    from claude_reset.reset import cleanup
    def denied(*_):
        raise PermissionError('private-user secret-password')
    monkeypatch.setattr(cleanup, 'tree_entries', denied)
    result = audit(paths)
    assert not result['complete'] and not result['zero_file_remainder']
    assert 'secret-password' not in json.dumps(result)


def test_bad_mode_and_overlapping_state_refused(paths):
    with pytest.raises(SafetyError):
        preview(paths, 'arbitrary')
    paths.state = paths.roaming / 'Claude/archive'
    with pytest.raises(SafetyError):
        preview(paths)


def test_link_refused_without_following(paths, monkeypatch):
    from claude_reset import safeio
    target = paths.home / '.claude'
    target.mkdir()
    original = safeio.reparse
    monkeypatch.setattr(safeio, 'reparse', lambda p: p == target or original(p))
    result = audit(paths)
    assert not result['complete'] and not result['zero_file_remainder']


@pytest.mark.parametrize('mode', ['wipe', 'wipe_memory'])
def test_wipe_and_dpapi_memory_byte_equality(paths, mode):
    profile = paths.home / '.claude'
    profile.mkdir()
    memory = b'\xff\x00\r\nsecret-password 192.0.2.12 private-user'
    (profile / 'CLAUDE.md').write_bytes(memory)
    (profile / 'settings.json').write_text('{}')
    (paths.home / '.claude.json.backup').write_text('old login')
    outside = paths.home / 'unrelated.txt'
    outside.write_bytes(b'keep')
    package = fixed_targets(paths)[0].path
    package.mkdir(parents=True)
    (package / 'state').write_bytes(b'old')
    plan = prepared(paths, mode)
    result = execute(paths, plan)
    assert result['audit_before_memory_restore']['zero_file_remainder']
    assert outside.read_bytes() == b'keep' and package.is_dir()
    assert not (profile / 'settings.json').exists()
    assert result['status'] == 'fixed_locations_wiped'
    assert result['accepted_unlisted_version']
    archive = paths.state / 'runs' / plan.id / 'memory.dpapi'
    if mode == 'wipe_memory':
        assert (profile / 'CLAUDE.md').read_bytes() == memory
        assert memory not in archive.read_bytes()
        assert json.loads(DPAPI().decrypt(archive.read_bytes()))['schema'] == 1
        assert result['memory'] == 'restored_verbatim'
        assert not result['audit']['zero_file_remainder']
    else:
        assert not profile.exists() and not archive.exists()
        assert result['audit']['zero_file_remainder']
    public = json.dumps(result) + (archive.parent / 'result.json').read_text('utf-8')
    assert all(secret not in public for secret in ('secret-password', '192.0.2.12', 'private-user'))


@pytest.mark.parametrize('change', ['word', 'id', 'server', 'new_file', 'modified', 'process'])
def test_wipe_refuses_without_mutation(paths, change):
    target = paths.home / '.claude.json'
    target.write_bytes(b'old')
    plan = prepared(paths)
    options = dict(confirmation=Confirmation.ERASE, consent_id=plan.id, server_step_complete=True)
    inspect = offline
    if change == 'word': options['confirmation'] = 'стереть'
    if change == 'id': options['consent_id'] = 'other'
    if change == 'server': options['server_step_complete'] = False
    if change == 'new_file': (paths.home / '.claude.json.new').write_bytes(b'new')
    if change == 'modified': target.write_bytes(b'changed')
    if change == 'process': inspect = lambda: {'processes': [{'kind': 'Code.exe'}]}
    before = target.read_bytes()
    with pytest.raises(SafetyError):
        WipeExecutor(paths, inspect=inspect).apply(plan, **options)
    assert target.read_bytes() == before


@pytest.mark.parametrize('kind', ['junction', 'symlink'])
def test_real_link_and_junction_refused(paths, kind):
    import subprocess
    outside = paths.home.parent / 'outside'
    outside.mkdir()
    sentinel = outside / 'sentinel'
    sentinel.write_bytes(b'untouched')
    profile = paths.home / '.claude'
    profile.mkdir()
    plan = prepared(paths)
    link = profile / 'memory'
    if kind == 'junction':
        # Native PowerShell creates only a junction in the pytest temporary profile.
        command = "New-Item -ItemType Junction -Path $args[0] -Target $args[1] | Out-Null"
        result = subprocess.run(['powershell.exe', '-NoProfile', '-Command',
                                 f"& {{ {command} }} '{link}' '{outside}'"], capture_output=True)
        assert result.returncode == 0
    else:
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            if getattr(exc, 'winerror', None) == 1314:
                pytest.skip('Создание symlink требует отсутствующей привилегии Windows (1314)')
            raise
    try:
        assert not preview(paths)['complete']
        with pytest.raises(SafetyError):
            execute(paths, plan)
        assert sentinel.read_bytes() == b'untouched'
    finally:
        # Remove only the exact temporary link, without recursive traversal.
        link.rmdir() if kind == 'junction' else link.unlink()


def test_encryption_failure_precedes_deletion(paths):
    profile = paths.home / '.claude'
    profile.mkdir()
    (profile / 'CLAUDE.md').write_bytes(b'memory')
    class Broken:
        def encrypt(self, _):
            raise RuntimeError('secret-password private-user')
    plan = prepared(paths, 'wipe_memory')
    with pytest.raises(SafetyError) as error:
        WipeExecutor(paths, inspect=offline, crypto=Broken()).apply(
            plan, confirmation=Confirmation.ERASE, consent_id=plan.id, server_step_complete=True)
    assert (profile / 'CLAUDE.md').read_bytes() == b'memory'
    assert 'secret-password' not in str(error.value)


def test_blocker_inventory_versions_and_extras(paths):
    profile = paths.home / '.claude'
    profile.mkdir()
    (profile / 'custom-source').write_bytes(b'keep')
    plan = prepare_wipe(paths, inspect=offline)
    assert set(plan.blockers) == {'extra_entries', 'unlisted_version'}
    with pytest.raises(SafetyError):
        execute(paths, plan)
    assert (profile / 'custom-source').exists()


def test_service_and_restore_sources_block_wipe(paths):
    from claude_reset.reset import cleanup
    state = cleanup.inspect_cleanup(windows=lambda: {'restore_sources': ['active']}, query=lambda _: {'running': True})
    plan = prepare_wipe(paths, inspect=lambda: state)
    assert set(plan.blockers) == {'restore_sources', 'cowork_service'}
    with pytest.raises(SafetyError):
        execute(paths, plan)


def test_restore_failure_keeps_encrypted_memory(paths):
    profile = paths.home / '.claude'
    profile.mkdir()
    (profile / 'CLAUDE.md').write_bytes(b'original')
    plan = prepared(paths, 'wipe_memory')
    def fail(*_):
        raise PermissionError('private-user')
    with pytest.raises(SafetyError):
        execute(paths, plan, restore=fail)
    run = paths.state / 'runs' / plan.id
    assert json.loads((run / 'result.json').read_text('utf-8'))['status'] == 'failed_or_partial'
    assert json.loads(DPAPI().decrypt((run / 'memory.dpapi').read_bytes()))['files']

@pytest.mark.parametrize('change', ['none', 'source', 'archive', 'missing'])
def test_multilocation_export_and_wipe(paths, monkeypatch, change):
    from claude_reset.reset import cowork
    monkeypatch.setattr(cowork, 'no_owners', lambda: None)
    sources = cowork.profiles(paths)
    for source in sources:
        work = source / 'local-agent-mode-sessions/task/outputs/result.txt'
        work.parent.mkdir(parents=True)
        work.write_text('private-user secret-password 192.0.2.12')
    outside = sources[0].parent / 'unrelated'
    outside.mkdir()
    (outside / 'keep').write_bytes(b'unchanged')
    result = cowork.export_all(paths)
    assert result['profiles'] == 6
    runs = tuple(result['runs'])
    if change == 'missing': runs = runs[:1]
    if change == 'source':
        (sources[0] / 'local-agent-mode-sessions/new.txt').write_text('new')
    if change == 'archive':
        (paths.state / 'cowork-runs' / runs[0] / 'files/0.dpapi').write_bytes(b'bad')
    inspect = lambda: {'desktop_versions': ['future-version']}
    plan = prepare_wipe(paths, inspect=inspect, cowork_export=runs)
    def apply():
        return WipeExecutor(paths, inspect=inspect).apply(plan, confirmation=Confirmation.ERASE,
            consent_id=plan.id, server_step_complete=True)
    assert not plan.blockers
    if change == 'none':
        report = apply()
        assert report['cowork_source_removed'] and report['audit']['zero_file_remainder']
        assert all(not (p / 'local-agent-mode-sessions').exists() for p in sources)
        public = json.dumps(report) + json.dumps(result)
        for file in paths.state.rglob('result.json'):
            public += file.read_text('utf8')
        assert all(s not in public for s in ('private-user', 'secret-password', '192.0.2.12'))
        recovered = cowork.recover_export(paths, runs[0])
        assert next(recovered.rglob('*.txt')).read_text() == 'private-user secret-password 192.0.2.12'
    else:
        with pytest.raises(SafetyError) as error:
            apply()
        assert 'private-user' not in str(error.value)
        assert all(p.exists() for p in sources)
    assert (outside / 'keep').read_bytes() == b'unchanged'


def test_cowork_arbitrary_profile_refused(paths):
    from claude_reset.reset import cowork
    with pytest.raises(SafetyError):
        cowork.create_export(paths, paths.home / 'arbitrary', include_work=True)
