import json
import pytest
from test_reset import paths, write, FakeCrypto
from claude_reset import cowork as cw
from claude_reset import desktop_keys as dk
from claude_reset.safeio import SafetyError


@pytest.fixture
def setup_cowork(paths, monkeypatch):
    profile = paths.local / 'desktop'
    write(profile / 'local-agent-mode-sessions/session/.claude/memory/MEMORY.md', '')
    (profile / 'local-agent-mode-sessions/session/.claude/memory/MEMORY.md').write_bytes(b'verbatim\r\nmemory')
    write(profile / 'local-agent-mode-sessions/session/outputs/result.txt', 'RESULT')
    write(profile / 'local-agent-mode-sessions/session/.audit-key', 'NEVER EXPORT')
    write(profile / 'local-agent-mode-sessions/session/.claude/.credentials.json', '{"token":"DO NOT EXPORT"}')
    write(profile / 'vm_bundles/claudevm.bundle/rootfs.vhdx', 'SYSTEM IMAGE')
    write(profile / 'vm_bundles/claudevm.bundle/smol-bin.vhdx', 'SYSTEM TOOL IMAGE')
    monkeypatch.setattr(cw, 'profile_path', lambda paths, value: profile)
    monkeypatch.setattr(cw, 'no_owners', lambda: None)
    monkeypatch.setattr(cw, 'DPAPI', FakeCrypto)
    monkeypatch.setattr(dk, 'DPAPI', FakeCrypto)
    return profile


def test_cowork_export_reset_recover_preserves_images(paths, setup_cowork):
    profile = setup_cowork
    report = cw.create_export(paths, profile, include_work=True)
    assert report['status'] == 'encrypted_export_verified'
    assert report['memory_files'] == report['work_files'] == 1
    recovered = cw.recover_export(paths, report['run'])
    assert (recovered / 'memory/000000.md').read_bytes() == b'verbatim\r\nmemory'
    assert (recovered / 'work/000001.txt').read_bytes() == b'RESULT'
    result = cw.reset_exported(paths, report['run'], server_step_complete=True)
    assert result['status'] == 'completed'
    assert not (profile / 'local-agent-mode-sessions').exists()
    assert (profile / 'vm_bundles/claudevm.bundle/rootfs.vhdx').read_text() == 'SYSTEM IMAGE'
    assert (profile / 'vm_bundles/claudevm.bundle/smol-bin.vhdx').exists()


@pytest.mark.parametrize('change', ['none', 'source', 'archive', 'memory_only'])
def test_cleanup_export_verification(paths, setup_cowork, change):
    report = cw.create_export(paths, setup_cowork, include_work=change != 'memory_only')
    if change == 'source':
        write(setup_cowork / 'local-agent-mode-sessions/new.txt', 'changed')
    if change == 'archive':
        write(paths.state / 'cowork-runs' / report['run'] / 'files/0.dpapi', 'bad')
    if change == 'none':
        result = cw.verify_export_for_cleanup(paths, report['run'])
        assert result['status'] == 'cowork_export_verified'
        assert str(setup_cowork) not in json.dumps(result)
    else:
        with pytest.raises(Exception):
            cw.verify_export_for_cleanup(paths, report['run'])
    assert (setup_cowork / 'local-agent-mode-sessions').exists()


def test_dirty_vm_is_inventory_only_and_never_reset(paths, setup_cowork, monkeypatch):
    original = cw.inventory
    def dirty(profile):
        result = original(profile)
        result['consistent'] = False
        return result
    monkeypatch.setattr(cw, 'inventory', dirty)
    result = cw.create_export(paths, setup_cowork, include_work=True)
    assert result['blockers'] and result['status'] == 'inventory_complete'
    with pytest.raises(SafetyError):
        cw.reset_exported(paths, result['run'], server_step_complete=True)
    assert (setup_cowork / 'local-agent-mode-sessions').exists()


def test_new_work_after_export_blocks_deletion(paths, setup_cowork):
    result = cw.create_export(paths, setup_cowork, include_work=True)
    write(setup_cowork / 'local-agent-mode-sessions/session/outputs/new.txt', 'NEW')
    with pytest.raises(SafetyError):
        cw.reset_exported(paths, result['run'], server_step_complete=True)
    assert (setup_cowork / 'local-agent-mode-sessions/session/outputs/new.txt').read_text() == 'NEW'


def test_corrupt_archive_blocks_reset(paths, setup_cowork):
    result = cw.create_export(paths, setup_cowork)
    write(paths.state / 'cowork-runs' / result['run'] / 'files/0.dpapi', 'BAD')
    with pytest.raises(Exception):
        cw.reset_exported(paths, result['run'], server_step_complete=True)
    assert (setup_cowork / 'local-agent-mode-sessions').exists()


def test_work_with_credentials_blocks_export_but_memory_preserved(paths, setup_cowork):
    token = 'sk-ant-' + 'x'*32
    write(setup_cowork / 'local-agent-mode-sessions/session/outputs/token.txt', token)
    with pytest.raises(SafetyError):
        cw.create_export(paths, setup_cowork, include_work=True)
    result = cw.create_export(paths, setup_cowork, include_work=False)
    assert result['memory_files'] == 1 and result['work_files'] == 0


@pytest.mark.parametrize('path', ['session/outputs/.credentials.json', 'session/outputs/.ssh/key.md',
    'session/.audit-key', 'session/.config/chromium/Cookies', 'session/outputs/config.json'])
def test_cowork_credentials_never_selected(path):
    assert cw.category(path) is None


def test_invalid_vhdx_rejected_before_parsing():
    import io
    with pytest.raises(SafetyError):
        cw.open_extfs(io.BytesIO(b'vhdxfile' + b'\0'*300000))
