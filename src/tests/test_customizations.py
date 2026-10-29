import pytest
from test_reset import paths, write, FakeCrypto
from claude_reset import customizations as cs, desktop_keys as dk
from claude_reset.safeio import SafetyError, remove_owned


@pytest.fixture
def customization(paths, monkeypatch):
    root = paths.home / '.claude'
    write(root / 'scripts/user.py', 'print("source")')
    write(root / 'unknown-old-auth.json', '{"token":"synthetic credential"}')
    write(root / 'memory/MEMORY.md', 'MEMORY')
    monkeypatch.setattr(cs, 'no_code_owners', lambda: None)
    monkeypatch.setattr(dk, 'DPAPI', FakeCrypto)
    return root


def test_sources_exported_without_importing_old_auth(paths, customization):
    plan = cs.create_plan(paths, ['scripts'])
    destination = cs.recover(paths, plan['run'])
    assert (destination / 'scripts/user.py').read_text() == 'print("source")'
    assert not (destination / 'unknown-old-auth.json').exists()
    assert cs.apply_plan(paths, plan['run'], server_step_complete=True)['status'] == 'completed'
    assert (customization / 'memory/MEMORY.md').read_text() == 'MEMORY'
    assert not (customization / 'scripts').exists()


def test_credential_in_source_is_not_archived(paths, customization):
    write(customization / 'scripts/secret.txt', 'sk-ant-' + 'z'*40)
    with pytest.raises(SafetyError):
        cs.create_plan(paths, ['scripts'])
    assert (customization / 'scripts').exists()


def test_new_customization_blocks_scope_expansion(paths, customization):
    plan = cs.create_plan(paths, ['scripts'])
    write(customization / 'new-source.txt','NEW')
    with pytest.raises(SafetyError):
        cs.apply_plan(paths, plan['run'], server_step_complete=True)


def test_readonly_owned_file_can_be_deleted(paths):
    import os,stat
    if os.name != 'nt':
        pytest.skip('Windows read-only attribute')
    target = paths.home / 'readonly-owned'
    write(target / 'file.txt', 'owned')
    (target / 'file.txt').chmod(stat.S_IREAD)
    remove_owned(target, paths.home)
    assert not target.exists()
