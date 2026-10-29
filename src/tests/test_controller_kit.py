"""Prebuilt controller kit: used only with matching sources and intact files."""
import hashlib
import json

import pytest

from claude_reset import l1_install
from claude_reset.safeio import SafetyError


@pytest.fixture
def root(tmp_path):
    (tmp_path / 'src/claude_reset').mkdir(parents=True)
    (tmp_path / 'src/launcher.py').write_text('main')
    (tmp_path / 'src/launcher_run.py').write_text('run')
    (tmp_path / 'src/claude_reset/core.py').write_text('code')
    return tmp_path


def make_kit(root, *, digest=None):
    kit = root / 'controller'
    kit.mkdir()
    files = {}
    for name, _, _ in l1_install.BUILDS:
        data = f'{name} binary'.encode()
        (kit / f'{name}.exe').write_bytes(data)
        files[f'{name}.exe'] = hashlib.sha256(data).hexdigest()
    manifest = {'schema': 1, 'source_sha256': digest or l1_install.source_digest(root), 'files': files}
    (kit / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return kit


def test_source_checkout_has_no_kit(root):
    assert l1_install.controller_kit(root=root) is None


def test_matching_kit_is_used(root):
    kit = make_kit(root)
    assert l1_install.controller_kit(root=root) == kit


def test_kit_from_other_sources_is_not_used(root):
    make_kit(root)
    (root / 'src/claude_reset/core.py').write_text('updated code')
    assert l1_install.controller_kit(root=root) is None


def test_changed_executable_is_refused(root):
    kit = make_kit(root)
    (kit / 'ClaudeReset.exe').write_bytes(b'replaced')
    with pytest.raises(SafetyError, match='повреждён'):
        l1_install.controller_kit(root=root)
    (kit / 'ClaudeResetRun.exe').unlink()
    with pytest.raises(SafetyError):
        l1_install.controller_kit(root=root)


def test_broken_manifest_is_refused(root):
    kit = make_kit(root)
    (kit / 'manifest.json').write_text('{not json')
    with pytest.raises(SafetyError):
        l1_install.controller_kit(root=root)


def test_digest_covers_names_and_contents(root):
    first = l1_install.source_digest(root)
    (root / 'src/claude_reset/new.py').write_text('')
    second = l1_install.source_digest(root)
    (root / 'src/claude_reset/new.py').rename(root / 'src/claude_reset/other.py')
    assert len({first, second, l1_install.source_digest(root)}) == 3


def test_install_prefers_the_kit_and_builds_only_without_it(monkeypatch, tmp_path):
    built = []
    monkeypatch.setattr(l1_install, 'build_executables', lambda out: built.append(out) or out / 'dist')
    monkeypatch.setattr(l1_install, 'controller_kit', lambda: tmp_path / 'kit')
    assert l1_install.prepare_executables(tmp_path) == tmp_path / 'kit' and not built
    monkeypatch.setattr(l1_install, 'controller_kit', lambda: None)
    assert l1_install.prepare_executables(tmp_path) == tmp_path / 'dist' and built == [tmp_path]
    assert l1_install.Deps.build.__name__ == 'prepare_executables'
