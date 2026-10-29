from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
from claude_reset import safeio, state_location, backend_profiles, strict_wfp
from test_reset import paths


def test_mapped_remote_drive_rejected_before_any_file_lookup(tmp_path, paths, monkeypatch):
    api = SimpleNamespace(GetDriveTypeW=MagicMock(return_value=4))
    monkeypatch.setattr(safeio.ctypes, 'WinDLL', lambda *args, **kwargs: api)
    def forbidden(*args, **kwargs): raise AssertionError('Remote filesystem must not be touched')
    monkeypatch.setattr(safeio.Path, 'open', forbidden)
    monkeypatch.setattr(safeio.Path, 'lstat', forbidden)
    monkeypatch.setattr(safeio.Path, 'exists', forbidden)
    for action in (lambda: state_location.validate_root(tmp_path / 'state', tmp_path),
                   lambda: backend_profiles.import_profile(paths, tmp_path / 'profile.json'),
                   lambda: strict_wfp.Identity('app', str(tmp_path / 'fixture.exe')).validate()):
        with pytest.raises(safeio.SafetyError): action()


def test_codex_package_cannot_be_targeted_through_renamed_binary(tmp_path):
    path = tmp_path / 'OpenAI.Codex_1.0_x64__fixture' / 'renamed.exe'
    with pytest.raises(safeio.SafetyError): strict_wfp.Identity('app', str(path)).validate()
