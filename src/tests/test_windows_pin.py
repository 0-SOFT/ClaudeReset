import hashlib
import pytest
from claude_reset.windows_pin import PinnedFile
from claude_reset.safeio import SafetyError


def test_pin_denies_overwrite_delete_and_replacement_until_closed(tmp_path):
    path = tmp_path/'input.json'; path.write_bytes(b'fixture')
    replacement = tmp_path/'other.json'; replacement.write_bytes(b'other')
    with PinnedFile(path, expected_sha256=hashlib.sha256(b'fixture').hexdigest(), limit=1024) as pin:
        assert pin.data == b'fixture'
        assert path.read_bytes() == b'fixture'
        with pytest.raises(OSError): path.write_bytes(b'changed')
        with pytest.raises(OSError): path.unlink()
        with pytest.raises(OSError): replacement.replace(path)
    replacement.replace(path)
    assert path.read_bytes() == b'other'


def test_bad_hash_and_size_release_handle(tmp_path):
    path = tmp_path/'input.json'; path.write_bytes(b'fixture')
    with pytest.raises(SafetyError): PinnedFile(path, expected_sha256='0'*64)
    with pytest.raises(SafetyError): PinnedFile(path, limit=3)
    path.unlink()
