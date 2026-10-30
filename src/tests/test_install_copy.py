import hashlib
import pytest
from claude_reset.windows.pin import PinnedFile
from claude_reset.backend.payload_copy import copy_pinned
from claude_reset.safeio import SafetyError


def test_stream_copy_rewinds_and_pins_actual_destination(tmp_path):
    data=bytes(range(256))*1025
    source=tmp_path/'source';source.write_bytes(data)
    with PinnedFile(source) as pin:
        for name in ('copy1','copy2'):
            with copy_pinned(pin,tmp_path/name) as copied:
                assert copied.sha256==hashlib.sha256(data).hexdigest()
                assert (tmp_path/name).read_bytes()==data
                with pytest.raises(OSError):(tmp_path/name).write_bytes(b'changed')
        with pytest.raises(OSError):source.unlink()


def test_existing_file_is_not_truncated(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'payload')
    target=tmp_path/'target';target.write_bytes(b'previous owner')
    with PinnedFile(source) as pin:
        with pytest.raises(FileExistsError):copy_pinned(pin,target)
    assert target.read_bytes()==b'previous owner'


def test_closed_pin_creates_nothing(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'payload')
    pin=PinnedFile(source);pin.close()
    with pytest.raises(SafetyError):copy_pinned(pin,tmp_path/'target')
    assert not (tmp_path/'target').exists()


def test_failed_digest_preserves_partial_file_for_transaction_recovery(tmp_path):
    source=tmp_path/'source';source.write_bytes(b'payload')
    with PinnedFile(source) as pin:
        pin.sha256='0'*64
        with pytest.raises(SafetyError):copy_pinned(pin,tmp_path/'target')
        assert pin.handle
    assert (tmp_path/'target').read_bytes()==b'payload'


def test_flush_failure_preserves_file_and_source_handle(tmp_path,monkeypatch):
    source=tmp_path/'source';source.write_bytes(b'payload')
    def fail(_):raise OSError('simulated destination flush failure')
    monkeypatch.setattr('claude_reset.backend.payload_copy.os.fsync',fail)
    with PinnedFile(source) as pin:
        with pytest.raises(OSError):copy_pinned(pin,tmp_path/'target')
        assert pin.handle
    assert (tmp_path/'target').read_bytes()==b'payload'
