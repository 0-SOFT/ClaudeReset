import os
import pytest
from claude_reset.install_journal import _LocalFile, ProtectedJournal
from claude_reset.install_transaction import Transaction
from claude_reset.safeio import SafetyError

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows file sharing and write-through I/O')


def value(): return Transaction(None, 'a'*32, 'b'*64).value


def test_exclusive_lock_actual_file_and_restart_readback(tmp_path):
    with _LocalFile(tmp_path) as journal:
        assert journal.load() is None
        with pytest.raises(SafetyError): _LocalFile(tmp_path)
        journal.save(value())
        assert journal.load() == value()
        with pytest.raises(OSError): (tmp_path/'install.lock').unlink()
    with _LocalFile(tmp_path) as journal:
        assert journal.load() == value()
    with pytest.raises(SafetyError): journal.save(value())


def test_atomic_replace_and_generation_collision(tmp_path):
    with _LocalFile(tmp_path) as journal:
        original = value(); journal.save(original)
        original['entries'].append({'step': 'inventory_backup', 'state': 'intent'})
        journal.save(original)
        assert journal.load() == original
        with pytest.raises(SafetyError): journal.save({**original, 'generation': 'c'*32})
        assert journal.load() == original
        assert list(tmp_path.glob('journal-*.tmp')) == []


def test_failed_replace_preserves_prior_complete_record(tmp_path):
    from claude_reset.windows_pin import PinnedFile
    with _LocalFile(tmp_path) as journal:
        original = value(); journal.save(original)
        changed = {**original, 'state': 'recovering'}
        with PinnedFile(tmp_path/'install-journal.json', limit=65536):
            with pytest.raises(SafetyError, match='commit'): journal.save(changed)
        assert journal.load() == original
        assert len(list(tmp_path.glob('journal-*.tmp'))) == 1


def test_corrupt_journal_is_not_replaced(tmp_path):
    (tmp_path/'install-journal.json').write_bytes(b'{"schema":1,"schema":2}')
    with _LocalFile(tmp_path) as journal:
        with pytest.raises(SafetyError): journal.save(value())
    assert (tmp_path/'install-journal.json').read_bytes() == b'{"schema":1,"schema":2}'
