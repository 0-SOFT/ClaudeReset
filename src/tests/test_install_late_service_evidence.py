"""Recovery must stop between owned deletions when later evidence appears."""
import pytest
from claude_reset import install_rollback as rollback
from claude_reset.safeio import SafetyError
from test_install_recovery import staged,run


def test_late_service_metadata_stops_remaining_file_deletions(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        target=store.journal.directory/'service-marker-receipts.json'
        deleted=[];original=rollback._mark_delete
        def remove(pin):
            original(pin);deleted.append(pin.path)
            target.write_bytes(b'late unknown service ownership')
        monkeypatch.setattr(rollback,'_mark_delete',remove)
        with pytest.raises(SafetyError,match='without durable service intent'):
            run(store,tx)
        assert len(deleted)==1 and not deleted[0].exists()
        assert target.read_bytes()==b'late unknown service ownership'
        assert store.journal.load()['state']=='recovery_required'
        assert all((store.directories['root'].path/n).exists()
                   for n in source.pins if store.directories['root'].path/n not in deleted)
        before=list(deleted)
        with pytest.raises(SafetyError,match='without durable service intent'):
            run(store,tx)
        assert deleted==before
