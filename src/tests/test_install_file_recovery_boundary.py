"""Closed client verification must hold between each owned file deletion."""
import pytest
from claude_reset import install_rollback as rollback
from claude_reset.safeio import SafetyError
from test_install_recovery import staged,run


def test_file_only_cleanup_stops_after_boundary_loss(tmp_path,monkeypatch):
    with staged(tmp_path,monkeypatch) as (store,source,tx):
        closed={'value':True};deleted=[];original=rollback._mark_delete
        def remove(pin):
            original(pin);deleted.append(pin.path);closed['value']=False
        monkeypatch.setattr(rollback,'_mark_delete',remove)
        with pytest.raises(SafetyError,match='closed'):
            run(store,tx,closed=lambda generation:closed['value'])
        assert len(deleted)==1 and not deleted[0].exists()
        assert store.journal.load()['state']=='recovery_required'
        assert all((store.directories['root'].path/n).exists()
                   for n in source.pins if store.directories['root'].path/n not in deleted)
