import ctypes as C
from pathlib import Path
from types import SimpleNamespace
import uuid
import pytest
from claude_reset import install_metadata_commit as m
from claude_reset.install_journal import _LocalFile
from claude_reset.windows_pin import PinnedFile
from claude_reset.safeio import SafetyError


def fixture(tmp_path,monkeypatch):
    destination=tmp_path/'stage-receipts.json';destination.write_bytes(b'old')
    temporary=tmp_path/('receipt-'+uuid.uuid4().hex+'.tmp');temporary.write_bytes(b'new')
    native=_LocalFile(tmp_path)
    real=native.api.MoveFileExW;events=[]
    def move(*args):events.append('move');return real(*args)
    journal=SimpleNamespace(directory=tmp_path,lock=native.lock,api=SimpleNamespace(MoveFileExW=move))
    monkeypatch.setattr(m.time,'sleep',lambda delay:events.append('wait'))
    return native,journal,temporary,destination,events


def test_reader_release_allows_only_unchanged_bounded_retry(tmp_path,monkeypatch):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native,PinnedFile(dest) as reader:
        def released(delay):
            assert dest.read_bytes()==b'old' and temp.read_bytes()==b'new'
            events.append('wait');reader.close()
        monkeypatch.setattr(m.time,'sleep',released)
        m.replace_metadata(journal,temp,dest,b'new')
        assert events==['move','wait','move'] and dest.read_bytes()==b'new' and not temp.exists()


def test_persistent_reader_refuses_after_bound_and_preserves_both_files(tmp_path,monkeypatch):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native,PinnedFile(dest):
        with pytest.raises(SafetyError,match=r'Win32 error (5|32)'):m.replace_metadata(journal,temp,dest,b'new')
        assert events.count('move')==4 and events.count('wait')==3
        assert dest.read_bytes()==b'old' and temp.read_bytes()==b'new'


@pytest.mark.parametrize('fault',['source','destination','same-bytes-replacement','lock'])
def test_changed_identity_or_bytes_never_reaches_second_rename(tmp_path,monkeypatch,fault):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native,PinnedFile(dest) as reader:
        def drift(delay):
            reader.close()
            if fault=='source':temp.write_bytes(b'changed')
            if fault=='destination':dest.write_bytes(b'foreign')
            if fault=='same-bytes-replacement':dest.rename(dest.with_suffix('.old'));dest.write_bytes(b'old')
            if fault=='lock':journal.lock=None
        monkeypatch.setattr(m.time,'sleep',drift)
        with pytest.raises(SafetyError,match='no retry'):m.replace_metadata(journal,temp,dest,b'new')
        assert events==['move'] and temp.exists()


def test_failure_report_after_actual_rename_is_not_promoted_or_replayed(tmp_path,monkeypatch):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native:
        real=journal.api.MoveFileExW
        def uncertain(*args):
            assert real(*args);C.set_last_error(5);return 0
        journal.api.MoveFileExW=uncertain
        with pytest.raises(SafetyError,match='outcome requires recovery'):m.replace_metadata(journal,temp,dest,b'new')
        assert events==['move','wait'] and dest.read_bytes()==b'new' and not temp.exists()


def test_other_native_errors_are_not_retried(tmp_path,monkeypatch):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native:
        def error(*args):events.append('move');C.set_last_error(87);return 0
        journal.api.MoveFileExW=error
        with pytest.raises(SafetyError,match='Win32 error 87'):m.replace_metadata(journal,temp,dest,b'new')
        assert events==['move'] and dest.read_bytes()==b'old' and temp.read_bytes()==b'new'


@pytest.mark.parametrize('fault',['name','parent','bytes','hardlink'])
def test_rename_scope_and_source_identity_are_fixed(tmp_path,monkeypatch,fault):
    native,journal,temp,dest,events=fixture(tmp_path,monkeypatch)
    with native:
        if fault=='name':dest=tmp_path/'other.json'
        if fault=='parent':dest=tmp_path.parent/'stage-receipts.json'
        if fault=='hardlink':(tmp_path/'alias').hardlink_to(temp)
        with pytest.raises(SafetyError):m.replace_metadata(journal,temp,dest,b'bad' if fault=='bytes' else b'new')
        assert not events and temp.read_bytes()==b'new'
