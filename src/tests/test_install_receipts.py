import copy
import json
import pytest
from claude_reset.install_receipts import Receipts,validate
from claude_reset.install_stage import _stage_payload,_inspect_staging
from claude_reset.safeio import SafetyError
from claude_reset.windows_pin import PinnedFile
from test_install_stage import fixture


def statuses(store):
    report=_inspect_staging(store,'a'*32)
    assert report['client_admission'] is False and report['mutation_authorized'] is False
    return {row['name']:row['status'] for row in report['files']}


def test_complete_receipts_survive_closed_payload_pins(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        value=Receipts(store.journal).load()
        assert len(value['files'])==23
        assert {r['state'] for r in value['files']}=={'complete'}
        assert set(statuses(store).values())=={'owned_complete'}
        with pytest.raises(SafetyError):Receipts(store.journal).begin()


def test_failure_after_receipt_leaves_owned_empty_file(tmp_path,monkeypatch):
    real=Receipts.created
    def fail(self,handle):
        real(self,handle)
        raise OSError('injected before first byte')
    monkeypatch.setattr(Receipts,'created',fail)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(OSError):_stage_payload(store,source,'a'*32,lambda g:True)
        row=Receipts(store.journal).load()['files'][0]
        path=store.directories['root'].path/row['name']
        assert path.read_bytes()==b''
        assert row['state']=='created'
        assert statuses(store)[row['name']]=='owned_partial'


def test_failed_creation_receipt_never_claims_the_file(tmp_path,monkeypatch):
    def fail(self,handle):raise OSError('injected receipt write failure')
    monkeypatch.setattr(Receipts,'created',fail)
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with pytest.raises(OSError):_stage_payload(store,source,'a'*32,lambda g:True)
        row=Receipts(store.journal).load()['files'][0]
        assert row['identity'] is None and row['state']=='intent'
        assert statuses(store)[row['name']]=='unrecorded'


def test_same_bytes_replacement_is_not_owned(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        row=Receipts(store.journal).load()['files'][0]
        path=store.directories['root'].path/row['name']
        data=path.read_bytes()
        path.rename(path.with_suffix('.old'))
        path.write_bytes(data)
        assert statuses(store)[row['name']]=='replaced'
        assert path.read_bytes()==data


def test_completed_copy_modified_in_place_is_conflict(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        row=Receipts(store.journal).load()['files'][0]
        path=store.directories['root'].path/row['name'];path.write_bytes(b'altered')
        assert statuses(store)[row['name']]=='changed'


def test_hardlinked_copy_is_not_a_removal_candidate(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        row=Receipts(store.journal).load()['files'][0]
        path=store.directories['root'].path/row['name']
        path.with_suffix('.alias').hardlink_to(path)
        assert statuses(store)[row['name']]=='unverifiable'


def test_unrecorded_existing_file_is_preserved(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        path=store.directories['root'].path/'Engine/engine.exe';path.write_bytes(b'other owner')
        assert statuses(store)['Engine/engine.exe']=='unrecorded'
        assert path.read_bytes()==b'other owner'


def test_receipt_generation_mismatch_is_rejected(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        receipts=Receipts(store.journal);receipts.begin()
        value=receipts.load();value['generation']='b'*32
        receipts.path.write_text(json.dumps(value),encoding='utf-8')
        with pytest.raises(SafetyError):receipts.load()


def test_failed_atomic_replace_preserves_prior_receipt(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        receipts=Receipts(store.journal);receipts.begin();before=receipts.load()
        first=sorted(source.pins)[0]
        with PinnedFile(receipts.path,limit=65536):
            with pytest.raises(SafetyError,match=r'commit protected metadata \(Win32 error (5|32)\)'):
                receipts.intent(first,source.pins[first].sha256)
        assert receipts.load()==before
        assert len(list(receipts.path.parent.glob('receipt-*.tmp')))==1


def test_closed_lock_cannot_write_or_inspect_receipts(tmp_path,monkeypatch):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        receipts=Receipts(store.journal);receipts.begin();store.journal.close()
        with pytest.raises(SafetyError):receipts.load()
        with pytest.raises(SafetyError):receipts.begin()


@pytest.mark.parametrize('edit',[
    lambda v:v.update(schema=True),
    lambda v:v['files'][0].update(name='../other.exe'),
    lambda v:v['files'][0].update(identity=[True,0,0,0,0]),
    lambda v:v['files'][0].update(identity=[0]*4),
    lambda v:v['files'][0].update(identity=[-1]*5),
    lambda v:v['files'][0].update(state='intent'),
    lambda v:v['files'][0].update(state='created'),
    lambda v:v['files'].reverse(),
])
def test_malformed_receipt_cannot_drive_recovery(tmp_path,monkeypatch,edit):
    with fixture(tmp_path,monkeypatch) as (store,source,state):
        with _stage_payload(store,source,'a'*32,lambda g:True):pass
        value=copy.deepcopy(Receipts(store.journal).load());edit(value)
        with pytest.raises(SafetyError):validate(value)
