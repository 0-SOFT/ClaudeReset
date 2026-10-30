import json
from pathlib import Path
import pytest
from claude_reset import layout as state
from claude_reset.safeio import SafetyError


def layout(tmp_path):
    home=tmp_path/'home'; local=home/'AppData/Local'; local.mkdir(parents=True)
    redirected=local/'Packages/OpenAI.Codex_fixture/LocalCache/Local'
    redirected.mkdir(parents=True)
    return home,local,redirected


def test_packaged_and_ordinary_use_same_new_default(tmp_path):
    home,local,redirected=layout(tmp_path)
    assert state.resolve(home,local,local)==state.resolve(home,local,redirected)==home/'.claude-reset/state'
    assert not (home/'.claude-reset').exists()


def test_old_archive_is_discovered_but_never_selected_or_moved(tmp_path):
    home,local,redirected=layout(tmp_path)
    old=redirected/'ClaudeReset/runs/example'; old.mkdir(parents=True)
    archive=old/'memory.dpapi'; archive.write_bytes(b'not-a-real-user-archive')
    for env in (local,redirected):
        report=state.inspect(home,local,env)
        assert report['selection_required'] and report['selected'] is None
        assert next(c for c in report['candidates'] if c['nonempty'])['path']==str(redirected/'ClaudeReset')
        with pytest.raises(SafetyError,match='explicit selection'): state.resolve(home,local,env)
    assert archive.read_bytes()==b'not-a-real-user-archive'
    assert not (local/'ClaudeReset').exists()


def test_one_persisted_selection_is_shared_and_missing_root_is_not_replaced(tmp_path):
    home,local,redirected=layout(tmp_path)
    chosen=tmp_path/'archives'; chosen.mkdir()
    assert state.select(home,chosen)['archives_moved'] is False
    for env in (local,redirected): assert state.resolve(home,local,env)==chosen
    chosen.rmdir()
    with pytest.raises(SafetyError,match='missing'): state.resolve(home,local,local)
    assert not chosen.exists()


def test_two_stores_require_explicit_choice_even_when_one_is_unrecognized(tmp_path):
    home,local,redirected=layout(tmp_path)
    for root in (local,redirected):
        store=root/'ClaudeReset'; store.mkdir(); (store/'unknown-schema.json').write_text('{}')
    with pytest.raises(SafetyError): state.resolve(home,local,local)
    chosen=redirected/'ClaudeReset'
    assert state.resolve(home,local,local,explicit=chosen)==chosen
    assert not state.selection_file(home).exists()


@pytest.mark.parametrize('value',['relative', '../escape'])
def test_relative_roots_refused(tmp_path,value):
    with pytest.raises(SafetyError): state.validate_root(value,tmp_path)


def test_missing_choice_and_unknown_pointer_schema_refused(tmp_path):
    home,local,redirected=layout(tmp_path)
    with pytest.raises(SafetyError): state.select(home,tmp_path/'missing')
    pointer=state.selection_file(home); pointer.parent.mkdir()
    pointer.write_text(json.dumps({'schema':1,'state_root':str(local),'execute':'bad'}))
    with pytest.raises(SafetyError,match='schema'): state.resolve(home,local,local)


def test_resolved_drops_only_the_local_long_path_prefix(tmp_path):
    from claude_reset import safeio
    missing=tmp_path/'missing'/'file'
    assert safeio.resolved(Path('\\\\?\\'+str(missing)))==missing.resolve()
    assert str(safeio.resolved(missing))==str(missing.resolve())


def test_folder_created_at_the_same_moment_is_not_refused(tmp_path):
    """Regression: a lock file guarded while another instance creates its folder was refused as outside the root."""
    import threading
    from claude_reset import safeio
    local=tmp_path/'local'; local.mkdir()
    for attempt in range(60):
        folder=local/f'ClaudeReset{attempt}'
        creator=threading.Thread(target=lambda: folder.mkdir(parents=True, exist_ok=True))
        creator.start()
        for _ in range(20):
            safeio.guarded(folder/'admission.lock', local)
        creator.join()


def test_reparse_state_is_refused(tmp_path,monkeypatch):
    home,local,redirected=layout(tmp_path)
    from claude_reset import safeio
    original=safeio.reparse
    monkeypatch.setattr(safeio,'reparse',lambda path: path==local/'ClaudeReset' or original(path))
    with pytest.raises(SafetyError,match='Reparse'): state.discover(home,local,local)


@pytest.mark.parametrize('case',['duplicate_root','duplicate_schema','boolean_schema','float_schema','deep_json'])
def test_ambiguous_or_noncanonical_selection_never_chooses_a_store(tmp_path,case):
    home,local,redirected=layout(tmp_path)
    pointer=state.selection_file(home);pointer.parent.mkdir()
    first=json.dumps(str(local));second=json.dumps(str(redirected))
    bodies={
        'duplicate_root':'{"schema":1,"state_root":'+first+',"state_root":'+second+'}',
        'duplicate_schema':'{"schema":2,"schema":1,"state_root":'+first+'}',
        'boolean_schema':'{"schema":true,"state_root":'+first+'}',
        'float_schema':'{"schema":1.0,"state_root":'+first+'}',
        'deep_json':'['*2000+'0'+']'*2000,
    }
    pointer.write_text(bodies[case],encoding='utf-8')
    before=pointer.read_bytes()
    with pytest.raises(SafetyError):state.resolve(home,local,redirected)
    assert pointer.read_bytes()==before
    assert not (local/'ClaudeReset').exists() and not (redirected/'ClaudeReset').exists()


@pytest.mark.parametrize('size',[8192,8193])
def test_selection_byte_limit_preserves_valid_unicode_paths(tmp_path,size):
    home,local,redirected=layout(tmp_path)
    chosen=home/'архив';chosen.mkdir()
    pointer=state.selection_file(home);pointer.parent.mkdir()
    raw=json.dumps({'schema':1,'state_root':str(chosen)},ensure_ascii=False).encode('utf-8')
    raw=raw+b' '*(size-len(raw));pointer.write_bytes(raw)
    if size==8192:
        assert state.resolve(home,local,redirected)==chosen
    else:
        with pytest.raises(SafetyError,match='size limit'):state.resolve(home,local,redirected)
    assert pointer.read_bytes()==raw
