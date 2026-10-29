import importlib.util
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('frozen_sources_tool',ROOT/'tools/frozen_sources.py')
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


def setup(tmp_path,monkeypatch):
    monkeypatch.setattr(tool,'ROOT',tmp_path)
    folder=tmp_path/'src/claude_reset';folder.mkdir(parents=True)
    used=folder/'used.py';used.write_text('value=1')
    unused=folder/'unused.py';unused.write_text('value=1')
    entry=tmp_path/'src/main.py';entry.write_text('import claude_reset.used')
    toc=tmp_path/'PYZ-00.toc'
    toc.write_text(repr(('output.pyz',[('claude_reset.used',str(used),'PYMODULE')])))
    return entry,used,unused,toc


def test_only_actual_frozen_modules_and_entry_are_claimed(tmp_path,monkeypatch):
    entry,used,unused,toc=setup(tmp_path,monkeypatch)
    before=tool.snapshot(entry);unused.write_text('unrelated_change=2')
    assert set(tool.selected(toc,before,entry))=={'src/main.py','src/claude_reset/used.py'}


@pytest.mark.parametrize('which',['entry','used'])
def test_edits_during_build_are_rejected(tmp_path,monkeypatch,which):
    entry,used,unused,toc=setup(tmp_path,monkeypatch)
    before=tool.snapshot(entry)
    (entry if which=='entry' else used).write_text('changed=3')
    with pytest.raises(RuntimeError,match='changed during'):tool.selected(toc,before,entry)


def test_module_missing_from_snapshot_is_not_silently_added(tmp_path,monkeypatch):
    entry,used,unused,toc=setup(tmp_path,monkeypatch)
    before=tool.snapshot(entry);del before['src/claude_reset/used.py']
    with pytest.raises(RuntimeError):tool.selected(toc,before,entry)
