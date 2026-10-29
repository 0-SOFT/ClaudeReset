"""Bind receipts to the source modules actually frozen, and detect build-time edits."""
import ast
import hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(entry):
    result={}
    for path in [entry,*sorted((ROOT/'src/claude_reset').rglob('*.py'))]:
        if path.is_symlink() or getattr(path.lstat(),'st_file_attributes',0)&0x400:
            raise RuntimeError('Reparse point in frozen sources')
        result[path.relative_to(ROOT).as_posix()]=digest(path)
    return result


def selected(toc, before, entry):
    data=toc.read_bytes()
    if len(data)>16*1024*1024:raise RuntimeError('Unexpected PyInstaller module table size')
    table=ast.literal_eval(data.decode('utf-8'))
    if not isinstance(table,tuple) or len(table)<2 or not isinstance(table[1],list):
        raise RuntimeError('Unknown PyInstaller module table')
    names={entry.relative_to(ROOT).as_posix()}
    for row in table[1]:
        if not isinstance(row,tuple) or len(row)!=3:raise RuntimeError('Unknown frozen module record')
        if not isinstance(row[1],str):continue
        path=Path(row[1])
        try:relative=path.relative_to(ROOT/'src')
        except ValueError:continue
        names.add('src/'+relative.as_posix())
    for name in names:
        if name not in before or digest(ROOT/name)!=before[name]:
            raise RuntimeError('A frozen source changed during the build: '+name)
    return {name:before[name] for name in sorted(names)}
