"""Messages the logic reports for people: a code and the values its text needs.

A Note is its code as a string, so reports and JSON keep the code. The windows and the command line show its
text from ui.text, in their language.
"""
from __future__ import annotations
from collections.abc import Iterable

__all__ = ['Note', 'unique']


class Note(str):
    """A code such as 'plan.processes_open', with the values its text needs (kind='desktop')."""

    def __new__(cls, code, **values):
        note = super().__new__(cls, code)
        note.values = values
        return note

    def __repr__(self):
        return 'Note(' + ', '.join([str.__repr__(self)] + [f'{k}={v!r}' for k, v in self.values.items()]) + ')'


def unique(notes: Iterable[str]) -> list[str]:
    """The notes in order without repeats; the same code with other values is not a repeat."""
    seen, result = set(), []
    for note in notes:
        key = (str(note), tuple(sorted(getattr(note, 'values', {}).items())))
        if key not in seen:
            seen.add(key)
            result.append(note)
    return result
