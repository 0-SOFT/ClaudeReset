"""windows/api: every DLL function the program calls has one declared prototype, and the DLL has that function."""
from collections import Counter
import importlib
import pkgutil

import pytest

import claude_reset.windows as platform
from claude_reset.windows import api


def tables():
    """Each prototype table of the platform layer once: the shared one and the tables beside their structures."""
    seen = {}
    for info in pkgutil.iter_modules(platform.__path__):
        table = getattr(importlib.import_module('claude_reset.windows.' + info.name), 'PROTOTYPES', None)
        if table is not None:
            seen.setdefault(id(table), (info.name, table))
    return list(seen.values())


def test_every_function_is_declared_in_one_table():
    declared = Counter((dll, function) for _, table in tables() for dll, functions in table.items() for function in functions)
    assert [key for key, count in declared.items() if count > 1] == []
    assert len(declared) > 80   # the tables were found


def test_every_declared_function_exists_in_its_dll():
    missing = []
    for module, table in tables():
        for dll, functions in table.items():
            library = api.Library(dll, table)
            missing += [(module, dll, name) for name in functions if not callable(getattr(library, name, None))]
    assert missing == []


def test_a_function_without_a_declared_prototype_cannot_be_read():
    with pytest.raises(AttributeError, match='no declared prototype'):
        api.Library('kernel32').GetTickCount
