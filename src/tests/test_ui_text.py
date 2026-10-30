"""English window: every shown text has a translation, templates keep their fields, nothing Russian is left."""
import ast
import re
import string
from pathlib import Path

import pytest

from claude_reset.services import diagnostics
from claude_reset.ui import help_docs, protection_panel, proxy_flow, reset_flow, shell
from claude_reset.ui import text as ui_text
from claude_reset import layout
from claude_reset.ui.text import gui_message
from claude_reset.ui.text.en import EN

CYR = re.compile('[А-Яа-яЁё]')
SHELL = Path(shell.__file__).read_text(encoding='utf-8')


def window_keys():
    for node in ast.walk(ast.parse(SHELL)):
        name = node.func.attr if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) else \
            getattr(node.func, 'id', None) if isinstance(node, ast.Call) else None
        if name in ('tr', 'tr_text') and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and CYR.search(arg.value):
                yield arg.value


def shown_by_logic():
    yield from shell.STEPS.values()
    yield shell.UAC_TEXT
    yield from shell.OUTSIDE
    yield from reset_flow.BLOCKERS.values()
    yield reset_flow.UNKNOWN_BLOCKER
    yield from reset_flow.LABELS.values()
    yield from proxy_flow.PROBLEMS.values()
    yield from (words for pair in proxy_flow.STATES.values() for words in pair)
    yield from proxy_flow.FIXES.values()
    yield from proxy_flow.MESSAGES.values()
    yield from proxy_flow.CLIENTS.values()
    yield from protection_panel.LIMITS.values()
    yield from (line.strip('\n') for line in protection_panel.RESULTS.values())
    yield from (title for title, _ in help_docs.DOCUMENTS.values())
    for key in ('cancelled', 'cancel_unavailable', 'callback_failed', 'uac_close_unknown'):
        yield gui_message(key)


def test_every_window_text_has_english():
    keys = set(window_keys())
    assert len(keys) > 200  # the window's own texts are found, so an empty scan cannot pass
    assert sorted(k for k in keys if k not in EN) == []


def test_every_text_from_the_logic_has_english():
    missing = sorted(set(k for k in shown_by_logic() if k not in EN))
    assert missing == []


def test_templates_keep_their_fields():
    fields = lambda text: {name for _, name, _, _ in string.Formatter().parse(text) if name}
    assert [k for k, v in EN.items() if fields(k) != fields(v)] == []


def test_english_has_no_russian_left():
    assert [v for v in EN.values() if CYR.search(v)] == []


def test_translation_lines_and_sizes():
    english = ui_text.ENGLISH
    assert english.tr('Сброс') == 'Reset'
    assert english.tr('Прокси: {name}', name='SOCKS5') == 'Proxy: SOCKS5'
    assert english.tr('нет такого текста') == 'нет такого текста'
    text = protection_panel.RESULTS['restarted'] + '\nВремя без реле: 4.5 с.'
    assert english.tr_text(text) == 'The controller restarted and the new relay is confirmed.\nTime without the relay: 4.5 s.'
    assert english.sizes('1,2 ГБ и 512 Б') == '1.2 GB и 512 B'
    assert ui_text.RUSSIAN.tr('Сброс') == 'Сброс' and ui_text.RUSSIAN.sizes('1,2 ГБ') == '1,2 ГБ'


def test_a_language_is_chosen_by_code_and_holds_no_shared_state():
    assert ui_text.Language.of('en') is ui_text.ENGLISH
    assert ui_text.Language.of('ru') is ui_text.Language.of(None) is ui_text.Language.of('de') is ui_text.RUSSIAN
    with pytest.raises(ValueError):
        ui_text.Language('de')
    with pytest.raises(AttributeError):
        ui_text.ENGLISH.code = 'ru'
    assert ui_text.RUSSIAN.tr('Сброс') == 'Сброс'  # using English elsewhere changes nothing here


def note_codes():
    """Every code given to Note(...) in the program, with the names of its values."""
    for path in layout.PACKAGE_DIR.rglob('*.py'):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'Note' and node.args:
                code = node.args[0]
                for branch in (code.body, code.orelse) if isinstance(code, ast.IfExp) else (code,):
                    for constant in ([branch] if isinstance(branch, ast.Constant) else
                                     [branch.body, branch.orelse] if isinstance(branch, ast.IfExp) else []):
                        yield constant.value, {k.arg for k in node.keywords}


def test_every_note_has_its_text_in_both_languages():
    import importlib
    russian = importlib.import_module('claude_reset.ui.text.ru').NOTES
    english = importlib.import_module('claude_reset.ui.text.en').NOTES
    fields = lambda text: {name for _, name, _, _ in string.Formatter().parse(text) if name}
    used = dict(note_codes())
    assert set(used) == set(russian) == set(english)
    assert [code for code, values in used.items() if not fields(russian[code]) == fields(english[code]) == values] == []
    assert [text for text in english.values() if CYR.search(text)] == []


def test_a_note_is_its_code_in_json_and_its_text_when_shown():
    import json
    from claude_reset.model.notes import Note
    note = Note('plan.processes_open', kind='desktop')
    assert json.dumps({'blockers': [note]}) == '{"blockers": ["plan.processes_open"]}'
    assert ui_text.render({'blockers': [note]}, 'en') == {'blockers': ['Close related processes before applying: desktop']}
    assert ui_text.say(note, 'ru').endswith(': desktop') and ui_text.say('free text', 'ru') == 'free text'


def error_codes():
    """Codes given to errors (code='...') and the specific codes of error classes."""
    from claude_reset import errors
    generic = {'refused', 'unsafe_path', 'schema', 'limit', 'platform', 'wfp'}
    yield from (cls.code for cls in vars(errors).values()
                if isinstance(cls, type) and issubclass(cls, errors.SafetyError) and cls.code not in generic)
    for path in layout.PACKAGE_DIR.rglob('*.py'):
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', '').endswith('Error'):
                yield from (k.value.value for k in node.keywords if k.arg == 'code' and isinstance(k.value, ast.Constant))


def test_every_error_code_has_its_text_in_both_languages():
    import importlib
    russian = importlib.import_module('claude_reset.ui.text.ru').ERRORS
    english = importlib.import_module('claude_reset.ui.text.en').ERRORS
    assert set(error_codes()) == set(russian) == set(english)
    assert [text for text in english.values() if CYR.search(text)] == []


def test_an_error_shows_its_catalog_text_by_code():
    from claude_reset.errors import BrowsersOpenError, SafetyError
    assert ui_text.error_text(SafetyError('Unsupported Cowork location', code='cowork_location'), 'ru') == 'Неподдержанное расположение Cowork'
    assert ui_text.error_text(BrowsersOpenError('Close Chrome and Edge yourself and check again'), 'en').startswith('Close Chrome')
    assert ui_text.error_text(SafetyError('A message without its own text'), 'ru') == 'A message without its own text'
