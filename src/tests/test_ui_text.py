"""English window: every shown text has a translation, templates keep their fields, nothing Russian is left."""
import ast
import re
import string
from pathlib import Path

import pytest

from claude_reset import diagnostics, help_docs, i18n, protection_panel, proxy_flow, reset_flow, shell, ui_text
from claude_reset.ui_text_en import EN

CYR = re.compile('[А-Яа-яЁё]')
SHELL = Path(shell.__file__).read_text(encoding='utf-8')


def window_keys():
    for node in ast.walk(ast.parse(SHELL)):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) in ('tr', 'tr_text') and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and CYR.search(arg.value):
                yield arg.value


def shown_by_logic():
    yield from shell.STEPS.values()
    yield shell.UAC_TEXT
    yield from shell.OUTSIDE
    yield from (text for _, text in reset_flow.BLOCKERS.values())
    yield from reset_flow.LABELS.values()
    yield from (reason for reason, _ in proxy_flow.PROBLEMS.values())
    yield from proxy_flow.FIXES.values()
    yield from proxy_flow.MESSAGES.values()
    yield from (name for _, name in proxy_flow.CLIENTS)
    yield from protection_panel.LIMITS.values()
    yield from (line.strip('\n') for line in protection_panel.RESULTS.values())
    yield from (advice[2] for advice in diagnostics.ADVICE.values())
    yield from (title for title, _ in help_docs.DOCUMENTS.values())
    for key in ('cancelled', 'cancel_unavailable', 'callback_failed', 'uac_close_unknown'):
        yield i18n.gui_message(key)


def test_every_window_text_has_english():
    missing = sorted(set(k for k in window_keys() if k not in EN))
    assert missing == []


def test_every_text_from_the_logic_has_english():
    missing = sorted(set(k for k in shown_by_logic() if k not in EN))
    assert missing == []


def test_templates_keep_their_fields():
    fields = lambda text: {name for _, name, _, _ in string.Formatter().parse(text) if name}
    assert [k for k, v in EN.items() if fields(k) != fields(v)] == []


def test_english_has_no_russian_left():
    assert [v for v in EN.values() if CYR.search(v)] == []


def test_translation_switch_lines_and_sizes():
    try:
        ui_text.set_language('en')
        assert ui_text.tr('Сброс') == 'Reset'
        assert ui_text.tr('Прокси: {name}', name='SOCKS5') == 'Proxy: SOCKS5'
        assert ui_text.tr('нет такого текста') == 'нет такого текста'
        text = protection_panel.RESULTS['restarted'] + '\nВремя без реле: 4.5 с.'
        assert ui_text.tr_text(text) == 'The controller restarted and the new relay is confirmed.\nTime without the relay: 4.5 s.'
        assert ui_text.sizes('1,2 ГБ и 512 Б') == '1.2 GB и 512 B'
    finally:
        ui_text.set_language('ru')
    assert ui_text.tr('Сброс') == 'Сброс' and ui_text.sizes('1,2 ГБ') == '1,2 ГБ'
