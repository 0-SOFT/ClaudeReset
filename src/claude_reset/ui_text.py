"""The window's language. Russian strings are the keys; English comes from ui_text_en.EN.

The language is set once when the window is built (as in Windows or chosen by the person). Texts produced by
the logic modules (blockers, protection states, messages) stay Russian there and are translated when shown.
"""
import re

_language = 'ru'
SIZE = re.compile(r'(\d+),(\d) (ГБ|МБ|КБ)\b|(\d+) Б\b')
UNITS = {'ГБ': 'GB', 'МБ': 'MB', 'КБ': 'KB'}


def set_language(code):
    global _language
    _language = 'en' if code == 'en' else 'ru'


def language():
    return _language


def tr(text, **values):
    """The text in the window's language; {name} fields are filled after translation."""
    if _language == 'en' and isinstance(text, str):
        from .ui_text_en import EN
        text = EN.get(text, text)
    return text.format(**values) if values else text


def sizes(text):
    if _language != 'en':
        return text
    return SIZE.sub(lambda m: f'{m.group(1)}.{m.group(2)} {UNITS[m.group(3)]}' if m.group(1) else f'{m.group(4)} B', text)


def tr_text(text):
    """A message that may join several fixed lines and a measured number: translated line by line."""
    if _language != 'en' or not isinstance(text, str):
        return text
    from .ui_text_en import EN, PATTERNS
    lines = []
    for line in text.split('\n'):
        if line in EN:
            lines.append(EN[line])
            continue
        for pattern, english in PATTERNS:
            match = re.fullmatch(pattern, line)
            if match:
                lines.append(english.format(*match.groups()))
                break
        else:
            lines.append(line)
    return sizes('\n'.join(lines))
