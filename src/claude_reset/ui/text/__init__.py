"""Every text the program shows, in Russian and English.

The window's texts are written in Russian and are the keys of `en.EN`.

The window chooses its `Language` when it is built (as in Windows or chosen by the person) and passes it to its
parts. Texts produced by the logic modules (blockers, protection states, messages) stay Russian there and are
translated when shown.
"""
import re
from dataclasses import dataclass
from types import MappingProxyType

from .ru import GUI_MESSAGES

__all__ = ['ENGLISH', 'JSON_FILES', 'RUSSIAN', 'Language', 'error_text', 'gui_message', 'render', 'say']

# The file-dialog filter of every JSON file the windows open or save.
JSON_FILES = (('JSON', '*.json'),)

SIZE = re.compile(r'(\d+),(\d) (ГБ|МБ|КБ)\b|(\d+) Б\b')
UNITS = MappingProxyType({'ГБ': 'GB', 'МБ': 'MB', 'КБ': 'KB'})
CODES = ('ru', 'en')


@dataclass(frozen=True)
class Language:
    """The language a window shows its texts in."""
    code: str

    def __post_init__(self):
        if self.code not in CODES:
            raise ValueError(f'Unknown language: {self.code!r}')

    @staticmethod
    def of(code):
        """The language of a saved or detected choice: English when chosen, otherwise Russian."""
        return ENGLISH if code == 'en' else RUSSIAN

    def tr(self, text, **values):
        """The text in this language; {name} fields are filled after translation."""
        if self.code == 'en' and isinstance(text, str):
            from .en import EN
            text = EN.get(text, text)
        return text.format(**values) if values else text

    def sizes(self, text):
        if self.code != 'en':
            return text
        return SIZE.sub(lambda m: f'{m.group(1)}.{m.group(2)} {UNITS[m.group(3)]}' if m.group(1) else f'{m.group(4)} B',
                        text)

    def tr_text(self, text):
        """A message that may join several fixed lines and a measured number: translated line by line."""
        if self.code != 'en' or not isinstance(text, str):
            return text
        from .en import EN, PATTERNS
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
        return self.sizes('\n'.join(lines))

    def error_text(self, exc):
        return error_text(exc, self.code)

    def say(self, note):
        return say(note, self.code)

    def render(self, value):
        return render(value, self.code)


RUSSIAN, ENGLISH = Language('ru'), Language('en')


def error_text(exc, language):
    """What an error says to people: its text by code when the catalog has one, else its own message."""
    from .en import ERRORS as english
    from .ru import ERRORS as russian
    table = english if language == 'en' else russian
    code = getattr(exc, 'code', None)
    return table[code] if code in table else str(exc)


def say(note, language):
    """The text of a note (or of a bare note code) in the given language; other text unchanged."""
    from .en import NOTES as english
    from .ru import NOTES as russian
    table = english if language == 'en' else russian
    if isinstance(note, str) and str(note) in table:
        values = {name: say(value, language) for name, value in getattr(note, 'values', {}).items()}
        return table[str(note)].format(**values)
    return note


def render(value, language):
    """A report with every note replaced by its text."""
    from ...model.notes import Note
    if isinstance(value, Note):
        return say(value, language)
    if isinstance(value, dict):
        return {key: render(item, language) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [render(item, language) for item in value]
    return value


def gui_message(key):
    return GUI_MESSAGES.get(key, GUI_MESSAGES['operation_failed'])
