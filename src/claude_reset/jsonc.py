"""Strict JSON-with-comments reader and small, comment-preserving top-level edits."""
from __future__ import annotations
import json
from pathlib import Path
from .safeio import SafetyError, guarded, atomic_bytes


def clean(text: str) -> str:
    chars = list(text)
    i, quoted, escaped = 0, False, False
    while i < len(chars):
        c = text[i]
        if quoted:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif text[i:i + 2] == '//':
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
            chars[i:end] = ' ' * (end - i)
            i = end - 1
        elif text[i:i + 2] == '/*':
            end = text.find('*/', i + 2)
            if end < 0:
                raise SafetyError('Unterminated JSONC comment')
            end += 2
            chars[i:end] = ['\n' if x == '\n' else ' ' for x in text[i:end]]
            i = end - 1
        i += 1
    # Remove trailing commas outside strings without changing character offsets.
    quoted, escaped = False, False
    for i, c in enumerate(chars):
        if quoted:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c == ',':
            j = i + 1
            while j < len(chars) and chars[j].isspace():
                j += 1
            if j < len(chars) and chars[j] in '}]':
                chars[i] = ' '
    return ''.join(chars)


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise SafetyError('Duplicate configuration key')
        obj[key] = value
    return obj


def loads(text: str):
    try:
        obj = json.loads(clean(text), object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(obj, dict):
            raise ValueError()
        return obj
    except (ValueError, TypeError, RecursionError):
        raise SafetyError('Configuration cannot be parsed safely') from None


def read(path: Path, root: Path):
    guarded(path, root)
    if not path.exists():
        return {}
    if path.stat().st_size > 20_000_000:
        raise SafetyError('Configuration file is too large')
    try:
        return loads(path.read_text('utf-8-sig'))
    except (UnicodeError, OSError):
        raise SafetyError('Configuration cannot be read safely') from None


def set_property(path: Path, root: Path, key: str, value):
    guarded(path, root)
    original = path.read_text('utf-8-sig') if path.exists() else '{}'
    obj = loads(original)
    if key in obj and obj[key] == value:
        return
    stripped = clean(original)
    decoder = json.JSONDecoder()
    pos = stripped.index('{') + 1
    replacement = json.dumps(value, ensure_ascii=False)
    last_end = None
    while True:
        while stripped[pos].isspace() or stripped[pos] == ',':
            pos += 1
        if stripped[pos] == '}':
            closing = pos
            break
        name, pos = decoder.raw_decode(stripped, pos)
        while stripped[pos].isspace() or stripped[pos] == ':':
            pos += 1
        start = pos
        _, pos = decoder.raw_decode(stripped, pos)
        last_end = pos
        if name == key:
            updated = original[:start] + replacement + original[pos:]
            break
    else:  # pragma: no cover
        raise SafetyError('Invalid configuration')
    if key not in obj:
        # Insert before the first property, preserving all existing comments.
        opening = stripped.index('{') + 1
        addition = '\n  ' + json.dumps(key) + ': ' + replacement + (',' if obj else '') + '\n'
        updated = original[:opening] + addition + original[opening:]
    expected = dict(obj, **{key: value})
    if loads(updated) != expected:
        raise SafetyError('Configuration edit validation failed')
    atomic_bytes(path, updated.encode('utf-8'), root)
