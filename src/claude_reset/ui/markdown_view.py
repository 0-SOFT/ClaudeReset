"""Readable rendering of the bundled Markdown help: headings, paragraphs, lists, code and tables. No Tk.

Only what the program's own documents use is supported; anything else is shown as plain text.
Links show their text: the help never opens a browser.
"""
import re

__all__ = ['blocks', 'inline']

HEADING = re.compile(r'(#{1,6})\s+(.*)')
BULLET = re.compile(r'(\s*)[-*+]\s+(.*)')
NUMBER = re.compile(r'(\s*)(\d+)[.)]\s+(.*)')
RULE = re.compile(r'(-{3,}|\*{3,}|_{3,})')
SEPARATOR = re.compile(r':?-{2,}:?')
INLINE = re.compile(r'`([^`]+)`|\*\*([^*]+)\*\*|\[([^\]]+)\]\(([^)]+)\)')


def blocks(text):
    """[(kind, payload)]: h1, h2, h3 and para carry text; bullet (depth, text); number (depth, n, text);
    code text; table rows (lists of cells, separator rows dropped); rule."""
    out, paragraph = [], []
    lines = text.splitlines()

    def flush():
        if paragraph:
            out.append(('para', ' '.join(paragraph)))
            paragraph.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith('```'):
            flush()
            code, i = [], i + 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code.append(lines[i])
                i += 1
            out.append(('code', '\n'.join(code)))
            i += 1
            continue
        heading = HEADING.fullmatch(stripped)
        if heading:
            flush()
            out.append((f'h{min(len(heading.group(1)), 3)}', heading.group(2).strip()))
        elif stripped.startswith('|'):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                cells = [cell.strip() for cell in lines[i].strip().strip('|').split('|')]
                if not all(SEPARATOR.fullmatch(cell) for cell in cells if cell):
                    rows.append(cells)
                i += 1
            out.append(('table', rows))
            continue
        elif RULE.fullmatch(stripped):
            flush()
            out.append(('rule', ''))
        elif not stripped:
            flush()
        elif BULLET.fullmatch(line):
            flush()
            match = BULLET.fullmatch(line)
            out.append(('bullet', (len(match.group(1)) // 2, match.group(2).strip())))
        elif NUMBER.fullmatch(line):
            flush()
            match = NUMBER.fullmatch(line)
            out.append(('number', (len(match.group(1)) // 2, match.group(2), match.group(3).strip())))
        elif out and out[-1][0] in ('bullet', 'number') and not paragraph and line.startswith(' '):
            kind, payload = out[-1]  # an indented continuation of the list item above
            out[-1] = (kind, payload[:-1] + (payload[-1] + ' ' + stripped,))
        else:
            paragraph.append(stripped)
        i += 1
    flush()
    return out


def inline(text):
    """[(segment, style)] with style text, bold, code or link."""
    out, position = [], 0
    for match in INLINE.finditer(text):
        if match.start() > position:
            out.append((text[position:match.start()], 'text'))
        if match.group(1) is not None:
            out.append((match.group(1), 'code'))
        elif match.group(2) is not None:
            out.append((match.group(2), 'bold'))
        else:
            out.append((match.group(3), 'link'))
        position = match.end()
    if position < len(text):
        out.append((text[position:], 'text'))
    return out
