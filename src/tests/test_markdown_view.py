"""Markdown help rendering: blocks and inline styles."""
from claude_reset.ui import markdown_view


def test_blocks_cover_the_guide_constructs():
    text = '\n'.join([
        '# Title', '', 'First line', 'second line.', '', '## Steps', '',
        '1. Do this', '   and continue.', '2. Then that', '', '- point', '  - nested', '',
        '```', 'cd C:\\X', '```', '', '| Файл | Что |', '|---|---|', '| `a.cmd` | runs |', '', '---', '### End'])
    assert markdown_view.blocks(text) == [
        ('h1', 'Title'), ('para', 'First line second line.'), ('h2', 'Steps'),
        ('number', (0, '1', 'Do this and continue.')), ('number', (0, '2', 'Then that')),
        ('bullet', (0, 'point')), ('bullet', (1, 'nested')),
        ('code', 'cd C:\\X'), ('table', [['Файл', 'Что'], ['`a.cmd`', 'runs']]), ('rule', ''), ('h3', 'End')]


def test_deep_headings_are_shown_as_level_three():
    assert markdown_view.blocks('#### Deep') == [('h3', 'Deep')]


def test_inline_styles_and_links_show_text_only():
    assert markdown_view.inline('Run `ClaudeReset.cmd`, read **this** and [the guide](docs/USER-GUIDE.md).') == [
        ('Run ', 'text'), ('ClaudeReset.cmd', 'code'), (', read ', 'text'), ('this', 'bold'),
        (' and ', 'text'), ('the guide', 'link'), ('.', 'text')]
    assert markdown_view.inline('plain') == [('plain', 'text')]


def test_the_bundled_guide_parses_without_losing_text():
    from claude_reset.ui import help_docs
    _, content = help_docs.read_document('guide')
    blocks = markdown_view.blocks(content)
    assert blocks[0][0] == 'h1' and any(kind == 'number' for kind, _ in blocks)
    words = sum(len(str(payload).split()) for _, payload in blocks)
    assert words > len(content.split()) * 0.9
