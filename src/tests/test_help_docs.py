import pytest

from claude_reset import help_docs
from claude_reset.safeio import SafetyError
from test_gui_shell import ui, button, Widget


@pytest.mark.parametrize('kind', ['guide', 'limits'])
def test_bundled_document(kind):
    title, content = help_docs.read_document(kind)
    assert title and 'Сброс' in content and 'прокси' in content and 'не проверен' in content.lower()
    assert '????' not in content


def test_missing_empty_invalid_and_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(help_docs, 'ROOT', tmp_path)
    for payload in (None, b'', b'\xff'):
        target = tmp_path / 'docs/USER-GUIDE.md'
        target.parent.mkdir(exist_ok=True)
        if payload is not None:
            target.write_bytes(payload)
        with pytest.raises(SafetyError, match='Справка недоступна'):
            help_docs.read_document('guide')
    with pytest.raises(SafetyError, match='Неизвестный раздел'):
        help_docs.read_document('../../private-person')


@pytest.mark.parametrize('kind', ['guide', 'limits', 'licenses'])
def test_reader_error_does_not_disclose_path(monkeypatch, kind):
    def fail(*args, **kwargs):
        raise OSError('private-person password-canary 203.0.113.45 2001:db8::45')
    monkeypatch.setattr(help_docs.Path, 'read_text', fail)
    with pytest.raises(SafetyError) as caught:
        help_docs.read_document(kind)
    assert all(marker not in str(caught.value) for marker in
               ('private-person', 'password-canary', '203.0.113.45', '2001:db8::45'))


def test_help_buttons_read_only_and_refusal(ui, monkeypatch):
    calls = []
    monkeypatch.setattr(help_docs, 'read_document', lambda kind: calls.append(kind) or ('Справка', 'Текст'))
    for label in ('Руководство', 'Границы и приёмка', 'Лицензионные уведомления'):
        button(label).options['command']()
        assert any(w.content == ['Текст'] and w.options.get('state') == 'disabled' for w in Widget.all)
        button('Закрыть').options['command']()
    assert calls == ['guide', 'limits', 'licenses']
    def fail(kind):
        raise OSError('private-person password-canary 203.0.113.45 2001:db8::45')
    monkeypatch.setattr(help_docs, 'read_document', fail)
    button('Лицензионные уведомления').options['command']()
    assert ui.messages
    assert all(marker not in str(ui.messages) for marker in
               ('private-person', 'password-canary', '203.0.113.45', '2001:db8::45'))


def test_license_texts_are_complete():
    title, content = help_docs.read_document('licenses')
    assert title == 'Лицензионные уведомления'
    assert 'лицензия MIT' in content and 'AGPL-3.0' in content
    actual = {p.relative_to(help_docs.ROOT).as_posix()
              for p in (help_docs.ROOT / 'third_party/licenses').rglob('*') if p.is_file()}
    assert actual == set(help_docs.LICENSE_DOCUMENTS) - {'third_party/NOTICES.md'}
    for relative in help_docs.LICENSE_DOCUMENTS:
        assert (help_docs.ROOT / relative).read_text(encoding='utf-8') in content


@pytest.mark.parametrize('payload', ['Текст', None, '', b'\xff'])
def test_bundle_check_from_window(ui, tmp_path, monkeypatch, payload):
    paths = [path for _, path in help_docs.DOCUMENTS.values()] + list(help_docs.LICENSE_DOCUMENTS)
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Текст', encoding='utf-8')
    target = tmp_path / paths[-1]
    if payload is None:
        target.unlink()
    elif isinstance(payload, bytes):
        target.write_bytes(payload)
    else:
        target.write_text(payload, encoding='utf-8')
    monkeypatch.setattr(help_docs, 'ROOT', tmp_path)
    button('Проверить комплект справки').options['command']()
    content = next(w.content[0] for w in reversed(Widget.all) if w.content)
    assert ('Справка комплектна.' in content) == (payload == 'Текст')
    assert 'Руководство: доступен' in content
    assert ('Лицензионные уведомления: недоступен' in content) == (payload != 'Текст')
    assert str(tmp_path) not in content and 'не проверены' in content
    assert any(w.content == [content] and w.options.get('state') == 'disabled' for w in Widget.all)


def test_bundle_failure_redacts_errors(monkeypatch):
    markers = ('private-person', 'password-canary', '203.0.113.45', '2001:db8::45')
    def fail(*args, **kwargs):
        raise OSError(' '.join(markers))
    monkeypatch.setattr(help_docs.Path, 'read_text', fail)
    _, content = help_docs.check_bundle()
    assert content.count(': недоступен') == len(help_docs.DOCUMENTS)
    assert all(marker not in content for marker in markers)


@pytest.mark.parametrize('payload', [None, b'', b'\xff'])
def test_license_section_refuses_incomplete_bundle(tmp_path, monkeypatch, payload):
    paths = ('docs/LICENSE-REVIEW-G6.md',) + help_docs.LICENSE_DOCUMENTS
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Текст', encoding='utf-8')
    target = tmp_path / paths[-1]
    if payload is None:
        target.unlink()
    else:
        target.write_bytes(payload)
    monkeypatch.setattr(help_docs, 'ROOT', tmp_path)
    with pytest.raises(SafetyError, match='Справка недоступна'):
        help_docs.read_document('licenses')
