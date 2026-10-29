import json

import pytest
from test_reset import paths

from claude_reset import diagnostics as d
from claude_reset.safeio import SafetyError, atomic_json


SECRET = 'private-person password-canary 203.0.113.45 2001:db8::45'


@pytest.fixture(autouse=True)
def substitute_native_reader(monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace

    @contextmanager
    def read(path, *, limit):
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise SafetyError('fixture size limit')
        yield SimpleNamespace(data=data)

    monkeypatch.setattr(d, 'PinnedFile', read)


def test_temporary_profile_is_read_only(paths, monkeypatch):
    monkeypatch.setattr(d.l1_check, 'check', lambda p: {'protection': 'not_installed'})
    target = paths.home / '.claude.json'
    target.write_text(SECRET, encoding='utf-8')
    result = d.collect(paths)
    assert result['files']['present_locations'] >= 1
    assert not result['files']['zero_fixed_file_remainder']
    assert target.read_text(encoding='utf-8') == SECRET
    assert all(word not in json.dumps(result) for word in SECRET.split())


def test_collect_and_export(tmp_path, monkeypatch):
    monkeypatch.setattr(d.l1_check, 'check', lambda p: {
        'protection': 'partial', 'detail': SECRET, SECRET: SECRET})
    monkeypatch.setattr(d.cleanup, 'audit', lambda p: {
        'complete': True, 'rows': [{'status': 'absent', 'label': SECRET}], 'extra': SECRET})
    result = d.collect(tmp_path)
    assert result['collection_complete'] is True
    assert result['files']['zero_fixed_file_remainder'] is True
    assert result['files']['zero_total_remainder'] is False
    assert result['protection']['components'] == 'partial'
    assert not result['ready_for_new_account']
    path = tmp_path / 'report.json'
    atomic_json(path, result, tmp_path)
    saved = path.read_text(encoding='utf-8')
    for word in SECRET.split():
        assert word not in saved
    assert json.loads(saved) == result
    assert any('Chrome/Edge' in x for x in result['limitations'])
    assert any('Cowork' in x for x in result['limitations'])


@pytest.mark.parametrize('raw', [
    {'complete': False, 'rows': [{'status': 'unavailable', 'label': SECRET}]},
    {'complete': True, 'rows': []},
    {'complete': True, 'rows': [{'status': SECRET}]},
    {'complete': True, 'rows': None},
])
def test_incomplete_never_zero(monkeypatch, raw):
    monkeypatch.setattr(d.l1_check, 'check', lambda p: {'protection': SECRET})
    monkeypatch.setattr(d.cleanup, 'audit', lambda p: raw)
    result = d.collect(None)
    assert not result['collection_complete']
    assert not result['files']['zero_fixed_file_remainder']
    assert SECRET not in json.dumps(result)


def fail(*args):
    raise RuntimeError(SECRET)


def test_failures_are_independent_and_private(monkeypatch):
    monkeypatch.setattr(d.l1_check, 'check', fail)
    calls = []
    monkeypatch.setattr(d.cleanup, 'audit', lambda p: calls.append(p) or fail())
    result = d.collect('fixture')
    assert calls == ['fixture']
    assert result['files']['collection'] == 'unavailable'
    assert result['protection']['collection'] == 'unavailable'
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize('country,zone,locale,matches', [
    ('de', 'W. Europe Standard Time', 'de-DE', True),
    ('TR', 'Turkey Standard Time', 'tr-TR', True),
    ('GB', 'GMT Standard Time', 'en-GB', True),
    ('DE', SECRET, SECRET, False),
])
def test_advisor(monkeypatch, country, zone, locale, matches):
    monkeypatch.setattr(d, 'inspect_windows', lambda: {'timezone': {'id': zone}, 'locale': locale})
    result = d.advise(country)
    assert result['timezone_matches'] is matches
    assert result['language_matches'] is matches
    assert not result['settings_changed'] and not result['exit_country_verified']
    assert SECRET not in json.dumps(result)


def test_advisor_refusals(monkeypatch):
    monkeypatch.setattr(d, 'inspect_windows', fail)
    assert d.advise(SECRET)['status'] == 'unsupported'
    result = d.advise('DE')
    assert result['status'] == 'unavailable'
    assert SECRET not in json.dumps(result)


def test_settings_only_known_uris(monkeypatch):
    calls = []
    monkeypatch.setattr('os.startfile', calls.append)
    for kind in ('timezone', 'language'):
        assert d.open_settings(kind) == {'opened': True, 'settings_changed': False}
    assert calls == ['ms-settings:dateandtime', 'ms-settings:regionlanguage']
    with pytest.raises(SafetyError):
        d.open_settings(SECRET)
    monkeypatch.setattr('os.startfile', fail)
    with pytest.raises(SafetyError) as exc:
        d.open_settings('language')
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize('facts', [None, {}, {'timezone': {'id': None}, 'locale': None},
                                  {'timezone': {'id': ''}, 'locale': 'de-DE'}])
def test_advisor_unknown_is_not_mismatch(monkeypatch, facts):
    monkeypatch.setattr(d, 'inspect_windows', lambda: facts)
    result = d.advise('DE')
    assert result['status'] == 'unavailable'
    assert 'timezone_matches' not in result


def test_history_read_only_export(paths, tmp_path):
    root = paths.state / 'runs'
    root.mkdir(parents=True)
    expected = ['started', 'failed_or_partial', 'local_operations_completed_partial_coverage',
                'fixed_locations_wiped']
    originals = {}
    for i, status in enumerate(expected):
        folder = root / str(i)
        folder.mkdir()
        path = folder / 'result.json'
        path.write_text(json.dumps({'status': status, 'run': SECRET, 'error': SECRET,
                                    'ready_for_new_account': True}), encoding='utf-8')
        originals[path] = path.read_bytes()
        (folder / 'journal.dpapi').write_bytes(b'never decrypt')
    report = d.operation_history(paths)
    assert report['collection'] == 'complete'
    assert {r['status'] for r in report['rows']} == set(expected)
    assert not report['live_result_verified']
    output = tmp_path / 'history.json'
    atomic_json(output, report, tmp_path)
    assert all(word not in output.read_text('utf-8') for word in SECRET.split())
    assert all(path.read_bytes() == data for path, data in originals.items())


def test_history_empty_and_unavailable(paths, monkeypatch):
    assert d.operation_history(paths)['rows'] == []
    root = paths.state / 'runs'
    root.mkdir(parents=True)
    (root / 'one').mkdir()
    monkeypatch.setattr(d, 'PinnedFile', fail)
    report = d.operation_history(paths)
    assert report['collection'] == 'partial'
    assert report['rows'][0]['status'] == 'unavailable'
    assert SECRET not in json.dumps(report)
    monkeypatch.setattr(d, 'guarded', fail)
    assert d.operation_history(paths)['collection'] == 'unavailable'


@pytest.mark.parametrize('data', [b'broken', b'[]', b'{"status": []}', b'x' * (1024 * 1024 + 1)],
                         ids=['broken', 'list', 'status-list', 'oversized'])
def test_history_invalid_reports(paths, data):
    folder = paths.state / 'runs' / 'one'
    folder.mkdir(parents=True)
    (folder / 'result.json').write_bytes(data)
    report = d.operation_history(paths)
    assert report['collection'] == 'partial'
    assert report['rows'][0]['status'] == 'unavailable'


def test_history_limit(paths):
    root = paths.state / 'runs'
    root.mkdir(parents=True)
    for i in range(101):
        (root / str(i)).mkdir()
    report = d.operation_history(paths)
    assert report['truncated'] and len(report['rows']) == 100
    assert report['collection'] == 'partial'
