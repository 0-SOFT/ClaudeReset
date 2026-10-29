import json
from types import SimpleNamespace

import pytest

from claude_reset import privacy_observations as p


def journal(tmp_path, hosts):
    path = tmp_path / 'private-person.jsonl'
    path.write_text('\n'.join(json.dumps({'t': 123, 'host': h, 'port': 443}) for h in hosts), encoding='utf-8')
    return path


def test_native_read_summary_and_no_leaks(tmp_path):
    hosts = ['a.sentry.io', 'HTTP-INTAKE.LOGS.US5.DATADOGHQ.COM.', 'claude.ai',
             'bridge.claudeusercontent.com', 'assets.anthropic.com', 'notsentry.io',
             'sentry.io.other.test', 'private-person.example', '203.0.113.45', '2001:db8::45']
    path = journal(tmp_path, hosts)
    before = path.read_bytes()
    result = p.summarize(path)
    assert result['collection'] == 'complete'
    assert result['counts'] == dict(sentry=1, datadog=1, claude_domains=3, other=5)
    assert result['records'] == 10
    assert set(result['payload_fields'].values()) == {'unknown'}
    assert not result['live_client_verified'] and not result['network_measured']
    public = json.dumps(result)
    assert all(host not in public for host in hosts)
    assert 'private-person' not in public
    assert path.read_bytes() == before


@pytest.mark.parametrize('content,status,rejected', [
    ('', 'empty', 0), ('{"password":"canary-secret"}', 'partial', 1),
    ('null\n[]\ninvalid', 'partial', 3),
    ('{"t":1,"host":"canary-secret","port":true}', 'partial', 1),
    ('x' * 65537, 'unavailable', 0),
], ids=['empty', 'unknown-schema', 'malformed', 'invalid-port', 'oversized'])
def test_refusal_and_empty(tmp_path, content, status, rejected):
    path = tmp_path / 'canary-secret.jsonl'
    path.write_text(content, encoding='utf-8')
    result = p.summarize(path)
    assert result['collection'] == status
    assert result['rejected_records'] == rejected
    assert 'canary-secret' not in json.dumps(result)


def test_unreadable(tmp_path):
    assert p.summarize(tmp_path / 'missing')['collection'] == 'unavailable'


def test_partial_keeps_valid_counts(tmp_path):
    path = journal(tmp_path, ['claude.ai'])
    with path.open('a') as stream:
        stream.write('\nbroken')
    result = p.summarize(path)
    assert result['collection'] == 'partial'
    assert result['records'] == result['rejected_records'] == 1


def test_button_and_cancel(tmp_path, monkeypatch):
    from claude_reset.app import App
    path = journal(tmp_path, ['claude.ai'])
    shown = []
    app = SimpleNamespace(run=lambda job, done: done(job()), show_json=shown.append)
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **kw: str(path))
    App.show_privacy_observations(app)
    assert shown[0]['records'] == 1
    monkeypatch.setattr('claude_reset.app.filedialog.askopenfilename', lambda **kw: '')
    App.show_privacy_observations(app)
    assert len(shown) == 1
