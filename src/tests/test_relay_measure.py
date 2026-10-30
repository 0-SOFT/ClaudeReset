import json
import threading

from claude_reset.network.tunnel_transport import ConnectRelay


def relay(path):
    item = ConnectRelay.__new__(ConnectRelay)
    item.lock = threading.Lock()
    item.measure = path
    return item


def test_note_records_only_host_and_port(tmp_path):
    path = tmp_path / 'd.jsonl'
    relay(path).note('example.com', 443)
    row = json.loads(path.read_text('ascii'))
    assert set(row) == {'t', 'host', 'port'} and row['host'] == 'example.com' and row['port'] == 443


def test_note_is_off_by_default_and_bounded(tmp_path):
    assert relay(None).note('example.com', 443) is None
    path = tmp_path / 'd.jsonl'
    path.write_bytes(b'x' * 1_000_001)
    relay(path).note('example.com', 443)
    assert path.stat().st_size == 1_000_001


def test_note_survives_unwritable_path(tmp_path):
    relay(tmp_path / 'missing' / 'd.jsonl').note('example.com', 443)
