import json
import pytest
from test_backend_attestation import config
from test_reset import paths, FakeCrypto
from claude_reset import backend_profiles as b
from claude_reset.safeio import SafetyError


def profile():
    return {'schema': 1, 'adapter': 'sing_box_vless_reality_v1',
        'engine_path': 'C:\\Runtime\\engine.exe', 'engine_sha256': 'a' * 64,
        'engine_version': '1.12.0', 'config': config()}


def test_roundtrip_is_inactive_redacted_and_cannot_replace_existing_profile(tmp_path, paths):
    p = paths
    source = tmp_path / 'fixture.json'
    source.write_text(json.dumps(profile()))
    first = b.import_profile(p, source, crypto=FakeCrypto())
    second = b.import_profile(p, source, crypto=FakeCrypto())
    assert first['profile_id'] != second['profile_id']
    assert b.load(p, first['profile_id'], crypto=FakeCrypto()) == profile()
    assert b.status(p, first['profile_id'], crypto=FakeCrypto()) == first
    assert not first['selected'] and not first['client_network_opened']
    assert not first['engine_build_verified']
    assert len(list((p.state / 'backend-profiles').glob('*.dpapi'))) == 2
    for secret in ('fixture.invalid', '12345678-1234', 'C:\\Runtime', '1.1.1.1'):
        assert secret not in json.dumps(first)


@pytest.mark.parametrize('data', [b'{"schema":1,"schema":1}', b'[]', b'null', b'{' * 2000, b'x' * (b.LIMIT + 1)], ids=['duplicate','array','null','deep','oversized'])
def test_invalid_documents(data):
    with pytest.raises(SafetyError): b.decode(data)


@pytest.mark.parametrize('update', [
    {'schema': True}, {'engine_version': 'latest'}, {'engine_sha256': 'unknown'},
    {'engine_path': '\\\\server\\engine.exe'}, {'active': True}, {'config': None},
    {'adapter': 'auto'}, {'config': {'log': {'disabled': True}, 'inbounds': None}}])
def test_no_inferred_configuration_or_activation(update):
    value = profile(); value.update(update)
    with pytest.raises(SafetyError): b.decode(json.dumps(value).encode())


def test_duplicate_nested_configuration_keys():
    data = json.dumps(profile()).replace('"disabled": true', '"disabled": true, "disabled": false')
    with pytest.raises(SafetyError): b.decode(data.encode())


def test_no_file_open_for_remote_import_or_bad_identifier(paths, monkeypatch):
    p = paths
    def forbidden(*a, **kw): raise AssertionError('Must reject before file access')
    monkeypatch.setattr(b.Path, 'open', forbidden)
    with pytest.raises(SafetyError): b.import_profile(p, b.Path('\\\\server\\share\\profile.json'))
    with pytest.raises(SafetyError): b.load(p, '../other')


def test_catalog_is_redacted_inactive_and_reports_corrupt_profile(tmp_path, paths):
    assert b.catalog(paths,crypto=FakeCrypto())['profiles'] == []
    source=tmp_path/'fixture.json'; source.write_text(json.dumps(profile()))
    imported=b.import_profile(paths,source,crypto=FakeCrypto())
    broken='f'*32
    (paths.state/'backend-profiles'/(broken+'.dpapi')).write_bytes(FakeCrypto().encrypt(b'not json'))
    report=b.catalog(paths,crypto=FakeCrypto())
    assert len(report['profiles']) == 2 and report['selected_profile'] is None
    assert report['client_admission'] is False and report['network_requests'] == 0
    by_id={row['profile_id']:row for row in report['profiles']}
    assert by_id[imported['profile_id']] == imported
    assert by_id[broken]['status'] == 'unreadable_or_invalid'
    for secret in ('fixture.invalid','12345678-1234','1.1.1.1','C:\\Runtime'):
        assert secret not in json.dumps(report)
