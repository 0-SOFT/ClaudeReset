"""Profile mutations use temporary files and synthetic encryption only."""
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from claude_reset import connections, remote_backend, uac_request as uac
from claude_reset.safeio import SafetyError
from test_reset import paths, FakeCrypto
from test_connections import profile as connection_profile
from test_remote_backend import profile as remote_profile


@pytest.fixture(params=[(connections, connection_profile, connections.PROFILE_FILE),
                       (remote_backend, remote_profile, remote_backend.FILE)])
def entry(request):
    return request.param


@pytest.mark.parametrize('operation', ['save', 'remove'])
def test_busy_profile_entry_has_no_effect(paths, entry, operation):
    module, profile, filename = entry
    module.save(paths, profile(), crypto=FakeCrypto())
    before = (paths.state / filename).read_bytes()
    request = uac.prepare(paths, 'filters')
    claim = uac.pending_path(paths).read_bytes()
    with pytest.raises(SafetyError, match='ownership unavailable'):
        if operation == 'save':
            module.save(paths, profile(), crypto=FakeCrypto())
        else:
            module.remove(paths)
    assert (paths.state / filename).read_bytes() == before
    assert uac.pending_path(paths).read_bytes() == claim
    assert request.operation == 'filters'


def test_nested_profile_chain_keeps_claim_and_return_contract(paths, entry):
    module, profile, _ = entry

    @uac.serialized('test_chain', completed={'done'})
    def chain(paths):
        before = uac.pending_path(paths).read_bytes()
        saved = module.save(paths, profile(), crypto=FakeCrypto())
        assert saved is None if module is remote_backend else saved['passed'] is True
        assert module.load(paths, crypto=FakeCrypto()) == profile()
        # An independent caller with another archive must share arbitration.
        other = SimpleNamespace(local=paths.local, state=paths.state / 'other')
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(SafetyError):
                pool.submit(module.remove, other).result()
        assert module.remove(paths) is True
        assert module.remove(paths) is True
        assert uac.pending_path(paths).read_bytes() == before
        return {'status': 'done'}

    assert chain(paths) == {'status': 'done'}
    assert not uac.blocked(paths)


def test_partial_profile_write_cannot_be_hidden(paths, entry, monkeypatch):
    module, profile, filename = entry

    def fail(path, data, root):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'partial synthetic write')
        raise OSError('synthetic failure')

    monkeypatch.setattr(module, 'atomic_bytes', fail)

    @uac.serialized('test_chain', completed={'done'})
    def chain(paths):
        with pytest.raises(OSError):
            module.save(paths, profile(), crypto=FakeCrypto())
        with pytest.raises(SafetyError):
            module.remove(paths)
        return {'status': 'done'}

    assert chain(paths)['retry_blocked'] is True
    assert (paths.state / filename).read_bytes() == b'partial synthetic write'
    assert uac.blocked(paths)


def test_primitive_false_retains_claim(paths):
    @uac.serialized_effect('test_false', succeeded=lambda value: value is True)
    def effect(paths):
        return False

    with pytest.raises(SafetyError):
        effect(paths)
    assert uac.blocked(paths)
