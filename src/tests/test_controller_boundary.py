"""Fake API and uniquely named test mutexes; never touch the installed mutex."""
import pytest

from claude_reset import controller_boundary as boundary


class Kernel:
    def __init__(self, *, opened=7, waited=0, release=True, close=True, failure=None):
        self.opened, self.waited = opened, waited
        self.release, self.close, self.failure = release, close, failure
        self.calls = []

    def call(self, name, result):
        self.calls.append(name)
        if self.failure == name:
            raise OSError('private fixture detail')
        return result

    def OpenMutexW(self, access, inherit, name):
        assert (access, inherit, name) == (0x100001, False, boundary.NAME)
        return self.call('open', self.opened)

    def WaitForSingleObject(self, handle, milliseconds):
        assert (handle, milliseconds) == (7, 0)
        return self.call('wait', self.waited)

    def ReleaseMutex(self, handle):
        assert handle == 7
        return self.call('release', self.release)

    def CloseHandle(self, handle):
        assert handle == 7
        return self.call('close', self.close)


@pytest.mark.parametrize('waited,expected', [(0, 'acquired'), (0x80, 'abandoned'),
                                           (258, 'busy'), (0xffffffff, 'unknown')])
def test_wait_and_cleanup(waited, expected):
    api = Kernel(waited=waited)
    assert boundary.observe(api=api) == expected
    assert api.calls == ['open', 'wait'] + (
        ['release'] if waited in (0, 0x80) else []) + ['close']


@pytest.mark.parametrize('failure', ['open', 'wait', 'release', 'close'])
def test_api_errors_are_unknown_and_handle_closed(failure):
    api = Kernel(failure=failure)
    assert boundary.observe(api=api) == 'unknown'
    if failure != 'open':
        assert api.calls[-1] == 'close'


@pytest.mark.parametrize('options', [{'opened': 0}, {'release': False}, {'close': False}])
def test_missing_access_denied_or_cleanup_failure_is_unknown(options):
    api = Kernel(**options)
    assert boundary.observe(api=api) == 'unknown'
    assert api.calls == (['open'] if options.get('opened') == 0 else
                         ['open', 'wait', 'release', 'close'])


@pytest.mark.parametrize('waited', [0, 0x80, 258, 0xffffffff])
def test_scope_lifetime_and_exception_cleanup(waited):
    api = Kernel(waited=waited)
    with pytest.raises(RuntimeError, match='fixture'):
        with boundary.hold(api=api) as witness:
            assert witness.held == (waited in (0, 0x80))
            assert api.calls == ['open', 'wait']
            raise RuntimeError('fixture')
    assert not witness.held
    assert api.calls == ['open', 'wait'] + (
        ['release'] if waited in (0, 0x80) else []) + ['close']


@pytest.mark.parametrize('options', [{'release': False}, {'close': False},
                                    {'failure': 'release'}, {'failure': 'close'}])
def test_scope_cleanup_failure_invalidates_witness(options):
    api = Kernel(**options)
    with boundary.hold(api=api) as witness:
        assert witness.held and witness.observation == 'acquired'
    assert not witness.held and witness.observation == 'unknown'
    assert api.calls[-1] == 'close'


def test_native_private_mutex_held_by_other_thread(monkeypatch):
    import ctypes as C
    import os
    import threading
    import uuid
    from concurrent.futures import ThreadPoolExecutor
    if os.name != 'nt':
        pytest.skip('Windows mutex')
    monkeypatch.setattr(boundary, 'NAME', 'Local\\ClaudeReset.Test.' + uuid.uuid4().hex)
    api = boundary._kernel()
    api.CreateMutexW.argtypes = [C.c_void_p, C.c_int, C.c_wchar_p]
    api.CreateMutexW.restype = C.c_void_p
    ready, stop = threading.Event(), threading.Event()
    def owner():
        handle = api.CreateMutexW(None, True, boundary.NAME)
        assert handle
        try:
            ready.set()
            assert stop.wait(5)
            assert api.ReleaseMutex(handle)
        finally:
            api.CloseHandle(handle)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(owner)
        try:
            assert ready.wait(5)
            assert boundary.observe() == 'busy'
        finally:
            stop.set()
        future.result(timeout=5)
    # The last handle is closed; missing never means no controller exists.
    assert boundary.observe() == 'unknown'


def test_native_private_mutex_acquisition_balanced(monkeypatch):
    import ctypes as C
    import os
    import uuid
    from concurrent.futures import ThreadPoolExecutor
    if os.name != 'nt':
        pytest.skip('Windows mutex')
    monkeypatch.setattr(boundary, 'NAME', 'Local\\ClaudeReset.Test.' + uuid.uuid4().hex)
    api = boundary._kernel()
    api.CreateMutexW.argtypes = [C.c_void_p, C.c_int, C.c_wchar_p]
    api.CreateMutexW.restype = C.c_void_p
    handle = api.CreateMutexW(None, False, boundary.NAME)
    assert handle
    try:
        assert boundary.observe() == 'acquired'
        with boundary.hold() as witness:
            assert witness.held
            with ThreadPoolExecutor(1) as pool:
                assert pool.submit(boundary.observe).result(timeout=5) == 'busy'
            # Recursive acquisition on this thread is balanced and proves no exit.
            assert boundary.observe() == 'acquired'
            with ThreadPoolExecutor(1) as pool:
                assert pool.submit(boundary.observe).result(timeout=5) == 'busy'
        assert not witness.held
        # Another thread can acquire after observation: no leaked ownership.
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(boundary.observe).result(timeout=5) == 'acquired'
    finally:
        api.CloseHandle(handle)
