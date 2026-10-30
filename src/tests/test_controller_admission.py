"""Admission tests use temporary state and synthetic effects, never UAC/WFP."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from claude_reset.elevation import locks as admission, admission as gate, request as uac
from claude_reset.network import controller_status
from claude_reset.elevation import claims
from claude_reset.network import controller as guard, controller_process
from claude_reset.safeio import SafetyError
from test_uac_request import paths


@pytest.fixture
def effects(monkeypatch):
    calls = []
    kernel = MagicMock()
    kernel.CreateMutexW.return_value = 1
    kernel.WaitForSingleObject.return_value = 0
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel)
    monkeypatch.setattr(controller_process, 'generation', lambda pid: 123)
    monkeypatch.setattr(guard, 'run_admitted', lambda p, report, folder, state, **kw:
                        calls.append(state) or state)
    return calls


def serve(paths, request_id=None):
    return guard.serve(paths, paths.state / 'report.json', request_id=request_id)


@pytest.mark.parametrize('scheduler', [False, True])
def test_denial_only_binds_verified_explicit_identity(paths, effects, scheduler):
    request = uac.prepare(paths, 'start', scheduler=scheduler)
    uac.revoke(paths, request)
    for _ in range(2):
        with pytest.raises(SafetyError):
            serve(paths, None if scheduler else request.request_id)
    pattern = 'denied-unknown-*.json' if scheduler else 'child-*.json'
    rows = [json.loads(p.read_text()) for p in
            (paths.state / 'strict-guard').glob(pattern)]
    assert len(rows) == 2
    expected = None if scheduler else claims.receipt_identity(paths, 'start', request.request_id)
    assert all(r['identity'] == expected for r in rows)
    assert len({r['attempt_id'] for r in rows}) == 2
    assert effects == [] and claims.blocked(paths)


def test_stop_change_start_blocks_every_competitor_and_consumes_once(paths, effects):
    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        for phase in ('before_stop', 'after_stop', 'change'):
            with pytest.raises(SafetyError):
                serve(p)
            assert effects == [], phase
        request = uac.schedule(p.state / 'strict-guard')
        with pytest.raises(SafetyError):
            serve(SimpleNamespace(local=p.local, state=p.state.parent / 'other'))
        state = serve(p)
        assert state['request_id'] == request.request_id
        assert state['pid'] == os.getpid() and state['process_created'] == 123
        before = (p.state / 'strict-guard/status.json').read_bytes()
        with pytest.raises(SafetyError):
            serve(p)
        assert (p.state / 'strict-guard/status.json').read_bytes() == before
        return {'status': 'completed'}
    assert replace(paths)['status'] == 'completed'
    assert len(effects) == 1
    # A late parameterless scheduler invocation cannot become a fresh start
    # merely because the parent has successfully released its claim.
    with pytest.raises(SafetyError):
        serve(paths)
    assert len(effects) == 1


@pytest.mark.parametrize('damage', ['missing', 'corrupt', 'legacy'])
def test_missing_or_bad_status_never_grants_admission(paths, effects, damage):
    folder = paths.state / 'strict-guard'
    folder.mkdir(parents=True)
    if damage != 'missing':
        (folder / 'status.json').write_text('bad' if damage == 'corrupt' else '{}')
    before = (folder / 'status.json').read_bytes() if damage != 'missing' else None
    with pytest.raises(SafetyError):
        serve(paths)
    assert effects == []
    assert ((folder / 'status.json').read_bytes() if damage != 'missing' else None) == before


def test_direct_request_is_exact_one_use_and_late_uac_is_refused(paths, effects):
    request = uac.prepare(paths, 'start')
    for wrong in (None, 'b' * 32):
        with pytest.raises(SafetyError):
            serve(paths, wrong)
    assert effects == []
    assert serve(paths, request.request_id)['request_id'] == request.request_id
    with pytest.raises(SafetyError):
        serve(paths, request.request_id)
    uac.release(paths, request)
    with pytest.raises(SafetyError):
        serve(paths, request.request_id)
    assert len(effects) == 1


def test_denied_dispatch_revokes_the_late_start(paths, effects):
    saved = []
    assert uac.execute(paths, 'start', lambda r: saved.append(r) or 5)['status'] == 'denied'
    with pytest.raises(SafetyError):
        serve(paths, saved[0].request_id)
    assert effects == []


def test_owner_failure_keeps_claim_and_unconsumed_permission(paths, effects):
    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        uac.schedule(p.state / 'strict-guard')
        raise RuntimeError('modeled owner death')
    with pytest.raises(RuntimeError):
        replace(paths)
    assert claims.blocked(paths)
    # The already-issued child may still arrive. It remains fenced by the
    # durable claim; no recovery is allowed to assume that it cannot execute.
    serve(paths)
    assert len(effects) == 1 and claims.blocked(paths)


def test_uncertain_owner_cannot_issue_start(paths):
    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        claims.chain.get().uncertain = True
        with pytest.raises(SafetyError):
            uac.schedule(p.state / 'strict-guard')
        return {'status': 'incomplete'}
    assert replace(paths)['retry_blocked']
    assert not gate.permit_path(paths).exists()


@pytest.mark.parametrize('stage', ['request-before', 'request-after', 'permit-before', 'permit-after'])
@pytest.mark.parametrize('entry', ['execute', 'scheduler'])
def test_caught_preparation_failure_retains_claim_and_forbids_new_permit(paths, monkeypatch, stage, entry):
    effects = []
    saved = []
    original_save = claims.save_exclusive
    original_grant = gate.grant

    def save(path, data):
        if stage.startswith('request') and path.name.startswith('request-'):
            saved.append(data)
            if stage.endswith('after'):
                original_save(path, data)
            raise OSError('synthetic private write failure')
        original_save(path, data)

    def grant(p, request, **kwargs):
        if stage.startswith('permit'):
            if stage.endswith('after'):
                original_grant(p, request, **kwargs)
            raise OSError('synthetic private permit failure')
        original_grant(p, request, **kwargs)

    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        with monkeypatch.context() as patch:
            patch.setattr(claims, 'save_exclusive', save)
            patch.setattr(gate, 'grant', grant)
            with pytest.raises(OSError):
                if entry == 'execute':
                    uac.execute(p, 'start', lambda request: effects.append(request) or 42)
                else:
                    from claude_reset.network.l1_install import start_controller
                    start_controller(p.state / 'strict-guard', run=lambda *a, **k: effects.append('run'))
        # Restore the writers: refusal must come from ownership, not the fault.
        assert claims.blocked(p)
        before = gate.permit_path(p).read_bytes() if gate.permit_path(p).exists() else None
        with pytest.raises(SafetyError):
            uac.prepare(p, 'start')
        assert (gate.permit_path(p).read_bytes() if gate.permit_path(p).exists() else None) == before
        return {'status': 'completed'}

    assert replace(paths)['retry_blocked']
    assert claims.blocked(paths) and effects == []
    assert gate.permit_path(paths).exists() == (stage == 'permit-after')
    if stage == 'request-after':
        assert json.loads((paths.state / 'strict-guard' /
                           ('request-' + saved[0]['request_id'] + '.json')).read_text()) == saved[0]


def test_os_lock_excludes_an_independent_process_and_survives_release(paths):
    code = '''
import sys
from pathlib import Path
from types import SimpleNamespace
from claude_reset.elevation.locks import locked
from claude_reset.safeio import SafetyError
p = SimpleNamespace(local=Path(sys.argv[1]))
try:
    with locked(p):
        Path(sys.argv[2]).write_text('first effect')
except SafetyError:
    sys.exit(7)
'''
    marker = paths.state.parent / 'effect'
    def child():
        return subprocess.run([sys.executable, '-c', code, str(paths.local), str(marker)],
                              capture_output=True, timeout=15, creationflags=0x08000000)
    with admission.locked(paths):
        assert child().returncode == 7
        assert not marker.exists()
    lock = paths.local / 'ClaudeReset/admission.lock'
    inode = lock.stat().st_ino
    assert child().returncode == 0 and marker.read_text() == 'first effect'
    assert lock.stat().st_ino == inode


def test_busy_admission_does_not_create_claim_or_publish(paths, effects):
    with admission.locked(paths):
        with pytest.raises(SafetyError):
            uac.prepare(paths, 'start')
        with pytest.raises(SafetyError):
            serve(paths)
    assert not claims.pending_path(paths).exists()
    assert not (paths.state / 'strict-guard/status.json').exists()
    assert effects == []


def test_independent_start_process_is_fenced_through_change_and_handoff(paths):
    code = '''
import sys
from pathlib import Path
from types import SimpleNamespace
from claude_reset.elevation.locks import locked
from claude_reset.elevation.admission import consume
from claude_reset.safeio import SafetyError
p = SimpleNamespace(local=Path(sys.argv[1]), state=Path(sys.argv[2]))
try:
    with locked(p):
        identity = consume(p, None)
    Path(sys.argv[3]).write_text(identity['request_id'])
except SafetyError:
    sys.exit(7)
'''
    marker = paths.state.parent / 'child-effect'
    def start():
        return subprocess.run([sys.executable, '-c', code, str(paths.local), str(paths.state), str(marker)],
                              capture_output=True, timeout=15, creationflags=0x08000000).returncode
    @claims.serialized('replace', completed={'completed'})
    def replace(p):
        for phase in ('stop', 'change', 'before_start'):
            assert start() == 7, phase
            assert not marker.exists()
        request = uac.schedule(p.state / 'strict-guard')
        assert start() == 0
        assert marker.read_text() == request.request_id
        marker.unlink()
        assert start() == 7
        assert not marker.exists()
        return {'status': 'completed'}
    replace(paths)
    assert start() == 7
    assert not marker.exists()


@pytest.mark.parametrize('scheduler', [False, True])
@pytest.mark.parametrize('failure', ['generation', 'before-write', 'torn-write', 'status'])
def test_start_witness_failure_preserves_consumption(paths, effects, monkeypatch, scheduler, failure):
    from claude_reset.elevation import child_process as child
    request = uac.prepare(paths, 'start', scheduler=scheduler)
    save = claims.save_exclusive
    def fail(path, row):
        if path.name.startswith('process-'):
            if failure == 'torn-write':
                path.write_text('{')
            raise OSError('private fixture failure')
        save(path, row)
    if failure == 'generation':
        monkeypatch.setattr(controller_process, 'generation',
                            lambda pid: (_ for _ in ()).throw(OSError('private fixture failure')))
    elif failure == 'status':
        monkeypatch.setattr(controller_status, 'write',
                            lambda *args: (_ for _ in ()).throw(OSError('private fixture failure')))
    else:
        monkeypatch.setattr(claims, 'save_exclusive', fail)
    for attempt in range(2):
        expected = OSError if failure == 'status' and attempt == 0 else SafetyError
        with pytest.raises(expected):
            serve(paths, None if scheduler else request.request_id)
    assert json.loads(gate.permit_path(paths).read_text())['consumed'] is True
    assert effects == [] and claims.blocked(paths)
    assert not (paths.state / 'strict-guard/status.json').exists()
    if failure == 'status':
        assert json.loads(child.witness_path(request).read_text())['request']['request_id'] == request.request_id
